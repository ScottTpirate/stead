package ci_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

type lifecycleRecorder struct {
	events   []policyrelease.LifecycleEvent
	callback func(policyrelease.LifecycleEvent)
	err      error
	panics   bool
}

func (recorder *lifecycleRecorder) ObservePolicyRelease(event policyrelease.LifecycleEvent) error {
	recorder.events = append(recorder.events, event)
	if recorder.callback != nil {
		recorder.callback(event)
	}
	if recorder.panics {
		panic("observer protected panic text")
	}
	return recorder.err
}

func lifecycleContext(suffix string) policyrelease.LifecycleContext {
	return policyrelease.LifecycleContext{
		OperationID:   "operation-" + suffix,
		CorrelationID: "correlation-" + suffix,
		CausationID:   "causation-" + suffix,
	}
}

type observedCeremonyResult struct {
	unsigned        policyrelease.UnsignedActivation
	activation      policyrelease.ActivationArchive
	inspection      policyrelease.ArchiveInspection
	validated       policyrelease.ArchiveInspection
	attestation     policyrelease.UnsignedReleaseAttestation
	handoff         policyrelease.ImmutableReleaseHandoff
	descriptor      policyrelease.TransportDescriptorV1
	descriptorBytes []byte
	activationInput policyrelease.BuildInput
}

func runObservedCeremony(t testing.TB, context policyrelease.LifecycleContext, recorder *lifecycleRecorder) observedCeremonyResult {
	t.Helper()
	workflow, err := policyrelease.NewObservedWorkflow(context, recorder)
	if err != nil {
		t.Fatal(err)
	}
	input := fixtureBuildInput(t, "commercial", 1, false)
	unsigned, err := workflow.PrepareUnsigned(input)
	if err != nil {
		t.Fatalf("observed PrepareUnsigned: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	activationEnvelope, activationSigning := externallySign(t, policyrelease.ActivationManifestPayloadType, unsigned.ManifestPayload, 1, false)
	activation, err := workflow.FinalizeActivationArchive(unsigned, activationEnvelope, activationSigning)
	if err != nil {
		t.Fatalf("observed FinalizeActivationArchive: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	inspection, err := workflow.InspectArchive(activation.ArchiveBytes)
	if err != nil {
		t.Fatalf("observed InspectArchive: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	validated, err := workflow.ValidateArchive(activation.ArchiveBytes, activation.EnvelopeBytes, activation.Unsigned.Manifest.Files)
	if err != nil {
		t.Fatalf("observed ValidateArchive: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	releaseInput := policyrelease.ReleaseAttestationInput{
		ReleaseWorkflowIdentity: "stead-ci-policy-release-workflow-v1",
		ReviewReceipts: []policyrelease.ReviewReceipt{{
			ReviewerID:         "fixture-final-reviewer",
			Role:               "independent-release",
			SubjectDigest:      activation.ArchiveDigest,
			RecordDigest:       policyrelease.SHA256Digest([]byte("fixture-final-review-record")),
			ClaimedDisposition: "accept",
		}},
		OfflineCheckReceipt: policyrelease.OfflineCheckReceipt{
			ClaimedOutcome:       "pass",
			SubjectArchiveDigest: activation.ArchiveDigest,
			ReportDigest:         policyrelease.SHA256Digest([]byte("offline-check-report")),
		},
	}
	attestation, err := workflow.PrepareReleaseAttestation(activation, releaseInput)
	if err != nil {
		t.Fatalf("observed PrepareReleaseAttestation: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	releaseEnvelope, releaseSigning := externallySign(t, policyrelease.ReleaseAttestationPayloadType, attestation.PayloadBytes, 1, false)
	handoff, err := workflow.FinalizeReleaseHandoff(activation, attestation, releaseEnvelope, releaseSigning)
	if err != nil {
		t.Fatalf("observed FinalizeReleaseHandoff: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	descriptor, descriptorBytes, err := workflow.BuildTransportDescriptor(handoff)
	if err != nil {
		t.Fatalf("observed BuildTransportDescriptor: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	return observedCeremonyResult{
		unsigned: unsigned, activation: activation, inspection: inspection, validated: validated,
		attestation: attestation, handoff: handoff, descriptor: descriptor,
		descriptorBytes: descriptorBytes, activationInput: input,
	}
}

func TestObservedWorkflowIsOutOfArtifactAndDeterministic(t *testing.T) {
	firstContext := lifecycleContext("first-boundary")
	secondContext := lifecycleContext("second-boundary")
	firstRecorder := &lifecycleRecorder{}
	secondRecorder := &lifecycleRecorder{}
	first := runObservedCeremony(t, firstContext, firstRecorder)
	second := runObservedCeremony(t, secondContext, secondRecorder)

	bytePairs := []struct {
		name          string
		first, second []byte
	}{
		{"activation manifest", first.unsigned.ManifestPayload, second.unsigned.ManifestPayload},
		{"activation signing request", first.unsigned.SigningRequestBytes, second.unsigned.SigningRequestBytes},
		{"activation envelope", first.activation.EnvelopeBytes, second.activation.EnvelopeBytes},
		{"activation archive", first.activation.ArchiveBytes, second.activation.ArchiveBytes},
		{"release attestation", first.attestation.PayloadBytes, second.attestation.PayloadBytes},
		{"release signing request", first.attestation.SigningRequestBytes, second.attestation.SigningRequestBytes},
		{"release envelope", first.handoff.ReleaseAttestationEnvelopeBytes, second.handoff.ReleaseAttestationEnvelopeBytes},
		{"transport descriptor", first.descriptorBytes, second.descriptorBytes},
	}
	identifiers := []string{
		firstContext.OperationID, firstContext.CorrelationID, firstContext.CausationID,
		secondContext.OperationID, secondContext.CorrelationID, secondContext.CausationID,
	}
	for _, pair := range bytePairs {
		if !bytes.Equal(pair.first, pair.second) {
			t.Fatalf("%s changed with lifecycle identifiers", pair.name)
		}
		for _, identifier := range identifiers {
			if bytes.Contains(pair.first, []byte(identifier)) || bytes.Contains(pair.second, []byte(identifier)) {
				t.Fatalf("%s contains lifecycle identifier %q", pair.name, identifier)
			}
		}
	}
	if !reflect.DeepEqual(first.inspection, second.inspection) || !reflect.DeepEqual(first.validated, second.validated) || first.descriptor != second.descriptor {
		t.Fatal("typed operation outputs changed with lifecycle identifiers")
	}

	wantStages := []policyrelease.LifecycleStageCode{
		policyrelease.LifecycleStagePrepareUnsigned,
		policyrelease.LifecycleStageFinalizeActivationArchive,
		policyrelease.LifecycleStageInspectArchive,
		policyrelease.LifecycleStageValidateArchive,
		policyrelease.LifecycleStagePrepareReleaseAttestation,
		policyrelease.LifecycleStageFinalizeReleaseHandoff,
		policyrelease.LifecycleStageBuildTransportDescriptor,
	}
	for _, observation := range []struct {
		context policyrelease.LifecycleContext
		events  []policyrelease.LifecycleEvent
	}{{firstContext, firstRecorder.events}, {secondContext, secondRecorder.events}} {
		if len(observation.events) != len(wantStages) {
			t.Fatalf("terminal observations=%d, want %d", len(observation.events), len(wantStages))
		}
		for index, event := range observation.events {
			if event.Stage != wantStages[index] || event.Outcome != policyrelease.LifecycleOutcomeSuccess || event.ErrorCode != "" || event.Context != observation.context {
				t.Fatalf("success event[%d] = %#v", index, event)
			}
			if event.Authority != policyrelease.NonAuthorizingHandoffAuthority || event.ProducerOwner != policyrelease.LifecycleObservationProducerOwner || event.DurableAuditOwner != policyrelease.LifecycleObservationDurableOwner {
				t.Fatalf("event ownership/authority = %#v", event)
			}
		}
	}
	if firstRecorder.events[0].Facts.ActivationSetID != first.unsigned.ActivationSetID || firstRecorder.events[0].Facts.RequiredSignatureThreshold != 1 || firstRecorder.events[0].Facts.PresentedReviewReceiptCount != 1 ||
		firstRecorder.events[1].Facts.SignedEnvelopeDigest != first.activation.SignedEnvelopeDigest || firstRecorder.events[1].Facts.ArchiveDigest != first.activation.ArchiveDigest || firstRecorder.events[1].Facts.PresentedSigningReceiptSetDigest != first.activation.PresentedActivationSigning.ReceiptSetDigest ||
		firstRecorder.events[4].Facts.ReleaseAttestationID != first.attestation.AttestationID || firstRecorder.events[4].Facts.PresentedOfflineReportDigest == "" ||
		firstRecorder.events[5].Facts.ReleaseAttestationEnvelopeDigest != first.handoff.ReleaseAttestationEnvelopeDigest || firstRecorder.events[5].Facts.PresentedSigningReceiptSetDigest != first.handoff.PresentedReleaseSigning.ReceiptSetDigest ||
		firstRecorder.events[6].Facts.ArchiveDigest != first.handoff.ArchiveDigest || firstRecorder.events[6].Facts.ReleaseAttestationEnvelopeDigest != first.handoff.ReleaseAttestationEnvelopeDigest {
		t.Fatalf("required safe lifecycle facts are incomplete: %#v", firstRecorder.events)
	}
}

func TestObservedWorkflowEmitsEveryFailureTerminalOnce(t *testing.T) {
	activation, attestation, handoff := completeFixtureRelease(t, "commercial", 1, false)
	recorder := &lifecycleRecorder{}
	workflow, err := policyrelease.NewObservedWorkflow(lifecycleContext("failure-paths"), recorder)
	if err != nil {
		t.Fatal(err)
	}
	testCases := []struct {
		stage policyrelease.LifecycleStageCode
		run   func() (bool, error)
	}{
		{policyrelease.LifecycleStagePrepareUnsigned, func() (bool, error) {
			result, err := workflow.PrepareUnsigned(policyrelease.BuildInput{})
			return result.ManifestPayload == nil && result.SigningRequestBytes == nil, err
		}},
		{policyrelease.LifecycleStageFinalizeActivationArchive, func() (bool, error) {
			result, err := workflow.FinalizeActivationArchive(activation.Unsigned, nil, activation.PresentedActivationSigning)
			return result.ArchiveBytes == nil && result.EnvelopeBytes == nil, err
		}},
		{policyrelease.LifecycleStageInspectArchive, func() (bool, error) {
			result, err := workflow.InspectArchive(nil)
			return result.Files == nil && result.Directories == nil, err
		}},
		{policyrelease.LifecycleStageValidateArchive, func() (bool, error) {
			result, err := workflow.ValidateArchive(nil, nil, nil)
			return result.Files == nil && result.Directories == nil, err
		}},
		{policyrelease.LifecycleStagePrepareReleaseAttestation, func() (bool, error) {
			result, err := workflow.PrepareReleaseAttestation(activation, policyrelease.ReleaseAttestationInput{})
			return result.PayloadBytes == nil && result.SigningRequestBytes == nil, err
		}},
		{policyrelease.LifecycleStageFinalizeReleaseHandoff, func() (bool, error) {
			result, err := workflow.FinalizeReleaseHandoff(activation, attestation, nil, handoff.PresentedReleaseSigning)
			return result.ArchiveBytes == nil && result.ReleaseAttestationEnvelopeBytes == nil, err
		}},
		{policyrelease.LifecycleStageBuildTransportDescriptor, func() (bool, error) {
			descriptor, encoded, err := workflow.BuildTransportDescriptor(policyrelease.ImmutableReleaseHandoff{})
			return descriptor.ArchiveDigest == "" && encoded == nil, err
		}},
	}
	for _, testCase := range testCases {
		before := len(recorder.events)
		zero, err := testCase.run()
		if err == nil || !zero {
			t.Fatalf("%s did not fail with zero output: zero=%t err=%v", testCase.stage, zero, err)
		}
		if len(recorder.events) != before+1 {
			t.Fatalf("%s observations=%d, want exactly one new event", testCase.stage, len(recorder.events)-before)
		}
		event := recorder.events[before]
		if event.Stage != testCase.stage || event.Outcome != policyrelease.LifecycleOutcomeFailure || event.ErrorCode != policyrelease.ErrorCode(err) || event.ErrorCode == "" {
			t.Fatalf("%s failure event = %#v; err=%v", testCase.stage, event, err)
		}
	}
}

func TestLifecycleObserverFailuresPanicAndReentrancyFailClosed(t *testing.T) {
	input := fixtureBuildInput(t, "commercial", 1, false)
	testCases := []struct {
		name     string
		recorder *lifecycleRecorder
	}{
		{"error", &lifecycleRecorder{err: errors.New("protected observer error text")}},
		{"panic", &lifecycleRecorder{panics: true}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			workflow, err := policyrelease.NewObservedWorkflow(lifecycleContext("observer-"+testCase.name), testCase.recorder)
			if err != nil {
				t.Fatal(err)
			}
			result, err := workflow.PrepareUnsigned(input)
			if policyrelease.ErrorCode(err) != "lifecycle_observer_failed" || err.Error() != "lifecycle_observer_failed" || result.ManifestPayload != nil || result.SigningRequestBytes != nil || len(testCase.recorder.events) != 1 {
				t.Fatalf("observer %s result: output=%d/%d events=%d err=%v (%s)", testCase.name, len(result.ManifestPayload), len(result.SigningRequestBytes), len(testCase.recorder.events), err, policyrelease.ErrorCode(err))
			}
		})
	}

	type reentrantObserver struct {
		workflow *policyrelease.ObservedWorkflow
		calls    int
		innerErr error
	}
	observer := &reentrantObserver{}
	var adapter policyrelease.LifecycleObserverFunc = func(policyrelease.LifecycleEvent) error {
		observer.calls++
		inspection, err := observer.workflow.InspectArchive(nil)
		if inspection.Files != nil || inspection.Directories != nil {
			t.Fatal("reentrant call returned partial output")
		}
		observer.innerErr = err
		return nil
	}
	workflow, err := policyrelease.NewObservedWorkflow(lifecycleContext("observer-reentrant"), adapter)
	if err != nil {
		t.Fatal(err)
	}
	observer.workflow = workflow
	result, err := workflow.PrepareUnsigned(input)
	if policyrelease.ErrorCode(err) != "lifecycle_observer_failed" || policyrelease.ErrorCode(observer.innerErr) != "lifecycle_observer_failed" || result.ManifestPayload != nil || observer.calls != 1 {
		t.Fatalf("reentrancy result: output=%d calls=%d inner=%v outer=%v", len(result.ManifestPayload), observer.calls, observer.innerErr, err)
	}
}

func TestLifecycleContextAndEventsAreBoundedCopiedAndRedacted(t *testing.T) {
	exact := strings.Repeat("a", policyrelease.MaxLifecycleIdentifierBytes)
	context := policyrelease.LifecycleContext{OperationID: exact, CorrelationID: exact, CausationID: exact}
	seen := make([]policyrelease.LifecycleEvent, 0, 2)
	observer := policyrelease.LifecycleObserverFunc(func(event policyrelease.LifecycleEvent) error {
		seen = append(seen, event)
		event.Context.OperationID = "observer-mutated-copy"
		event.Facts.ArchiveDigest = policyrelease.SHA256Digest([]byte("observer-mutated-copy"))
		return nil
	})
	workflow, err := policyrelease.NewObservedWorkflow(context, observer)
	if err != nil {
		t.Fatalf("exact lifecycle identifier ceiling: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	context.OperationID = "caller-mutated-context"
	context.CorrelationID = "caller-mutated-context"
	if _, err := workflow.InspectArchive(nil); err == nil {
		t.Fatal("invalid archive unexpectedly inspected")
	}
	if _, err := workflow.InspectArchive(nil); err == nil {
		t.Fatal("second invalid archive unexpectedly inspected")
	}
	if len(seen) != 2 || seen[0].Context.OperationID != exact || seen[1].Context.OperationID != exact || seen[0].Facts.ArchiveDigest != "" || seen[1].Facts.ArchiveDigest != "" {
		t.Fatalf("context/event copies changed: %#v", seen)
	}

	for _, invalid := range []policyrelease.LifecycleContext{
		{OperationID: strings.Repeat("a", policyrelease.MaxLifecycleIdentifierBytes+1), CorrelationID: "correlation", CausationID: "causation"},
		{OperationID: "operation", CorrelationID: "contains protected whitespace", CausationID: "causation"},
		{OperationID: "operation", CorrelationID: "correlation", CausationID: ""},
	} {
		if candidate, err := policyrelease.NewObservedWorkflow(invalid, observer); policyrelease.ErrorCode(err) != "invalid_lifecycle_context" || candidate != nil {
			t.Fatalf("invalid lifecycle context = %#v err=%v (%s)", invalid, err, policyrelease.ErrorCode(err))
		}
	}
	if candidate, err := policyrelease.NewObservedWorkflow(lifecycleContext("nil-observer"), nil); policyrelease.ErrorCode(err) != "lifecycle_observer_required" || candidate != nil {
		t.Fatalf("nil observer = %#v err=%v (%s)", candidate, err, policyrelease.ErrorCode(err))
	}

	const protected = "protected/private-key/path parser credential body"
	recorder := &lifecycleRecorder{}
	redactedWorkflow, err := policyrelease.NewObservedWorkflow(lifecycleContext("redaction"), recorder)
	if err != nil {
		t.Fatal(err)
	}
	input := fixtureBuildInput(t, "commercial", 1, false)
	input.Evidence.BuilderIdentity = protected
	input.Manifest.DeploymentPolicy.Digest = protected
	if _, err := redactedWorkflow.PrepareUnsigned(input); err == nil {
		t.Fatal("protected invalid identifier unexpectedly accepted")
	}
	encoded, err := json.Marshal(recorder.events)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(protected)) || bytes.Contains(encoded, input.PayloadFiles[0].Content) || recorder.events[0].Facts.DeploymentPolicyDigest != "" {
		t.Fatalf("observation retained protected input: %s", encoded)
	}

	boundedInput := fixtureBuildInput(t, "commercial", 1, false)
	boundedInput.Evidence.ReviewReceipts = make([]policyrelease.ReviewReceipt, policyrelease.MaxReviewReceipts+100)
	if _, err := redactedWorkflow.PrepareUnsigned(boundedInput); policyrelease.ErrorCode(err) != "review_receipt_count_limit" {
		t.Fatalf("oversized observed reviews = %v (%s)", err, policyrelease.ErrorCode(err))
	}
	last := recorder.events[len(recorder.events)-1]
	if last.Facts.PresentedReviewReceiptCount != policyrelease.MaxReviewReceipts+1 {
		t.Fatalf("bounded review fact=%d, want overflow sentinel %d", last.Facts.PresentedReviewReceiptCount, policyrelease.MaxReviewReceipts+1)
	}
}

type lifecycleContractFixture struct {
	SchemaVersion       string                                `json:"schema_version"`
	Authority           string                                `json:"authority"`
	ProducerOwner       string                                `json:"producer_owner"`
	DurableAuditOwner   string                                `json:"durable_audit_owner"`
	IdentifierMaxBytes  int                                   `json:"identifier_max_bytes"`
	ObserverFailureCode string                                `json:"observer_failure_code"`
	Workflows           []policyrelease.LifecycleWorkflowCode `json:"workflows"`
	Outcomes            []policyrelease.LifecycleOutcomeCode  `json:"outcomes"`
	Stages              []policyrelease.LifecycleStageCode    `json:"stages"`
	EventFields         []string                              `json:"event_fields"`
	FactFields          []string                              `json:"fact_fields"`
}

func jsonFieldNames(kind reflect.Type) []string {
	result := make([]string, 0, kind.NumField())
	for index := 0; index < kind.NumField(); index++ {
		name := strings.Split(kind.Field(index).Tag.Get("json"), ",")[0]
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func TestLifecycleObservationFixtureClosesTheSafeSurface(t *testing.T) {
	var fixture lifecycleContractFixture
	if err := json.Unmarshal(fixtureBytes(t, "observation/lifecycle-contract.json"), &fixture); err != nil {
		t.Fatal(err)
	}
	wantStages := []policyrelease.LifecycleStageCode{
		policyrelease.LifecycleStagePrepareUnsigned,
		policyrelease.LifecycleStageFinalizeActivationArchive,
		policyrelease.LifecycleStageInspectArchive,
		policyrelease.LifecycleStageValidateArchive,
		policyrelease.LifecycleStagePrepareReleaseAttestation,
		policyrelease.LifecycleStageFinalizeReleaseHandoff,
		policyrelease.LifecycleStageBuildTransportDescriptor,
	}
	if fixture.SchemaVersion != policyrelease.LifecycleObservationSchemaVersion || fixture.Authority != policyrelease.NonAuthorizingHandoffAuthority || fixture.ProducerOwner != policyrelease.LifecycleObservationProducerOwner || fixture.DurableAuditOwner != policyrelease.LifecycleObservationDurableOwner || fixture.IdentifierMaxBytes != policyrelease.MaxLifecycleIdentifierBytes || fixture.ObserverFailureCode != "lifecycle_observer_failed" {
		t.Fatalf("lifecycle fixture header = %#v", fixture)
	}
	if !reflect.DeepEqual(fixture.Workflows, []policyrelease.LifecycleWorkflowCode{policyrelease.LifecycleWorkflowActivation, policyrelease.LifecycleWorkflowRelease, policyrelease.LifecycleWorkflowTransport}) || !reflect.DeepEqual(fixture.Outcomes, []policyrelease.LifecycleOutcomeCode{policyrelease.LifecycleOutcomeFailure, policyrelease.LifecycleOutcomeSuccess}) || !reflect.DeepEqual(fixture.Stages, wantStages) {
		t.Fatalf("lifecycle fixture codes: workflows=%v outcomes=%v stages=%v", fixture.Workflows, fixture.Outcomes, fixture.Stages)
	}
	sort.Strings(fixture.EventFields)
	sort.Strings(fixture.FactFields)
	if !reflect.DeepEqual(fixture.EventFields, jsonFieldNames(reflect.TypeOf(policyrelease.LifecycleEvent{}))) || !reflect.DeepEqual(fixture.FactFields, jsonFieldNames(reflect.TypeOf(policyrelease.LifecycleFacts{}))) {
		t.Fatalf("fixture safe fields drifted: events=%v facts=%v", fixture.EventFields, fixture.FactFields)
	}
	for _, kind := range []reflect.Type{reflect.TypeOf(policyrelease.LifecycleContext{}), reflect.TypeOf(policyrelease.LifecycleFacts{}), reflect.TypeOf(policyrelease.LifecycleEvent{})} {
		for index := 0; index < kind.NumField(); index++ {
			fieldKind := kind.Field(index).Type.Kind()
			if fieldKind == reflect.Slice || fieldKind == reflect.Map || fieldKind == reflect.Pointer || fieldKind == reflect.Interface {
				t.Fatalf("%s.%s admits mutable or unbounded kind %s", kind.Name(), kind.Field(index).Name, fieldKind)
			}
		}
	}
}

func TestLifecycleObservationSeamHasNoIOAuthority(t *testing.T) {
	source := repositoryBytes(t, "modules/ci/policyrelease/observation.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), "observation.go", source, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"strings": true, "sync/atomic": true}
	for _, imported := range parsed.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if !allowed[path] {
			t.Fatalf("lifecycle seam acquired I/O or provider dependency %q", path)
		}
	}
}
