package ci_test

import (
	"bytes"
	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
	"testing"
)

func TestRuntimeConsumerReusesCompleteArchiveAndContentValidation(t *testing.T) {
	activation := fixtureActivation(t)
	workflow, err := newTestObservedWorkflow()
	if err != nil {
		t.Fatal(err)
	}
	unsigned, envelope, err := workflow.ValidateActivationArchive(activation.ArchiveBytes)
	if err != nil {
		t.Fatalf("consumer: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	if unsigned.ActivationSetID != activation.Unsigned.ActivationSetID || !bytes.Equal(envelope, activation.EnvelopeBytes) {
		t.Fatal("consumer changed presented identity")
	}
	corrupt := append([]byte(nil), activation.ArchiveBytes...)
	corrupt[0] ^= 1
	if _, _, err := workflow.ValidateActivationArchive(corrupt); err == nil {
		t.Fatal("corrupt archive accepted")
	}
}
