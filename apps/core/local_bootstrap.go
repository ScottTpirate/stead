package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/devweb"
	"github.com/ScottTpirate/stead/apps/core/internal/localdev"
	"github.com/ScottTpirate/stead/apps/core/internal/postgres"
	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/ci/policyrelease"
	"github.com/ScottTpirate/stead/modules/identity"
)

type localBootstrapRecord struct {
	SchemaVersion    string `json:"schema_version"`
	InstanceID       string `json:"instance_id"`
	SecurityDomain   string `json:"security_domain"`
	StoreID          string `json:"openfga_store_id"`
	ModelID          string `json:"openfga_model_id"`
	PrincipalID      string `json:"principal_id"`
	SessionID        string `json:"session_id"`
	LabelID          string `json:"label_id"`
	ActivationDigest string `json:"activation_digest"`
	DevelopmentOnly  bool   `json:"development_only"`
}

type localStageError string

func (err localStageError) Error() string { return string(err) }

func runDevTemplateInspect(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: stead-api dev-template-inspect")
		return 2
	}
	repository, err := os.Getwd()
	if err != nil {
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	core, err := authorization.InspectLocalTemplateSource(ctx, repository)
	if err != nil {
		fmt.Fprintln(stderr, "stead-api: clean immutable template source inspection failed")
		return 1
	}
	if json.NewEncoder(stdout).Encode(core) != nil {
		return 1
	}
	return 0
}

func runDevPolicyCheck(args []string, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if localdev.RunOfflineCommand(ctx, args, os.Stdin, os.Stdout) != nil {
		fmt.Fprintln(stderr, "stead-api: local offline policy verification failed")
		return 1
	}
	return 0
}

func runDevBootstrap(args []string, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: stead-api dev-bootstrap (explicit private local configuration required)")
		return 2
	}
	config, err := localdev.Load(os.Getenv, true)
	if err != nil {
		fmt.Fprintln(stderr, "stead-api: local bootstrap configuration rejected")
		return 1
	}
	repository, err := os.Getwd()
	if err != nil {
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	err = bootstrapLocal(ctx, repository, config, os.Getenv, localdev.CheckRunner{RepositoryRoot: repository})
	if err != nil {
		stage := "verification"
		var code localStageError
		if errors.As(err, &code) {
			stage = string(code)
		}
		fmt.Fprintf(stderr, "stead-api: local bootstrap failed at %s; existing evidence and state were preserved\n", stage)
		return 1
	}
	fmt.Fprintln(stderr, "stead-api: synthetic-only local bootstrap complete; private one-time login token retained in state directory")
	return 0
}

func newLocalPolicyWorkflow(directory string) (*policyrelease.ObservedWorkflow, error) {
	if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if localdev.PrivateDirectory(directory) != nil {
		return nil, localStageError("policy-observation")
	}
	id, err := postgres.NewID()
	if err != nil {
		return nil, err
	}
	observer := policyrelease.LifecycleObserverFunc(func(event policyrelease.LifecycleEvent) (policyrelease.LifecycleAcknowledgement, error) {
		ack := policyrelease.AcknowledgeLifecycleEvent(event)
		encoded, err := json.Marshal(event)
		if err != nil {
			return policyrelease.LifecycleAcknowledgement{}, err
		}
		fileID, err := postgres.NewID()
		if err != nil {
			return policyrelease.LifecycleAcknowledgement{}, err
		}
		if err := localdev.WriteExclusive(filepath.Join(directory, fileID+".json"), encoded); err != nil {
			return policyrelease.LifecycleAcknowledgement{}, err
		}
		return ack, nil
	})
	return policyrelease.NewObservedWorkflow(policyrelease.LifecycleContext{OperationID: id, CorrelationID: id, CausationID: id}, observer)
}

func bootstrapLocal(ctx context.Context, repository string, config localdev.Config, getenv func(string) string, runner authorization.LocalCheckRunner) error {
	if localdev.PrivateDirectory(config.StateDirectory) != nil || localdev.PrivateDirectory(config.PolicyDirectory) != nil || config.PolicyDirectory != filepath.Join(config.StateDirectory, "policy") || config.SecurityDomain != authorization.LocalDevelopmentSecurityDomain || !identity.ValidID(config.InstanceID) || getenv("STEAD_TLS_CERT_FILE") != filepath.Join(config.StateDirectory, "tls/localhost.crt") || getenv("STEAD_TLS_KEY_FILE") != filepath.Join(config.StateDirectory, "tls/localhost.key") || localdev.PrivateDirectory(filepath.Join(config.StateDirectory, "tls")) != nil {
		return localStageError("private-configuration")
	}
	if err := postgres.CheckFreshBootstrapDatabase(ctx, config.DatabaseAdminURL, "stead"); err != nil {
		return localStageError("fresh-database")
	}
	started, _ := json.Marshal(struct{ SchemaVersion, InstallationID string }{"1.0.0", config.InstanceID})
	if err := localdev.WriteExclusive(filepath.Join(config.StateDirectory, "bootstrap.started"), started); err != nil {
		return localStageError("existing-bootstrap")
	}
	workflow, err := newLocalPolicyWorkflow(filepath.Join(config.StateDirectory, "policy-events"))
	if err != nil {
		return localStageError("policy-observation")
	}
	draft, err := authorization.PrepareLocalDevelopment(ctx, authorization.LocalDevelopmentConfig{RepositoryRoot: repository, InstallationID: config.InstanceID, PublicOrigin: config.Origin, OpenFGAURL: config.OpenFGAURL, OpenFGAToken: config.OpenFGAToken, InstallerID: "stead-local-development-installer", Now: time.Now().UTC(), LocalDevelopment: true, Runner: runner, Workflow: workflow})
	if err != nil {
		return localStageError("reviewed-template")
	}
	artifacts, err := draft.Finalize(ctx)
	if err != nil {
		return localStageError("actual-policy-evidence")
	}
	if artifacts.Activation == nil || !artifacts.Activation.ValidAt(time.Now().UTC()) || artifacts.Anchor.Binding.InstallationID != config.InstanceID || artifacts.Anchor.Binding.DeploymentPolicyID != config.SecurityDomain {
		return localStageError("activation-binding")
	}
	for _, file := range []struct {
		name string
		data []byte
	}{{"activation.tar", artifacts.Archive}, {"derivation.dsse.json", artifacts.DerivationEnvelope}, {"trust-keys.json", marshalLocal(artifacts.TrustedKeys)}} {
		if err := localdev.WriteExclusive(filepath.Join(config.PolicyDirectory, file.name), file.data); err != nil {
			return localStageError("policy-persistence")
		}
	}
	for i, file := range artifacts.EvidenceFiles {
		if err := localdev.WriteExclusive(filepath.Join(config.PolicyDirectory, fmt.Sprintf("evidence-%02d.json", i)), file.Content); err != nil {
			return localStageError("evidence-persistence")
		}
	}
	anchor, err := authorization.CreateLocalAnchor(filepath.Join(config.StateDirectory, "policy-anchor.json"), artifacts.Anchor)
	if err != nil {
		return localStageError("independent-anchor")
	}
	principalID, err := postgres.NewID()
	if err != nil {
		return localStageError("identity-randomness")
	}
	sessionID, err := postgres.NewID()
	if err != nil {
		return localStageError("identity-randomness")
	}
	labelID, err := postgres.NewID()
	if err != nil {
		return localStageError("identity-randomness")
	}
	token, digest, err := identity.NewLocalToken()
	if err != nil {
		return localStageError("identity-randomness")
	}
	grant := []authorization.Tuple{{User: "user:" + principalID, Relation: "organization_creator", Object: "instance:" + config.InstanceID}}
	intent := struct {
		InstanceID, PrincipalID, SessionID, LabelID, ActivationDigest string
		TokenDigest                                                   [32]byte
		Tuples                                                        []authorization.Tuple
	}{config.InstanceID, principalID, sessionID, labelID, artifacts.Anchor.Binding.Digest(), digest, grant}
	if err := localdev.WriteExclusive(filepath.Join(config.StateDirectory, "bootstrap-identity-intent.json"), marshalLocal(intent)); err != nil {
		return localStageError("identity-intent-persistence")
	}
	receipt, err := artifacts.OpenFGA.WriteVerified(ctx, grant)
	if err != nil || !receipt.Match(grant) {
		return localStageError("explicit-instance-grant")
	}
	grantEvidence := struct {
		StoreID, ModelID string
		VerifiedAt       time.Time
		Tuples           []authorization.Tuple
	}{receipt.StoreID(), receipt.ModelID(), receipt.VerifiedAt(), grant}
	if err := localdev.WriteExclusive(filepath.Join(config.StateDirectory, "bootstrap-instance-grant.json"), marshalLocal(grantEvidence)); err != nil {
		return localStageError("grant-evidence-persistence")
	}
	now := time.Now().UTC()
	label, ceilings, err := artifacts.Activation.LocalBootstrapDefaults()
	if err != nil {
		return localStageError("signed-bootstrap-label")
	}
	session := identity.SessionRecord{ID: sessionID, Principal: identity.Principal{Type: "user", ID: principalID}, InstanceID: config.InstanceID, SecurityDomain: config.SecurityDomain, Authority: "stead_local_identity", AuthenticationStrength: "local_bootstrap", NetworkZone: "loopback", DeviceTrust: "local", Environment: "local-development", ClassificationCeilings: ceilings, IssuedAt: now, ExpiresAt: now.Add(8 * time.Hour), Revision: 1, PrincipalRevision: 1, Active: true, PrincipalActive: true}
	result, err := postgres.Bootstrap(ctx, postgres.BootstrapConfig{AdminDSN: config.DatabaseAdminURL, AppPassword: config.DatabasePassword, InstanceID: config.InstanceID, SecurityDomain: config.SecurityDomain, OpenFGAStoreID: artifacts.OpenFGA.StoreID(), ActivationBinding: artifacts.Anchor.Binding, PolicyTimeHighWater: artifacts.Anchor.PolicyTimeHighWater, PolicyTimeRevision: artifacts.Anchor.PolicyTimeRevision, LabelID: labelID, Label: label, Session: session, TokenDigest: digest})
	if err != nil {
		return localStageError("database-bootstrap")
	}
	runtimeURL, err := localdev.RuntimeDatabaseURL(config.DatabaseAdminURL, result.RuntimeRole, config.DatabasePassword)
	if err != nil {
		return localStageError("runtime-credential")
	}
	store, err := postgres.Open(ctx, postgres.Config{DSN: runtimeURL, InstanceID: config.InstanceID, SecurityDomain: config.SecurityDomain, OpenFGAStoreID: artifacts.OpenFGA.StoreID(), Anchor: anchor})
	if err != nil {
		return localStageError("runtime-database")
	}
	defer store.Close()
	authenticator, err := identity.NewLocalAuthenticator(store, config.InstanceID, time.Now)
	if err != nil {
		return localStageError("central-identity")
	}
	authenticated, err := authenticator.Authenticate(ctx, token)
	if err != nil {
		return localStageError("central-identity")
	}
	coordinator, err := authorization.NewCoordinator(authorization.Config{Repository: store, Denials: store, OpenFGA: artifacts.OpenFGA, Activation: artifacts.Activation, Anchor: anchor, Clock: time.Now})
	if err != nil {
		return localStageError("central-authorization")
	}
	decision, err := coordinator.Authorize(ctx, authenticated, authorization.OrganizationCreate, authorization.ResourceRef{Kind: "instance", ID: config.InstanceID})
	if err != nil {
		return localStageError("fresh-authorization")
	}
	if _, err := store.FinalizeResponse(ctx, []*authorization.Decision{decision}); err != nil {
		return localStageError("final-authorization-fence")
	}
	if err := devweb.GenerateCertificate(filepath.Join(config.StateDirectory, "tls"), now); err != nil {
		return localStageError("localhost-tls")
	}
	if err := localdev.WriteExclusive(filepath.Join(config.StateDirectory, "database-url"), []byte(runtimeURL)); err != nil {
		return localStageError("runtime-credential-persistence")
	}
	if err := localdev.WriteExclusive(filepath.Join(config.StateDirectory, "one-time-login-token"), []byte(token)); err != nil {
		return localStageError("one-time-token-persistence")
	}
	record := localBootstrapRecord{SchemaVersion: "1.0.0", InstanceID: config.InstanceID, SecurityDomain: config.SecurityDomain, StoreID: artifacts.OpenFGA.StoreID(), ModelID: artifacts.OpenFGA.ModelID(), PrincipalID: principalID, SessionID: sessionID, LabelID: labelID, ActivationDigest: artifacts.Anchor.Binding.Digest(), DevelopmentOnly: true}
	if err := localdev.WriteExclusive(filepath.Join(config.StateDirectory, "bootstrap.json"), marshalLocal(record)); err != nil {
		return localStageError("bootstrap-completion")
	}
	return nil
}

func marshalLocal(value any) []byte { data, _ := json.Marshal(value); return data }

// Every local metadata file is canonical bytes emitted by this reviewed
// installer. Decode+exact re-encoding rejects duplicate, omitted, unknown or
// case-aliased fields rather than inheriting encoding/json overwrite behavior.
func readLocalMetadata[T any](path string, maximum int64) (T, error) {
	var value T
	data, err := localdev.ReadPrivate(path, maximum)
	if err != nil {
		return value, err
	}
	if json.Unmarshal(data, &value) != nil || !bytes.Equal(data, marshalLocal(value)) {
		var zero T
		return zero, localStageError("noncanonical-local-metadata")
	}
	return value, nil
}
