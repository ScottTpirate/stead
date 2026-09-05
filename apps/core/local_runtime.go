package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/app"
	"github.com/ScottTpirate/stead/apps/core/internal/httpapi"
	"github.com/ScottTpirate/stead/apps/core/internal/localdev"
	"github.com/ScottTpirate/stead/apps/core/internal/postgres"
	"github.com/ScottTpirate/stead/modules/authorization"
	"github.com/ScottTpirate/stead/modules/identity"
)

type localRuntime struct {
	config     localdev.Config
	store      *postgres.Store
	anchor     *authorization.LocalAnchor
	activation *authorization.VerifiedActivation
	openfga    *authorization.OpenFGA
	handler    *httpapi.Server
}

func openLocalRuntime(ctx context.Context, repository string, config localdev.Config, observe func(httpapi.Observation)) (*localRuntime, error) {
	if localdev.PrivateDirectory(config.PolicyDirectory) != nil {
		return nil, localStageError("policy-directory")
	}
	record, err := readLocalMetadata[localBootstrapRecord](filepath.Join(config.StateDirectory, "bootstrap.json"), 64<<10)
	if err != nil || record.SchemaVersion != "1.0.0" || !record.DevelopmentOnly || record.InstanceID != config.InstanceID || record.SecurityDomain != config.SecurityDomain || record.StoreID != config.StoreID || record.ModelID != config.ModelID || !identity.ValidID(record.PrincipalID) || !identity.ValidID(record.SessionID) || !identity.ValidID(record.LabelID) {
		return nil, localStageError("completed-bootstrap")
	}
	archive, err := localdev.ReadPrivate(filepath.Join(config.PolicyDirectory, "activation.tar"), 64<<20)
	if err != nil {
		return nil, localStageError("archive")
	}
	derivation, err := localdev.ReadPrivate(filepath.Join(config.PolicyDirectory, "derivation.dsse.json"), 4<<20)
	if err != nil {
		return nil, localStageError("derivation")
	}
	keys, err := readLocalMetadata[[]authorization.TrustedKey](filepath.Join(config.PolicyDirectory, "trust-keys.json"), 64<<10)
	if err != nil {
		return nil, localStageError("pinned-trust")
	}
	anchor, err := authorization.OpenLocalAnchor(filepath.Join(config.StateDirectory, "policy-anchor.json"))
	if err != nil {
		return nil, localStageError("independent-anchor")
	}
	current, err := anchor.Read(ctx)
	if err != nil || current.Binding.Digest() != record.ActivationDigest {
		return nil, localStageError("anchor-binding")
	}
	fga, err := authorization.NewOpenFGA(authorization.OpenFGAConfig{URL: config.OpenFGAURL, StoreID: config.StoreID, ModelID: config.ModelID, Token: config.OpenFGAToken, LocalDevelopment: true})
	if err != nil {
		return nil, localStageError("model-configuration")
	}
	workflow, err := newLocalPolicyWorkflow(filepath.Join(config.StateDirectory, "policy-events"))
	if err != nil {
		return nil, localStageError("policy-observation")
	}
	activation, err := authorization.LoadLocalDevelopment(ctx, authorization.LocalDevelopmentLoadInput{RepositoryRoot: repository, PublicOrigin: config.Origin, OpenFGAURL: config.OpenFGAURL, OpenFGA: fga, Archive: archive, DerivationEnvelope: derivation, TrustedKeys: keys, Anchor: current, Now: time.Now().UTC(), LocalDevelopment: true, Workflow: workflow})
	if err != nil {
		return nil, localStageError("verified-existing-policy")
	}
	store, err := postgres.Open(ctx, postgres.Config{DSN: config.DatabaseURL, InstanceID: config.InstanceID, SecurityDomain: config.SecurityDomain, OpenFGAStoreID: config.StoreID, Anchor: anchor})
	if err != nil {
		return nil, localStageError("runtime-database")
	}
	failed := true
	defer func() {
		if failed {
			store.Close()
		}
	}()
	runtime := &localRuntime{config: config, store: store, anchor: anchor, activation: activation, openfga: fga}
	if err := runtime.ready(ctx); err != nil {
		return nil, localStageError("runtime-readiness")
	}
	authenticator, err := identity.NewLocalAuthenticator(store, config.InstanceID, time.Now)
	if err != nil {
		return nil, localStageError("identity")
	}
	coordinator, err := authorization.NewCoordinator(authorization.Config{Repository: store, Denials: store, OpenFGA: fga, Activation: activation, Anchor: anchor, Clock: time.Now})
	if err != nil {
		return nil, localStageError("central-authorization")
	}
	creator, err := app.NewCreatorActivator(store, coordinator, fga)
	if err != nil {
		return nil, localStageError("creator-activation")
	}
	handler, err := httpapi.New(httpapi.Config{Origin: config.Origin, InstanceID: config.InstanceID, Repository: store, Identity: authenticator, Authorization: coordinator, ActivateCreated: creator.Activate, Ready: runtime.ready, Observe: observe})
	if err != nil {
		return nil, localStageError("platform-api")
	}
	runtime.handler = handler
	failed = false
	return runtime, nil
}

func (runtime *localRuntime) ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if runtime == nil || runtime.store == nil || runtime.activation == nil || runtime.anchor == nil || runtime.openfga == nil {
		return authorization.ErrDenied
	}
	now := time.Now().UTC()
	anchor, err := runtime.anchor.Read(ctx)
	if err != nil || anchor.Binding != runtime.activation.Binding() || now.Before(anchor.PolicyTimeHighWater.Add(-authorization.MaxPolicyClockSkew)) {
		return authorization.ErrDenied
	}
	if now.Before(anchor.PolicyTimeHighWater) {
		now = anchor.PolicyTimeHighWater
	}
	if !runtime.activation.ValidAt(now) || runtime.store.Health(ctx) != nil || runtime.store.CheckActivation(ctx, anchor.Binding) != nil {
		return authorization.ErrDenied
	}
	model, err := runtime.openfga.VerifyModel(ctx)
	if err != nil || model.StoreID() != anchor.Binding.OpenFGAStoreID || model.ModelID() != anchor.Binding.OpenFGAModelID || model.SourceDigest() != anchor.Binding.ModelSourceDigest {
		return authorization.ErrDenied
	}
	return nil
}

func runLocalAPI(stderr io.Writer) int {
	config, err := localdev.Load(os.Getenv, false)
	if err != nil {
		fmt.Fprintln(stderr, "stead-api: explicit local runtime configuration rejected")
		return 1
	}
	repository, err := os.Getwd()
	if err != nil {
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	observations := json.NewEncoder(stderr)
	var observationLock sync.Mutex
	runtime, err := openLocalRuntime(startup, repository, config, func(observation httpapi.Observation) {
		observationLock.Lock()
		defer observationLock.Unlock()
		_ = observations.Encode(observation)
	})
	cancel()
	if err != nil {
		stage := "verification"
		var code localStageError
		if errors.As(err, &code) {
			stage = string(code)
		}
		fmt.Fprintf(stderr, "stead-api: local startup failed at %s; existing state was preserved\n", stage)
		return 1
	}
	defer runtime.store.Close()
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		fmt.Fprintln(stderr, "stead-api: local listener unavailable")
		return 1
	}
	server := &http.Server{Handler: runtime.handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	fmt.Fprintln(stderr, "stead-api: synthetic-only local Platform API ready")
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(stderr, "stead-api: local HTTP service stopped")
			return 1
		}
		return 0
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if server.Shutdown(shutdown) != nil {
			_ = server.Close()
			return 1
		}
		return 0
	}
}
