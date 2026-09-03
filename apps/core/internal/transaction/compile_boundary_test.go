package transaction_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ScottTpirate/stead/apps/core/internal/outbox"
	transaction "github.com/ScottTpirate/stead/apps/core/internal/transaction"
	testbackendadapter "github.com/ScottTpirate/stead/apps/core/internal/transaction/testbackendadapter"
	testowneradapter "github.com/ScottTpirate/stead/apps/core/internal/transaction/testowneradapter"
)

type compileCase struct {
	ID        string `json:"id"`
	Placement string `json:"placement"`
	Source    string `json:"source"`
	Expected  string `json:"expected"`
}

func TestOwnerAuthoredTypedAdapterCompilesOutsideTransactionPackage(t *testing.T) {
	applyType, exists := reflect.TypeOf((*testowneradapter.Adapter)(nil)).MethodByName("Apply")
	if !exists || applyType.Type.NumIn() != 4 ||
		applyType.Type.In(2) != reflect.TypeOf(transaction.OperationPort[testowneradapter.Command]{}) ||
		applyType.Type.In(3) != reflect.TypeOf(testowneradapter.Command{}) {
		t.Fatalf("external typed adapter surface drifted: %v", applyType.Type)
	}
	for _, banned := range []string{"Owner", "Session", "SQL", "Role", "Commit", "Rollback"} {
		if _, exists := reflect.TypeOf(transaction.OperationPort[testowneradapter.Command]{}).FieldByName(banned); exists {
			t.Fatalf("operation port exposed %s", banned)
		}
	}
}

type externalAppender struct{}

func (externalAppender) Append(_ context.Context, scope outbox.TransactionScope[transaction.SessionBinding, transaction.BindingReceipt], intent outbox.ValidatedIntent) (outbox.ScopeReceipt[transaction.SessionBinding, transaction.BindingReceipt], transaction.BindingReceipt, error) {
	return scope.Use(func(binding transaction.SessionBinding) (transaction.BindingReceipt, error) {
		return binding.Use(intent.Verify)
	})
}

func TestCoordinatorInvokesExternalOwnerAdapterThroughTypedContract(t *testing.T) {
	backend := &testbackendadapter.Backend{}
	backendContract, err := transaction.NewBackendContract(backend)
	if err != nil {
		t.Fatal(err)
	}
	backendOperation, err := testbackendadapter.RegisterCommandOperation(backend, backendContract, "owner_a")
	if err != nil {
		t.Fatal(err)
	}
	registeredOperation, err := transaction.NewRegisteredOperation(backendOperation, testowneradapter.Adapter{}.Apply)
	if err != nil {
		t.Fatal(err)
	}
	template, contract, err := transaction.NewPlanContract(
		transaction.ContractVersionV1,
		"external_typed_adapter",
		[]transaction.TypedParticipant[testowneradapter.Command]{
			{
				Key: "owner_write", DeclaresWrite: true, Operation: registeredOperation,
			},
		},
		transaction.OutboxOptional,
	)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := transaction.NewRegistry([]transaction.PlanTemplate{template})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := transaction.NewCoordinator(transaction.Configuration{
		Backend: backendContract, Registry: registry, Outbox: externalAppender{},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := contract.Bind(registry, testowneradapter.Command{Value: "typed-command"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Execute(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	committed, rolledBack, active, executed := backend.Snapshot()
	begins, commits, rollbacks := backend.Lifecycle()
	if !reflect.DeepEqual(committed, []testbackendadapter.Record{{SessionID: 1, Owner: "owner_a", Value: "typed-command"}}) ||
		len(rolledBack) != 0 || active != 0 || executed["owner_a"] != 1 || begins != 1 || commits != 1 || rollbacks != 0 {
		t.Fatalf("external transaction commit=%v rollback=%v active=%d executed=%v lifecycle=%d/%d/%d", committed, rolledBack, active, executed, begins, commits, rollbacks)
	}
}

func TestForeignModulesAndCallersCannotCompileForbiddenCapabilities(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	fixtureRoot := filepath.Join(repositoryRoot, "packages/test-fixtures/core/compile-fail")
	file, err := os.Open(filepath.Join(fixtureRoot, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var inventory struct {
		Scope string        `json:"scope"`
		Cases []compileCase `json:"cases"`
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inventory); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatal("compile-fail inventory contains trailing data")
	}
	if inventory.Scope != "P1-015-CORE-PORTS compile-time negative boundaries" || len(inventory.Cases) != 17 {
		t.Fatalf("compile-fail inventory drifted: %q cases=%d", inventory.Scope, len(inventory.Cases))
	}
	seen := make(map[string]struct{}, len(inventory.Cases))
	for _, testCase := range inventory.Cases {
		if _, duplicate := seen[testCase.ID]; duplicate {
			t.Fatalf("duplicate compile-fail case %q", testCase.ID)
		}
		seen[testCase.ID] = struct{}{}
		t.Run(testCase.ID, func(t *testing.T) {
			parent := filepath.Join(repositoryRoot, "apps/core")
			if testCase.Placement == "foreign" {
				parent = filepath.Join(repositoryRoot, "tests/integration/core")
			} else if testCase.Placement != "apps_core" {
				t.Fatalf("unknown placement %q", testCase.Placement)
			}
			temporary, err := os.MkdirTemp(parent, "compilecontract-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(temporary)
			source, err := os.ReadFile(filepath.Join(fixtureRoot, testCase.Source))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(temporary, "negative_test.go"), source, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "go", "test", ".")
			command.Dir = temporary
			command.Env = append(os.Environ(), "GOFLAGS=-mod=readonly")
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("forbidden fixture compiled successfully:\n%s", output)
			}
			if ctx.Err() != nil {
				t.Fatalf("compile-fail case timed out: %v", ctx.Err())
			}
			if !strings.Contains(string(output), testCase.Expected) {
				t.Fatalf("compile error did not prove expected boundary %q:\n%s", testCase.Expected, output)
			}
		})
	}
}

func TestOpaqueAndCoordinatorExportedSurfacesHaveNoBypassMethods(t *testing.T) {
	bannedMethods := []string{"Add", "AddParticipant", "Allowed", "Begin", "Commit", "Exec", "PrepareEffect", "Query", "Raw", "Retry", "Rollback", "SetMode", "SetRole"}
	types := []reflect.Type{
		reflect.TypeOf(transaction.OperationPort[struct{}]{}),
		reflect.TypeOf(transaction.ExecutorBinding{}),
		reflect.TypeOf(transaction.BackendContract{}),
		reflect.TypeOf(transaction.BackendOperation[struct{}]{}),
		reflect.TypeOf(transaction.RegisteredOperation[struct{}]{}),
		reflect.TypeOf(transaction.SessionBinding{}),
		reflect.TypeOf(transaction.BindingReceipt{}),
		reflect.TypeOf(transaction.PlanTemplate{}),
		reflect.TypeOf(transaction.PlanContract[struct{}]{}),
		reflect.TypeOf(transaction.Plan{}),
		reflect.TypeOf(transaction.BoundRevision{}),
		reflect.TypeOf(transaction.DurableEffectReceipt{}),
		reflect.TypeOf((*transaction.Coordinator)(nil)),
	}
	for _, valueType := range types {
		for index := 0; index < valueType.NumMethod(); index++ {
			method := valueType.Method(index)
			if slices.Contains(bannedMethods, method.Name) {
				t.Fatalf("%s exposes prohibited method %s", valueType, method.Name)
			}
		}
	}
	for _, valueType := range []reflect.Type{
		reflect.TypeOf(transaction.OperationPort[struct{}]{}),
		reflect.TypeOf(transaction.ExecutorBinding{}),
		reflect.TypeOf(transaction.BackendContract{}),
		reflect.TypeOf(transaction.BackendOperation[struct{}]{}),
		reflect.TypeOf(transaction.RegisteredOperation[struct{}]{}),
		reflect.TypeOf(transaction.SessionBinding{}),
		reflect.TypeOf(transaction.BindingReceipt{}),
		reflect.TypeOf(transaction.PlanTemplate{}),
		reflect.TypeOf(transaction.PlanContract[struct{}]{}),
		reflect.TypeOf(transaction.Plan{}),
		reflect.TypeOf(transaction.BoundRevision{}),
		reflect.TypeOf(transaction.DurableEffectReceipt{}),
	} {
		for index := 0; index < valueType.NumField(); index++ {
			if valueType.Field(index).IsExported() {
				t.Fatalf("opaque type %s exports field %s", valueType, valueType.Field(index).Name)
			}
		}
	}
}

func TestCoreSeamsHaveNoDatabaseNetworkProviderOrPolicyRuntimeDependency(t *testing.T) {
	repositoryRoot := testRepositoryRoot(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "list", "-deps",
		"./apps/core/internal/transaction", "./apps/core/internal/outbox")
	command.Dir = repositoryRoot
	command.Env = append(os.Environ(), "GOFLAGS=-mod=readonly")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("go list failed: %v\n%s", err, output)
	}
	dependencies := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, forbidden := range []string{
		"database/sql",
		"net/http",
		"github.com/jackc/",
		"github.com/nats-io/",
		"github.com/openfga/",
		"github.com/ScottTpirate/stead/modules/",
		"github.com/ScottTpirate/stead/providers/",
	} {
		for _, dependency := range dependencies {
			if dependency == forbidden || strings.HasPrefix(dependency, forbidden) {
				t.Fatalf("forbidden dependency %q in core seam", dependency)
			}
		}
	}
}

func testRepositoryRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "../../../.."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
