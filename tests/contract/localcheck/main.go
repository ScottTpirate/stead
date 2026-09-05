// Command localcheck executes real native-policy tests and compiler overlays.
// It is development verification tooling, never a runtime authorization API.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ScottTpirate/stead/modules/authorization"
)

type event struct{ Action, Test, Package, Output string }
type mutant struct {
	ID, Path  string
	Function  string
	Line      int
	Condition string
	Source    []byte
}

const authorizationPackage = "github.com/ScottTpirate/stead/modules/authorization"
const classificationPackage = "github.com/ScottTpirate/stead/modules/classification"

// processResult requires actual executed tests and completed package results.
// A compiler failure, missing output, skipped-only selection, interruption, or
// package failure without a failing test is not a killed policy mutant.
func processResult(events []event, code int, packages []string) (bool, error) {
	if code != 0 && code != 1 {
		return false, errors.New("test process did not exit normally")
	}
	allowed := map[string]bool{}
	for _, name := range packages {
		allowed[name] = true
	}
	terminal, ran, completed := map[string]string{}, map[string]bool{}, map[string]bool{}
	failed, counts := false, map[string]int{}
	for _, entry := range events {
		if entry.Action == "build-fail" || strings.Contains(entry.Output, "[build failed]") {
			return false, errors.New("compiler failure is not a mutation kill")
		}
		if !allowed[entry.Package] {
			return false, errors.New("unexpected test package")
		}
		key := entry.Package + "/" + entry.Test
		if entry.Test != "" && entry.Action == "run" {
			if ran[key] {
				return false, errors.New("duplicate test execution")
			}
			ran[key] = true
		}
		if entry.Test != "" && (entry.Action == "pass" || entry.Action == "fail" || entry.Action == "skip") {
			if !ran[key] || completed[key] {
				return false, errors.New("unmatched or duplicate test result")
			}
			completed[key] = true
			if entry.Action != "skip" {
				counts[entry.Package]++
			}
			failed = failed || entry.Action == "fail"
		}
		if entry.Test == "" && (entry.Action == "pass" || entry.Action == "fail" || entry.Action == "skip") {
			if terminal[entry.Package] != "" {
				return false, errors.New("duplicate package result")
			}
			terminal[entry.Package] = entry.Action
		}
	}
	for key := range ran {
		if !completed[key] {
			return false, errors.New("incomplete test execution")
		}
	}
	packageFailed := false
	for name := range allowed {
		if counts[name] == 0 || (terminal[name] != "pass" && terminal[name] != "fail") {
			return false, errors.New("missing actual package tests")
		}
		packageFailed = packageFailed || terminal[name] == "fail"
	}
	if (code == 1) != failed || failed != packageFailed {
		return false, errors.New("test and process outcomes disagree")
	}
	return failed, nil
}

func captureRows(ids []string, events []event, code int) ([]authorization.LocalCheckCase, error) {
	if _, err := processResult(events, code, []string{authorizationPackage}); err != nil {
		return nil, err
	}
	wanted, results := map[string]bool{}, map[string]bool{}
	for _, id := range ids {
		if id == "" || wanted[id] {
			return nil, errors.New("invalid policy row inventory")
		}
		wanted[id] = true
	}
	rootPassed := false
	for _, entry := range events {
		if entry.Test == "TestNativePolicyRows" && entry.Action == "pass" {
			rootPassed = true
		}
		if !strings.HasPrefix(entry.Test, "TestNativePolicyRows/") {
			continue
		}
		id := strings.TrimPrefix(entry.Test, "TestNativePolicyRows/")
		if !wanted[id] {
			return nil, errors.New("unexpected executed policy row")
		}
		if entry.Action == "skip" {
			return nil, errors.New("policy row was skipped")
		}
		if entry.Action == "pass" || entry.Action == "fail" {
			results[id] = entry.Action == "pass"
		}
	}
	if len(results) != len(ids) || (code == 0 && !rootPassed) {
		return nil, errors.New("actual row execution did not cover inventory")
	}
	cases, failures := []authorization.LocalCheckCase{}, 0
	for _, id := range ids {
		passed, ok := results[id]
		if !ok {
			return nil, errors.New("missing executed policy row")
		}
		if !passed {
			failures++
		}
		cases = append(cases, authorization.LocalCheckCase{ID: id, Passed: passed})
	}
	if (code == 1) != (failures > 0) {
		return nil, errors.New("row and process outcomes disagree")
	}
	return cases, nil
}

func execute(ctx context.Context, args ...string) ([]event, int, error) {
	command := exec.CommandContext(ctx, "go", args...)
	command.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly")
	output, err := command.Output()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return nil, -1, err
		}
		code = exit.ExitCode()
		if len(exit.Stderr) > 0 {
			fmt.Fprint(os.Stderr, string(exit.Stderr))
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	events := []event{}
	for {
		var entry event
		err := decoder.Decode(&entry)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, code, err
		}
		events = append(events, entry)
	}
	return events, code, nil
}

func rowIDs() ([]string, error) {
	data, err := os.ReadFile("modules/authorization/contract/decision-table.json")
	if err != nil {
		return nil, err
	}
	var table struct{ Cases []struct{ ID string } }
	if err = json.Unmarshal(data, &table); err != nil {
		return nil, err
	}
	ids := []string{}
	seen := map[string]bool{}
	for _, row := range table.Cases {
		if row.ID == "" || seen[row.ID] {
			return nil, errors.New("invalid policy row inventory")
		}
		seen[row.ID] = true
		ids = append(ids, row.ID)
	}
	return ids, nil
}

func conformance(ctx context.Context) ([]authorization.LocalCheckCase, error) {
	ids, err := rowIDs()
	if err != nil {
		return nil, err
	}
	events, code, err := execute(ctx, "test", "-json", "-count=1", "./modules/authorization", "-run", "^TestNativePolicyRows$")
	if err != nil {
		return nil, err
	}
	return captureRows(ids, events, code)
}

// Each mutation removes one actual policy/security guard. Mutants that do not
// compile are invalid evidence, not credited kills. The unchanged source is a
// required positive control. Original files are never modified.
func mutations() ([]mutant, error) {
	selected := map[string]map[string]bool{
		"modules/authorization/native_policy.go": {"NativePolicyDecision": true},
		"modules/authorization/coordinator.go":   {"Authorize": true, "ValidateFinal": true, "validState": true},
		"modules/authorization/read_set.go":      {"AuthorizeSet": true},
		"modules/authorization/openfga_batch.go": {"BatchCheck": true},
		"modules/classification/evaluator.go":    {"Evaluate": true},
	}
	paths := []string{}
	for path := range selected {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	result := []mutant{}
	ordinal := 0
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, path, data, 0)
		if err != nil {
			return nil, err
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || !selected[path][function.Name.Name] {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				condition, ok := node.(*ast.IfStmt)
				if !ok {
					return true
				}
				start, end := set.Position(condition.Cond.Pos()).Offset, set.Position(condition.Cond.End()).Offset
				ordinal++
				guard := string(data[start:end])
				// Inventory is authorization semantics, not arbitrary error plumbing.
				// The current concrete classifier always returns a nonempty denial
				// reason on error. Both finished<now clamps are equivalent: expiry
				// is already strictly after now and the seal never stores finished.
				// The early existence branch duplicates deny's unconditional
				// suppression for precisely the same facts. None earns kill credit.
				exclusion := ""
				if guard == `err != nil && result.DenialReason == ""` {
					exclusion = "unreachable error-without-reason from concrete evaluator"
				}
				if guard == "finished.Before(now)" {
					exclusion = "equivalent elapsed-time clamp under already-valid expiry"
				}
				if path == "modules/authorization/native_policy.go" && guard == "!input.RelationshipAllowed && input.ExistenceSensitive" {
					exclusion = "equivalent duplicate of deny helper existence suppression"
				}
				if init, ok := condition.Init.(*ast.AssignStmt); ok && len(init.Rhs) == 1 {
					if call, ok := init.Rhs[0].(*ast.CallExpr); ok {
						if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
							if receiver, ok := selector.X.(*ast.Ident); ok && receiver.Name == "rand" && selector.Sel.Name == "Read" {
								exclusion = "entropy-source failure plumbing, not a policy predicate"
							}
						}
					}
				}
				if exclusion != "" {
					fmt.Fprintf(os.Stderr, "excluded guard-%03d %s:%d: %s\n", ordinal, path, set.Position(condition.Pos()).Line, exclusion)
					return true
				}
				changed := append([]byte{}, data[:start]...)
				changed = append(changed, []byte("false && (")...)
				changed = append(changed, data[start:end]...)
				changed = append(changed, ')')
				changed = append(changed, data[end:]...)
				result = append(result, mutant{ID: fmt.Sprintf("guard-%03d", ordinal), Path: path, Function: function.Name.Name, Line: set.Position(condition.Pos()).Line, Condition: string(data[start:end]), Source: changed})
				return true
			})
		}
	}
	if len(result) == 0 {
		return nil, errors.New("empty critical mutation inventory")
	}
	return result, nil
}

func critical(ctx context.Context) ([]authorization.LocalCheckCase, error) {
	inventory, err := mutations()
	if err != nil {
		return nil, err
	}
	selection := "^(TestNativePolicy|TestNativeClassification|TestCoordinator|TestOpenFGABatch|TestActivationRejects|TestHostAnchor)"
	control, code, err := execute(ctx, "test", "-json", "-count=1", "./modules/authorization", "./modules/classification", "-run", selection)
	if err != nil || code != 0 {
		return nil, errors.New("unmutated policy positive control failed")
	}
	if failed, err := processResult(control, code, []string{authorizationPackage, classificationPackage}); err != nil || failed {
		return nil, errors.New("unmutated positive control did not execute valid tests")
	}
	directory, err := os.MkdirTemp("", "stead-local-policy-mutations-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	cases := make([]authorization.LocalCheckCase, len(inventory))
	for index, candidate := range inventory {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		changed := filepath.Join(directory, candidate.ID+".go")
		overlay := filepath.Join(directory, candidate.ID+".json")
		original, err := filepath.Abs(candidate.Path)
		if err != nil {
			return nil, err
		}
		data, _ := json.Marshal(map[string]any{"Replace": map[string]string{original: changed}})
		if os.WriteFile(changed, candidate.Source, 0600) != nil || os.WriteFile(overlay, data, 0600) != nil {
			return nil, errors.New("cannot create isolated compiler overlay")
		}
		events, code, err := execute(ctx, "test", "-json", "-count=1", "-overlay", overlay, "./modules/authorization", "./modules/classification", "-run", selection)
		if err != nil {
			return nil, err
		}
		failedTest, err := processResult(events, code, []string{authorizationPackage, classificationPackage})
		if err != nil {
			return nil, fmt.Errorf("%s invalid evidence: %w", candidate.ID, err)
		}
		cases[index] = authorization.LocalCheckCase{ID: candidate.ID, Passed: failedTest}
		fmt.Fprintf(os.Stderr, "%s %s:%d %s killed=%v\n", candidate.ID, candidate.Path, candidate.Line, candidate.Function, cases[index].Passed)
	}
	return cases, nil
}

func main() {
	id := flag.String("check-id", "", "fixed check ID")
	subject := flag.String("subject-digest", "", "exact derived input subject")
	revision := flag.String("source-revision", "", "reviewed code revision")
	tree := flag.String("source-tree", "", "reviewed source tree")
	inventoryOnly := flag.Bool("inventory", false, "show derived expected case IDs only")
	details := flag.Bool("inventory-details", false, "show actual mutated guards for review")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	var cases []authorization.LocalCheckCase
	var err error
	if *details {
		inventory, err := mutations()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, candidate := range inventory {
			candidate.Source = nil
			json.NewEncoder(os.Stdout).Encode(candidate)
		}
		return
	}
	if *inventoryOnly {
		rows, e := rowIDs()
		mutants, m := mutations()
		if e != nil || m != nil {
			os.Exit(1)
		}
		names := []string{}
		for _, candidate := range mutants {
			names = append(names, candidate.ID)
		}
		json.NewEncoder(os.Stdout).Encode(map[string][]string{"policy-conformance": rows, "critical-mutations": names})
		return
	}
	switch *id {
	case "policy-conformance":
		cases, err = conformance(ctx)
	case "critical-mutations":
		cases, err = critical(ctx)
	default:
		err = errors.New("unsupported local check")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	report := authorization.LocalCheckReport{SchemaVersion: "1.0.0", CheckID: *id, SubjectDigest: *subject, SourceRevision: *revision, SourceTree: *tree, Total: len(cases), Cases: cases}
	for _, entry := range cases {
		if entry.Passed {
			report.Passed++
		} else {
			report.Failed++
		}
	}
	if json.NewEncoder(os.Stdout).Encode(report) != nil {
		os.Exit(1)
	}
	required := 100
	if *id == "critical-mutations" {
		required = 90
	}
	if report.Total == 0 || report.Passed*100 < required*report.Total {
		os.Exit(1)
	}
}
