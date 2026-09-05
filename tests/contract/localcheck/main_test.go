package main

import "testing"

func rowEvents(action string) []event {
	return []event{
		{Action: "run", Package: authorizationPackage, Test: "TestNativePolicyRows"},
		{Action: "run", Package: authorizationPackage, Test: "TestNativePolicyRows/POLICY-001"},
		{Action: action, Package: authorizationPackage, Test: "TestNativePolicyRows/POLICY-001"},
		{Action: action, Package: authorizationPackage, Test: "TestNativePolicyRows"},
		{Action: action, Package: authorizationPackage},
	}
}

func TestCaptureRowsRequiresActualExactExecution(t *testing.T) {
	for _, action := range []string{"pass", "fail"} {
		code := 0
		if action == "fail" {
			code = 1
		}
		rows, err := captureRows([]string{"POLICY-001"}, rowEvents(action), code)
		if err != nil || len(rows) != 1 || rows[0].Passed != (action == "pass") {
			t.Fatal("actual row outcome lost", err)
		}
	}
	for _, tc := range []struct {
		name   string
		events []event
		code   int
		ids    []string
	}{
		{"missing", nil, 0, []string{"POLICY-001"}},
		{"skipped", rowEvents("skip"), 0, []string{"POLICY-001"}},
		{"missing-row", rowEvents("pass"), 0, []string{"POLICY-001", "POLICY-002"}},
		{"unexpected-row", rowEvents("pass"), 0, []string{"POLICY-002"}},
		{"duplicate-inventory", rowEvents("pass"), 0, []string{"POLICY-001", "POLICY-001"}},
		{"exit-mismatch", rowEvents("pass"), 1, []string{"POLICY-001"}},
		{"exit-hidden-fail", rowEvents("fail"), 0, []string{"POLICY-001"}},
		{"duplicate-terminal", append(rowEvents("pass"), rowEvents("pass")[2]), 0, []string{"POLICY-001"}},
		{"no-start", rowEvents("pass")[2:], 0, []string{"POLICY-001"}},
		{"incomplete", rowEvents("pass")[:2], 1, []string{"POLICY-001"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := captureRows(tc.ids, tc.events, tc.code); err == nil {
				t.Fatal("invalid process capture accepted")
			}
		})
	}
}

func TestCaptureRowsPreservesContractOrderNotExecutionOrLexicalOrder(t *testing.T) {
	ids := []string{"POLICY-Z", "POLICY-A"}
	events := []event{{Action: "run", Package: authorizationPackage, Test: "TestNativePolicyRows"}}
	for _, id := range []string{"POLICY-A", "POLICY-Z"} {
		events = append(events,
			event{Action: "run", Package: authorizationPackage, Test: "TestNativePolicyRows/" + id},
			event{Action: "pass", Package: authorizationPackage, Test: "TestNativePolicyRows/" + id})
	}
	events = append(events,
		event{Action: "pass", Package: authorizationPackage, Test: "TestNativePolicyRows"},
		event{Action: "pass", Package: authorizationPackage})
	rows, err := captureRows(ids, events, 0)
	if err != nil || len(rows) != len(ids) || rows[0].ID != ids[0] || rows[1].ID != ids[1] {
		t.Fatal("contract row order changed", err)
	}
}

func TestProcessResultCannotCreditCompilerOrPackageFailures(t *testing.T) {
	good := rowEvents("fail")
	for _, tc := range []struct {
		name   string
		events []event
		code   int
	}{
		{"compiler", append(good, event{Action: "build-fail", Package: authorizationPackage}), 1},
		{"build-output", append(good, event{Action: "output", Package: authorizationPackage, Output: "FAIL [build failed]"}), 1},
		{"package-only", []event{{Action: "fail", Package: authorizationPackage}}, 1},
		{"interrupted", good, 137},
		{"unrelated-package", append(good, event{Action: "pass", Package: "unrelated"}), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := processResult(tc.events, tc.code, []string{authorizationPackage}); err == nil {
				t.Fatal("invalid mutation kill credited")
			}
		})
	}
	if _, err := processResult(good, 1, []string{authorizationPackage, classificationPackage}); err == nil {
		t.Fatal("omitted package credited")
	}
}
