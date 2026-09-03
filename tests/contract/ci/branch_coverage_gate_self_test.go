package ci_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const branchCoverageSelfTestModeEnv = "STEAD_BRANCH_COVERAGE_SELF_TEST_MODE"

func writeBranchCoverageSelfTestModule(t *testing.T, source, testSource string) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"go.mod":          "module example.test/branchfixture\n\ngo 1.27.0\n",
		"fixture.go":      source,
		"fixture_test.go": testSource,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write synthetic branch fixture %s: %v", name, err)
		}
	}
	return root
}

func runOrdinaryStatementCoverage(goBinary, root string, environment map[string]string) (int, int, string, error) {
	profilePath := filepath.Join(root, "ordinary-count.cover")
	command := exec.Command(goBinary,
		"test", ".",
		"-count=1",
		"-covermode=count",
		"-coverpkg=example.test/branchfixture",
		"-coverprofile="+profilePath,
	)
	command.Dir = root
	command.Env = commandEnvironment(environment)
	output, err := command.CombinedOutput()
	if err != nil {
		return 0, 0, string(output), err
	}
	profile, err := os.ReadFile(profilePath)
	if err != nil {
		return 0, 0, string(output), err
	}
	blocks, err := parseCountProfile(profile)
	if err != nil {
		return 0, 0, string(output), err
	}
	covered, total := 0, 0
	for _, fileBlocks := range blocks {
		for _, block := range fileBlocks {
			total += block.statements
			if block.count > 0 {
				covered += block.statements
			}
		}
	}
	return covered, total, string(output), nil
}

func runBranchCoverageSelfTest(t *testing.T, root, mode string) (branchCoverageReport, []branchArm) {
	t.Helper()
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	sources, importPath, err := activePackageSources(goBinary, root, ".")
	if err != nil {
		t.Fatal(err)
	}
	report, arms, childOutput, err := executeInstrumentedBranchCoverage(
		goBinary,
		root,
		".",
		importPath,
		sources,
		map[string]string{branchCoverageSelfTestModeEnv: mode},
	)
	if err != nil {
		t.Fatalf("synthetic branch coverage child failed: %v\n%s", err, childOutput)
	}
	return report, arms
}

func armCountsByKind(arms []branchArm) map[string][]uint64 {
	counts := make(map[string][]uint64)
	for _, arm := range arms {
		counts[arm.kind] = append(counts[arm.kind], arm.count)
	}
	for kind := range counts {
		sort.Slice(counts[kind], func(i, j int) bool { return counts[kind][i] < counts[kind][j] })
	}
	return counts
}

func formatArmCounts(counts map[string][]uint64) string {
	kinds := make([]string, 0, len(counts))
	for kind := range counts {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	var formatted strings.Builder
	for _, kind := range kinds {
		fmt.Fprintf(&formatted, "%s=%v ", kind, counts[kind])
	}
	return strings.TrimSpace(formatted.String())
}

func TestBranchCoverageGateDetectsImplicitFalseBehindFullStatementCoverage(t *testing.T) {
	if os.Getenv(branchCoverageChildEnv) == "1" {
		return
	}
	root := writeBranchCoverageSelfTestModule(t, `package branchfixture

func Decision(flag bool) int {
	value := 1
	if flag {
		value++
	}
	return value
}
`, `package branchfixture

import (
	"os"
	"testing"
)

func TestDecision(t *testing.T) {
	if Decision(true) != 2 {
		t.Fatal("true result")
	}
	if os.Getenv("STEAD_BRANCH_COVERAGE_SELF_TEST_MODE") == "all" && Decision(false) != 1 {
		t.Fatal("false result")
	}
}
`)
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	environment := map[string]string{branchCoverageSelfTestModeEnv: "taken-only"}
	statementCovered, statementTotal, childOutput, err := runOrdinaryStatementCoverage(goBinary, root, environment)
	if err != nil {
		t.Fatalf("ordinary coverage child failed: %v\n%s", err, childOutput)
	}
	if statementTotal == 0 || statementCovered != statementTotal {
		t.Fatalf("ordinary statement coverage = %d/%d, want nonzero 100%%", statementCovered, statementTotal)
	}

	takenOnly, arms := runBranchCoverageSelfTest(t, root, "taken-only")
	counts := armCountsByKind(arms)
	if takenOnly.covered != 1 || takenOnly.total != 2 || len(counts["if.true"]) != 1 || counts["if.true"][0] == 0 || len(counts["if.false.implicit"]) != 1 || counts["if.false.implicit"][0] != 0 {
		t.Fatalf("taken-only branch coverage = %d/%d, arms %s; want true covered and synthetic false uncovered", takenOnly.covered, takenOnly.total, formatArmCounts(counts))
	}
	if meetsBranchCoverageFloor(takenOnly, policyReleaseBranchThreshold) {
		t.Fatal("one covered arm out of two incorrectly satisfies the 80% branch floor")
	}

	all, allArms := runBranchCoverageSelfTest(t, root, "all")
	if all.total != takenOnly.total || all.covered != all.total {
		t.Fatalf("all-outcomes branch coverage = %d/%d, arms %s; want stable denominator and full coverage", all.covered, all.total, formatArmCounts(armCountsByKind(allArms)))
	}
	if !meetsBranchCoverageFloor(all, policyReleaseBranchThreshold) {
		t.Fatal("fully covered branch fixture does not satisfy the 80% branch floor")
	}
}

func TestBranchCoverageFloorUsesExactIntegerComparison(t *testing.T) {
	if !meetsBranchCoverageFloor(branchCoverageReport{covered: 4, total: 5}, 80) {
		t.Fatal("exactly 80% must satisfy the floor")
	}
	if meetsBranchCoverageFloor(branchCoverageReport{covered: 799, total: 1000}, 80) {
		t.Fatal("79.9% must not satisfy the floor")
	}
	if meetsBranchCoverageFloor(branchCoverageReport{}, 80) {
		t.Fatal("an empty denominator must not satisfy the floor")
	}
}

func TestBranchCoverageGateRejectsStaticallyImpossibleLoopArms(t *testing.T) {
	testCases := []struct {
		name   string
		source string
		want   string
	}{
		{"conditionless", `package branchfixture

func NeverReturns() {
	for {
	}
}
`, "conditionless for loop has no independently measurable normal-exit arm"},
		{"named constant", `package branchfixture

const always = true

func NeverReturns() {
	for always {
	}
}
`, "constant-condition for loop requires unsupported break-aware feasibility analysis"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			root := writeBranchCoverageSelfTestModule(t, testCase.source, `package branchfixture

import "testing"

func TestFixture(t *testing.T) {}
`)
			goBinary, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			sources, importPath, err := activePackageSources(goBinary, root, ".")
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = instrumentBranchSources(sources, t.TempDir(), importPath)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("loop analyzer error = %v, want text %q", err, testCase.want)
			}
		})
	}
}

func TestBranchCoverageGateCountsCasesDefaultsSelectAndLoopOutcomes(t *testing.T) {
	if os.Getenv(branchCoverageChildEnv) == "1" {
		return
	}
	root := writeBranchCoverageSelfTestModule(t, `package branchfixture

func Constructs(choice int, typed any, channel <-chan int, values []int) int {
	result := 0
	switch choice {
	case 1:
		result++
	case 2:
		result += 2
	}
	switch typed.(type) {
	case string:
		result += 3
	case int:
		result += 4
	}
	select {
	case <-channel:
		result += 5
	default:
		result += 6
	}
	for index := 0; index < 1; index++ {
		result += 7
	}
	for range values {
		result += 8
	}
	return result
}
`, `package branchfixture

import (
	"os"
	"testing"
)

func TestConstructs(t *testing.T) {
	Constructs(1, "text", nil, nil)
	if os.Getenv("STEAD_BRANCH_COVERAGE_SELF_TEST_MODE") == "all" {
		ready := make(chan int, 1)
		ready <- 1
		Constructs(2, 1, ready, []int{1})
		Constructs(9, struct{}{}, nil, nil)
	}
}
`)

	takenOnly, arms := runBranchCoverageSelfTest(t, root, "taken-only")
	counts := armCountsByKind(arms)
	expected := map[string][]uint64{
		"for.body":                     {1},
		"for.exit":                     {1},
		"range.body":                   {0},
		"range.exit":                   {1},
		"select.case":                  {0},
		"select.default":               {1},
		"switch.case":                  {0, 1},
		"switch.default.implicit":      {0},
		"type-switch.case":             {0, 1},
		"type-switch.default.implicit": {0},
	}
	if formatArmCounts(counts) != formatArmCounts(expected) {
		t.Fatalf("taken-only arms %s, want %s", formatArmCounts(counts), formatArmCounts(expected))
	}
	if takenOnly.covered != 6 || takenOnly.total != 12 {
		t.Fatalf("taken-only branch coverage = %d/%d, want 6/12", takenOnly.covered, takenOnly.total)
	}

	all, allArms := runBranchCoverageSelfTest(t, root, "all")
	if all.total != takenOnly.total || all.covered != all.total {
		t.Fatalf("all-outcomes branch coverage = %d/%d, arms %s; want stable denominator and full coverage", all.covered, all.total, formatArmCounts(armCountsByKind(allArms)))
	}
}
