package ci_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/constant"
	"go/format"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	policyReleaseImportPath      = "github.com/ScottTpirate/stead/modules/ci/policyrelease"
	branchCoverageChildEnv       = "STEAD_POLICYRELEASE_BRANCH_COVERAGE_CHILD"
	branchCoverageMarkerPrefix   = "STEAD_BRANCH_ARM_V1:"
	branchCoverageMarkerFunction = "steadBranchCoverageArmV1"
	policyReleaseBranchThreshold = 80
	policyReleasePackageArgument = "./modules/ci/policyrelease"
	policyReleaseTestArgument    = "./tests/contract/ci"
)

type branchSourceFile struct {
	path    string
	display string
}

type branchArm struct {
	id            string
	kind          string
	sourceFile    string
	line          int
	column        int
	profileFile   string
	profileLine   int
	profileColumn int
	count         uint64
}

type branchCoverageReport struct {
	covered   int
	total     int
	uncovered []branchArm
}

type countProfileBlock struct {
	startLine   int
	startColumn int
	endLine     int
	endColumn   int
	statements  int
	count       uint64
}

type listedPackage struct {
	Dir        string
	ImportPath string
	GoFiles    []string
	CgoFiles   []string
}

var countProfileLine = regexp.MustCompile(`^(.+):([0-9]+)\.([0-9]+),([0-9]+)\.([0-9]+) ([0-9]+) ([0-9]+)$`)

type branchInstrumenter struct {
	fileSet     *token.FileSet
	source      branchSourceFile
	profileFile string
	arms        *[]branchArm
}

func (instrumenter *branchInstrumenter) marker(kind string, position token.Pos) ast.Stmt {
	sourcePosition := instrumenter.fileSet.Position(position)
	id := fmt.Sprintf("%s%06d", branchCoverageMarkerPrefix, len(*instrumenter.arms))
	*instrumenter.arms = append(*instrumenter.arms, branchArm{
		id:          id,
		kind:        kind,
		sourceFile:  instrumenter.source.display,
		line:        sourcePosition.Line,
		column:      sourcePosition.Column,
		profileFile: instrumenter.profileFile,
	})
	return &ast.ExprStmt{X: &ast.CallExpr{
		Fun:  ast.NewIdent(branchCoverageMarkerFunction),
		Args: []ast.Expr{&ast.BasicLit{Kind: token.STRING, Value: strconv.Quote(id)}},
	}}
}

func branchMarkerDeclaration() ast.Decl {
	return &ast.FuncDecl{
		Name: ast.NewIdent(branchCoverageMarkerFunction),
		Type: &ast.FuncType{Params: &ast.FieldList{List: []*ast.Field{{
			Type: ast.NewIdent("string"),
		}}}},
		Body: &ast.BlockStmt{},
	}
}

func (instrumenter *branchInstrumenter) instrumentBlock(block *ast.BlockStmt) {
	if block == nil {
		return
	}
	block.List = instrumenter.instrumentStatementList(block.List)
}

func (instrumenter *branchInstrumenter) instrumentStatementList(statements []ast.Stmt) []ast.Stmt {
	instrumented := make([]ast.Stmt, 0, len(statements))
	for _, statement := range statements {
		instrumenter.instrumentStatement(statement)
		instrumented = append(instrumented, statement)
		if loop, kind, ok := sourceLoop(statement); ok {
			instrumented = append(instrumented, instrumenter.marker(kind+".exit", loop.Body.Rbrace))
		}
	}
	return instrumented
}

type loopStatement struct {
	Body *ast.BlockStmt
}

func sourceLoop(statement ast.Stmt) (loopStatement, string, bool) {
	switch value := statement.(type) {
	case *ast.ForStmt:
		return loopStatement{Body: value.Body}, "for", true
	case *ast.RangeStmt:
		return loopStatement{Body: value.Body}, "range", true
	case *ast.LabeledStmt:
		return sourceLoop(value.Stmt)
	default:
		return loopStatement{}, "", false
	}
}

func (instrumenter *branchInstrumenter) instrumentStatement(statement ast.Stmt) {
	switch value := statement.(type) {
	case *ast.BlockStmt:
		instrumenter.instrumentBlock(value)
	case *ast.IfStmt:
		instrumenter.instrumentBlock(value.Body)
		value.Body.List = append([]ast.Stmt{instrumenter.marker("if.true", value.Body.Lbrace)}, value.Body.List...)
		switch alternative := value.Else.(type) {
		case nil:
			value.Else = &ast.BlockStmt{List: []ast.Stmt{instrumenter.marker("if.false.implicit", value.Pos())}}
		case *ast.BlockStmt:
			instrumenter.instrumentBlock(alternative)
			alternative.List = append([]ast.Stmt{instrumenter.marker("if.false", alternative.Lbrace)}, alternative.List...)
		case *ast.IfStmt:
			instrumenter.instrumentStatement(alternative)
			value.Else = &ast.BlockStmt{List: []ast.Stmt{
				instrumenter.marker("if.false.else-if", alternative.Pos()),
				alternative,
			}}
		}
	case *ast.ForStmt:
		instrumenter.instrumentBlock(value.Body)
		value.Body.List = append([]ast.Stmt{instrumenter.marker("for.body", value.Body.Lbrace)}, value.Body.List...)
	case *ast.RangeStmt:
		instrumenter.instrumentBlock(value.Body)
		value.Body.List = append([]ast.Stmt{instrumenter.marker("range.body", value.Body.Lbrace)}, value.Body.List...)
	case *ast.SwitchStmt:
		instrumenter.instrumentCaseClauses(value.Body, "switch", value.Body.Rbrace)
	case *ast.TypeSwitchStmt:
		instrumenter.instrumentCaseClauses(value.Body, "type-switch", value.Body.Rbrace)
	case *ast.SelectStmt:
		for _, rawClause := range value.Body.List {
			clause, ok := rawClause.(*ast.CommClause)
			if !ok {
				continue
			}
			clause.Body = instrumenter.instrumentStatementList(clause.Body)
			kind := "select.case"
			if clause.Comm == nil {
				kind = "select.default"
			}
			clause.Body = append([]ast.Stmt{instrumenter.marker(kind, clause.Case)}, clause.Body...)
		}
	case *ast.LabeledStmt:
		instrumenter.instrumentStatement(value.Stmt)
	}
}

func (instrumenter *branchInstrumenter) instrumentCaseClauses(body *ast.BlockStmt, prefix string, implicitDefaultPosition token.Pos) {
	hasDefault := false
	for _, rawClause := range body.List {
		clause, ok := rawClause.(*ast.CaseClause)
		if !ok {
			continue
		}
		clause.Body = instrumenter.instrumentStatementList(clause.Body)
		kind := prefix + ".case"
		if clause.List == nil {
			hasDefault = true
			kind = prefix + ".default"
		}
		clause.Body = append([]ast.Stmt{instrumenter.marker(kind, clause.Case)}, clause.Body...)
	}
	if !hasDefault {
		body.List = append(body.List, &ast.CaseClause{
			Body: []ast.Stmt{instrumenter.marker(prefix+".default.implicit", implicitDefaultPosition)},
		})
	}
}

func unsupportedControlFlow(file *ast.File, typeInfo *types.Info) (string, token.Pos) {
	reason := ""
	position := token.NoPos
	ast.Inspect(file, func(node ast.Node) bool {
		if reason != "" {
			return false
		}
		branch, ok := node.(*ast.BranchStmt)
		if ok && branch.Tok == token.FALLTHROUGH {
			reason = "fallthrough cannot distinguish case selection from fallthrough entry"
			position = branch.Pos()
			return false
		}
		loop, ok := node.(*ast.ForStmt)
		if !ok {
			return true
		}
		if loop.Cond == nil {
			reason = "conditionless for loop has no independently measurable normal-exit arm"
			position = loop.Pos()
			return false
		}
		condition := typeInfo.Types[loop.Cond]
		if condition.Value != nil && condition.Value.Kind() == constant.Bool {
			reason = "constant-condition for loop requires unsupported break-aware feasibility analysis"
			position = loop.Pos()
			return false
		}
		return true
	})
	return reason, position
}

func instrumentBranchSources(sources []branchSourceFile, outputDirectory, importPath string) (map[string]string, []branchArm, error) {
	overlay := make(map[string]string, len(sources))
	arms := make([]branchArm, 0)
	fileSet := token.NewFileSet()
	parsedFiles := make([]*ast.File, 0, len(sources))
	for _, source := range sources {
		parsed, err := parser.ParseFile(fileSet, source.path, nil, parser.ParseComments)
		if err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", source.display, err)
		}
		parsedFiles = append(parsedFiles, parsed)
	}
	typeInfo := &types.Info{Types: make(map[ast.Expr]types.TypeAndValue)}
	typeChecker := types.Config{Importer: importer.Default()}
	if _, err := typeChecker.Check(importPath, fileSet, parsedFiles, typeInfo); err != nil {
		return nil, nil, fmt.Errorf("type-check branch coverage sources: %w", err)
	}
	for fileIndex, source := range sources {
		parsed := parsedFiles[fileIndex]
		if reason, position := unsupportedControlFlow(parsed, typeInfo); reason != "" {
			where := fileSet.Position(position)
			return nil, nil, fmt.Errorf("%s:%d:%d is unsupported: %s", source.display, where.Line, where.Column, reason)
		}
		if fileIndex == 0 {
			parsed.Decls = append(parsed.Decls, branchMarkerDeclaration())
		}

		instrumenter := branchInstrumenter{
			fileSet:     fileSet,
			source:      source,
			profileFile: pathpkg.Join(importPath, filepath.Base(source.path)),
			arms:        &arms,
		}
		var functionBodies []*ast.BlockStmt
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.FuncDecl:
				if value.Body != nil {
					functionBodies = append(functionBodies, value.Body)
				}
			case *ast.FuncLit:
				functionBodies = append(functionBodies, value.Body)
			}
			return true
		})
		for _, body := range functionBodies {
			instrumenter.instrumentBlock(body)
		}

		var formatted bytes.Buffer
		if err := format.Node(&formatted, fileSet, parsed); err != nil {
			return nil, nil, fmt.Errorf("format instrumented %s: %w", source.display, err)
		}
		replacement := filepath.Join(outputDirectory, fmt.Sprintf("%03d-%s", fileIndex, filepath.Base(source.path)))
		if err := os.WriteFile(replacement, formatted.Bytes(), 0o600); err != nil {
			return nil, nil, fmt.Errorf("write instrumented %s: %w", source.display, err)
		}
		overlay[source.path] = replacement
	}

	armIndexes := make(map[string]int, len(arms))
	for index := range arms {
		armIndexes[arms[index].id] = index
	}
	seenMarkers := make(map[string]bool, len(arms))
	for original, replacement := range overlay {
		fileSet := token.NewFileSet()
		parsed, err := parser.ParseFile(fileSet, replacement, nil, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("reparse instrumented %s: %w", original, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			expression, ok := node.(*ast.ExprStmt)
			if !ok {
				return true
			}
			call, ok := expression.X.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			identifier, ok := call.Fun.(*ast.Ident)
			literal, literalOK := call.Args[0].(*ast.BasicLit)
			if !ok || identifier.Name != branchCoverageMarkerFunction || !literalOK || literal.Kind != token.STRING {
				return true
			}
			value, unquoteErr := strconv.Unquote(literal.Value)
			if unquoteErr != nil || !strings.HasPrefix(value, branchCoverageMarkerPrefix) {
				return true
			}
			armIndex, present := armIndexes[value]
			if !present || seenMarkers[value] {
				err = fmt.Errorf("instrumented branch marker %q is missing from or duplicated in the arm inventory", value)
				return false
			}
			position := fileSet.Position(expression.Pos())
			arms[armIndex].profileLine = position.Line
			arms[armIndex].profileColumn = position.Column
			seenMarkers[value] = true
			return true
		})
		if err != nil {
			return nil, nil, err
		}
	}
	for _, arm := range arms {
		if !seenMarkers[arm.id] {
			return nil, nil, fmt.Errorf("instrumented branch marker %q was not emitted", arm.id)
		}
	}
	return overlay, arms, nil
}

func parseCountProfile(profile []byte) (map[string][]countProfileBlock, error) {
	scanner := bufio.NewScanner(bytes.NewReader(profile))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	if !scanner.Scan() || scanner.Text() != "mode: count" {
		return nil, fmt.Errorf("coverage profile must begin with mode: count")
	}
	blocks := make(map[string][]countProfileBlock)
	for scanner.Scan() {
		matches := countProfileLine.FindStringSubmatch(scanner.Text())
		if matches == nil {
			return nil, fmt.Errorf("malformed count profile line %q", scanner.Text())
		}
		values := make([]uint64, 0, 6)
		for _, raw := range matches[2:] {
			value, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("malformed count profile integer %q: %w", raw, err)
			}
			values = append(values, value)
		}
		blocks[matches[1]] = append(blocks[matches[1]], countProfileBlock{
			startLine:   int(values[0]),
			startColumn: int(values[1]),
			endLine:     int(values[2]),
			endColumn:   int(values[3]),
			statements:  int(values[4]),
			count:       values[5],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return blocks, nil
}

func profilePositionBefore(line, column, otherLine, otherColumn int) bool {
	return line < otherLine || line == otherLine && column < otherColumn
}

func blockContains(block countProfileBlock, line, column int) bool {
	startsBeforeOrAt := !profilePositionBefore(line, column, block.startLine, block.startColumn)
	endsAfter := profilePositionBefore(line, column, block.endLine, block.endColumn)
	return startsBeforeOrAt && endsAfter
}

func reportBranchCoverage(arms []branchArm, profile []byte) (branchCoverageReport, error) {
	blocksByFile, err := parseCountProfile(profile)
	if err != nil {
		return branchCoverageReport{}, err
	}
	for armIndex := range arms {
		matching := make([]countProfileBlock, 0, 1)
		for _, block := range blocksByFile[arms[armIndex].profileFile] {
			if blockContains(block, arms[armIndex].profileLine, arms[armIndex].profileColumn) {
				matching = append(matching, block)
			}
		}
		if len(matching) != 1 {
			available := blocksByFile[arms[armIndex].profileFile]
			preview := available
			if len(preview) > 8 {
				preview = preview[:8]
			}
			return branchCoverageReport{}, fmt.Errorf("%s:%d:%d %s marker at profile %s:%d:%d maps to %d compiler counter blocks (file blocks=%d, first=%+v)", arms[armIndex].sourceFile, arms[armIndex].line, arms[armIndex].column, arms[armIndex].kind, arms[armIndex].profileFile, arms[armIndex].profileLine, arms[armIndex].profileColumn, len(matching), len(available), preview)
		}
		arms[armIndex].count = matching[0].count
	}

	report := branchCoverageReport{total: len(arms)}
	for _, arm := range arms {
		if arm.count > 0 {
			report.covered++
		} else {
			report.uncovered = append(report.uncovered, arm)
		}
	}
	sort.Slice(report.uncovered, func(i, j int) bool {
		left, right := report.uncovered[i], report.uncovered[j]
		if left.sourceFile != right.sourceFile {
			return left.sourceFile < right.sourceFile
		}
		if left.line != right.line {
			return left.line < right.line
		}
		if left.column != right.column {
			return left.column < right.column
		}
		return left.kind < right.kind
	})
	return report, nil
}

func commandEnvironment(overrides map[string]string) []string {
	blocked := map[string]bool{
		"GOFLAGS":                     true,
		branchCoverageChildEnv:        true,
		branchCoverageSelfTestModeEnv: true,
		"STEAD_PRINT_POLICY_GOLDEN":   true,
		"STEAD_PRINT_WS06_CANONICAL":  true,
		"STEAD_UPDATE_POLICY_GOLDEN":  true,
	}
	for key := range overrides {
		blocked[key] = true
	}
	environment := make([]string, 0, len(os.Environ())+len(overrides)+1)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !blocked[key] {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "GOFLAGS=")
	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		environment = append(environment, key+"="+overrides[key])
	}
	return environment
}

func copyBranchCoverageTree(sourceRoot, destinationRoot string) error {
	return filepath.WalkDir(sourceRoot, func(sourcePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(sourceRoot, sourcePath)
		if err != nil {
			return err
		}
		// Local service data and signing/credential state are never test source.
		if entry.Name() == ".git" || entry.Name() == "node_modules" || entry.Name() == ".cache" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		destinationPath := filepath.Join(destinationRoot, relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		switch {
		case entry.IsDir():
			return os.MkdirAll(destinationPath, info.Mode().Perm())
		case info.Mode().IsRegular():
			content, err := os.ReadFile(sourcePath)
			if err != nil {
				return err
			}
			return os.WriteFile(destinationPath, content, info.Mode().Perm())
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(sourcePath)
			if err != nil {
				return err
			}
			return os.Symlink(target, destinationPath)
		default:
			return fmt.Errorf("unsupported file type in branch coverage copy: %s", sourcePath)
		}
	})
}

func activePackageSources(goBinary, root, packageArgument string) ([]branchSourceFile, string, error) {
	command := exec.Command(goBinary, "list", "-json", packageArgument)
	command.Dir = root
	command.Env = commandEnvironment(nil)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, "", fmt.Errorf("go list %s: %w\n%s", packageArgument, err, output)
	}
	var listed listedPackage
	if err := json.Unmarshal(output, &listed); err != nil {
		return nil, "", fmt.Errorf("decode go list output: %w", err)
	}
	activeFiles := append(append([]string(nil), listed.GoFiles...), listed.CgoFiles...)
	sources := make([]branchSourceFile, 0, len(activeFiles))
	for _, name := range activeFiles {
		absolute := filepath.Join(listed.Dir, name)
		relative, err := filepath.Rel(root, absolute)
		if err != nil {
			return nil, "", err
		}
		sources = append(sources, branchSourceFile{path: absolute, display: filepath.ToSlash(relative)})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].path < sources[j].path })
	return sources, listed.ImportPath, nil
}

func executeInstrumentedBranchCoverage(goBinary, root, testArgument, importPath string, sources []branchSourceFile, environment map[string]string) (branchCoverageReport, []branchArm, string, error) {
	temporary, err := os.MkdirTemp("", "stead-branch-coverage-")
	if err != nil {
		return branchCoverageReport{}, nil, "", err
	}
	defer os.RemoveAll(temporary)
	copiedRoot := filepath.Join(temporary, "repository")
	if err := copyBranchCoverageTree(root, copiedRoot); err != nil {
		return branchCoverageReport{}, nil, "", fmt.Errorf("copy branch coverage repository: %w", err)
	}

	instrumentedDirectory := filepath.Join(temporary, "instrumented")
	if err := os.MkdirAll(instrumentedDirectory, 0o700); err != nil {
		return branchCoverageReport{}, nil, "", err
	}
	replacements, arms, err := instrumentBranchSources(sources, instrumentedDirectory, importPath)
	if err != nil {
		return branchCoverageReport{}, nil, "", err
	}
	if len(arms) == 0 {
		return branchCoverageReport{}, nil, "", fmt.Errorf("no control-flow branch arms found in %s", importPath)
	}
	for original, replacement := range replacements {
		relative, err := filepath.Rel(root, original)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return branchCoverageReport{}, nil, "", fmt.Errorf("instrumented source %s is outside branch coverage root %s", original, root)
		}
		content, err := os.ReadFile(replacement)
		if err != nil {
			return branchCoverageReport{}, nil, "", err
		}
		info, err := os.Stat(original)
		if err != nil {
			return branchCoverageReport{}, nil, "", err
		}
		if err := os.WriteFile(filepath.Join(copiedRoot, relative), content, info.Mode().Perm()); err != nil {
			return branchCoverageReport{}, nil, "", err
		}
	}
	profilePath := filepath.Join(temporary, "count.cover")
	arguments := []string{
		"test", testArgument,
		"-count=1",
		"-covermode=count",
		"-coverpkg=" + importPath,
		"-coverprofile=" + profilePath,
	}
	command := exec.Command(goBinary, arguments...)
	command.Dir = copiedRoot
	command.Env = commandEnvironment(environment)
	output, err := command.CombinedOutput()
	if err != nil {
		return branchCoverageReport{}, nil, string(output), fmt.Errorf("instrumented go test: %w", err)
	}
	profile, err := os.ReadFile(profilePath)
	if err != nil {
		return branchCoverageReport{}, nil, string(output), err
	}
	report, err := reportBranchCoverage(arms, profile)
	return report, arms, string(output), err
}

func formatBranchCoverageReport(report branchCoverageReport) string {
	percentage := 0.0
	if report.total != 0 {
		percentage = float64(report.covered) * 100 / float64(report.total)
	}
	var result strings.Builder
	fmt.Fprintf(&result, "policyrelease control-flow branch-arm coverage: %.2f%% (%d/%d; threshold %d%%)\n", percentage, report.covered, report.total, policyReleaseBranchThreshold)
	result.WriteString("method: compiler -covermode=count over semantic no-op markers for if true/false, switch/type-switch case/default, select clauses, and for/range body/normal-exit arms; short-circuit expression operands excluded\n")
	if len(report.uncovered) == 0 {
		result.WriteString("uncovered branch arms: none\n")
	} else {
		result.WriteString("uncovered branch arms:\n")
		for _, arm := range report.uncovered {
			fmt.Fprintf(&result, "- %s:%d:%d %s\n", arm.sourceFile, arm.line, arm.column, arm.kind)
		}
	}
	return result.String()
}

func meetsBranchCoverageFloor(report branchCoverageReport, floor int) bool {
	return report.total > 0 && report.covered*100 >= floor*report.total
}

func TestPolicyReleaseControlFlowBranchCoverage(t *testing.T) {
	if os.Getenv(branchCoverageChildEnv) == "1" {
		return
	}
	root := repositoryRoot(t)
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	sources, importPath, err := activePackageSources(goBinary, root, policyReleasePackageArgument)
	if err != nil {
		t.Fatal(err)
	}
	if importPath != policyReleaseImportPath {
		t.Fatalf("policyrelease import path = %q, want %q", importPath, policyReleaseImportPath)
	}
	report, _, childOutput, err := executeInstrumentedBranchCoverage(
		goBinary,
		root,
		policyReleaseTestArgument,
		importPath,
		sources,
		map[string]string{branchCoverageChildEnv: "1"},
	)
	if err != nil {
		t.Fatalf("branch coverage child failed: %v\n%s", err, childOutput)
	}
	formatted := formatBranchCoverageReport(report)
	if !meetsBranchCoverageFloor(report, policyReleaseBranchThreshold) {
		t.Fatalf("RG-03 branch coverage is below its exact floor\n%s", formatted)
	}
	fmt.Print(formatted)
}
