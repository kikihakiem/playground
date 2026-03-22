package orchestrator_test

import (
	"context"
	"strings"
	"testing"

	"github.com/khakiem/playground/ai-orchestrator/pkg/orchestrator"
)

// ─────────────────────────────────────────────────────────────────────────────
// ImportFixer — unit tests
// ─────────────────────────────────────────────────────────────────────────────

func TestImportFixer_AddsSimpleMissingImport(t *testing.T) {
	code := `package main

func main() {
	fmt.Println("hello")
}
`
	got, err := orchestrator.ImportFixer{}.Process(code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, `"fmt"`) {
		t.Errorf("expected fmt import to be added:\n%s", got)
	}
}

func TestImportFixer_AddsStrconv(t *testing.T) {
	code := `package main

import "fmt"

func main() {
	fmt.Println(strconv.Itoa(42))
}
`
	got, err := orchestrator.ImportFixer{}.Process(code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, `"strconv"`) {
		t.Errorf("expected strconv import to be added:\n%s", got)
	}
	// Existing import must be preserved.
	if !strings.Contains(got, `"fmt"`) {
		t.Errorf("existing fmt import should be preserved:\n%s", got)
	}
}

func TestImportFixer_AddsNetHttp(t *testing.T) {
	code := `package main

func main() {
	http.ListenAndServe(":8080", nil)
}
`
	got, err := orchestrator.ImportFixer{}.Process(code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, `"net/http"`) {
		t.Errorf("expected net/http import to be added:\n%s", got)
	}
}

func TestImportFixer_AddsMultipleMissing(t *testing.T) {
	code := `package main

func main() {
	fmt.Println(strconv.Itoa(42))
	os.Exit(1)
}
`
	got, err := orchestrator.ImportFixer{}.Process(code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{`"fmt"`, `"strconv"`, `"os"`} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %s import to be added:\n%s", want, got)
		}
	}
}

func TestImportFixer_NoChangeWhenAllImportsPresent(t *testing.T) {
	code := `package main

import (
	"fmt"
	"strconv"
)

func main() {
	fmt.Println(strconv.Itoa(42))
}
`
	got, err := orchestrator.ImportFixer{}.Process(code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only formatting may differ; no new imports should appear.
	if strings.Count(got, `"fmt"`) != 1 || strings.Count(got, `"strconv"`) != 1 {
		t.Errorf("imports should appear exactly once:\n%s", got)
	}
}

func TestImportFixer_DoesNotAddUnknownPackage(t *testing.T) {
	code := `package main

func main() {
	unknownpkg.DoSomething()
}
`
	got, err := orchestrator.ImportFixer{}.Process(code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(got, "unknownpkg") && strings.Contains(got, "import") {
		// unknownpkg could only appear in an import if we wrongly added it.
		if strings.Contains(got, `"unknownpkg"`) {
			t.Error("should not add an unknown package to imports")
		}
	}
}

func TestImportFixer_UnparsableCodeReturnedUnchanged(t *testing.T) {
	code := `this is not valid go code at all {{{`
	got, err := orchestrator.ImportFixer{}.Process(code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != code {
		t.Errorf("unparseable code should be returned unchanged")
	}
}

func TestImportFixer_NoImportBlockCreatesOne(t *testing.T) {
	// Code with no import statement at all.
	code := `package main

func main() {
	fmt.Println("hi")
	os.Exit(0)
}
`
	got, err := orchestrator.ImportFixer{}.Process(code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "import") {
		t.Errorf("expected an import block to be created:\n%s", got)
	}
	for _, want := range []string{`"fmt"`, `"os"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in output:\n%s", want, got)
		}
	}
}

func TestImportFixer_LocalFieldAccessNotMistaken(t *testing.T) {
	// r.URL is a field access on a local variable, not a package reference.
	// ImportFixer must not attempt to add an import for "r" or "URL".
	code := `package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Path
}

func main() {
	http.HandleFunc("/", handler)
}
`
	got, err := orchestrator.ImportFixer{}.Process(code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// net/http should appear exactly once.
	if strings.Count(got, `"net/http"`) != 1 {
		t.Errorf("net/http should appear exactly once:\n%s", got)
	}
}

func TestImportFixer_ResultCompilesAfterFix(t *testing.T) {
	// End-to-end: fix a known broken snippet and verify it now builds.
	code := `package main

func main() {
	fmt.Println(strconv.Itoa(42))
}
`
	fixed, err := orchestrator.ImportFixer{}.Process(code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	loop := &orchestrator.ExecutionLoop{
		Judge:      &orchestrator.MockJudge{},
		MaxRetries: 0,
	}
	task := &orchestrator.Task{ID: "fixer-compile", Code: fixed}
	if err := loop.Run(context.Background(), task); err != nil {
		t.Errorf("fixed code should compile cleanly, got: %v\ncode:\n%s", err, fixed)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ExecutionLoop integration: preprocessors run before each build attempt
// ─────────────────────────────────────────────────────────────────────────────

func TestExecutionLoop_PreprocessorRunsBeforeBuild(t *testing.T) {
	// Code that has a missing import — would fail to compile without the fixer.
	missingImportCode := `package main

func main() {
	fmt.Println("hello")
}
`
	mj := &orchestrator.MockJudge{}
	loop := &orchestrator.ExecutionLoop{
		Generator:     mj,
		Judge:         mj,
		Preprocessors: []orchestrator.Preprocessor{orchestrator.ImportFixer{}},
		MaxRetries:    0,
	}
	task := &orchestrator.Task{ID: "pp-1", Code: missingImportCode}

	if err := loop.Run(context.Background(), task); err != nil {
		t.Errorf("ImportFixer should have fixed the missing import; got: %v", err)
	}
	if task.Status != orchestrator.StatusSuccess {
		t.Errorf("want success, got %q", task.Status)
	}
	if task.Attempts != 1 {
		t.Errorf("want 1 attempt (no retry needed), got %d", task.Attempts)
	}
}

func TestExecutionLoop_NoPreprocessor_MissingImportFails(t *testing.T) {
	// Same code without the fixer must fail to compile.
	missingImportCode := `package main

func main() {
	fmt.Println("hello")
}
`
	mj := &orchestrator.MockJudge{}
	loop := &orchestrator.ExecutionLoop{
		Judge:      mj,
		MaxRetries: 0,
		// No Preprocessors
	}
	task := &orchestrator.Task{ID: "pp-2", Code: missingImportCode}

	if err := loop.Run(context.Background(), task); err == nil {
		t.Error("expected compile error without ImportFixer")
	}
}

func TestExecutionLoop_PreprocessorAppliedOnEveryAttempt(t *testing.T) {
	// Use a toggleLinterTool so the first attempt fails (tool finding) and
	// the judge is called, then the second attempt succeeds.
	// The preprocessor must be invoked on both attempts.
	toggle := &toggleLinterTool{findingOnFirst: orchestrator.Finding{
		Tool: "toggle", File: "main.go", Line: 1,
		Severity: orchestrator.SeverityHigh, Rule: "T001", Message: "first pass finding",
	}}

	fixer := &countingPreprocessor{inner: orchestrator.ImportFixer{}}
	loop := &orchestrator.ExecutionLoop{
		Judge:         &orchestrator.MockJudge{Responses: []string{validCode}},
		Preprocessors: []orchestrator.Preprocessor{fixer},
		Tools:         []orchestrator.AnalysisTool{toggle},
		MaxRetries:    2,
	}
	task := &orchestrator.Task{ID: "pp-3", Code: validCode}
	_ = loop.Run(context.Background(), task)

	if fixer.calls != task.Attempts {
		t.Errorf("preprocessor should run once per attempt: want %d calls, got %d",
			task.Attempts, fixer.calls)
	}
	if fixer.calls < 2 {
		t.Errorf("expected at least 2 preprocessor calls, got %d", fixer.calls)
	}
}

// countingPreprocessor wraps another Preprocessor and counts invocations.
type countingPreprocessor struct {
	inner orchestrator.Preprocessor
	calls int
}

func (c *countingPreprocessor) Process(code string) (string, error) {
	c.calls++
	return c.inner.Process(code)
}
