package orchestrator_test

import (
	"context"
	"strings"
	"testing"

	"github.com/khakiem/playground/langchain/pkg/orchestrator"
)

// ─────────────────────────────────────────────────────────────────────────────
// TestGenerator / oracle tests
// ─────────────────────────────────────────────────────────────────────────────

// stubCode compiles but does nothing useful — the oracle must catch this.
const stubCode = `package main

func calculate(expr string) int { return 0 }

func main() {}
`

// stubTestCode is a test that will FAIL against stubCode because calculate("2+3") != 5.
const stubTestCode = `package main

import "testing"

func TestCalculate_Addition(t *testing.T) {
	if got := calculate("2+3"); got != 5 {
		t.Errorf("calculate(\"2+3\") = %d, want 5", got)
	}
}
`

// workingCode passes the test.
const workingCode = `package main

import "strconv"

func calculate(expr string) int {
	// Trivial: only handles single-digit addition for this test.
	parts := []byte(expr)
	if len(parts) == 3 && parts[1] == '+' {
		a, _ := strconv.Atoi(string(parts[0]))
		b, _ := strconv.Atoi(string(parts[2]))
		return a + b
	}
	return 0
}

func main() {}
`

func TestOracle_StubCode_FailsBuild(t *testing.T) {
	// The stub compiles and has no audit findings, but the test oracle must
	// surface "got 0, want 5" as a build error so the judge knows it's wrong.
	loop := &orchestrator.ExecutionLoop{
		Judge:      &orchestrator.MockJudge{},
		MaxRetries: 0,
	}
	task := &orchestrator.Task{
		ID:       "oracle-stub",
		Code:     stubCode,
		TestCode: stubTestCode,
	}

	err := loop.Run(context.Background(), task)
	if err == nil {
		t.Fatal("expected error: stub should fail the oracle tests")
	}
	if task.Status != orchestrator.StatusFailed {
		t.Errorf("want failed, got %q", task.Status)
	}
	// The build errors should contain the test assertion failure.
	joined := strings.Join(task.Errors, "\n")
	if !strings.Contains(joined, "want 5") {
		t.Errorf("build errors should contain test assertion; got:\n%s", joined)
	}
}

func TestOracle_WorkingCode_Passes(t *testing.T) {
	loop := &orchestrator.ExecutionLoop{
		Judge:      &orchestrator.MockJudge{},
		MaxRetries: 0,
	}
	task := &orchestrator.Task{
		ID:       "oracle-pass",
		Code:     workingCode,
		TestCode: stubTestCode,
	}

	if err := loop.Run(context.Background(), task); err != nil {
		t.Fatalf("working code should pass oracle: %v", err)
	}
	if task.Status != orchestrator.StatusSuccess {
		t.Errorf("want success, got %q", task.Status)
	}
}

func TestOracle_NoTestCode_SkipsTestPhase(t *testing.T) {
	// When no TestGenerator was set, TestCode is "" and the pipeline must
	// behave exactly as before — build + audit only.
	loop := &orchestrator.ExecutionLoop{
		Judge:      &orchestrator.MockJudge{},
		MaxRetries: 0,
	}
	task := &orchestrator.Task{
		ID:   "oracle-none",
		Code: validCode, // compiles, no test
	}

	if err := loop.Run(context.Background(), task); err != nil {
		t.Fatalf("should succeed without test oracle: %v", err)
	}
}

func TestOracle_JudgeReceivesTestCode(t *testing.T) {
	// When the stub fails the oracle, the judge must receive the test file
	// in the RepairRequest so it knows what behaviour is expected.
	judge := &orchestrator.MockJudge{Responses: []string{workingCode}}
	loop := &orchestrator.ExecutionLoop{
		Judge:      judge,
		MaxRetries: 1,
	}
	task := &orchestrator.Task{
		ID:       "oracle-judge",
		Code:     stubCode,
		TestCode: stubTestCode,
	}

	if err := loop.Run(context.Background(), task); err != nil {
		t.Fatalf("should succeed after judge fixes: %v", err)
	}
	if len(judge.Calls) == 0 {
		t.Fatal("judge should be called when tests fail")
	}
	req := judge.Calls[0]
	if req.TestCode != stubTestCode {
		t.Error("RepairRequest.TestCode should contain the oracle test file")
	}
}

func TestOracle_TestCodeAppearsInAuditorPrompt(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{Responses: []string{"package main\nfunc main(){}"}}
	judge := &orchestrator.AuditorJudge{LLM: llm}

	req := orchestrator.RepairRequest{
		Code:        stubCode,
		TestCode:    stubTestCode,
		BuildErrors: []string{"FAIL TestCalculate_Addition"},
	}
	_, err := judge.Fix(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	prompt := llm.Prompts[0]
	if !strings.Contains(prompt, "TEST FILE") {
		t.Error("prompt should contain TEST FILE section when TestCode is present")
	}
	if !strings.Contains(prompt, "TestCalculate_Addition") {
		t.Error("prompt should contain the test function name")
	}
}

func TestOracle_TestCodeOmittedFromPromptWhenEmpty(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{Responses: []string{"package main\nfunc main(){}"}}
	judge := &orchestrator.AuditorJudge{LLM: llm}

	req := orchestrator.RepairRequest{
		Code:        "package main\nfunc main(){}",
		BuildErrors: []string{"main.go:1:1: undefined: x"},
	}
	_, _ = judge.Fix(context.Background(), req)
	if strings.Contains(llm.Prompts[0], "TEST FILE") {
		t.Error("prompt should not contain TEST FILE section when TestCode is empty")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// RunFromRequirement integration: TestGenerator is called
// ─────────────────────────────────────────────────────────────────────────────

// mockTestGenerator returns a canned test file.
type mockTestGenerator struct {
	testCode string
	calls    int
}

func (m *mockTestGenerator) GenerateTests(_ context.Context, _, _ string) (string, error) {
	m.calls++
	return m.testCode, nil
}

func TestRunFromRequirement_TestGeneratorCalled(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{workingCode}}
	tg := &mockTestGenerator{testCode: stubTestCode}
	loop := &orchestrator.ExecutionLoop{
		Generator:     mj,
		Judge:         mj,
		TestGenerator: tg,
		MaxRetries:    1,
	}
	task := &orchestrator.Task{ID: "tg-1"}

	if err := loop.RunFromRequirement(context.Background(), task, "calculator"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tg.calls != 1 {
		t.Errorf("TestGenerator should be called once, got %d", tg.calls)
	}
	if task.TestCode != stubTestCode {
		t.Error("task.TestCode should be populated by the pipeline")
	}
}

func TestRunFromRequirement_NilTestGenerator_SkipsOracle(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{
		Generator: mj,
		Judge:     mj,
		MaxRetries: 0,
	}
	task := &orchestrator.Task{ID: "tg-nil"}

	if err := loop.RunFromRequirement(context.Background(), task, "print ok"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.TestCode != "" {
		t.Error("TestCode should be empty when no TestGenerator is set")
	}
}
