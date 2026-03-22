package orchestrator_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/khakiem/playground/ai-orchestrator/pkg/orchestrator"
)

const validCode = `package main

import "fmt"

func main() {
	fmt.Println("ok")
}
`

const brokenCode = `package main

func main() {
	fmt.Println("missing import")
}
`

// fakeBuild is a mock BuildFunc that checks whether code contains "missing import"
// (i.e. brokenCode) to decide pass/fail, without spawning real subprocesses.
func fakeBuild(_ context.Context, code, _ string, _ []orchestrator.AnalysisTool, _ []orchestrator.ApprovedDep) (
	[]string, []orchestrator.Finding, []error, error,
) {
	if strings.Contains(code, "missing import") {
		return []string{"main.go:4:2: undefined: fmt"}, nil, nil, nil
	}
	return nil, nil, nil, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// ExecutionLoop.Run (build + fix)
// ─────────────────────────────────────────────────────────────────────────────

func TestExecutionLoop_SucceedsFirstAttempt(t *testing.T) {
	loop := &orchestrator.ExecutionLoop{
		Judge:      &orchestrator.MockJudge{},
		MaxRetries: 3,
	}
	task := &orchestrator.Task{ID: "t1", Code: validCode}

	if err := loop.Run(context.Background(), task); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.Status != orchestrator.StatusSuccess {
		t.Errorf("want status %q, got %q", orchestrator.StatusSuccess, task.Status)
	}
	if task.Attempts != 1 {
		t.Errorf("want 1 attempt, got %d", task.Attempts)
	}
}

func TestExecutionLoop_JudgeRepairsOnFirstRetry(t *testing.T) {
	judge := &orchestrator.MockJudge{Responses: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{Judge: judge, MaxRetries: 3}
	task := &orchestrator.Task{ID: "t2", Code: brokenCode}

	if err := loop.Run(context.Background(), task); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.Status != orchestrator.StatusSuccess {
		t.Errorf("want %q, got %q", orchestrator.StatusSuccess, task.Status)
	}
	if task.Attempts != 2 {
		t.Errorf("want 2 attempts (1 fail + 1 repair), got %d", task.Attempts)
	}
	if len(judge.Calls) != 1 {
		t.Errorf("want judge called once, got %d", len(judge.Calls))
	}
}

func TestExecutionLoop_ExhaustsRetries(t *testing.T) {
	judge := &orchestrator.MockJudge{} // no fix → echoes broken code
	loop := &orchestrator.ExecutionLoop{Judge: judge, MaxRetries: 2}
	task := &orchestrator.Task{ID: "t3", Code: brokenCode}

	err := loop.Run(context.Background(), task)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if task.Status != orchestrator.StatusFailed {
		t.Errorf("want %q, got %q", orchestrator.StatusFailed, task.Status)
	}
	// MaxRetries=2: 1 initial + 2 retries = 3 total attempts.
	if task.Attempts != 3 {
		t.Errorf("want 3 attempts, got %d", task.Attempts)
	}
	if !strings.Contains(err.Error(), "exhausted") {
		t.Errorf("error should mention exhausted, got: %v", err)
	}
}

func TestExecutionLoop_ZeroRetries(t *testing.T) {
	judge := &orchestrator.MockJudge{}
	loop := &orchestrator.ExecutionLoop{Judge: judge, MaxRetries: 0}
	task := &orchestrator.Task{ID: "t4", Code: brokenCode}

	err := loop.Run(context.Background(), task)
	if err == nil {
		t.Fatal("expected error with MaxRetries=0 and broken code")
	}
	if len(judge.Calls) != 0 {
		t.Errorf("judge should never be called with MaxRetries=0, got %d calls", len(judge.Calls))
	}
	if task.Attempts != 1 {
		t.Errorf("want exactly 1 attempt, got %d", task.Attempts)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// RepairRequest: judge receives real tool output
// ─────────────────────────────────────────────────────────────────────────────

func TestExecutionLoop_JudgeReceivesBuildErrors(t *testing.T) {
	judge := &orchestrator.MockJudge{Responses: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{Judge: judge, MaxRetries: 1}
	task := &orchestrator.Task{ID: "t5", Code: brokenCode}

	_ = loop.Run(context.Background(), task)

	if len(judge.Calls) == 0 {
		t.Fatal("judge was never called")
	}
	req := judge.Calls[0]
	if req.Code != brokenCode {
		t.Error("judge should receive the original broken code")
	}
	if len(req.BuildErrors) == 0 {
		t.Error("judge should receive non-empty compiler errors from real go build")
	}
}

func TestExecutionLoop_JudgeReceivesToolFindings(t *testing.T) {
	// Inject a fake tool that always returns one finding.
	fakeFinding := orchestrator.Finding{
		Tool:     "fake-linter",
		File:     "main.go",
		Line:     1,
		Severity: orchestrator.SeverityHigh,
		Rule:     "F001",
		Message:  "synthetic finding for test",
	}
	fakeTool := &fakeLinterTool{findings: []orchestrator.Finding{fakeFinding}}

	judge := &orchestrator.MockJudge{Responses: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{
		Judge:      judge,
		Tools:      []orchestrator.AnalysisTool{fakeTool},
		MaxRetries: 1,
	}
	task := &orchestrator.Task{ID: "t6", Code: validCode} // valid code so build passes

	_ = loop.Run(context.Background(), task)

	if len(judge.Calls) == 0 {
		t.Fatal("judge should be called because the fake tool returned a finding")
	}
	req := judge.Calls[0]
	if len(req.Findings) == 0 {
		t.Fatal("judge should receive tool findings in RepairRequest")
	}
	if req.Findings[0].Rule != "F001" {
		t.Errorf("want finding rule F001, got %q", req.Findings[0].Rule)
	}
	if len(req.BuildErrors) != 0 {
		t.Error("build errors should be empty when compilation succeeded")
	}
}

func TestExecutionLoop_SucceedsOnceToolsAreClean(t *testing.T) {
	// Tool returns a finding on the first run, clean on the second.
	toggle := &toggleLinterTool{findingOnFirst: orchestrator.Finding{
		Tool: "toggle", File: "main.go", Line: 1,
		Severity: orchestrator.SeverityHigh, Rule: "T001", Message: "first pass finding",
	}}

	judge := &orchestrator.MockJudge{Responses: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{
		Judge:      judge,
		Tools:      []orchestrator.AnalysisTool{toggle},
		MaxRetries: 3,
	}
	task := &orchestrator.Task{ID: "t7", Code: validCode}

	if err := loop.Run(context.Background(), task); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.Status != orchestrator.StatusSuccess {
		t.Errorf("want success, got %q", task.Status)
	}
	if task.Attempts != 2 {
		t.Errorf("want 2 attempts (1 with finding, 1 clean), got %d", task.Attempts)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GenerateInitialCode / RunFromRequirement
// ─────────────────────────────────────────────────────────────────────────────

func TestExecutionLoop_GenerateInitialCode_PopulatesTaskCode(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{Generator: mj, Judge: mj, MaxRetries: 0}
	task := &orchestrator.Task{ID: "gen-1"}

	if err := loop.GenerateInitialCode(context.Background(), task, "print ok"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.Code != validCode {
		t.Errorf("task.Code not populated: got %q", task.Code)
	}
}

func TestExecutionLoop_GenerateInitialCode_NilGeneratorErrors(t *testing.T) {
	loop := &orchestrator.ExecutionLoop{Judge: &orchestrator.MockJudge{}, MaxRetries: 0}
	err := loop.GenerateInitialCode(context.Background(), &orchestrator.Task{}, "anything")
	if err == nil {
		t.Fatal("expected error when Generator is nil")
	}
}

func TestExecutionLoop_RunFromRequirement_FullPipeline_Success(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{Generator: mj, Judge: mj, MaxRetries: 3}
	task := &orchestrator.Task{ID: "full-1"}

	if err := loop.RunFromRequirement(context.Background(), task, "print ok"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.Status != orchestrator.StatusSuccess {
		t.Errorf("want %q, got %q", orchestrator.StatusSuccess, task.Status)
	}
	if task.Attempts != 1 {
		t.Errorf("want 1 build attempt, got %d", task.Attempts)
	}
}

func TestExecutionLoop_RunFromRequirement_GenerateAndFix(t *testing.T) {
	mj := &orchestrator.MockJudge{
		GeneratedCodes: []string{brokenCode},
		Responses:      []string{validCode},
	}
	loop := &orchestrator.ExecutionLoop{Generator: mj, Judge: mj, MaxRetries: 3}
	task := &orchestrator.Task{ID: "full-2"}

	if err := loop.RunFromRequirement(context.Background(), task, "print ok"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.Attempts != 2 {
		t.Errorf("want 2 attempts, got %d", task.Attempts)
	}
	if len(mj.Calls[0].BuildErrors) == 0 {
		t.Error("judge should receive real compiler errors from go build")
	}
}

func TestExecutionLoop_Timeout_ExpiresBeforeBuild(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{brokenCode}}
	loop := &orchestrator.ExecutionLoop{
		Generator:  mj,
		Judge:      mj,
		MaxRetries: 10,
		Timeout:    1 * time.Millisecond, // expires before or during first build
	}
	task := &orchestrator.Task{ID: "timeout-1"}

	err := loop.RunFromRequirement(context.Background(), task, "anything")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded in error chain, got: %v", err)
	}
}

func TestExecutionLoop_Timeout_ZeroMeansNoLimit(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{
		Generator:  mj,
		Judge:      mj,
		MaxRetries: 1,
		Timeout:    0, // no limit
	}
	task := &orchestrator.Task{ID: "timeout-zero"}

	if err := loop.RunFromRequirement(context.Background(), task, "print ok"); err != nil {
		t.Fatalf("unexpected error with zero timeout: %v", err)
	}
}

func TestExecutionLoop_RunFromRequirement_GenerationFails(t *testing.T) {
	mj := &orchestrator.MockJudge{} // no GeneratedCodes
	loop := &orchestrator.ExecutionLoop{Generator: mj, Judge: mj, MaxRetries: 3}
	task := &orchestrator.Task{ID: "full-3"}

	err := loop.RunFromRequirement(context.Background(), task, "anything")
	if err == nil {
		t.Fatal("expected error when generation fails")
	}
	if task.Attempts != 0 {
		t.Errorf("build should not have been attempted, got %d attempts", task.Attempts)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test doubles
// ─────────────────────────────────────────────────────────────────────────────

// fakeLinterTool always returns a fixed set of findings.
type fakeLinterTool struct {
	findings []orchestrator.Finding
}

func (f *fakeLinterTool) Name() string    { return "fake-linter" }
func (f *fakeLinterTool) Available() bool { return true }
func (f *fakeLinterTool) Run(_ context.Context, _ string) ([]orchestrator.Finding, error) {
	return f.findings, nil
}

// toggleLinterTool returns a finding on the first call, then clean forever.
type toggleLinterTool struct {
	findingOnFirst orchestrator.Finding
	called         int
}

func (t *toggleLinterTool) Name() string    { return "toggle-linter" }
func (t *toggleLinterTool) Available() bool { return true }
func (t *toggleLinterTool) Run(_ context.Context, _ string) ([]orchestrator.Finding, error) {
	t.called++
	if t.called == 1 {
		return []orchestrator.Finding{t.findingOnFirst}, nil
	}
	return nil, nil
}
