package orchestrator_test

import (
	"context"
	"strings"
	"testing"

	"github.com/khakiem/playground/langchain/pkg/orchestrator"
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
		t.Errorf("want 2 attempts (1 fail + 1 repaired), got %d", task.Attempts)
	}
	if len(judge.Calls) != 1 {
		t.Errorf("want judge called once, got %d", len(judge.Calls))
	}
	// Judge should have received the compiler errors.
	if len(judge.Calls[0].Errors) == 0 {
		t.Error("expected judge to receive non-empty build errors")
	}
}

func TestExecutionLoop_ExhaustsRetries(t *testing.T) {
	judge := &orchestrator.MockJudge{} // no fix → echoes broken code back
	loop := &orchestrator.ExecutionLoop{Judge: judge, MaxRetries: 2}
	task := &orchestrator.Task{ID: "t3", Code: brokenCode}

	err := loop.Run(context.Background(), task)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if task.Status != orchestrator.StatusFailed {
		t.Errorf("want %q, got %q", orchestrator.StatusFailed, task.Status)
	}
	// MaxRetries=2 means: 1 initial + 2 retries = 3 total attempts.
	if task.Attempts != 3 {
		t.Errorf("want 3 attempts, got %d", task.Attempts)
	}
	if !strings.Contains(err.Error(), "exhausted") {
		t.Errorf("error message should mention exhausted retries, got: %v", err)
	}
}

func TestExecutionLoop_ErrorsPassedToJudge(t *testing.T) {
	judge := &orchestrator.MockJudge{Responses: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{Judge: judge, MaxRetries: 1}
	task := &orchestrator.Task{ID: "t4", Code: brokenCode}

	_ = loop.Run(context.Background(), task)

	if len(judge.Calls) == 0 {
		t.Fatal("judge was never called")
	}
	call := judge.Calls[0]
	if call.Code != brokenCode {
		t.Error("judge should receive the original broken code")
	}
	if len(call.Errors) == 0 {
		t.Error("judge should receive non-empty compiler errors")
	}
}

func TestExecutionLoop_ZeroRetries(t *testing.T) {
	judge := &orchestrator.MockJudge{}
	loop := &orchestrator.ExecutionLoop{Judge: judge, MaxRetries: 0}
	task := &orchestrator.Task{ID: "t5", Code: brokenCode}

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

func TestExecutionLoop_GenerateInitialCode_ExhaustedMockErrors(t *testing.T) {
	mj := &orchestrator.MockJudge{} // no GeneratedCodes
	loop := &orchestrator.ExecutionLoop{Generator: mj, Judge: mj, MaxRetries: 0}
	err := loop.GenerateInitialCode(context.Background(), &orchestrator.Task{}, "anything")
	if err == nil {
		t.Fatal("expected error when MockJudge has no GeneratedCodes")
	}
}

func TestExecutionLoop_RunFromRequirement_FullPipeline_Success(t *testing.T) {
	// Generation produces valid code on the first call → no fix needed.
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
	if len(mj.Calls) != 0 {
		t.Errorf("judge should not be called when generated code compiles, got %d calls", len(mj.Calls))
	}
}

func TestExecutionLoop_RunFromRequirement_FullPipeline_GenerateAndFix(t *testing.T) {
	// Generation produces broken code; judge provides the fix.
	mj := &orchestrator.MockJudge{
		GeneratedCodes: []string{brokenCode},
		Responses:      []string{validCode},
	}
	loop := &orchestrator.ExecutionLoop{Generator: mj, Judge: mj, MaxRetries: 3}
	task := &orchestrator.Task{ID: "full-2"}

	if err := loop.RunFromRequirement(context.Background(), task, "print ok"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.Status != orchestrator.StatusSuccess {
		t.Errorf("want %q, got %q", orchestrator.StatusSuccess, task.Status)
	}
	// 1 attempt with generated (broken) code + 1 attempt with fixed code.
	if task.Attempts != 2 {
		t.Errorf("want 2 attempts, got %d", task.Attempts)
	}
	if len(mj.Calls) != 1 {
		t.Errorf("want judge called once, got %d", len(mj.Calls))
	}
	// Verify the judge received the actual compiler errors, not an empty slice.
	if len(mj.Calls[0].Errors) == 0 {
		t.Error("judge should receive real compiler errors from go build")
	}
}

func TestExecutionLoop_RunFromRequirement_GenerationFails_Propagates(t *testing.T) {
	mj := &orchestrator.MockJudge{} // no GeneratedCodes → GenerateInitialCode returns error
	loop := &orchestrator.ExecutionLoop{Generator: mj, Judge: mj, MaxRetries: 3}
	task := &orchestrator.Task{ID: "full-3"}

	err := loop.RunFromRequirement(context.Background(), task, "anything")
	if err == nil {
		t.Fatal("expected error when generation fails")
	}
	// Loop should not have attempted any build.
	if task.Attempts != 0 {
		t.Errorf("build should not have been attempted, got %d attempts", task.Attempts)
	}
}
