package orchestrator_test

import (
	"context"
	"strings"
	"testing"

	"github.com/khakiem/playground/langchain/pkg/orchestrator"
)

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint 1: RequirementReviewer (pre-flight)
// ─────────────────────────────────────────────────────────────────────────────

func TestHITL_RequirementReviewer_AbortsBeforeGeneration(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	rv := &orchestrator.MockRequirementReviewer{Decision: orchestrator.ReviewAbort, Feedback: "requirement violates policy"}
	loop := &orchestrator.ExecutionLoop{
		Generator:           mj,
		Judge:               mj,
		RequirementReviewer: rv,
		MaxRetries:          3,
	}
	task := &orchestrator.Task{ID: "hitl-req-1"}

	err := loop.RunFromRequirement(context.Background(), task, "do something dangerous")
	if err == nil {
		t.Fatal("expected error when requirement is aborted")
	}
	if !strings.Contains(err.Error(), "violates policy") {
		t.Errorf("error should contain reviewer feedback, got: %v", err)
	}
	if len(mj.GenerateRequirements) != 0 {
		t.Errorf("generator should not be called when requirement is aborted, got %d call(s)", len(mj.GenerateRequirements))
	}
	if task.Attempts != 0 {
		t.Errorf("no build attempt should be made, got %d", task.Attempts)
	}
}

func TestHITL_RequirementReviewer_ApprovesAndPipelineContinues(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	rv := &orchestrator.MockRequirementReviewer{Decision: orchestrator.ReviewApprove}
	loop := &orchestrator.ExecutionLoop{
		Generator:           mj,
		Judge:               mj,
		RequirementReviewer: rv,
		MaxRetries:          1,
	}
	task := &orchestrator.Task{ID: "hitl-req-2"}

	if err := loop.RunFromRequirement(context.Background(), task, "print hello"); err != nil {
		t.Fatalf("unexpected error after requirement approval: %v", err)
	}
	if len(rv.Requirements) != 1 {
		t.Errorf("reviewer should be called exactly once, got %d", len(rv.Requirements))
	}
	if rv.Requirements[0] != "print hello" {
		t.Errorf("reviewer should receive the original requirement, got %q", rv.Requirements[0])
	}
	if task.Status != orchestrator.StatusSuccess {
		t.Errorf("want success, got %q", task.Status)
	}
}

func TestHITL_RequirementReviewer_ApproveWithFeedbackEnrichesGeneration(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	rv := &orchestrator.MockRequirementReviewer{
		Decision: orchestrator.ReviewApprove,
		Feedback: "make sure to handle edge cases",
	}
	loop := &orchestrator.ExecutionLoop{
		Generator:           mj,
		Judge:               mj,
		RequirementReviewer: rv,
		MaxRetries:          1,
	}
	task := &orchestrator.Task{ID: "hitl-req-fb"}

	if err := loop.RunFromRequirement(context.Background(), task, "build a parser"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Human feedback should be stored on task.
	if task.HumanContext != "make sure to handle edge cases" {
		t.Errorf("want HumanContext set, got %q", task.HumanContext)
	}
	// The enriched requirement should contain the feedback.
	if len(mj.GenerateRequirements) == 0 {
		t.Fatal("generator should be called")
	}
	if !strings.Contains(mj.GenerateRequirements[0], "handle edge cases") {
		t.Errorf("generator should receive enriched requirement with feedback, got %q", mj.GenerateRequirements[0])
	}
}

func TestHITL_RequirementReviewer_ReviseStoresFeedback(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	rv := &orchestrator.MockRequirementReviewer{
		Decision: orchestrator.ReviewRevise,
		Feedback: "also support subtraction",
	}
	loop := &orchestrator.ExecutionLoop{
		Generator:           mj,
		Judge:               mj,
		RequirementReviewer: rv,
		MaxRetries:          1,
	}
	task := &orchestrator.Task{ID: "hitl-req-rev"}

	if err := loop.RunFromRequirement(context.Background(), task, "build a calculator"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.HumanContext != "also support subtraction" {
		t.Errorf("want HumanContext from revise, got %q", task.HumanContext)
	}
	// The enriched requirement should contain the feedback.
	if !strings.Contains(mj.GenerateRequirements[0], "also support subtraction") {
		t.Errorf("generator should receive enriched requirement, got %q", mj.GenerateRequirements[0])
	}
}

func TestHITL_RequirementReviewer_NilSkipsCheckpoint(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{Generator: mj, Judge: mj, MaxRetries: 1}
	task := &orchestrator.Task{ID: "hitl-req-3"}

	if err := loop.RunFromRequirement(context.Background(), task, "anything"); err != nil {
		t.Fatalf("unexpected error with no reviewer: %v", err)
	}
}

func TestHITL_RequirementStored_OnTask(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{Generator: mj, Judge: mj, MaxRetries: 0}
	task := &orchestrator.Task{ID: "hitl-req-4"}

	_ = loop.RunFromRequirement(context.Background(), task, "serve HTTP on :9090")
	if task.Requirement != "serve HTTP on :9090" {
		t.Errorf("task.Requirement should be set; got %q", task.Requirement)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint 3: Post-success compliance gate
// ─────────────────────────────────────────────────────────────────────────────

func TestHITL_PostSuccess_ReviewerApproves(t *testing.T) {
	rv := &orchestrator.MockReviewer{Decisions: []orchestrator.ReviewDecision{orchestrator.ReviewApprove}}
	loop := &orchestrator.ExecutionLoop{
		Judge:      &orchestrator.MockJudge{},
		Reviewer:   rv,
		MaxRetries: 0,
	}
	task := &orchestrator.Task{ID: "hitl-post-1", Code: validCode}

	if err := loop.Run(context.Background(), task); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.Status != orchestrator.StatusSuccess {
		t.Errorf("want success after approval, got %q", task.Status)
	}
	if len(rv.Calls) != 1 {
		t.Errorf("reviewer should be called exactly once, got %d", len(rv.Calls))
	}
}

func TestHITL_PostSuccess_ReviewerAborts(t *testing.T) {
	rv := &orchestrator.MockReviewer{Decisions: []orchestrator.ReviewDecision{orchestrator.ReviewAbort}, Feedback: "weak hash function"}
	loop := &orchestrator.ExecutionLoop{
		Judge:      &orchestrator.MockJudge{},
		Reviewer:   rv,
		MaxRetries: 0,
	}
	task := &orchestrator.Task{ID: "hitl-post-2", Code: validCode}

	err := loop.Run(context.Background(), task)
	if err == nil {
		t.Fatal("expected error when compliance reviewer aborts")
	}
	if !strings.Contains(err.Error(), "weak hash function") {
		t.Errorf("error should contain reviewer feedback, got: %v", err)
	}
	if task.Status != orchestrator.StatusFailed {
		t.Errorf("want failed, got %q", task.Status)
	}
}

func TestHITL_PostSuccess_ReviewerRevises(t *testing.T) {
	// First call: human says "revise" → judge fixes → re-enters loop → clean build.
	// Second call: human approves.
	rv := &orchestrator.MockReviewer{
		Decisions: []orchestrator.ReviewDecision{orchestrator.ReviewRevise, orchestrator.ReviewApprove},
		Feedback:  "add input validation",
	}
	judge := &orchestrator.MockJudge{Responses: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{
		Judge:      judge,
		Reviewer:   rv,
		MaxRetries: 3,
	}
	task := &orchestrator.Task{ID: "hitl-post-rev", Code: validCode}

	if err := loop.Run(context.Background(), task); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.Status != orchestrator.StatusSuccess {
		t.Errorf("want success after revise+approve, got %q", task.Status)
	}
	// Reviewer should be called twice: first revise, then approve.
	if len(rv.Calls) != 2 {
		t.Errorf("reviewer should be called twice, got %d", len(rv.Calls))
	}
	// Judge should receive human feedback.
	if len(judge.Calls) == 0 {
		t.Fatal("judge should be called for revision")
	}
	if judge.Calls[0].HumanFeedback != "add input validation" {
		t.Errorf("judge should receive human feedback, got %q", judge.Calls[0].HumanFeedback)
	}
}

func TestHITL_PostSuccess_ReviewerSeesCode(t *testing.T) {
	rv := &orchestrator.MockReviewer{Decisions: []orchestrator.ReviewDecision{orchestrator.ReviewApprove}}
	loop := &orchestrator.ExecutionLoop{
		Judge:      &orchestrator.MockJudge{},
		Reviewer:   rv,
		MaxRetries: 0,
	}
	task := &orchestrator.Task{ID: "hitl-post-3", Code: validCode}

	_ = loop.Run(context.Background(), task)

	if len(rv.Calls) == 0 {
		t.Fatal("reviewer was never called")
	}
	if rv.Calls[0].Code != validCode {
		t.Error("reviewer should see the final code")
	}
}

func TestHITL_PostSuccess_NilReviewerSkipsCheckpoint(t *testing.T) {
	loop := &orchestrator.ExecutionLoop{
		Judge:      &orchestrator.MockJudge{},
		MaxRetries: 0,
	}
	task := &orchestrator.Task{ID: "hitl-post-4", Code: validCode}

	if err := loop.Run(context.Background(), task); err != nil {
		t.Fatalf("unexpected error with no reviewer: %v", err)
	}
	if task.Status != orchestrator.StatusSuccess {
		t.Errorf("want success, got %q", task.Status)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint 2: Flip-flop escape hatch
// ─────────────────────────────────────────────────────────────────────────────

// buildErrorJudge always returns a fixed code snippet that produces the same
// build error on every attempt, simulating a stuck judge.
type buildErrorJudge struct {
	code string
}

func (b *buildErrorJudge) Fix(_ context.Context, _ orchestrator.RepairRequest) (string, error) {
	return b.code, nil
}

func TestHITL_FlipFlop_ReviewerCalledOnStuckLoop(t *testing.T) {
	rv := &orchestrator.MockReviewer{Decisions: []orchestrator.ReviewDecision{orchestrator.ReviewAbort}, Feedback: "cannot fix; please rewrite"}
	loop := &orchestrator.ExecutionLoop{
		Judge:      &buildErrorJudge{code: brokenCode},
		Reviewer:   rv,
		MaxRetries: 10,
	}
	task := &orchestrator.Task{ID: "hitl-flip-1", Code: brokenCode}

	err := loop.Run(context.Background(), task)
	if err == nil {
		t.Fatal("expected error when reviewer aborts flip-flop")
	}
	if len(rv.Calls) == 0 {
		t.Error("reviewer should be called when flip-flop is detected")
	}
	if task.Attempts >= 10 {
		t.Errorf("escape hatch should have triggered early; got %d attempts", task.Attempts)
	}
}

func TestHITL_FlipFlop_ApprovedWithFeedback_ContinuesPipeline(t *testing.T) {
	rv := &orchestrator.MockReviewer{Decisions: []orchestrator.ReviewDecision{orchestrator.ReviewApprove, orchestrator.ReviewApprove}, Feedback: "use os.Stderr instead of fmt"}
	judge := &orchestrator.MockJudge{Responses: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{
		Judge:      judge,
		Reviewer:   rv,
		MaxRetries: 5,
	}
	task := &orchestrator.Task{ID: "hitl-flip-2", Code: brokenCode}

	if err := loop.Run(context.Background(), task); err != nil {
		t.Fatalf("unexpected error after reviewer approves with feedback: %v", err)
	}
	if task.Status != orchestrator.StatusSuccess {
		t.Errorf("want success, got %q", task.Status)
	}
}

func TestHITL_FlipFlop_ReviseWithFeedback_ContinuesPipeline(t *testing.T) {
	// ReviewRevise at flip-flop escape hatch should also inject feedback and continue.
	rv := &orchestrator.MockReviewer{Decisions: []orchestrator.ReviewDecision{orchestrator.ReviewRevise, orchestrator.ReviewApprove}, Feedback: "try a different approach"}
	judge := &orchestrator.MockJudge{Responses: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{
		Judge:      judge,
		Reviewer:   rv,
		MaxRetries: 5,
	}
	task := &orchestrator.Task{ID: "hitl-flip-rev", Code: brokenCode}

	if err := loop.Run(context.Background(), task); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.Status != orchestrator.StatusSuccess {
		t.Errorf("want success, got %q", task.Status)
	}
}

func TestHITL_FlipFlop_FeedbackInjectedIntoRepairRequest(t *testing.T) {
	rv := &orchestrator.MockReviewer{Decisions: []orchestrator.ReviewDecision{orchestrator.ReviewApprove, orchestrator.ReviewApprove}, Feedback: "use sync.Mutex for thread safety"}
	judge := &orchestrator.MockJudge{Responses: []string{brokenCode, validCode}}
	loop := &orchestrator.ExecutionLoop{
		Judge:      judge,
		Reviewer:   rv,
		MaxRetries: 5,
	}
	task := &orchestrator.Task{ID: "hitl-flip-3", Code: brokenCode}

	_ = loop.Run(context.Background(), task)

	found := false
	for _, call := range judge.Calls {
		if call.HumanFeedback == "use sync.Mutex for thread safety" {
			found = true
			break
		}
	}
	if !found {
		t.Error("human feedback should be injected into the RepairRequest sent to the judge after flip-flop approval")
	}
}

func TestHITL_FlipFlop_NotTriggeredOnFirstAttempt(t *testing.T) {
	rv := &orchestrator.MockReviewer{Decisions: []orchestrator.ReviewDecision{orchestrator.ReviewApprove}}
	loop := &orchestrator.ExecutionLoop{
		Judge:      &orchestrator.MockJudge{Responses: []string{validCode}},
		Reviewer:   rv,
		MaxRetries: 3,
	}
	task := &orchestrator.Task{ID: "hitl-flip-4", Code: brokenCode}

	if err := loop.Run(context.Background(), task); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// One call expected: the post-success compliance gate.
	if len(rv.Calls) != 1 {
		t.Errorf("reviewer should be called exactly once (post-success only), got %d call(s)", len(rv.Calls))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HumanFeedback in CorrectionPrompt
// ─────────────────────────────────────────────────────────────────────────────

func TestHITL_HumanFeedback_AppearsInAuditorPrompt(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{Responses: []string{"package main\nfunc main(){}"}}
	judge := &orchestrator.AuditorJudge{LLM: llm}

	req := orchestrator.RepairRequest{
		Code:          "package main\nfunc main() {}",
		BuildErrors:   []string{"main.go:1:1: undefined: x"},
		HumanFeedback: "please use a const for the timeout value",
	}
	_, err := judge.Fix(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	prompt := llm.Prompts[0]
	if !strings.Contains(prompt, "HUMAN REVIEWER FEEDBACK") {
		t.Error("prompt should contain HUMAN REVIEWER FEEDBACK section when HumanFeedback is set")
	}
	if !strings.Contains(prompt, "please use a const for the timeout value") {
		t.Error("prompt should contain the human feedback text")
	}
}

func TestHITL_HumanFeedback_OmittedWhenEmpty(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{Responses: []string{"package main\nfunc main(){}"}}
	judge := &orchestrator.AuditorJudge{LLM: llm}

	req := orchestrator.RepairRequest{
		Code:        "package main\nfunc main() {}",
		BuildErrors: []string{"main.go:1:1: undefined: x"},
	}
	_, err := judge.Fix(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(llm.Prompts[0], "HUMAN REVIEWER FEEDBACK") {
		t.Error("prompt should not contain HUMAN REVIEWER FEEDBACK section when feedback is empty")
	}
}
