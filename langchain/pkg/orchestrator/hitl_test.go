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

func TestHITL_RequirementReviewer_RejectsBeforeGeneration(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	rv := &orchestrator.MockRequirementReviewer{Approved: false, Feedback: "requirement violates policy"}
	loop := &orchestrator.ExecutionLoop{
		Generator:           mj,
		Judge:               mj,
		RequirementReviewer: rv,
		MaxRetries:          3,
	}
	task := &orchestrator.Task{ID: "hitl-req-1"}

	err := loop.RunFromRequirement(context.Background(), task, "do something dangerous")
	if err == nil {
		t.Fatal("expected error when requirement is rejected")
	}
	if !strings.Contains(err.Error(), "violates policy") {
		t.Errorf("error should contain reviewer feedback, got: %v", err)
	}
	// Generator must never be called.
	if len(mj.GenerateRequirements) != 0 {
		t.Errorf("generator should not be called when requirement is rejected, got %d call(s)", len(mj.GenerateRequirements))
	}
	if task.Attempts != 0 {
		t.Errorf("no build attempt should be made, got %d", task.Attempts)
	}
}

func TestHITL_RequirementReviewer_ApprovesAndPipelineContinues(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	rv := &orchestrator.MockRequirementReviewer{Approved: true}
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

func TestHITL_RequirementReviewer_NilSkipsCheckpoint(t *testing.T) {
	// No RequirementReviewer — pipeline should behave as before.
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
	rv := &orchestrator.MockReviewer{Approved: true}
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

func TestHITL_PostSuccess_ReviewerRejects(t *testing.T) {
	rv := &orchestrator.MockReviewer{Approved: false, Feedback: "weak hash function"}
	loop := &orchestrator.ExecutionLoop{
		Judge:      &orchestrator.MockJudge{},
		Reviewer:   rv,
		MaxRetries: 0,
	}
	task := &orchestrator.Task{ID: "hitl-post-2", Code: validCode}

	err := loop.Run(context.Background(), task)
	if err == nil {
		t.Fatal("expected error when compliance reviewer rejects")
	}
	if !strings.Contains(err.Error(), "weak hash function") {
		t.Errorf("error should contain reviewer feedback, got: %v", err)
	}
	if task.Status != orchestrator.StatusFailed {
		t.Errorf("want failed, got %q", task.Status)
	}
}

func TestHITL_PostSuccess_ReviewerSeesCode(t *testing.T) {
	rv := &orchestrator.MockReviewer{Approved: true}
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
	code string // broken code to echo back
}

func (b *buildErrorJudge) Fix(_ context.Context, _ orchestrator.RepairRequest) (string, error) {
	return b.code, nil
}

func TestHITL_FlipFlop_ReviewerCalledOnStuckLoop(t *testing.T) {
	// The judge always echoes back brokenCode → same compile error every time.
	rv := &orchestrator.MockReviewer{Approved: false, Feedback: "cannot fix; please rewrite"}
	loop := &orchestrator.ExecutionLoop{
		Judge:      &buildErrorJudge{code: brokenCode},
		Reviewer:   rv,
		MaxRetries: 10, // would run 11 times without the escape hatch
	}
	task := &orchestrator.Task{ID: "hitl-flip-1", Code: brokenCode}

	err := loop.Run(context.Background(), task)
	if err == nil {
		t.Fatal("expected error when reviewer rejects flip-flop")
	}
	if len(rv.Calls) == 0 {
		t.Error("reviewer should be called when flip-flop is detected")
	}
	// Should halt well before MaxRetries=10 (flip-flop detected after attempt 2).
	if task.Attempts >= 10 {
		t.Errorf("escape hatch should have triggered early; got %d attempts", task.Attempts)
	}
}

func TestHITL_FlipFlop_ApprovedWithFeedback_ContinuesPipeline(t *testing.T) {
	// Reviewer approves on flip-flop with feedback.
	// After injection the judge returns valid code, so the loop succeeds.
	rv := &orchestrator.MockReviewer{Approved: true, Feedback: "use os.Stderr instead of fmt"}
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

func TestHITL_FlipFlop_FeedbackInjectedIntoRepairRequest(t *testing.T) {
	// Verify the human feedback actually reaches the judge's RepairRequest.
	// Sequence: attempt 1 → judge echoes brokenCode (flip not yet), attempt 2 →
	// same error → flip-flop detected → reviewer approves with feedback → judge
	// called with HumanFeedback set → returns validCode → success.
	rv := &orchestrator.MockReviewer{Approved: true, Feedback: "use sync.Mutex for thread safety"}
	judge := &orchestrator.MockJudge{Responses: []string{brokenCode, validCode}}
	loop := &orchestrator.ExecutionLoop{
		Judge:      judge,
		Reviewer:   rv,
		MaxRetries: 5,
	}
	task := &orchestrator.Task{ID: "hitl-flip-3", Code: brokenCode}

	_ = loop.Run(context.Background(), task)

	// Find the repair call that was made after the flip-flop reviewer approval.
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
	// Only one failed attempt followed by a successful fix — no flip-flop.
	// The Reviewer is called exactly once: at the post-success checkpoint, not
	// at the flip-flop escape hatch (which requires ≥2 consecutive identical failures).
	rv := &orchestrator.MockReviewer{Approved: true}
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
	// Zero extra calls means the flip-flop hatch was not mistakenly triggered.
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
		// HumanFeedback intentionally empty
	}
	_, err := judge.Fix(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(llm.Prompts[0], "HUMAN REVIEWER FEEDBACK") {
		t.Error("prompt should not contain HUMAN REVIEWER FEEDBACK section when feedback is empty")
	}
}
