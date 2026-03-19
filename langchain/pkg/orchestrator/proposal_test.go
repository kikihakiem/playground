package orchestrator_test

import (
	"context"
	"strings"
	"testing"

	"github.com/khakiem/playground/langchain/pkg/orchestrator"
)

// ─────────────────────────────────────────────────────────────────────────────
// SolutionProposer / proposal review tests
// ─────────────────────────────────────────────────────────────────────────────

// mockProposer tracks calls and returns canned proposals.
type mockProposer struct {
	Proposals []string // consumed in order; last one repeats
	Calls     []string // requirements passed to ProposeSolution
}

func (m *mockProposer) ProposeSolution(_ context.Context, requirement string) (string, error) {
	m.Calls = append(m.Calls, requirement)
	if len(m.Proposals) == 0 {
		return "default proposal", nil
	}
	p := m.Proposals[0]
	if len(m.Proposals) > 1 {
		m.Proposals = m.Proposals[1:]
	}
	return p, nil
}

func TestProposal_StoredOnTask(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	prop := &mockProposer{Proposals: []string{"Use a map for lookups"}}
	loop := &orchestrator.ExecutionLoop{
		Generator:  mj,
		Judge:      mj,
		Proposer:   prop,
		BuildFn: fakeBuild, MaxRetries: 0,
	}
	task := &orchestrator.Task{ID: "prop-1"}

	if err := loop.RunFromRequirement(context.Background(), task, "build a cache"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.Proposal != "Use a map for lookups" {
		t.Errorf("want proposal stored on task, got %q", task.Proposal)
	}
}

func TestProposal_EnrichesGeneration(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	prop := &mockProposer{Proposals: []string{"Use net/http with gorilla/mux"}}
	loop := &orchestrator.ExecutionLoop{
		Generator:  mj,
		Judge:      mj,
		Proposer:   prop,
		BuildFn: fakeBuild, MaxRetries: 0,
	}
	task := &orchestrator.Task{ID: "prop-2"}

	if err := loop.RunFromRequirement(context.Background(), task, "build a REST API"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mj.GenerateRequirements) == 0 {
		t.Fatal("generator should be called")
	}
	req := mj.GenerateRequirements[0]
	if !strings.Contains(req, "APPROVED APPROACH") {
		t.Errorf("generator should receive enriched requirement with proposal, got %q", req)
	}
	if !strings.Contains(req, "gorilla/mux") {
		t.Errorf("generator should see the proposal content, got %q", req)
	}
}

func TestProposal_NilProposerSkips(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{
		Generator:  mj,
		Judge:      mj,
		BuildFn: fakeBuild, MaxRetries: 0,
	}
	task := &orchestrator.Task{ID: "prop-3"}

	if err := loop.RunFromRequirement(context.Background(), task, "hello"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.Proposal != "" {
		t.Errorf("proposal should be empty when no proposer, got %q", task.Proposal)
	}
}

func TestProposal_ReviewerSeesProposal(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	prop := &mockProposer{Proposals: []string{"Use sync.Map for concurrency"}}
	rv := &orchestrator.MockRequirementReviewer{
		Decisions: []orchestrator.ReviewDecision{orchestrator.ReviewApprove},
		Feedbacks: []string{"also add TTL support"},
	}
	loop := &orchestrator.ExecutionLoop{
		Generator:           mj,
		Judge:               mj,
		Proposer:            prop,
		RequirementReviewer: rv,
		BuildFn: fakeBuild, MaxRetries:          0,
	}
	task := &orchestrator.Task{ID: "prop-4"}

	if err := loop.RunFromRequirement(context.Background(), task, "build a cache"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Reviewer should see the proposal on the task.
	if len(rv.Tasks) == 0 {
		t.Fatal("reviewer should be called")
	}
	if rv.Tasks[0].Proposal != "Use sync.Map for concurrency" {
		t.Errorf("reviewer should see proposal, got %q", rv.Tasks[0].Proposal)
	}
	// Feedback from approval should enrich generation.
	if !strings.Contains(task.HumanContext, "TTL support") {
		t.Errorf("approval feedback should be captured in HumanContext, got %q", task.HumanContext)
	}
}

func TestProposal_ReviewerAborts(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	prop := &mockProposer{Proposals: []string{"Use global variables"}}
	rv := &orchestrator.MockRequirementReviewer{
		Decisions: []orchestrator.ReviewDecision{orchestrator.ReviewAbort},
		Feedbacks: []string{"approach is fundamentally wrong"},
	}
	loop := &orchestrator.ExecutionLoop{
		Generator:           mj,
		Judge:               mj,
		Proposer:            prop,
		RequirementReviewer: rv,
		BuildFn: fakeBuild, MaxRetries:          0,
	}
	task := &orchestrator.Task{ID: "prop-5"}

	err := loop.RunFromRequirement(context.Background(), task, "build a server")
	if err == nil {
		t.Fatal("expected error when proposal is aborted")
	}
	if !strings.Contains(err.Error(), "fundamentally wrong") {
		t.Errorf("error should contain reviewer feedback, got: %v", err)
	}
	// Generator should NOT be called.
	if len(mj.GenerateRequirements) != 0 {
		t.Errorf("generator should not be called after abort, got %d call(s)", len(mj.GenerateRequirements))
	}
}

func TestProposal_ReviewerRevises_ReGeneratesProposal(t *testing.T) {
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	prop := &mockProposer{Proposals: []string{"Use raw SQL", "Use database/sql with prepared statements"}}
	rv := &orchestrator.MockRequirementReviewer{
		Decisions: []orchestrator.ReviewDecision{orchestrator.ReviewRevise, orchestrator.ReviewApprove},
		Feedbacks: []string{"use prepared statements for safety", ""},
	}
	loop := &orchestrator.ExecutionLoop{
		Generator:           mj,
		Judge:               mj,
		Proposer:            prop,
		RequirementReviewer: rv,
		BuildFn: fakeBuild, MaxRetries:          0,
	}
	task := &orchestrator.Task{ID: "prop-6"}

	if err := loop.RunFromRequirement(context.Background(), task, "build a DB layer"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Proposer should be called twice: initial + revision.
	if len(prop.Calls) != 2 {
		t.Errorf("proposer should be called twice (initial + revision), got %d", len(prop.Calls))
	}
	// Second call should include human feedback.
	if !strings.Contains(prop.Calls[1], "prepared statements") {
		t.Errorf("revised proposal call should include feedback, got %q", prop.Calls[1])
	}
	// Task should have the revised proposal.
	if task.Proposal != "Use database/sql with prepared statements" {
		t.Errorf("task.Proposal should be the revised version, got %q", task.Proposal)
	}
}

func TestProposal_DevAgent_ImplementsSolutionProposer(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{Responses: []string{"- Use http.Handler\n- Use sync.WaitGroup"}}
	dev := &orchestrator.DevAgent{LLM: llm}

	proposal, err := dev.ProposeSolution(context.Background(), "build a web server")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proposal == "" {
		t.Error("proposal should not be empty")
	}
	if len(llm.Prompts) != 1 {
		t.Errorf("LLM should be called once, got %d", len(llm.Prompts))
	}
	if !strings.Contains(llm.Prompts[0], "build a web server") {
		t.Errorf("prompt should contain the requirement, got %q", llm.Prompts[0])
	}
}

