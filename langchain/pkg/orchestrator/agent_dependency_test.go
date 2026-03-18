package orchestrator_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/khakiem/playground/langchain/pkg/orchestrator"
)

var testAllowlist = []orchestrator.ApprovedDep{
	{Name: "Google UUID", Module: "github.com/google/uuid", Version: "v1.6.0", Desc: "UUID generation (RFC 4122)"},
	{Name: "pkg/errors", Module: "github.com/pkg/errors", Version: "v0.9.1", Desc: "Error wrapping with stack traces"},
	{Name: "Zerolog", Module: "github.com/rs/zerolog", Version: "v1.33.0", Desc: "Structured JSON logging"},
}

// ─────────────────────────────────────────────────────────────────────────────
// AllowlistApprover
// ─────────────────────────────────────────────────────────────────────────────

func TestAllowlistApprover_ReturnsFullList(t *testing.T) {
	a := &orchestrator.AllowlistApprover{Allowlist: testAllowlist}
	got, err := a.ApproveDeps(context.Background(), "any requirement")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(testAllowlist) {
		t.Errorf("want %d deps, got %d", len(testAllowlist), len(got))
	}
}

func TestAllowlistApprover_EmptyList(t *testing.T) {
	a := &orchestrator.AllowlistApprover{}
	got, err := a.ApproveDeps(context.Background(), "anything")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want 0 deps, got %d", len(got))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// LLMDependencyAgent — uses MockLLMBackend as TextBackend
// ─────────────────────────────────────────────────────────────────────────────

func TestLLMDependencyAgent_ParsesValidResponse(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{Responses: []string{"github.com/google/uuid\n"}}
	agent := &orchestrator.LLMDependencyAgent{LLM: llm, Allowlist: testAllowlist}

	got, err := agent.ApproveDeps(context.Background(), "generate a unique ID")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Module != "github.com/google/uuid" {
		t.Errorf("want uuid dep, got %+v", got)
	}
}

func TestLLMDependencyAgent_IgnoresHallucinatedModule(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{Responses: []string{"github.com/evil/pwn\n"}}
	agent := &orchestrator.LLMDependencyAgent{LLM: llm, Allowlist: testAllowlist}

	got, err := agent.ApproveDeps(context.Background(), "do something")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("hallucinated module should be dropped, got %+v", got)
	}
}

func TestLLMDependencyAgent_HandlesNONEResponse(t *testing.T) {
	for _, resp := range []string{"NONE", "none", "None"} {
		llm := &orchestrator.MockLLMBackend{Responses: []string{resp}}
		agent := &orchestrator.LLMDependencyAgent{LLM: llm, Allowlist: testAllowlist}
		got, err := agent.ApproveDeps(context.Background(), "print hello")
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", resp, err)
		}
		if len(got) != 0 {
			t.Errorf("want 0 deps for %q, got %+v", resp, got)
		}
	}
}

func TestLLMDependencyAgent_StripsNumberPrefixAndPunctuation(t *testing.T) {
	// Model emits "1. github.com/google/uuid." despite instructions.
	llm := &orchestrator.MockLLMBackend{Responses: []string{"1. github.com/google/uuid."}}
	agent := &orchestrator.LLMDependencyAgent{LLM: llm, Allowlist: testAllowlist}

	got, err := agent.ApproveDeps(context.Background(), "generate a unique ID")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Module != "github.com/google/uuid" {
		t.Errorf("want uuid dep after stripping noise, got %+v", got)
	}
}

func TestLLMDependencyAgent_DeduplicatesRepeatedModule(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{
		Responses: []string{"github.com/google/uuid\ngithub.com/google/uuid\n"},
	}
	agent := &orchestrator.LLMDependencyAgent{LLM: llm, Allowlist: testAllowlist}

	got, err := agent.ApproveDeps(context.Background(), "generate IDs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("want 1 dep (deduped), got %d: %+v", len(got), got)
	}
}

func TestLLMDependencyAgent_MultipleModules(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{
		Responses: []string{"github.com/google/uuid\ngithub.com/rs/zerolog\n"},
	}
	agent := &orchestrator.LLMDependencyAgent{LLM: llm, Allowlist: testAllowlist}

	got, err := agent.ApproveDeps(context.Background(), "generate a UUID and log it as JSON")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("want 2 deps, got %d: %+v", len(got), got)
	}
}

func TestLLMDependencyAgent_PropagatesLLMError(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{} // no responses → error
	agent := &orchestrator.LLMDependencyAgent{LLM: llm, Allowlist: testAllowlist}

	_, err := agent.ApproveDeps(context.Background(), "anything")
	if err == nil {
		t.Fatal("expected error from exhausted mock backend")
	}
}

func TestLLMDependencyAgent_SystemPromptMentionsDependencySelector(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{Responses: []string{"NONE"}}
	agent := &orchestrator.LLMDependencyAgent{LLM: llm, Allowlist: testAllowlist}

	_, _ = agent.ApproveDeps(context.Background(), "print hello")
	if len(llm.SystemPrompts) == 0 {
		t.Fatal("expected a system prompt")
	}
	if !strings.Contains(llm.SystemPrompts[0], "dependency selector") {
		t.Errorf("system prompt should identify the agent role, got: %q", llm.SystemPrompts[0])
	}
}

func TestLLMDependencyAgent_UserPromptContainsRequirementAndModules(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{Responses: []string{"NONE"}}
	agent := &orchestrator.LLMDependencyAgent{LLM: llm, Allowlist: testAllowlist}

	_, _ = agent.ApproveDeps(context.Background(), "generate unique identifiers")
	userPrompt := llm.Prompts[0]
	for _, want := range []string{"generate unique identifiers", "github.com/google/uuid", "UUID generation"} {
		if !strings.Contains(userPrompt, want) {
			t.Errorf("user prompt missing %q", want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// enrichRequirement helper
// ─────────────────────────────────────────────────────────────────────────────

func TestEnrichRequirement_NoDeps_Unchanged(t *testing.T) {
	req := "print hello world"
	got := orchestrator.EnrichRequirement(req, nil)
	if got != req {
		t.Errorf("want unchanged requirement, got %q", got)
	}
}

func TestEnrichRequirement_InjectsImportHints(t *testing.T) {
	deps := []orchestrator.ApprovedDep{
		{Module: "github.com/google/uuid", Desc: "UUID generation"},
	}
	got := orchestrator.EnrichRequirement("generate IDs", deps)
	for _, want := range []string{"generate IDs", "github.com/google/uuid", "UUID generation"} {
		if !strings.Contains(got, want) {
			t.Errorf("enriched requirement missing %q:\n%s", want, got)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// buildGoMod helper
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildGoMod_NoDeps(t *testing.T) {
	got := orchestrator.BuildGoMod(nil)
	if !strings.Contains(got, "module sandbox") {
		t.Error("go.mod should contain module declaration")
	}
	if strings.Contains(got, "require") {
		t.Error("go.mod should have no require block when deps is nil")
	}
}

func TestBuildGoMod_WithDeps(t *testing.T) {
	deps := []orchestrator.ApprovedDep{
		{Module: "github.com/google/uuid", Version: "v1.6.0"},
	}
	got := orchestrator.BuildGoMod(deps)
	for _, want := range []string{"require", "github.com/google/uuid", "v1.6.0"} {
		if !strings.Contains(got, want) {
			t.Errorf("go.mod missing %q:\n%s", want, got)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ExecutionLoop integration with DependencyApprover
// ─────────────────────────────────────────────────────────────────────────────

func TestExecutionLoop_NilDepsApprover_NoChange(t *testing.T) {
	// Regression: existing behaviour unchanged when Deps is nil.
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{Generator: mj, Judge: mj, MaxRetries: 0}
	task := &orchestrator.Task{ID: "deps-nil"}

	if err := loop.RunFromRequirement(context.Background(), task, "print ok"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if task.Status != orchestrator.StatusSuccess {
		t.Errorf("want success, got %q", task.Status)
	}
}

func TestExecutionLoop_DepsApprover_RawRequirementPassedToGenerator(t *testing.T) {
	// On-demand pattern: the DevAgent receives the original requirement without
	// dep hints. The allowlist is reserved for the DependencyGuard and AuditorJudge.
	dep := orchestrator.ApprovedDep{
		Module:  "github.com/google/uuid",
		Version: "v1.6.0",
		Desc:    "UUID generation",
	}
	approver := &orchestrator.MockDependencyApprover{Deps: []orchestrator.ApprovedDep{dep}}
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{
		Generator: mj, Judge: mj, Deps: approver, MaxRetries: 0,
	}
	task := &orchestrator.Task{ID: "deps-raw"}
	_ = loop.RunFromRequirement(context.Background(), task, "generate a UUID")

	if len(approver.Calls) != 1 {
		t.Fatalf("want 1 ApproveDeps call, got %d", len(approver.Calls))
	}
	if len(mj.GenerateRequirements) == 0 {
		t.Fatal("MockJudge did not record the requirement")
	}
	// Requirement must be passed verbatim — no dep hints injected.
	got := mj.GenerateRequirements[0]
	if got != "generate a UUID" {
		t.Errorf("DevAgent should receive the raw requirement; got: %q", got)
	}
}

func TestExecutionLoop_ApprovedDepsSetOnTask(t *testing.T) {
	dep := orchestrator.ApprovedDep{Module: "github.com/google/uuid", Version: "v1.6.0"}
	approver := &orchestrator.MockDependencyApprover{Deps: []orchestrator.ApprovedDep{dep}}
	mj := &orchestrator.MockJudge{GeneratedCodes: []string{validCode}}
	loop := &orchestrator.ExecutionLoop{
		Generator: mj, Judge: mj, Deps: approver, MaxRetries: 0,
	}
	task := &orchestrator.Task{ID: "deps-task"}
	_ = loop.RunFromRequirement(context.Background(), task, "generate a UUID")

	if len(task.ApprovedDeps) != 1 || task.ApprovedDeps[0].Module != "github.com/google/uuid" {
		t.Errorf("task.ApprovedDeps not set correctly: %+v", task.ApprovedDeps)
	}
}

func TestExecutionLoop_DepsApproverError_FailsFast(t *testing.T) {
	approver := &orchestrator.MockDependencyApprover{Err: errors.New("registry unavailable")}
	mj := &orchestrator.MockJudge{}
	loop := &orchestrator.ExecutionLoop{
		Generator: mj, Judge: mj, Deps: approver, MaxRetries: 0,
	}
	task := &orchestrator.Task{ID: "deps-err"}
	err := loop.RunFromRequirement(context.Background(), task, "anything")

	if err == nil {
		t.Fatal("expected error when approver fails")
	}
	if task.Attempts != 0 {
		t.Error("build should not have been attempted when approver fails")
	}
}
