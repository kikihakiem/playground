package orchestrator

import (
	"context"
	"fmt"
)

// LLMBackend is the thin interface over any text-completion backend.
// Swap implementations without touching StructuredJudge.
type LLMBackend interface {
	Complete(ctx context.Context, prompt string) (string, error)
}

// StructuredJudge implements JudgeAgent.
// Its Fix pipeline is:
//  1. Security audit  — flag unsafe / hardcoded creds
//  2. Correction prompt — parse compiler errors, annotate source
//  3. LLM call        — send the formatted prompt, get repaired code back
type StructuredJudge struct {
	LLM LLMBackend
}

// Fix satisfies the JudgeAgent interface.
func (j *StructuredJudge) Fix(ctx context.Context, code string, buildErrors []string) (string, error) {
	audit := RunSecurityAudit(code)
	prompt := BuildCorrectionPrompt(code, buildErrors, audit.Issues)
	formatted := prompt.Format()

	fixed, err := j.LLM.Complete(ctx, formatted)
	if err != nil {
		return "", fmt.Errorf("llm backend: %w", err)
	}
	return fixed, nil
}

// ── Mock LLM backend for tests ────────────────────────────────────────────────

// MockLLMBackend is a test double for LLMBackend.
// It records every prompt it receives and returns injected responses in order.
type MockLLMBackend struct {
	Responses []string // consumed in order; last element repeats when exhausted
	Prompts   []string // all prompts received, for assertion in tests
}

func (m *MockLLMBackend) Complete(_ context.Context, prompt string) (string, error) {
	m.Prompts = append(m.Prompts, prompt)

	if len(m.Responses) == 0 {
		return "", fmt.Errorf("MockLLMBackend: no response configured")
	}
	resp := m.Responses[0]
	if len(m.Responses) > 1 {
		m.Responses = m.Responses[1:]
	}
	return resp, nil
}
