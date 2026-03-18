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

// StructuredJudge implements both JudgeAgent and CodeGenerator.
//
// Fix pipeline:
//  1. Security audit       — flag unsafe / hardcoded creds
//  2. Correction prompt    — parse compiler errors, annotate source line-by-line
//  3. LLM call             — send formatted prompt, receive repaired source
//
// GenerateInitialCode pipeline:
//  1. Generation prompt    — wrap requirement in a structured instruction
//  2. LLM call             — receive first-draft source
type StructuredJudge struct {
	LLM LLMBackend
}

// Fix satisfies JudgeAgent. It builds a structured prompt that contains the
// annotated source (with caret markers at every error location) and all
// security findings, then asks the LLM to return corrected Go source.
func (j *StructuredJudge) Fix(ctx context.Context, code string, buildErrors []string) (string, error) {
	audit := RunSecurityAudit(code)
	prompt := BuildCorrectionPrompt(code, buildErrors, audit.Issues)

	fixed, err := j.LLM.Complete(ctx, prompt.Format())
	if err != nil {
		return "", fmt.Errorf("llm backend (fix): %w", err)
	}
	return fixed, nil
}

// GenerateInitialCode satisfies CodeGenerator. It asks the LLM to write a
// complete Go program from a natural-language requirement.
func (j *StructuredJudge) GenerateInitialCode(ctx context.Context, requirement string) (string, error) {
	code, err := j.LLM.Complete(ctx, buildGenerationPrompt(requirement))
	if err != nil {
		return "", fmt.Errorf("llm backend (generate): %w", err)
	}
	return code, nil
}

// buildGenerationPrompt wraps a natural-language requirement into an
// instruction that nudges the model to return raw, compilable Go source.
func buildGenerationPrompt(requirement string) string {
	return "You are a Go code generator. Write a complete, working Go program that satisfies the requirement below.\n" +
		"Rules:\n" +
		"- Output ONLY valid Go source code, starting with 'package main'.\n" +
		"- The very first character of your response must be 'p' (from 'package').\n" +
		"- Do NOT include any explanation, prose, or markdown fences (no ```go).\n" +
		"- The code must compile with 'go build' using only the standard library.\n\n" +
		"Requirement: " + requirement + "\n"
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
