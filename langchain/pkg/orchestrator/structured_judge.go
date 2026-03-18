package orchestrator

import (
	"context"
	"fmt"
	"strings"
)

// LLMBackend is the completion interface over any text model.
type LLMBackend interface {
	Complete(ctx context.Context, prompt string) (string, error)
}

// StructuredJudge implements JudgeAgent and CodeGenerator.
//
// Fix pipeline (grounded in real tool output):
//  1. Build a CorrectionPrompt from the compiler errors + tool findings
//     (go vet, gosec, staticcheck) that arrived in the RepairRequest.
//  2. Format the prompt so every finding has file:line location and the
//     original offending snippet where available.
//  3. Send to the LLM; return the extracted Go source.
//
// GenerateInitialCode pipeline:
//  1. Wrap the requirement in a structured instruction.
//  2. Send to the LLM; return the extracted Go source.
type StructuredJudge struct {
	LLM LLMBackend
}

// Fix satisfies JudgeAgent.
// It never performs its own heuristic scanning — all findings come from the
// real AnalysisTools run by the orchestrator, so the LLM acts on concrete
// evidence (line numbers, rule IDs, offending snippets) rather than guesses.
func (j *StructuredJudge) Fix(ctx context.Context, req RepairRequest) (string, error) {
	prompt := BuildCorrectionPrompt(req.Code, req.BuildErrors, req.Findings)
	fixed, err := j.LLM.Complete(ctx, prompt.Format())
	if err != nil {
		return "", fmt.Errorf("llm backend (fix): %w", err)
	}
	return fixed, nil
}

// GenerateInitialCode satisfies CodeGenerator.
func (j *StructuredJudge) GenerateInitialCode(ctx context.Context, requirement string) (string, error) {
	code, err := j.LLM.Complete(ctx, buildGenerationPrompt(requirement))
	if err != nil {
		return "", fmt.Errorf("llm backend (generate): %w", err)
	}
	return code, nil
}

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

// MockLLMBackend records every prompt it receives and returns injected responses.
type MockLLMBackend struct {
	Responses []string
	Prompts   []string
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

// ── Response extraction ───────────────────────────────────────────────────────
// (shared with CodeLlamaBackend via the unexported helper below)

func extractGoSource(s string) string {
	s = strings.TrimSpace(s)
	if start := strings.Index(s, "```"); start != -1 {
		inner := s[start+3:]
		if nl := strings.Index(inner, "\n"); nl != -1 {
			inner = inner[nl+1:]
		}
		if end := strings.Index(inner, "```"); end != -1 {
			return strings.TrimSpace(inner[:end])
		}
	}
	if idx := strings.Index(s, "package "); idx != -1 {
		return strings.TrimSpace(s[idx:])
	}
	return s
}
