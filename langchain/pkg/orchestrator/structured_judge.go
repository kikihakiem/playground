package orchestrator

import (
	"context"
	"fmt"
	"strings"
)

// LLMBackend is the completion interface over any text model.
// systemPrompt establishes the model's persona and hard constraints;
// userPrompt carries the task-specific content (code, errors, findings).
// Pass an empty systemPrompt when no persona is needed.
type LLMBackend interface {
	Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}

// StructuredJudge implements JudgeAgent and CodeGenerator using a single LLM
// backend.  It combines both personas in one struct, which is convenient for
// tests and the mock path.  For production use prefer DevAgent + AuditorJudge,
// which give each persona its own system prompt.
type StructuredJudge struct {
	LLM LLMBackend
}

// Fix satisfies JudgeAgent.
// The auditor system prompt is sent as the model persona; the correction
// content (errors, findings, annotated source) is the user turn.
func (j *StructuredJudge) Fix(ctx context.Context, req RepairRequest) (string, error) {
	prompt := BuildCorrectionPrompt(req.Code, req.BuildErrors, req.Findings, req.History)
	fixed, err := j.LLM.Complete(ctx, auditorSystemPrompt, prompt.Format())
	if err != nil {
		return "", fmt.Errorf("llm backend (fix): %w", err)
	}
	return fixed, nil
}

// GenerateInitialCode satisfies CodeGenerator.
func (j *StructuredJudge) GenerateInitialCode(ctx context.Context, requirement string) (string, error) {
	code, err := j.LLM.Complete(ctx, devSystemPrompt, "Write a Go program that satisfies:\n"+requirement+"\n")
	if err != nil {
		return "", fmt.Errorf("llm backend (generate): %w", err)
	}
	return code, nil
}

// ── Mock LLM backend for tests ────────────────────────────────────────────────

// MockLLMBackend records every call it receives and returns injected responses.
// Prompts holds the user-turn content; SystemPrompts holds the persona/system turn.
// Both slices are parallel — index N in Prompts corresponds to index N in SystemPrompts.
type MockLLMBackend struct {
	Responses     []string
	Prompts       []string // user-turn prompts, for backward-compat test assertions
	SystemPrompts []string // system-turn prompts, for persona assertions
}

func (m *MockLLMBackend) Complete(_ context.Context, systemPrompt, userPrompt string) (string, error) {
	m.Prompts = append(m.Prompts, userPrompt)
	m.SystemPrompts = append(m.SystemPrompts, systemPrompt)
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
