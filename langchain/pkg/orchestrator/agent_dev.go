package orchestrator

import (
	"context"
	"fmt"
)

// devSystemPrompt is the persona injected as the LLM system turn for code
// generation.  Keeping it short and directive works better with small models
// like CodeLlama 7B than a long specification.
const devSystemPrompt = `You are a Junior Go developer. Write fast, working code.
Rules:
- Output ONLY valid Go source code, starting with 'package main'.
- The very first character of your response must be 'p' (from 'package').
- Do NOT include any explanation, prose, or markdown fences (no ` + "```" + `go).
- Use only the Go standard library — no external imports.`

// DevAgent implements CodeGenerator with the junior-dev persona.
// Its sole job is to produce an initial draft quickly; correctness and security
// are verified (and repaired) by the AuditorJudge in subsequent loop iterations.
type DevAgent struct {
	LLM LLMBackend
}

// GenerateInitialCode satisfies CodeGenerator.
func (d *DevAgent) GenerateInitialCode(ctx context.Context, requirement string) (string, error) {
	code, err := d.LLM.Complete(ctx, devSystemPrompt, "Write a Go program that satisfies:\n"+requirement+"\n")
	if err != nil {
		return "", fmt.Errorf("dev agent: %w", err)
	}
	return code, nil
}
