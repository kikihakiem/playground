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

// testSystemPrompt is the persona for generating the oracle test file.
// The tests define the expected behaviour so stubs like `return 0` will fail.
const testSystemPrompt = `You are a Go test writer. Given a requirement and an implementation, write a _test.go file.
Rules:
- Output ONLY valid Go test code, starting with 'package main'.
- The very first character of your response must be 'p' (from 'package').
- Import "testing" and write TestXxx functions that verify key behaviors from the requirement.
- Call exported functions or parse stdout to assert correctness.
- Keep tests focused: 3-5 test functions, each testing one behavior.
- Do NOT include any explanation, prose, or markdown fences (no ` + "```" + `go).
- Use only the Go standard library — no external test frameworks.`

// DevAgent implements CodeGenerator and TestGenerator with the junior-dev persona.
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

// GenerateTests satisfies TestGenerator.
// It receives the requirement and the implementation, and produces a test file
// whose assertions define the expected behaviour (the oracle).
func (d *DevAgent) GenerateTests(ctx context.Context, requirement, code string) (string, error) {
	prompt := "REQUIREMENT:\n" + requirement + "\n\nIMPLEMENTATION (main.go):\n" + code + "\n\nWrite a Go test file (main_test.go) that verifies the key behaviors.\n"
	testCode, err := d.LLM.Complete(ctx, testSystemPrompt, prompt)
	if err != nil {
		return "", fmt.Errorf("dev agent test generation: %w", err)
	}
	return testCode, nil
}
