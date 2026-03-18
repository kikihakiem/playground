package orchestrator

import (
	"context"
	"fmt"
)

// JudgeAgent is the interface for the "repair" step.
// Any backend — mock, OpenAI, LangChain, local LLM — must satisfy this
// interface, which is how you swap implementations without changing the loop.
type JudgeAgent interface {
	// Fix receives the broken Go source and the compiler errors from the last
	// attempt. It returns a corrected Go source string, or an error if the
	// backend itself failed.
	Fix(ctx context.Context, code string, buildErrors []string) (fixedCode string, err error)
}

// CodeGenerator is the interface for the "initial generation" step.
// It takes a natural-language requirement and produces the first version of
// the Go source code that the ExecutionLoop will then attempt to compile.
type CodeGenerator interface {
	GenerateInitialCode(ctx context.Context, requirement string) (string, error)
}

// MockJudge is a test double that implements both JudgeAgent and CodeGenerator.
// Inject Responses for Fix calls and GeneratedCodes for GenerateInitialCode
// calls so tests are deterministic and never hit a real LLM.
type MockJudge struct {
	// Responses is consumed in order by Fix; last element repeats when exhausted.
	Responses []string
	// GeneratedCodes is consumed in order by GenerateInitialCode.
	GeneratedCodes []string
	// Calls records every Fix invocation for assertion in tests.
	Calls []JudgeCall
}

// JudgeCall is a record of one Fix invocation.
type JudgeCall struct {
	Code   string
	Errors []string
}

func (m *MockJudge) Fix(_ context.Context, code string, buildErrors []string) (string, error) {
	m.Calls = append(m.Calls, JudgeCall{Code: code, Errors: buildErrors})

	if len(m.Responses) == 0 {
		return code, nil // echo back unchanged so MaxRetries is eventually hit
	}
	response := m.Responses[0]
	if len(m.Responses) > 1 {
		m.Responses = m.Responses[1:]
	}
	return response, nil
}

func (m *MockJudge) GenerateInitialCode(_ context.Context, _ string) (string, error) {
	if len(m.GeneratedCodes) == 0 {
		return "", fmt.Errorf("MockJudge: no GeneratedCodes configured")
	}
	code := m.GeneratedCodes[0]
	if len(m.GeneratedCodes) > 1 {
		m.GeneratedCodes = m.GeneratedCodes[1:]
	}
	return code, nil
}
