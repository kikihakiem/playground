package orchestrator

import (
	"context"
	"fmt"
)

// RepairRequest is everything the JudgeAgent needs to propose a fix.
// Keeping it as a struct (rather than positional args) makes it easy to
// extend — e.g. adding a Diff field or a History slice — without changing
// the interface signature.
type RepairRequest struct {
	Code          string        // current Go source under repair
	BuildErrors   []string      // compiler errors; empty when compilation succeeded
	Findings      []Finding     // diagnostics from real tools (go vet, gosec, staticcheck)
	History       []Attempt     // all prior failed attempts, oldest first
	HumanFeedback string        // optional guidance injected by a human reviewer at the escape hatch
	ApprovedDeps  []ApprovedDep // allowlisted external packages the judge may use
}

// HasIssues returns true when there is anything to fix.
func (r RepairRequest) HasIssues() bool {
	return len(r.BuildErrors) > 0 || len(r.Findings) > 0
}

// JudgeAgent repairs broken or unsafe Go source.
// It receives a RepairRequest that includes real tool output so the LLM is
// grounded in concrete evidence rather than guesswork.
type JudgeAgent interface {
	Fix(ctx context.Context, req RepairRequest) (fixedCode string, err error)
}

// CodeGenerator produces the first version of Go source from a natural-language
// requirement. It is the "plan" phase; JudgeAgent is the "repair" phase.
type CodeGenerator interface {
	GenerateInitialCode(ctx context.Context, requirement string) (string, error)
}

// ── MockJudge ────────────────────────────────────────────────────────────────

// MockJudge is a deterministic test double implementing both JudgeAgent and
// CodeGenerator. Inject Responses / GeneratedCodes to control what it returns.
type MockJudge struct {
	Responses            []string        // consumed in order by Fix
	GeneratedCodes       []string        // consumed in order by GenerateInitialCode
	Calls                []RepairRequest // every Fix invocation, for assertion in tests
	GenerateRequirements []string        // every requirement passed to GenerateInitialCode
}

func (m *MockJudge) Fix(_ context.Context, req RepairRequest) (string, error) {
	m.Calls = append(m.Calls, req)

	if len(m.Responses) == 0 {
		return req.Code, nil // echo back unchanged → MaxRetries will be hit
	}
	resp := m.Responses[0]
	if len(m.Responses) > 1 {
		m.Responses = m.Responses[1:]
	}
	return resp, nil
}

func (m *MockJudge) GenerateInitialCode(_ context.Context, req string) (string, error) {
	m.GenerateRequirements = append(m.GenerateRequirements, req)
	if len(m.GeneratedCodes) == 0 {
		return "", fmt.Errorf("MockJudge: no GeneratedCodes configured")
	}
	code := m.GeneratedCodes[0]
	if len(m.GeneratedCodes) > 1 {
		m.GeneratedCodes = m.GeneratedCodes[1:]
	}
	return code, nil
}
