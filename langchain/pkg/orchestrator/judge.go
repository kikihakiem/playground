package orchestrator

import "context"

// JudgeAgent is the interface for the "repair" step.
// Any backend — mock, OpenAI, LangChain, local LLM — must satisfy this
// interface, which is how you swap implementations without changing the loop.
type JudgeAgent interface {
	// Fix receives the broken Go source and the compiler errors from the last
	// attempt. It returns a corrected Go source string, or an error if the
	// backend itself failed.
	Fix(ctx context.Context, code string, buildErrors []string) (fixedCode string, err error)
}

// MockJudge is a test double. You inject the sequence of responses you expect
// so unit tests are deterministic and don't hit any real LLM.
type MockJudge struct {
	// Responses is consumed in order; each call to Fix pops the first element.
	// If the slice is exhausted, Fix returns the last element again.
	Responses []string

	// Calls records every invocation for inspection in tests.
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
		// Nothing injected — return the code unchanged so the loop eventually
		// hits MaxRetries and surfaces the real error to the caller.
		return code, nil
	}

	response := m.Responses[0]
	if len(m.Responses) > 1 {
		m.Responses = m.Responses[1:]
	}
	return response, nil
}
