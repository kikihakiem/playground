package orchestrator

import (
	"context"
	"fmt"
)

// auditorSystemPrompt is the persona injected as the LLM system turn for code
// repair.  The auditor receives real tool output (go vet, gosec, staticcheck)
// and the full attempt history so it can avoid flip-flopping.
const auditorSystemPrompt = `You are a Senior Go Security Auditor.
You receive broken or insecure Go code together with real tool findings (go vet, gosec, staticcheck).
Your job: return a corrected version that clears every reported issue.
Rules:
- Output ONLY valid Go source code, starting with 'package'.
- The very first character of your response must be 'p' (from 'package').
- Fix ALL reported issues. Do not introduce new ones.
- Do NOT repeat code patterns listed in ATTEMPT HISTORY — they already failed.
- Do NOT include any explanation, prose, or markdown fences (no ` + "```" + `go).`

// AuditorJudge implements JudgeAgent with the senior-auditor persona.
// It receives a RepairRequest that carries real tool output so the LLM is
// grounded in concrete evidence rather than heuristics.
type AuditorJudge struct {
	LLM LLMBackend
}

// Fix satisfies JudgeAgent.
func (a *AuditorJudge) Fix(ctx context.Context, req RepairRequest) (string, error) {
	prompt := BuildCorrectionPrompt(req.Code, req.BuildErrors, req.Findings, req.History)
	fixed, err := a.LLM.Complete(ctx, auditorSystemPrompt, prompt.Format())
	if err != nil {
		return "", fmt.Errorf("auditor judge: %w", err)
	}
	return fixed, nil
}
