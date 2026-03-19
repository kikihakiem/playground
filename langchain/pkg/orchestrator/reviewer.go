package orchestrator

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
)

// ── ReviewDecision ──────────────────────────────────────────────────────────

// ReviewDecision is the outcome of a human review checkpoint.
type ReviewDecision int

const (
	// ReviewApprove proceeds with the pipeline. Optional feedback is treated
	// as enrichment (e.g. extra context for code generation).
	ReviewApprove ReviewDecision = iota

	// ReviewRevise asks the agent to incorporate the feedback and try again.
	// The pipeline continues — it does NOT halt.
	ReviewRevise

	// ReviewAbort halts the pipeline immediately.
	ReviewAbort
)

func (d ReviewDecision) String() string {
	switch d {
	case ReviewApprove:
		return "approve"
	case ReviewRevise:
		return "revise"
	case ReviewAbort:
		return "abort"
	}
	return "unknown"
}

// ── Checkpoint 1: Requirement Review ────────────────────────────────────────

// RequirementReviewer is consulted before any code is generated.
// It gives a human (or a policy agent) the chance to approve, request revision,
// or abort a natural-language requirement before any LLM work begins.
type RequirementReviewer interface {
	ReviewRequirement(ctx context.Context, requirement string) (decision ReviewDecision, feedback string, err error)
}

// ── Checkpoints 2 & 3: Loop Review ──────────────────────────────────────────

// Reviewer is called at two later checkpoints:
//
//  1. Escape hatch  — when the agentic loop detects a flip-flop (the same
//     errors repeating on consecutive attempts), it pauses and asks for human
//     guidance.  ReviewApprove/ReviewRevise inject feedback and continue;
//     ReviewAbort halts.
//
//  2. Compliance gate — after automated checks pass (build + audit clean), a
//     senior engineer can inspect task.Code and task.History.
//     ReviewApprove finalises success; ReviewRevise sends the code back
//     through the judge with human feedback; ReviewAbort halts.
type Reviewer interface {
	Review(ctx context.Context, task *Task) (decision ReviewDecision, feedback string, err error)
}

// ── Terminal implementations ────────────────────────────────────────────────

// TerminalReviewer implements both RequirementReviewer and Reviewer via a
// single struct, so cmd/main.go can wire one value into both ExecutionLoop fields.
type TerminalReviewer struct{}

// ReviewRequirement satisfies RequirementReviewer (checkpoint 1).
func (TerminalReviewer) ReviewRequirement(ctx context.Context, requirement string) (ReviewDecision, string, error) {
	return (TerminalRequirementReviewer{}).ReviewRequirement(ctx, requirement)
}

// Review satisfies Reviewer (checkpoints 2 & 3).
func (TerminalReviewer) Review(_ context.Context, task *Task) (ReviewDecision, string, error) {
	fmt.Fprintf(os.Stderr, "\n╔══ FEEDBACK REQUIRED (Attempt %d) %s╗\n",
		task.Attempts, strings.Repeat("═", max(0, boxWidth-27-len(fmt.Sprintf("%d", task.Attempts)))))

	if isFlipFlop(task.History) {
		fmt.Fprintln(os.Stderr, "║  ⚠  The agent is stuck in a loop with the same error.")
	}

	if task.Status == StatusPendingReview && len(task.Errors) == 0 && len(task.Findings) == 0 {
		lines := strings.Count(task.Code, "\n") + 1
		fmt.Fprintf(os.Stderr, "║  Code compiles and passes all audits (%d lines).\n", lines)
	} else {
		if len(task.Errors) > 0 {
			fmt.Fprintln(os.Stderr, "║  Current errors:")
			for _, e := range task.Errors {
				fmt.Fprintf(os.Stderr, "║    %s\n", e)
			}
		}
		if len(task.Findings) > 0 {
			fmt.Fprintln(os.Stderr, "║  Current findings:")
			for _, f := range task.Findings {
				fmt.Fprintf(os.Stderr, "║    %s\n", f)
			}
		}
	}

	fmt.Fprintf(os.Stderr, "╚%s╝\n", strings.Repeat("═", boxWidth+4))
	return readTriStateDecision()
}

// TerminalRequirementReviewer is the standalone requirement-only reviewer.
// Prefer TerminalReviewer which implements both interfaces.
type TerminalRequirementReviewer struct{}

// boxWidth is the inner width of the review box (between the │ borders).
const boxWidth = 65

func (TerminalRequirementReviewer) ReviewRequirement(_ context.Context, requirement string) (ReviewDecision, string, error) {
	fmt.Fprintln(os.Stderr)
	printBox(requirement)
	return readTriStateDecision()
}

// readTriStateDecision prompts the operator for a tri-state decision.
func readTriStateDecision() (ReviewDecision, string, error) {
	fmt.Fprint(os.Stderr, "[a]pprove / [r]evise / [x] abort: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))

	switch {
	case answer == "a" || answer == "approve":
		fmt.Fprint(os.Stderr, "Optional feedback (Enter to skip): ")
		scanner.Scan()
		fb := strings.TrimSpace(scanner.Text())
		return ReviewApprove, fb, nil

	case answer == "r" || answer == "revise":
		fmt.Fprint(os.Stderr, "Feedback for the agent: ")
		scanner.Scan()
		fb := strings.TrimSpace(scanner.Text())
		if fb == "" {
			fb = "please revise"
		}
		return ReviewRevise, fb, nil

	default: // "x", "abort", empty, anything else
		fmt.Fprint(os.Stderr, "Reason (Enter for default): ")
		scanner.Scan()
		reason := strings.TrimSpace(scanner.Text())
		if reason == "" {
			reason = "aborted by operator"
		}
		return ReviewAbort, reason, nil
	}
}

// printBox renders the requirement inside a Unicode box, wrapping long text.
func printBox(requirement string) {
	border := strings.Repeat("═", boxWidth+4)
	fmt.Fprintf(os.Stderr, "╔%s╗\n", border)
	fmt.Fprintf(os.Stderr, "║  %-*s  ║\n", boxWidth, "HUMAN REVIEW REQUIRED")
	fmt.Fprintf(os.Stderr, "╠%s╣\n", border)

	label := "Requirement: "
	words := strings.Fields(requirement)
	line := label
	for _, w := range words {
		candidate := line + w
		if len([]rune(candidate)) > boxWidth && line != label {
			fmt.Fprintf(os.Stderr, "║  %-*s  ║\n", boxWidth, line)
			line = strings.Repeat(" ", len([]rune(label))) + w
		} else {
			if line != label {
				line += " " + w
			} else {
				line += w
			}
		}
	}
	if line != "" {
		fmt.Fprintf(os.Stderr, "║  %-*s  ║\n", boxWidth, line)
	}

	fmt.Fprintf(os.Stderr, "╚%s╝\n", border)
}

// ── Mock doubles ────────────────────────────────────────────────────────────

// MockRequirementReviewer is a deterministic test double for RequirementReviewer.
type MockRequirementReviewer struct {
	Decision     ReviewDecision
	Feedback     string
	Err          error
	Requirements []string // every requirement passed to ReviewRequirement, in order
}

func (m *MockRequirementReviewer) ReviewRequirement(_ context.Context, req string) (ReviewDecision, string, error) {
	m.Requirements = append(m.Requirements, req)
	return m.Decision, m.Feedback, m.Err
}

// MockReviewer is a deterministic test double for Reviewer.
type MockReviewer struct {
	Decisions []ReviewDecision // consumed in order; last one repeats
	Feedback  string
	Err       error
	Calls     []*Task // every task passed to Review, in order
}

func (m *MockReviewer) Review(_ context.Context, task *Task) (ReviewDecision, string, error) {
	m.Calls = append(m.Calls, task)
	d := ReviewAbort
	if len(m.Decisions) > 0 {
		d = m.Decisions[0]
		if len(m.Decisions) > 1 {
			m.Decisions = m.Decisions[1:]
		}
	}
	return d, m.Feedback, m.Err
}
