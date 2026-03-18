package orchestrator

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
)

// ── Checkpoint 1: Requirement Review ──────────────────────────────────────────

// RequirementReviewer is consulted before any code is generated.
// It gives a human (or a policy agent) the chance to reject or redirect a
// natural-language requirement before any LLM work begins.
//
// Returning approved=false stops the pipeline immediately; feedback is surfaced
// as the error message so the caller knows why.
type RequirementReviewer interface {
	ReviewRequirement(ctx context.Context, requirement string) (approved bool, feedback string, err error)
}

// ── Checkpoints 2 & 3: Loop Review ────────────────────────────────────────────

// Reviewer is called at two later checkpoints:
//
//  1. Escape hatch  — when the agentic loop detects a flip-flop (the same
//     errors repeating on consecutive attempts), it pauses and asks for human
//     guidance rather than exhausting all retries on a stuck pattern.
//     Returning approved=true lets the loop continue; any non-empty feedback
//     string is injected into the next RepairRequest so the judge has a human
//     hint.  Returning approved=false halts immediately.
//
//  2. Compliance gate — after automated checks pass (build + audit clean), a
//     senior engineer can inspect task.Code and task.History before the result
//     is promoted to StatusSuccess.
type Reviewer interface {
	Review(ctx context.Context, task *Task) (approved bool, feedback string, err error)
}

// ── Terminal implementations ──────────────────────────────────────────────────

// TerminalRequirementReviewer pauses the pipeline and asks the operator to
// approve or reject the requirement interactively on the terminal.
//
// Approve: type "y" or "yes" (case-insensitive).
// Reject:  anything else — the operator is then prompted for a one-line reason
//          which is returned as feedback and surfaces as the pipeline error.
type TerminalRequirementReviewer struct{}

// boxWidth is the inner width of the review box (between the │ borders).
const boxWidth = 65

func (TerminalRequirementReviewer) ReviewRequirement(_ context.Context, requirement string) (bool, string, error) {
	fmt.Fprintln(os.Stderr)
	printBox(requirement)
	fmt.Fprint(os.Stderr, "Approve this requirement? [y/N]: ")

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	answer := strings.TrimSpace(scanner.Text())

	if strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes") {
		return true, "", nil
	}

	fmt.Fprint(os.Stderr, "Reason for rejection (one line): ")
	scanner.Scan()
	reason := strings.TrimSpace(scanner.Text())
	if reason == "" {
		reason = "rejected by operator"
	}
	return false, reason, nil
}

// printBox renders the requirement inside a Unicode box, wrapping long text.
// Layout: ║  <content padded to boxWidth>  ║  → total line width = boxWidth+6
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

// ── Mock doubles ──────────────────────────────────────────────────────────────

// MockRequirementReviewer is a deterministic test double for RequirementReviewer.
type MockRequirementReviewer struct {
	Approved     bool
	Feedback     string
	Err          error
	Requirements []string // every requirement passed to ReviewRequirement, in order
}

func (m *MockRequirementReviewer) ReviewRequirement(_ context.Context, req string) (bool, string, error) {
	m.Requirements = append(m.Requirements, req)
	return m.Approved, m.Feedback, m.Err
}

// MockReviewer is a deterministic test double for Reviewer.
type MockReviewer struct {
	Approved bool
	Feedback string
	Err      error
	Calls    []*Task // every task passed to Review, in order
}

func (m *MockReviewer) Review(_ context.Context, task *Task) (bool, string, error) {
	m.Calls = append(m.Calls, task)
	return m.Approved, m.Feedback, m.Err
}
