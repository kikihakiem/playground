package hitl

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/tmc/langchaingo/schema"
)

// Decision is the outcome of a human review checkpoint.
type Decision int

const (
	Approve Decision = iota // proceed
	Revise                  // rephrase / adjust and retry
	Abort                   // stop entirely
)

func (d Decision) String() string {
	switch d {
	case Approve:
		return "approve"
	case Revise:
		return "revise"
	case Abort:
		return "abort"
	}
	return "unknown"
}

// IndexStats summarises what was discovered during file scanning, before
// embeddings are computed. The reviewer sees this to decide whether to proceed.
type IndexStats struct {
	Files    int
	Chunks   int
	Packages []string // unique package names found
}

// AnswerContext carries the LLM response plus retrieved sources so the
// reviewer can judge answer quality.
type AnswerContext struct {
	Question string
	Answer   string
	Sources  []schema.Document
}

// IndexReviewer is consulted after file discovery, before embedding.
// The human sees file/chunk counts and decides whether to proceed.
type IndexReviewer interface {
	ReviewIndex(ctx context.Context, stats IndexStats) (decision Decision, feedback string, err error)
}

// AnswerReviewer is consulted after each Q&A response.
// The human can accept the answer, rephrase the question, or quit.
type AnswerReviewer interface {
	ReviewAnswer(ctx context.Context, ac AnswerContext) (decision Decision, feedback string, err error)
}

// TerminalReviewer implements both IndexReviewer and AnswerReviewer via
// interactive terminal prompts (same tri-state pattern as the langchain/ project).
type TerminalReviewer struct{}

// ReviewIndex displays index stats and asks the human to proceed.
func (TerminalReviewer) ReviewIndex(_ context.Context, stats IndexStats) (Decision, string, error) {
	fmt.Fprintf(os.Stderr, "\n╔════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(os.Stderr, "║  INDEX REVIEW                                      ║\n")
	fmt.Fprintf(os.Stderr, "╠════════════════════════════════════════════════════╣\n")
	fmt.Fprintf(os.Stderr, "║  Files:    %-5d                                   ║\n", stats.Files)
	fmt.Fprintf(os.Stderr, "║  Chunks:   %-5d                                   ║\n", stats.Chunks)
	if len(stats.Packages) > 0 {
		pkgs := strings.Join(stats.Packages, ", ")
		fmt.Fprintf(os.Stderr, "║  Packages: %-40s║\n", pkgs)
	}
	fmt.Fprintf(os.Stderr, "╚════════════════════════════════════════════════════╝\n")

	return readDecision("Index these files?")
}

// ReviewAnswer displays the answer and sources, then asks the human to judge.
func (TerminalReviewer) ReviewAnswer(_ context.Context, ac AnswerContext) (Decision, string, error) {
	fmt.Fprintf(os.Stderr, "\n── Answer ──────────────────────────────────────────\n")
	fmt.Fprintln(os.Stderr, ac.Answer)

	if len(ac.Sources) > 0 {
		fmt.Fprintf(os.Stderr, "\n── Sources ─────────────────────────────────────────\n")
		for i, s := range ac.Sources {
			src, _ := s.Metadata["source"].(string)
			fmt.Fprintf(os.Stderr, "  %d. %s (score: %.2f)\n", i+1, src, s.Score)
		}
	}
	fmt.Fprintln(os.Stderr)

	return readDecision("Accept this answer?")
}

// readDecision prompts the operator for a tri-state decision.
func readDecision(prompt string) (Decision, string, error) {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Fprintf(os.Stderr, "%s [a]ccept / [r]ephrase / [x] exit: ", prompt)
	scanner.Scan()
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))

	switch {
	case answer == "a" || answer == "accept":
		return Approve, "", nil

	case answer == "r" || answer == "rephrase":
		fmt.Fprint(os.Stderr, "Feedback / rephrased question: ")
		scanner.Scan()
		fb := strings.TrimSpace(scanner.Text())
		if fb == "" {
			fb = "please rephrase"
		}
		return Revise, fb, nil

	default: // "x", "exit", anything else
		return Abort, "", nil
	}
}
