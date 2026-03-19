package orchestrator

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// LineAnnotation holds one parsed compiler diagnostic tied to a source location.
type LineAnnotation struct {
	File    string
	Line    int
	Column  int
	Message string
}

// CorrectionPrompt is the structured artefact sent to the LLM.
// Keeping it as a typed struct makes each section independently testable
// and lets you swap the Format() template without touching callers.
type CorrectionPrompt struct {
	AnnotatedSource string           // source with compiler-error caret markers
	Annotations     []LineAnnotation // one per parsed compiler diagnostic
	Findings        []Finding        // real tool output (go vet, gosec, staticcheck)
	RawErrors       []string         // verbatim compiler output
	History         []Attempt        // all prior failed attempts, for anti-flip-flop context
	HumanFeedback   string           // optional guidance from a human reviewer injected at the escape hatch
	ApprovedDeps    []ApprovedDep    // allowlisted external packages; injected by AuditorJudge only
	TestCode        string           // test file the implementation must satisfy (the oracle)
}

// maxHistoryInPrompt caps how many past attempts we include.
// Older attempts are less relevant and inflate token count unnecessarily.
const maxHistoryInPrompt = 3

var goErrorRe = regexp.MustCompile(`(?:\.\/)?(\S+\.go):(\d+):(\d+):\s*(.+)`)

// BuildCorrectionPrompt parses buildErrors into line annotations, attaches
// real tool findings and the attempt history, and builds the annotated source view.
func BuildCorrectionPrompt(code string, buildErrors []string, findings []Finding, history []Attempt) CorrectionPrompt {
	annotations := parseErrors(buildErrors)
	return CorrectionPrompt{
		AnnotatedSource: annotateSource(code, annotations),
		Annotations:     annotations,
		Findings:        findings,
		RawErrors:       buildErrors,
		History:         history,
	}
}

// Format renders the user-turn content sent to the LLM.
// The model persona (system prompt) is set by the calling agent (DevAgent or
// AuditorJudge), so Format() contains only the task-specific sections.
// All real tool output appears verbatim so the model is grounded in actual
// engineering diagnostics rather than rephrased summaries.
func (cp CorrectionPrompt) Format() string {
	var b strings.Builder

	// ── Allowed external packages (late-stage injection for auditor only) ────
	if len(cp.ApprovedDeps) > 0 {
		b.WriteString("=== ALLOWED EXTERNAL PACKAGES (use these or stdlib only) ===\n")
		for _, d := range cp.ApprovedDeps {
			b.WriteString(fmt.Sprintf("  import %q  // %s\n", d.Module, d.Desc))
		}
		b.WriteString("Do NOT import any other external package.\n\n")
	}

	// ── Human reviewer feedback (highest priority — address this first) ──────
	if cp.HumanFeedback != "" {
		b.WriteString("=== HUMAN REVIEWER FEEDBACK (address this before anything else) ===\n")
		b.WriteString(cp.HumanFeedback)
		b.WriteString("\n\n")
	}

	// ── Tool findings (grounded in real tool output) ─────────────────────────
	if len(cp.Findings) > 0 {
		b.WriteString("=== TOOL FINDINGS (fix all of these) ===\n")
		for _, f := range cp.Findings {
			b.WriteString(fmt.Sprintf("  %s\n", f.String()))
			if f.Snippet != "" {
				b.WriteString(fmt.Sprintf("  code: %s\n", f.Snippet))
			}
		}
		b.WriteString("\n")
	}

	// ── Compiler errors ──────────────────────────────────────────────────────
	if len(cp.RawErrors) > 0 {
		b.WriteString("=== COMPILER ERRORS ===\n")
		for _, e := range cp.RawErrors {
			b.WriteString("  " + e + "\n")
		}
		b.WriteString("\n")
	}

	// ── Attempt history (anti-flip-flop context) ─────────────────────────────
	if len(cp.History) > 0 {
		start := len(cp.History) - maxHistoryInPrompt
		if start < 0 {
			start = 0
		}
		recent := cp.History[start:]
		b.WriteString("=== ATTEMPT HISTORY (do NOT repeat these broken patterns) ===\n")
		for _, a := range recent {
			b.WriteString(fmt.Sprintf("--- Attempt %d ---\n", a.Number))
			b.WriteString(renderCodeCompact(a.Code))
			if len(a.BuildErrors) > 0 {
				b.WriteString("Build errors:\n")
				for _, e := range a.BuildErrors {
					b.WriteString("  " + e + "\n")
				}
			}
			for _, f := range a.Findings {
				b.WriteString("  " + f.String() + "\n")
			}
		}
		b.WriteString("\n")
	}

	// ── Test oracle (the expected behaviour the code MUST satisfy) ──────────
	if cp.TestCode != "" {
		b.WriteString("=== TEST FILE (main_test.go — your code MUST pass these tests) ===\n")
		b.WriteString(renderCodeCompact(cp.TestCode))
		b.WriteString("\n")
	}

	// ── Annotated source ─────────────────────────────────────────────────────
	b.WriteString("=== ANNOTATED SOURCE ===\n")
	b.WriteString(cp.AnnotatedSource)
	b.WriteString("\n")

	return b.String()
}

// renderCodeCompact returns code with line numbers, truncated to 40 lines so
// history in the prompt stays concise.
func renderCodeCompact(code string) string {
	const maxLines = 40
	lines := strings.Split(code, "\n")
	if len(lines) > maxLines {
		lines = append(lines[:maxLines], fmt.Sprintf("... (%d more lines)", len(lines)-maxLines))
	}
	var b strings.Builder
	for i, l := range lines {
		b.WriteString(fmt.Sprintf("%3d | %s\n", i+1, l))
	}
	return b.String()
}

func parseErrors(lines []string) []LineAnnotation {
	var out []LineAnnotation
	for _, line := range lines {
		m := goErrorRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		lineNum, _ := strconv.Atoi(m[2])
		colNum, _ := strconv.Atoi(m[3])
		out = append(out, LineAnnotation{
			File:    m[1],
			Line:    lineNum,
			Column:  colNum,
			Message: strings.TrimSpace(m[4]),
		})
	}
	return out
}

func annotateSource(code string, annotations []LineAnnotation) string {
	sourceLines := strings.Split(code, "\n")

	byLine := make(map[int][]LineAnnotation, len(annotations))
	for _, a := range annotations {
		byLine[a.Line] = append(byLine[a.Line], a)
	}

	width := len(strconv.Itoa(len(sourceLines)))
	format := fmt.Sprintf("%%%dd | %%s\n", width)

	var b strings.Builder
	for i, sl := range sourceLines {
		lineNum := i + 1
		b.WriteString(fmt.Sprintf(format, lineNum, sl))
		for _, a := range byLine[lineNum] {
			col := a.Column
			if col < 1 {
				col = 1
			}
			pad := strings.Repeat(" ", width+3+col-1)
			b.WriteString(fmt.Sprintf("%s^ col %d: %s\n", pad, a.Column, a.Message))
		}
	}
	return b.String()
}
