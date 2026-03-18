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
}

var goErrorRe = regexp.MustCompile(`(?:\.\/)?(\S+\.go):(\d+):(\d+):\s*(.+)`)

// BuildCorrectionPrompt parses buildErrors into line annotations, attaches
// real tool findings, and builds the annotated source view.
func BuildCorrectionPrompt(code string, buildErrors []string, findings []Finding) CorrectionPrompt {
	annotations := parseErrors(buildErrors)
	return CorrectionPrompt{
		AnnotatedSource: annotateSource(code, annotations),
		Annotations:     annotations,
		Findings:        findings,
		RawErrors:       buildErrors,
	}
}

// Format renders the prompt sent to the LLM.
// All real tool output appears verbatim so the model is grounded in actual
// engineering diagnostics rather than rephrased summaries.
func (cp CorrectionPrompt) Format() string {
	var b strings.Builder

	b.WriteString("You are a Go compiler repair tool. Your only job is to return fixed Go source code.\n")
	b.WriteString("Rules:\n")
	b.WriteString("- Output ONLY valid Go source code, starting with 'package'.\n")
	b.WriteString("- Do NOT include any explanation, comments about what changed, or markdown fences.\n")
	b.WriteString("- Do NOT write ``` or ```go.\n")
	b.WriteString("- The very first character of your response must be 'p' (from 'package').\n\n")

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

	// ── Annotated source ─────────────────────────────────────────────────────
	b.WriteString("=== ANNOTATED SOURCE ===\n")
	b.WriteString(cp.AnnotatedSource)
	b.WriteString("\n")

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
