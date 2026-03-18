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
// Keeping it as a typed struct (rather than a raw string) makes it easy to
// test each field independently and to swap prompt templates later.
type CorrectionPrompt struct {
	AnnotatedSource string           // original source with error markers inlined
	Annotations     []LineAnnotation // one per parsed compiler diagnostic
	SecurityIssues  []SecurityIssue  // from the static audit step
	RawErrors       []string         // verbatim compiler output lines
}

// goErrorRe matches lines like:
//
//	main.go:5:2: undefined: fmt
//	./main.go:10:15: syntax error: unexpected newline
var goErrorRe = regexp.MustCompile(`(?:\.\/)?(\S+\.go):(\d+):(\d+):\s*(.+)`)

// BuildCorrectionPrompt parses buildErrors into LineAnnotations, then
// produces an annotated view of the source so the LLM sees exactly which
// lines are broken and why.
func BuildCorrectionPrompt(code string, buildErrors []string, issues []SecurityIssue) CorrectionPrompt {
	annotations := parseErrors(buildErrors)
	annotated := annotateSource(code, annotations)
	return CorrectionPrompt{
		AnnotatedSource: annotated,
		Annotations:     annotations,
		SecurityIssues:  issues,
		RawErrors:       buildErrors,
	}
}

// Format renders the CorrectionPrompt into the prompt string sent to the LLM.
// Changing the prompt template only requires touching this one method.
func (cp CorrectionPrompt) Format() string {
	var b strings.Builder

	b.WriteString("You are a Go compiler repair tool. Your only job is to return fixed Go source code.\n")
	b.WriteString("Rules:\n")
	b.WriteString("- Output ONLY valid Go source code, starting with 'package'.\n")
	b.WriteString("- Do NOT include any explanation, comments about what changed, or markdown fences.\n")
	b.WriteString("- Do NOT write ``` or ```go.\n")
	b.WriteString("- The very first character of your response must be 'p' (from 'package').\n\n")

	if len(cp.SecurityIssues) > 0 {
		b.WriteString("=== SECURITY ISSUES (must also be fixed) ===\n")
		for _, s := range cp.SecurityIssues {
			b.WriteString(fmt.Sprintf("  [%s] line %d: %s\n", s.Severity, s.Line, s.Description))
		}
		b.WriteString("\n")
	}

	b.WriteString("=== COMPILER ERRORS ===\n")
	for _, e := range cp.RawErrors {
		b.WriteString("  " + e + "\n")
	}
	b.WriteString("\n")

	b.WriteString("=== ANNOTATED SOURCE ===\n")
	b.WriteString(cp.AnnotatedSource)
	b.WriteString("\n")

	return b.String()
}

// parseErrors extracts structured location information from raw compiler output.
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

// annotateSource rebuilds the source with error markers inserted directly
// after the offending lines, so the LLM sees both code and diagnosis together.
//
// Example output:
//
//	  5 | 	fmt.Println("hello"
//	    |	^ col 2: undefined: fmt
func annotateSource(code string, annotations []LineAnnotation) string {
	sourceLines := strings.Split(code, "\n")

	// Build a map from 1-based line number → list of annotations on that line.
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
			// Build a caret pointer aligned to the column.
			col := a.Column
			if col < 1 {
				col = 1
			}
			pad := strings.Repeat(" ", width+3+col-1) // account for "NNN | " prefix
			b.WriteString(fmt.Sprintf("%s^ col %d: %s\n", pad, a.Column, a.Message))
		}
	}
	return b.String()
}
