package orchestrator

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Severity is shared across tools and the security scanner.
type Severity string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
	SeverityInfo   Severity = "INFO"
)

// Finding is one diagnostic from a real analysis tool (go vet, gosec, staticcheck).
// Using real tools means findings are grounded in actual compiler/linter behaviour,
// not regex heuristics.
type Finding struct {
	Tool     string   // "go vet", "gosec", "staticcheck"
	File     string   // e.g. "main.go"
	Line     int      // 1-based
	Column   int      // 1-based, 0 when unknown
	Severity Severity // HIGH / MEDIUM / LOW / INFO
	Rule     string   // e.g. "G101", "SA1006", "printf"
	Message  string   // human-readable description
	Snippet  string   // offending code snippet, if the tool provides it
}

func (f Finding) String() string {
	loc := fmt.Sprintf("%s:%d", f.File, f.Line)
	if f.Column > 0 {
		loc = fmt.Sprintf("%s:%d", loc, f.Column)
	}
	rule := ""
	if f.Rule != "" {
		rule = fmt.Sprintf(" (%s)", f.Rule)
	}
	return fmt.Sprintf("[%s] %s %s%s: %s", f.Tool, f.Severity, loc, rule, f.Message)
}

// AnalysisTool runs one static analysis pass over Go source in a temp directory.
// The orchestrator calls Available() first and skips tools that are not installed.
type AnalysisTool interface {
	Name() string
	// Available returns true if the tool binary is on PATH.
	Available() bool
	// Run analyses the Go source files in dir and returns findings.
	// A non-empty findings list is not itself an error; it means the tool ran
	// and found issues. Return an error only for infrastructure failures
	// (binary not runnable, unreadable output, etc.).
	Run(ctx context.Context, dir string) ([]Finding, error)
}

// RunTools runs every available tool against dir and collects findings.
// Per-tool errors are surfaced alongside findings so the caller can log them
// without halting the pipeline.
func RunTools(ctx context.Context, tools []AnalysisTool, dir string) (findings []Finding, toolErrs []error) {
	for _, t := range tools {
		if !t.Available() {
			continue
		}
		ff, err := t.Run(ctx, dir)
		if err != nil {
			toolErrs = append(toolErrs, fmt.Errorf("%s: %w", t.Name(), err))
			continue
		}
		findings = append(findings, ff...)
	}
	return findings, toolErrs
}

// ── shared parsing helper ────────────────────────────────────────────────────

// toolLineRe parses lines emitted by go vet and staticcheck (text mode):
//
//	[./]file.go:line:col: message
//	[./]file.go:line: message     (col omitted)
var toolLineRe = regexp.MustCompile(`(?:\.\/)?(\S+\.go):(\d+)(?::(\d+))?:\s*(.+)`)

// parseToolLine tries to turn a raw text line into a Finding.
func parseToolLine(toolName string, severity Severity, line string) (Finding, bool) {
	m := toolLineRe.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return Finding{}, false
	}
	lineNum, _ := strconv.Atoi(m[2])
	colNum, _ := strconv.Atoi(m[3])
	// Extract an optional rule tag like "printf:" or "S1006:" at the start of
	// the message so we can surface it as a structured Rule field.
	msg := strings.TrimSpace(m[4])
	rule := ""
	if idx := strings.Index(msg, ":"); idx > 0 {
		candidate := msg[:idx]
		if !strings.ContainsAny(candidate, " \t") {
			rule = candidate
			msg = strings.TrimSpace(msg[idx+1:])
		}
	}
	return Finding{
		Tool:     toolName,
		File:     m[1],
		Line:     lineNum,
		Column:   colNum,
		Severity: severity,
		Rule:     rule,
		Message:  msg,
	}, true
}
