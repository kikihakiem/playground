package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
)

// GosecTool wraps `gosec -fmt=json ./...`.
// gosec performs AST-level security analysis and catches issues like:
//   - Hardcoded credentials          (G101)
//   - SQL injection                  (G201, G202)
//   - Weak cryptography              (G401–G405)
//   - Command injection              (G204)
//   - File permission issues         (G306)
//   - Use of unsafe                  (G103)
//
// Install: go install github.com/securego/gosec/v2/cmd/gosec@latest
type GosecTool struct{}

func (GosecTool) Name() string { return "gosec" }

func (GosecTool) Available() bool {
	_, err := exec.LookPath("gosec")
	return err == nil
}

// Run executes `gosec -fmt=json -quiet ./...` in dir.
// gosec exits non-zero when it finds issues; we treat that as "findings present",
// not as an infrastructure error.
func (GosecTool) Run(ctx context.Context, dir string) ([]Finding, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "gosec", "-fmt=json", "-quiet", "-nosec-tag=nosec", "./...")
	cmd.Dir = dir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Non-zero exit is normal when findings exist; capture but don't return it.
	_ = cmd.Run()

	if stdout.Len() == 0 {
		// gosec produced no JSON output — either no issues or a startup error.
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("gosec stderr: %s", stderr.String())
		}
		return nil, nil
	}

	return parseGosecJSON(stdout.Bytes())
}

// ── gosec JSON schema (subset we care about) ─────────────────────────────────

type gosecReport struct {
	Issues []gosecIssue `json:"Issues"`
}

type gosecIssue struct {
	Severity   string `json:"severity"`   // "HIGH", "MEDIUM", "LOW"
	RuleID     string `json:"rule_id"`    // "G101"
	Details    string `json:"details"`    // human-readable message
	File       string `json:"file"`       // absolute path
	Code       string `json:"code"`       // offending snippet
	Line       string `json:"line"`       // string, not int
	Column     string `json:"column"`
}

func parseGosecJSON(data []byte) ([]Finding, error) {
	var report gosecReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse gosec output: %w", err)
	}

	findings := make([]Finding, 0, len(report.Issues))
	for _, issue := range report.Issues {
		lineNum, _ := strconv.Atoi(issue.Line)
		colNum, _ := strconv.Atoi(issue.Column)

		// Normalise the file path to a relative basename so the LLM sees
		// "main.go" not "/tmp/orchestrator-1234567/main.go".
		file := issue.File
		if idx := lastSlash(file); idx >= 0 {
			file = file[idx+1:]
		}

		findings = append(findings, Finding{
			Tool:     "gosec",
			File:     file,
			Line:     lineNum,
			Column:   colNum,
			Severity: normaliseSeverity(issue.Severity),
			Rule:     issue.RuleID,
			Message:  issue.Details,
			Snippet:  issue.Code,
		})
	}
	return findings, nil
}

func normaliseSeverity(s string) Severity {
	switch s {
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' || s[i] == '\\' {
			return i
		}
	}
	return -1
}
