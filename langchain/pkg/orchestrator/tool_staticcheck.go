package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// StaticcheckTool wraps `staticcheck -f json ./...`.
// staticcheck catches a wide range of correctness, performance, and style
// issues that go vet misses, including:
//   - Incorrect API usage          (SA checks)
//   - Unnecessary work             (S checks)
//   - Code simplification          (S checks)
//   - Deprecated API use           (SA1019)
//
// Install: go install honnef.co/go/tools/cmd/staticcheck@latest
type StaticcheckTool struct{}

func (StaticcheckTool) Name() string { return "staticcheck" }

func (StaticcheckTool) Available() bool {
	_, err := exec.LookPath("staticcheck")
	return err == nil
}

// Run executes `staticcheck -f json ./...` in dir.
// staticcheck outputs one JSON object per line (NDJSON) and exits non-zero
// when findings exist — that is expected, not an infrastructure failure.
func (StaticcheckTool) Run(ctx context.Context, dir string) ([]Finding, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "staticcheck", "-f", "json", "./...")
	cmd.Dir = dir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run() // non-zero when findings exist

	if stdout.Len() == 0 {
		if s := strings.TrimSpace(stderr.String()); s != "" {
			return nil, fmt.Errorf("staticcheck stderr: %s", s)
		}
		return nil, nil
	}

	return parseStaticcheckNDJSON(stdout.Bytes())
}

// ── staticcheck NDJSON schema ─────────────────────────────────────────────────

type staticcheckResult struct {
	Code     string                 `json:"code"`     // "SA1006", "S1039"
	Severity string                 `json:"severity"` // "error", "warning", "ignored"
	Location staticcheckLocation    `json:"location"`
	Message  string                 `json:"message"`
}

type staticcheckLocation struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

func parseStaticcheckNDJSON(data []byte) ([]Finding, error) {
	var findings []Finding
	for _, raw := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var result staticcheckResult
		if err := json.Unmarshal([]byte(raw), &result); err != nil {
			// Skip unparse-able lines rather than failing the whole run.
			continue
		}
		if result.Severity == "ignored" {
			continue
		}

		file := result.Location.File
		if idx := lastSlash(file); idx >= 0 {
			file = file[idx+1:]
		}

		findings = append(findings, Finding{
			Tool:     "staticcheck",
			File:     file,
			Line:     result.Location.Line,
			Column:   result.Location.Column,
			Severity: staticcheckSeverity(result.Severity),
			Rule:     result.Code,
			Message:  result.Message,
		})
	}
	return findings, nil
}

func staticcheckSeverity(s string) Severity {
	switch s {
	case "error":
		return SeverityHigh
	case "warning":
		return SeverityMedium
	default:
		return SeverityInfo
	}
}
