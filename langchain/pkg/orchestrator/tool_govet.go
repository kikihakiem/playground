package orchestrator

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
)

// GoVetTool wraps `go vet ./...`.
// go vet catches suspicious constructs the compiler accepts but are likely bugs:
// wrong printf verbs, unreachable code, misuse of sync.Mutex, etc.
// It is always available wherever Go is installed.
type GoVetTool struct{}

func (GoVetTool) Name() string { return "go vet" }

func (GoVetTool) Available() bool {
	_, err := exec.LookPath("go")
	return err == nil
}

// Run executes `go vet ./...` in dir. go vet writes diagnostics to stderr and
// exits non-zero when issues are found — that is expected, not an error.
func (GoVetTool) Run(ctx context.Context, dir string) ([]Finding, error) {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "go", "vet", "./...")
	cmd.Dir = dir
	cmd.Stderr = &stderr
	// Ignore the exit error: non-zero means findings were reported.
	_ = cmd.Run()

	raw := strings.TrimSpace(stderr.String())
	if raw == "" {
		return nil, nil
	}

	var findings []Finding
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if f, ok := parseToolLine("go vet", SeverityMedium, line); ok {
			findings = append(findings, f)
		}
	}
	return findings, nil
}
