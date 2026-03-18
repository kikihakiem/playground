package orchestrator

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExecutionLoop is the core agentic loop:
//
//	generate → build+audit → issues? ask judge to fix → repeat
type ExecutionLoop struct {
	Generator   CodeGenerator  // produces initial code from a requirement
	Judge       JudgeAgent     // repairs code given real tool output
	Tools       []AnalysisTool // run after each successful build (go vet, gosec, staticcheck)
	MaxRetries  int            // max judge-and-retry cycles (0 = build once, no repair)
	MinSeverity Severity       // findings below this level are reported but don't trigger repair (default: LOW)
}

// GenerateInitialCode populates task.Code from a natural-language requirement.
func (el *ExecutionLoop) GenerateInitialCode(ctx context.Context, task *Task, requirement string) error {
	if el.Generator == nil {
		return fmt.Errorf("ExecutionLoop.Generator is nil")
	}
	code, err := el.Generator.GenerateInitialCode(ctx, requirement)
	if err != nil {
		return fmt.Errorf("generate initial code: %w", err)
	}
	task.Code = code
	return nil
}

// RunFromRequirement generates initial code then runs the build+audit+fix loop.
// It is the single entry-point for the full agentic pipeline.
func (el *ExecutionLoop) RunFromRequirement(ctx context.Context, task *Task, requirement string) error {
	if err := el.GenerateInitialCode(ctx, task, requirement); err != nil {
		return err
	}
	return el.Run(ctx, task)
}

// Run executes the build+audit+fix loop on task.Code, mutating task in place.
// It returns nil only when both compilation and all audit tools come back clean.
func (el *ExecutionLoop) Run(ctx context.Context, task *Task) error {
	for {
		task.Status = StatusRunning
		task.Attempts++

		buildErrs, findings, toolErrs, err := buildAndAudit(ctx, task.Code, el.Tools)
		if err != nil {
			task.Status = StatusFailed
			return fmt.Errorf("build/audit error on attempt %d: %w", task.Attempts, err)
		}
		for _, te := range toolErrs {
			log.Printf("tool warning: %v", te)
		}

		task.Errors = buildErrs
		task.Findings = findings

		// Filter findings to only those at or above the minimum severity.
		// Lower-severity findings are attached to the task for visibility
		// but do not trigger a repair cycle.
		actionable := el.filterFindings(findings)

		req := RepairRequest{
			Code:        task.Code,
			BuildErrors: buildErrs,
			Findings:    actionable,
		}

		if !req.HasIssues() {
			task.Status = StatusSuccess
			return nil
		}

		// Snapshot this failed attempt before calling the judge so the judge
		// receives the full history including the current failure. The LLM
		// can then avoid repeating code patterns that already produced errors.
		task.History = append(task.History, Attempt{
			Number:      task.Attempts,
			Code:        task.Code,
			BuildErrors: buildErrs,
			Findings:    actionable,
		})
		req.History = task.History

		retriesUsed := task.Attempts - 1
		if retriesUsed >= el.MaxRetries {
			task.Status = StatusFailed
			var summary []string
			summary = append(summary, buildErrs...)
			for _, f := range findings {
				summary = append(summary, f.String())
			}
			return fmt.Errorf("failed after %d attempt(s), max retries (%d) exhausted:\n  %s",
				task.Attempts, el.MaxRetries, strings.Join(summary, "\n  "))
		}

		fixed, err := el.Judge.Fix(ctx, req)
		if err != nil {
			return fmt.Errorf("judge failed on attempt %d: %w", task.Attempts, err)
		}
		task.Code = fixed
		task.Status = StatusRepaired
	}
}

// filterFindings returns only the findings at or above el.MinSeverity.
// When MinSeverity is unset it defaults to LOW, keeping HIGH and MEDIUM.
func (el *ExecutionLoop) filterFindings(findings []Finding) []Finding {
	min := el.MinSeverity
	if min == "" {
		min = SeverityLow
	}
	order := map[Severity]int{SeverityHigh: 3, SeverityMedium: 2, SeverityLow: 1, SeverityInfo: 0}
	threshold := order[min]

	var out []Finding
	for _, f := range findings {
		if order[f.Severity] >= threshold {
			out = append(out, f)
		}
	}
	return out
}

// buildAndAudit writes code to a temp dir, runs `go build`, and — if the build
// succeeds — runs all configured audit tools.  It returns compiler errors and
// tool findings separately so the prompt builder can render them distinctly.
func buildAndAudit(ctx context.Context, code string, tools []AnalysisTool) (
	buildErrors []string, findings []Finding, toolErrs []error, err error,
) {
	dir, err := os.MkdirTemp("", "orchestrator-*")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	gomod := "module sandbox\n\ngo 1.25\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o600); err != nil {
		return nil, nil, nil, fmt.Errorf("write go.mod: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(code), 0o600); err != nil {
		return nil, nil, nil, fmt.Errorf("write main.go: %w", err)
	}

	// ── 1. Compile ───────────────────────────────────────────────────────────
	var stderr bytes.Buffer
	buildCmd := exec.CommandContext(ctx, "go", "build", "./...")
	buildCmd.Dir = dir
	buildCmd.Stderr = &stderr
	if runErr := buildCmd.Run(); runErr != nil {
		raw := strings.TrimSpace(stderr.String())
		if raw == "" {
			raw = runErr.Error()
		}
		// Compilation failed — skip tools, there's nothing compilable to analyse.
		return strings.Split(raw, "\n"), nil, nil, nil
	}

	// ── 2. Audit tools ───────────────────────────────────────────────────────
	// Tools only run on code that compiles, so their output is always meaningful.
	ff, errs := RunTools(ctx, tools, dir)
	return nil, ff, errs, nil
}
