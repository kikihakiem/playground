package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ExecutionLoop is the core agentic loop:
//
//	approve deps → generate → build+audit → issues? ask judge to fix → repeat
type ExecutionLoop struct {
	Generator     CodeGenerator      // produces initial code from a requirement
	Judge         JudgeAgent         // repairs code given real tool output
	Deps          DependencyApprover // optional; nil = stdlib-only
	Preprocessors []Preprocessor     // applied to code before every build attempt
	Tools         []AnalysisTool     // run after each successful build (go vet, gosec, staticcheck)
	MaxRetries    int                // max judge-and-retry cycles (0 = build once, no repair)
	MinSeverity   Severity           // findings below this level are reported but don't trigger repair (default: LOW)
	Timeout       time.Duration      // wall-clock cap for the full pipeline; 0 = no limit
	Logger        io.Writer          // progress log destination; nil = silent
}

// logf writes a formatted line to the logger when one is configured.
func (el *ExecutionLoop) logf(format string, args ...any) {
	if el.Logger == nil {
		return
	}
	fmt.Fprintf(el.Logger, format, args...)
}

// logPhase writes a single labelled phase line:  "  %-11s  <msg>\n"
func (el *ExecutionLoop) logPhase(label, msg string) {
	el.logf("  %-11s  %s\n", label, msg)
}

// logCont writes a continuation line indented to align under a phase label.
func (el *ExecutionLoop) logCont(msg string) {
	el.logf("               %s\n", msg)
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
//
// Pipeline:
//  1. (optional) Timeout is applied to the context for the entire pipeline
//  2. (optional) DependencyApprover selects allowed external packages
//  3. Requirement is enriched with dep hints and passed to GenerateInitialCode
//  4. Build+audit+fix loop runs until clean or retries are exhausted
func (el *ExecutionLoop) RunFromRequirement(ctx context.Context, task *Task, requirement string) error {
	if el.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, el.Timeout)
		defer cancel()
	}

	enriched := requirement

	if el.Deps != nil {
		el.logPhase("deps", "approving packages...")
		deps, err := el.Deps.ApproveDeps(ctx, requirement)
		if err != nil {
			return fmt.Errorf("dependency approver: %w", err)
		}
		task.ApprovedDeps = deps
		if len(deps) > 0 {
			names := make([]string, len(deps))
			for i, d := range deps {
				names[i] = d.Module + " " + d.Version
			}
			el.logPhase("deps", fmt.Sprintf("✓ %d approved: %s", len(deps), strings.Join(names, ", ")))
			enriched = EnrichRequirement(requirement, deps)
		} else {
			el.logPhase("deps", "none needed (stdlib only)")
		}
	}

	el.logPhase("generate", "requesting initial code from DevAgent...")
	if err := el.GenerateInitialCode(ctx, task, enriched); err != nil {
		return err
	}
	el.logPhase("generate", fmt.Sprintf("✓ received %d line(s)", strings.Count(task.Code, "\n")+1))

	return el.Run(ctx, task)
}

// Run executes the build+audit+fix loop on task.Code, mutating task in place.
// It returns nil only when both compilation and all audit tools come back clean.
func (el *ExecutionLoop) Run(ctx context.Context, task *Task) error {
	maxAttempts := el.MaxRetries + 1
	for {
		task.Status = StatusRunning
		task.Attempts++

		el.logf("\n▶ attempt %d/%d %s\n", task.Attempts, maxAttempts,
			strings.Repeat("─", max(0, 44-len(fmt.Sprintf("%d/%d", task.Attempts, maxAttempts)))))

		// ── Preprocessors ──────────────────────────────────────────────────
		for _, p := range el.Preprocessors {
			before := task.Code
			processed, ppErr := p.Process(before)
			if ppErr != nil {
				log.Printf("preprocessor warning (%T): %v", p, ppErr)
				continue
			}
			if processed != before {
				added := importDiff(before, processed)
				if len(added) > 0 {
					el.logPhase("preprocess", fmt.Sprintf("✚ added imports: %s",
						strings.Join(quoteAll(added), ", ")))
				} else {
					el.logPhase("preprocess", "✚ modified code")
				}
			}
			task.Code = processed
		}

		// ── Build + audit ──────────────────────────────────────────────────
		buildErrs, findings, toolErrs, err := buildAndAudit(ctx, task.Code, el.Tools, task.ApprovedDeps)
		if err != nil {
			task.Status = StatusFailed
			if errors.Is(err, context.DeadlineExceeded) {
				el.logPhase("build", "✗ timeout")
				el.logResult(false, task.Attempts, "timeout")
				return fmt.Errorf("pipeline timeout (%v) exceeded on attempt %d: %w", el.Timeout, task.Attempts, err)
			}
			el.logPhase("build", fmt.Sprintf("✗ internal error: %v", err))
			el.logResult(false, task.Attempts, "internal error")
			return fmt.Errorf("build/audit error on attempt %d: %w", task.Attempts, err)
		}
		for _, te := range toolErrs {
			log.Printf("tool warning: %v", te)
		}

		task.Errors = buildErrs
		task.Findings = findings

		if len(buildErrs) > 0 {
			el.logPhase("build", fmt.Sprintf("✗ %d error(s)", len(buildErrs)))
			for _, e := range buildErrs {
				el.logCont(e)
			}
		} else {
			el.logPhase("build", "✓ compiled")
		}

		if len(buildErrs) == 0 {
			if len(findings) == 0 {
				el.logPhase("audit", "✓ clean")
			} else {
				el.logPhase("audit", fmt.Sprintf("✗ %d finding(s)", len(findings)))
				for _, f := range findings {
					el.logCont(fmt.Sprintf("[%s] %s  %s:%d  %s",
						f.Severity, f.Rule, f.File, f.Line, f.Message))
				}
			}
		}

		// ── Check for issues ───────────────────────────────────────────────
		actionable := el.filterFindings(findings)
		req := RepairRequest{
			Code:        task.Code,
			BuildErrors: buildErrs,
			Findings:    actionable,
		}

		if !req.HasIssues() {
			task.Status = StatusSuccess
			el.logResult(true, task.Attempts, "")
			return nil
		}

		// Snapshot this failed attempt before calling the judge so the judge
		// receives the full history including the current failure.
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
			el.logResult(false, task.Attempts, fmt.Sprintf("max retries (%d) exhausted", el.MaxRetries))
			return fmt.Errorf("failed after %d attempt(s), max retries (%d) exhausted:\n  %s",
				task.Attempts, el.MaxRetries, strings.Join(summary, "\n  "))
		}

		el.logPhase("judge", "→ requesting repair...")
		fixed, err := el.Judge.Fix(ctx, req)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				task.Status = StatusFailed
				el.logResult(false, task.Attempts, "judge timeout")
				return fmt.Errorf("pipeline timeout (%v) exceeded waiting for judge on attempt %d: %w", el.Timeout, task.Attempts, err)
			}
			return fmt.Errorf("judge failed on attempt %d: %w", task.Attempts, err)
		}
		el.logPhase("judge", fmt.Sprintf("✓ received %d line(s)", strings.Count(fixed, "\n")+1))
		task.Code = fixed
		task.Status = StatusRepaired
	}
}

func (el *ExecutionLoop) logResult(ok bool, attempts int, reason string) {
	el.logf("\n")
	if ok {
		el.logf("✓ success · %d attempt(s)\n", attempts)
	} else {
		if reason != "" {
			el.logf("✗ failed · %d attempt(s) · %s\n", attempts, reason)
		} else {
			el.logf("✗ failed · %d attempt(s)\n", attempts)
		}
	}
}

// quoteAll returns each string wrapped in double quotes.
func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = `"` + s + `"`
	}
	return out
}

// max returns the larger of two ints (builtin in Go 1.21+, kept here for clarity).
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
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
// When deps are non-empty, go mod tidy is run before compilation so the sandbox
// go.mod includes the approved external packages; tidy failures are surfaced as
// build errors (not fatal errors) so the judge can diagnose wrong import paths.
func buildAndAudit(ctx context.Context, code string, tools []AnalysisTool, deps []ApprovedDep) (
	buildErrors []string, findings []Finding, toolErrs []error, err error,
) {
	dir, err := os.MkdirTemp("", "orchestrator-*")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(BuildGoMod(deps)), 0o600); err != nil {
		return nil, nil, nil, fmt.Errorf("write go.mod: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(code), 0o600); err != nil {
		return nil, nil, nil, fmt.Errorf("write main.go: %w", err)
	}

	// ── 0. Fetch external deps ────────────────────────────────────────────────
	// go mod tidy downloads approved packages and generates go.sum.
	// Errors are returned as build errors — a wrong import path in the generated
	// code is a code problem, not an infrastructure problem.
	if len(deps) > 0 {
		var tidyStderr bytes.Buffer
		tidyCmd := exec.CommandContext(ctx, "go", "mod", "tidy")
		tidyCmd.Dir = dir
		tidyCmd.Stderr = &tidyStderr
		if tidyErr := tidyCmd.Run(); tidyErr != nil {
			if ctx.Err() != nil {
				return nil, nil, nil, ctx.Err()
			}
			raw := strings.TrimSpace(tidyStderr.String())
			if raw == "" {
				raw = tidyErr.Error()
			}
			return strings.Split("go mod tidy: "+raw, "\n"), nil, nil, nil
		}
	}

	// ── 1. Compile ───────────────────────────────────────────────────────────
	var stderr bytes.Buffer
	buildCmd := exec.CommandContext(ctx, "go", "build", "./...")
	buildCmd.Dir = dir
	buildCmd.Stderr = &stderr
	if runErr := buildCmd.Run(); runErr != nil {
		if ctx.Err() != nil {
			return nil, nil, nil, ctx.Err()
		}
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
