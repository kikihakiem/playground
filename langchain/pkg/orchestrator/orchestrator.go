package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
		deps, err := el.Deps.ApproveDeps(ctx, requirement)
		if err != nil {
			return fmt.Errorf("dependency approver: %w", err)
		}
		task.ApprovedDeps = deps
		if len(deps) > 0 {
			enriched = EnrichRequirement(requirement, deps)
		}
	}

	if err := el.GenerateInitialCode(ctx, task, enriched); err != nil {
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

		// Apply preprocessors before each build attempt.  ImportFixer is the
		// canonical example: it silently adds missing stdlib imports so the LLM
		// does not waste a repair cycle on a trivially fixable error.
		for _, p := range el.Preprocessors {
			processed, ppErr := p.Process(task.Code)
			if ppErr != nil {
				log.Printf("preprocessor warning (%T): %v", p, ppErr)
				continue
			}
			task.Code = processed
		}

		buildErrs, findings, toolErrs, err := buildAndAudit(ctx, task.Code, el.Tools, task.ApprovedDeps)
		if err != nil {
			task.Status = StatusFailed
			if errors.Is(err, context.DeadlineExceeded) {
				return fmt.Errorf("pipeline timeout (%v) exceeded on attempt %d: %w", el.Timeout, task.Attempts, err)
			}
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
			if errors.Is(err, context.DeadlineExceeded) {
				task.Status = StatusFailed
				return fmt.Errorf("pipeline timeout (%v) exceeded waiting for judge on attempt %d: %w", el.Timeout, task.Attempts, err)
			}
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
