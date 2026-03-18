package orchestrator

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExecutionLoop ties together code generation, the build executor, and the
// judge agent into one self-healing agentic loop:
//
//	generate code → write to disk → go build → success? done : ask judge to fix → repeat
type ExecutionLoop struct {
	Generator  CodeGenerator // produces the first version of the code from a requirement
	Judge      JudgeAgent    // repairs code given compiler errors
	MaxRetries int           // maximum judge-and-retry cycles (0 = build once, no repair)
}

// GenerateInitialCode calls the configured CodeGenerator to populate task.Code
// from a natural-language requirement. Call this before Run, or use the
// combined RunFromRequirement helper below.
func (el *ExecutionLoop) GenerateInitialCode(ctx context.Context, task *Task, requirement string) error {
	if el.Generator == nil {
		return fmt.Errorf("ExecutionLoop.Generator is nil — set a CodeGenerator before calling GenerateInitialCode")
	}
	code, err := el.Generator.GenerateInitialCode(ctx, requirement)
	if err != nil {
		return fmt.Errorf("generate initial code: %w", err)
	}
	task.Code = code
	return nil
}

// RunFromRequirement is the single entry-point for the full agentic pipeline:
// generate → build → (fix → build)* → done.
// It first calls GenerateInitialCode to populate task.Code, then calls Run.
func (el *ExecutionLoop) RunFromRequirement(ctx context.Context, task *Task, requirement string) error {
	if err := el.GenerateInitialCode(ctx, task, requirement); err != nil {
		return err
	}
	return el.Run(ctx, task)
}

// Run executes the build→fix loop on task.Code, mutating task.Status,
// task.Errors, and task.Code in place so the caller can inspect each step.
//
// It returns nil only when the build succeeds.
// It returns an error if MaxRetries is exhausted or if any infrastructure call
// (file I/O, judge) fails unexpectedly.
func (el *ExecutionLoop) Run(ctx context.Context, task *Task) error {
	for {
		task.Status = StatusRunning
		task.Attempts++

		errs, err := buildCode(ctx, task.Code)
		if err != nil {
			// Unexpected infrastructure failure — surface immediately.
			task.Status = StatusFailed
			return fmt.Errorf("build infrastructure error on attempt %d: %w", task.Attempts, err)
		}

		if len(errs) == 0 {
			task.Status = StatusSuccess
			task.Errors = nil
			return nil
		}

		// Build failed — record errors on the task.
		task.Status = StatusFailed
		task.Errors = errs

		retriesUsed := task.Attempts - 1 // first attempt is not a retry
		if retriesUsed >= el.MaxRetries {
			return fmt.Errorf("build failed after %d attempt(s), max retries (%d) exhausted: %s",
				task.Attempts, el.MaxRetries, strings.Join(errs, "; "))
		}

		// Hand off to the judge agent for repair.
		fixed, err := el.Judge.Fix(ctx, task.Code, task.Errors)
		if err != nil {
			return fmt.Errorf("judge failed on attempt %d: %w", task.Attempts, err)
		}

		task.Code = fixed
		task.Status = StatusRepaired
	}
}

// buildCode writes code to a temporary directory, runs `go build ./...`, and
// returns any compiler error lines. A nil slice means success.
func buildCode(ctx context.Context, code string) ([]string, error) {
	dir, err := os.MkdirTemp("", "orchestrator-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	// A minimal go.mod so the sandbox is a valid module.
	gomod := "module sandbox\n\ngo 1.22\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o600); err != nil {
		return nil, fmt.Errorf("write go.mod: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(code), 0o600); err != nil {
		return nil, fmt.Errorf("write main.go: %w", err)
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "go", "build", "./...")
	cmd.Dir = dir
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// go build exited non-zero — parse stderr into individual error lines.
		raw := strings.TrimSpace(stderr.String())
		if raw == "" {
			raw = err.Error() // fallback if stderr was empty
		}
		return strings.Split(raw, "\n"), nil
	}

	return nil, nil
}
