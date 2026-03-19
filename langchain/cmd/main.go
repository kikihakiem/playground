package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/khakiem/playground/langchain/pkg/orchestrator"
)

// standardAllowlist is the set of external packages the DevAgent is allowed to
// import.  Add entries here as the project matures; each package is pinned to
// a specific version so the sandbox go.mod is deterministic.
var standardAllowlist = []orchestrator.ApprovedDep{
	{
		Name:    "Google UUID",
		Module:  "github.com/google/uuid",
		Version: "v1.6.0",
		Desc:    "UUID generation (RFC 4122)",
	},
	{
		Name:    "pkg/errors",
		Module:  "github.com/pkg/errors",
		Version: "v0.9.1",
		Desc:    "Error wrapping with stack traces",
	},
}

func main() {
	requirement := flag.String(
		"requirement",
		"Build a simple HTTP server that listens on port 8080 and responds to GET /health with status 200 and body 'ok'",
		"natural-language description of the Go program to generate",
	)
	live    := flag.Bool("live", false, "use Qwen2.5-Coder via Ollama instead of the mock")
	model   := flag.String("model", orchestrator.DefaultModel, "model tag (e.g. qwen2.5-coder:14b)")
	baseURL := flag.String("base-url", orchestrator.DefaultBaseURL, "OpenAI-compatible API base URL")
	timeout := flag.Duration("timeout", 0, "wall-clock limit for the full pipeline (e.g. 5m); 0 = no limit")
	review  := flag.Bool("review", false, "pause before generation and ask a human to approve the requirement")
	flag.Parse()

	ctx := context.Background()

	// ── Audit tool chain ─────────────────────────────────────────────────────
	tools := []orchestrator.AnalysisTool{
		orchestrator.GoVetTool{},
		orchestrator.GosecTool{},
		orchestrator.StaticcheckTool{},
	}
	reportToolchain(tools)

	// ── Agents ───────────────────────────────────────────────────────────────
	var (
		judge    orchestrator.JudgeAgent
		generator orchestrator.CodeGenerator
		testGen   orchestrator.TestGenerator      // nil = no oracle tests
		depsAgent orchestrator.DependencyApprover  // nil = stdlib-only
		proposer  orchestrator.SolutionProposer    // nil = skip proposal step
	)

	maxRetries := 3

	if *live {
		backend := orchestrator.NewOpenAIBackend(
			orchestrator.WithModel(*model),
			orchestrator.WithBaseURL(*baseURL),
		)
		// Three-agent pipeline:
		//   DevAgent           — junior dev, writes code fast
		//   AuditorJudge       — senior auditor, fixes compiler + tool issues
		//   AllowlistApprover  — enforces approved packages
		devAgent := &orchestrator.DevAgent{LLM: backend}
		generator = devAgent
		testGen = devAgent  // DevAgent implements CodeGenerator, TestGenerator, and SolutionProposer
		proposer = devAgent
		judge = &orchestrator.AuditorJudge{LLM: backend}
		depsAgent = &orchestrator.AllowlistApprover{
			Allowlist: standardAllowlist,
		}
		maxRetries = 6
		fmt.Printf("backend  : %s via %s\n", *model, *baseURL)
		fmt.Printf("generator: DevAgent          (junior dev persona)\n")
		fmt.Printf("tests    : DevAgent          (oracle test writer)\n")
		fmt.Printf("judge    : AuditorJudge       (senior security auditor persona)\n")
		fmt.Printf("deps     : AllowlistApprover  (%d packages in allowlist)\n\n", len(standardAllowlist))
	} else {
		// Mock path: clean server code that passes all audit tools.
		mj := &orchestrator.MockJudge{
			GeneratedCodes: []string{`package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	fmt.Println("listening on :8080")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
`},
		}
		judge, generator = mj, mj
		fmt.Println("backend  : mock (pass -live to use CodeLlama)")
		fmt.Println()
	}

	loop := &orchestrator.ExecutionLoop{
		Generator:     generator,
		Judge:         judge,
		Deps:          depsAgent,
		TestGenerator: testGen,
		Proposer:      proposer,
		Preprocessors: []orchestrator.Preprocessor{orchestrator.ImportFixer{}},
		Tools:         tools,
		MaxRetries:    maxRetries,
		Timeout:       *timeout,
		Logger:        os.Stderr,
	}

	if *review {
		tr := orchestrator.TerminalReviewer{}
		loop.RequirementReviewer = tr
		loop.Reviewer = tr
	}

	task := &orchestrator.Task{ID: "task-1"}
	fmt.Printf("requirement: %s\n\n", *requirement)

	if err := loop.RunFromRequirement(ctx, task, *requirement); err != nil {
		fmt.Printf("FAILED after %d attempt(s): %v\n", task.Attempts, err)
		if len(task.Errors) > 0 {
			fmt.Println("last compiler errors:")
			for _, e := range task.Errors {
				fmt.Println("  ", e)
			}
		}
		if len(task.Findings) > 0 {
			fmt.Println("last tool findings:")
			for _, f := range task.Findings {
				fmt.Println("  ", f)
			}
		}
		return
	}

	fmt.Printf("=== result (status=%s, attempts=%d) ===\n", task.Status, task.Attempts)
	if len(task.ApprovedDeps) > 0 {
		fmt.Println("approved deps used:")
		for _, d := range task.ApprovedDeps {
			fmt.Printf("  %s %s\n", d.Module, d.Version)
		}
	}
	fmt.Println(task.Code)
}

func reportToolchain(tools []orchestrator.AnalysisTool) {
	fmt.Println("toolchain:")
	for _, t := range tools {
		status := "skipped (not installed)"
		if t.Available() {
			status = "available"
		}
		fmt.Printf("  %-14s %s\n", t.Name(), status)
	}
	fmt.Println()
}
