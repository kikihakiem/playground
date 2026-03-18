package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/khakiem/playground/langchain/pkg/orchestrator"
)

func main() {
	requirement := flag.String(
		"requirement",
		"Build a simple HTTP server that listens on port 8080 and responds to GET /health with status 200 and body 'ok'",
		"natural-language description of the Go program to generate",
	)
	live  := flag.Bool("live", false, "use CodeLlama via Ollama instead of the mock")
	model := flag.String("model", orchestrator.DefaultModel, "Ollama model tag")
	flag.Parse()

	ctx := context.Background()

	// ── Audit tool chain ─────────────────────────────────────────────────────
	// All three tools are included. Each calls Available() before running;
	// unavailable tools are silently skipped so the pipeline stays portable.
	tools := []orchestrator.AnalysisTool{
		orchestrator.GoVetTool{},
		orchestrator.GosecTool{},
		orchestrator.StaticcheckTool{},
	}
	reportToolchain(tools)

	// ── Judge / Generator ────────────────────────────────────────────────────
	var judge     orchestrator.JudgeAgent
	var generator orchestrator.CodeGenerator

	if *live {
		backend, err := orchestrator.NewCodeLlamaBackend(
			orchestrator.WithCodeLlamaModel(*model),
		)
		if err != nil {
			log.Fatalf("init CodeLlama backend: %v", err)
		}
		// Two-persona split: DevAgent writes fast; AuditorJudge repairs safely.
		generator = &orchestrator.DevAgent{LLM: backend}
		judge = &orchestrator.AuditorJudge{LLM: backend}
		fmt.Printf("backend  : CodeLlama (%s) via Ollama\n", *model)
		fmt.Printf("generator: DevAgent    (junior dev persona)\n")
		fmt.Printf("judge    : AuditorJudge (senior security auditor persona)\n\n")
	} else {
		// The mock code is written to be clean: server has timeouts (gosec G114)
		// and the error from ListenAndServe is handled (gosec G104).
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
		fmt.Println("backend  : mock (pass -live to use CodeLlama)\n")
	}

	maxRetries := 3
	if *live {
		maxRetries = 6
	}

	loop := &orchestrator.ExecutionLoop{
		Generator:  generator,
		Judge:      judge,
		Tools:      tools,
		MaxRetries: maxRetries,
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
