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

	var judge     orchestrator.JudgeAgent
	var generator orchestrator.CodeGenerator

	if *live {
		backend, err := orchestrator.NewCodeLlamaBackend(
			orchestrator.WithCodeLlamaModel(*model),
		)
		if err != nil {
			log.Fatalf("init CodeLlama backend: %v", err)
		}
		sj := &orchestrator.StructuredJudge{LLM: backend}
		judge, generator = sj, sj
		fmt.Printf("backend : CodeLlama (%s) via Ollama\n", *model)
	} else {
		// Mock pipeline: GeneratedCodes[0] is what "generation" returns;
		// Responses[0] would be used if the initial code fails to build.
		mj := &orchestrator.MockJudge{
			GeneratedCodes: []string{`package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	fmt.Println("listening on :8080")
	http.ListenAndServe(":8080", nil)
}
`},
		}
		judge, generator = mj, mj
		fmt.Println("backend : mock (pass -live to use CodeLlama)")
	}

	maxRetries := 3
	if *live {
		maxRetries = 6
	}

	loop := &orchestrator.ExecutionLoop{
		Generator:  generator,
		Judge:      judge,
		MaxRetries: maxRetries,
	}

	task := &orchestrator.Task{ID: "task-1"}

	fmt.Printf("requirement: %s\n\n", *requirement)

	if err := loop.RunFromRequirement(ctx, task, *requirement); err != nil {
		fmt.Printf("FAILED after %d attempt(s): %v\n", task.Attempts, err)
		if len(task.Errors) > 0 {
			fmt.Println("last build errors:")
			for _, e := range task.Errors {
				fmt.Println(" ", e)
			}
		}
		return
	}

	fmt.Printf("=== result (status=%s, attempts=%d) ===\n", task.Status, task.Attempts)
	fmt.Println(task.Code)
}
