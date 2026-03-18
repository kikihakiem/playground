package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/khakiem/playground/langchain/pkg/orchestrator"
)

// brokenCode has two problems the model must fix:
//   1. Missing closing parenthesis in Println call
//   2. Hardcoded credential (flagged by the security audit)
const brokenCode = `package main

import "fmt"

const apiKey = "SUPER_SECRET_KEY_123"

func main() {
	fmt.Println("starting server"
}
`

func main() {
	live := flag.Bool("live", false, "use CodeLlama via Ollama instead of the mock judge")
	model := flag.String("model", orchestrator.DefaultModel, "Ollama model tag")
	flag.Parse()

	ctx := context.Background()

	var judge orchestrator.JudgeAgent
	if *live {
		backend, err := orchestrator.NewCodeLlamaBackend(
			orchestrator.WithCodeLlamaModel(*model),
		)
		if err != nil {
			log.Fatalf("init CodeLlama backend: %v", err)
		}
		judge = &orchestrator.StructuredJudge{LLM: backend}
		fmt.Printf("judge: CodeLlama (%s) via Ollama\n\n", *model)
	} else {
		// Mock judge: returns valid code on the first fix attempt.
		judge = &orchestrator.MockJudge{
			Responses: []string{`package main

import "fmt"

func main() {
	fmt.Println("starting server")
}
`},
		}
		fmt.Println("judge: mock (run with -live to use CodeLlama)\n")
	}

	task := &orchestrator.Task{
		ID:   "demo",
		Code: brokenCode,
	}

	maxRetries := 3
	if *live {
		maxRetries = 6 // 7B model may take several iterations to converge
	}
	loop := &orchestrator.ExecutionLoop{
		Judge:      judge,
		MaxRetries: maxRetries,
	}

	fmt.Println("=== Initial code ===")
	fmt.Println(brokenCode)

	if err := loop.Run(ctx, task); err != nil {
		fmt.Printf("FAILED after %d attempt(s): %v\n", task.Attempts, err)
		if len(task.Errors) > 0 {
			fmt.Println("Last build errors:")
			for _, e := range task.Errors {
				fmt.Println(" ", e)
			}
		}
		return
	}

	fmt.Printf("=== Repaired code (status=%s, attempts=%d) ===\n", task.Status, task.Attempts)
	fmt.Println(task.Code)
}
