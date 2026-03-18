package main

import (
	"context"
	"fmt"
	"log"

	"github.com/khakiem/playground/langchain/pkg/orchestrator"
)

func main() {
	// --- Scenario 1: broken code that the mock judge repairs on the first try ---
	brokenCode := `package main

import "fmt"

func main() {
	fmt.Println("hello"   // missing closing paren
}
`

	fixedCode := `package main

import "fmt"

func main() {
	fmt.Println("hello")
}
`

	judge := &orchestrator.MockJudge{
		Responses: []string{fixedCode},
	}

	task := &orchestrator.Task{
		ID:   "demo-task-1",
		Code: brokenCode,
	}

	loop := &orchestrator.ExecutionLoop{
		Judge:      judge,
		MaxRetries: 3,
	}

	ctx := context.Background()
	if err := loop.Run(ctx, task); err != nil {
		log.Fatalf("task %s failed: %v", task.ID, err)
	}

	fmt.Printf("task %s finished\n", task.ID)
	fmt.Printf("  status:   %s\n", task.Status)
	fmt.Printf("  attempts: %d\n", task.Attempts)
	fmt.Printf("  judge called %d time(s)\n", len(judge.Calls))

	// --- Scenario 2: code that can't be repaired (judge echoes it back) ---
	fmt.Println()

	unreparableTask := &orchestrator.Task{
		ID:   "demo-task-2",
		Code: `this is not valid Go`,
	}

	silentJudge := &orchestrator.MockJudge{} // no responses → always echoes code back

	loop2 := &orchestrator.ExecutionLoop{Judge: silentJudge, MaxRetries: 2}
	if err := loop2.Run(ctx, unreparableTask); err != nil {
		fmt.Printf("task %s correctly failed after %d attempt(s): %v\n",
			unreparableTask.ID, unreparableTask.Attempts, err)
	}
}
