package orchestrator

// Status represents the lifecycle state of a Task.
type Status string

const (
	StatusPending  Status = "pending"
	StatusRunning  Status = "running"
	StatusSuccess  Status = "success"
	StatusFailed   Status = "failed"
	StatusRepaired Status = "repaired" // judge rewrote the code; will retry
)

// Task is the unit of work the orchestrator manages.
// Code holds the Go source the executor will compile; Errors accumulates
// build diagnostics across attempts so the Judge has full context.
type Task struct {
	ID       string
	Status   Status
	Code     string   // Go source code to write and compile
	Errors   []string // build errors from the most recent failed attempt
	Attempts int      // how many build attempts have been made
}
