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
type Task struct {
	ID       string
	Status   Status
	Code     string    // Go source code being compiled and audited
	Errors   []string  // compiler errors from the most recent build attempt
	Findings []Finding // tool findings from the most recent audit (go vet, gosec, staticcheck)
	Attempts int       // total build+audit attempts made
}
