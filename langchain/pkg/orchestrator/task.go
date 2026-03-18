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

// Attempt is an immutable snapshot of one build+audit cycle.
// Every failed attempt is appended to Task.History before the judge is called,
// giving the LLM the full repair trajectory so it can avoid repeating patterns
// that already failed.
type Attempt struct {
	Number      int       // 1-based attempt index
	Code        string    // the source code that was compiled
	BuildErrors []string  // compiler output; empty when compilation succeeded
	Findings    []Finding // actionable tool findings from this attempt
}

// Task is the unit of work the orchestrator manages.
type Task struct {
	ID           string
	Status       Status
	Code         string       // current Go source (updated after each judge repair)
	Errors       []string     // build errors from the most recent attempt
	Findings     []Finding    // tool findings from the most recent attempt
	Attempts     int          // total build+audit attempts made
	History      []Attempt    // every failed attempt in order, oldest first
	ApprovedDeps []ApprovedDep // deps approved for this task's sandbox go.mod
}
