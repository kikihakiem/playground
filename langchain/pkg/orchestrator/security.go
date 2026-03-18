package orchestrator

import (
	"fmt"
	"regexp"
	"strings"
)

// SecurityIssue is a finding from the regex-based pre-flight scanner.
// This is kept as a lightweight fallback for when gosec is not installed.
// Severity is defined in tools.go and shared across both approaches.
type SecurityIssue struct {
	Line        int
	Severity    Severity
	Description string
}

// SecurityAudit holds the outcome of the regex-based audit.
type SecurityAudit struct {
	Issues []SecurityIssue
	Clean  bool
}

// credentialRe matches assignments whose identifier contains a credential
// keyword anywhere (prefix, suffix, or whole name).
var credentialRe = regexp.MustCompile(
	`(?i)(?:^|[\s,({])` +
		`\w*?` +
		`(password|passwd|pwd|secret|api[_-]?key|apikey|token|credential|auth[_-]?key|private[_-]?key|access[_-]?key)` +
		`\w*` +
		`\s*(?::=|=)\s*` +
		`"([^"]{3,})"`,
)

var unsafeImportRe = regexp.MustCompile(`(?m)^\s*"unsafe"\s*$|import\s+"unsafe"`)

// RunSecurityAudit is the lightweight, regex-based fallback scanner.
// When gosec is available, the orchestrator uses GosecTool instead and this
// function is not called in the main pipeline.  It remains useful for fast
// pre-flight checks in tests and environments without gosec.
func RunSecurityAudit(code string) SecurityAudit {
	lines := strings.Split(code, "\n")
	var issues []SecurityIssue

	for i, line := range lines {
		lineNum := i + 1

		if unsafeImportRe.MatchString(line) {
			issues = append(issues, SecurityIssue{
				Line:        lineNum,
				Severity:    SeverityHigh,
				Description: `import "unsafe" detected — bypass of Go's type safety; remove unless strictly necessary`,
			})
		}

		if m := credentialRe.FindStringSubmatch(line); m != nil {
			issues = append(issues, SecurityIssue{
				Line:     lineNum,
				Severity: SeverityHigh,
				Description: fmt.Sprintf(
					`hardcoded credential detected — change to: var %s = os.Getenv("%s"); add "os" to imports if not present`,
					m[1], strings.ToUpper(m[1]),
				),
			})
		}
	}

	return SecurityAudit{Issues: issues, Clean: len(issues) == 0}
}
