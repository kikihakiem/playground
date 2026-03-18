package orchestrator

import (
	"regexp"
	"strings"
)

// Severity classifies how serious a security finding is.
type Severity string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
)

// SecurityIssue is one finding from the static audit.
type SecurityIssue struct {
	Line        int
	Severity    Severity
	Description string
}

// SecurityAudit holds the outcome of auditing a source file.
type SecurityAudit struct {
	Issues []SecurityIssue
	Clean  bool // true when Issues is empty
}

// credentialRe matches variable/constant/field assignments whose left-hand
// identifier *contains* a credential keyword anywhere (prefix, suffix, or whole
// name).  Examples caught:
//
//	password      = "s3cr3t"      keyword is the full name
//	dbPassword    = "hunter2"     keyword is a suffix
//	authToken     = "Bearer ..."  keyword ("token") is a suffix
//	myApiKey      := "AKIA..."    keyword is a suffix
//
// Pattern breakdown:
//
//	(?:^|[\s,({])   word-start: beginning of line or a non-word character
//	\w*?            lazy prefix — the part of the identifier before the keyword
//	(keyword)       the sensitive term, case-insensitive
//	\w*             optional suffix (e.g. "Manager" in "passwordManager")
//	\s*(?::=|=)\s*  assignment operator
//	"([^"]{3,})"    string literal ≥ 3 chars (avoids flagging empty/trivial strings)
var credentialRe = regexp.MustCompile(
	`(?i)(?:^|[\s,({])` +
		`\w*?` +
		`(password|passwd|pwd|secret|api[_-]?key|apikey|token|credential|auth[_-]?key|private[_-]?key|access[_-]?key)` +
		`\w*` +
		`\s*(?::=|=)\s*` +
		`"([^"]{3,})"`,
)

// unsafeImportRe matches both single-import and block-import forms:
//
//	import "unsafe"
//	import ( "unsafe" )
var unsafeImportRe = regexp.MustCompile(`(?m)^\s*"unsafe"\s*$|import\s+"unsafe"`)

// RunSecurityAudit performs static analysis on the source and returns all
// findings.  It does NOT modify the source; the caller decides what to do
// with the issues (e.g. include them in the correction prompt).
func RunSecurityAudit(code string) SecurityAudit {
	lines := strings.Split(code, "\n")
	var issues []SecurityIssue

	for i, line := range lines {
		lineNum := i + 1

		// ── 1. unsafe package usage ──────────────────────────────────────────
		if unsafeImportRe.MatchString(line) {
			issues = append(issues, SecurityIssue{
				Line:        lineNum,
				Severity:    SeverityHigh,
				Description: `import "unsafe" detected — bypass of Go's type safety; remove unless strictly necessary`,
			})
		}

		// ── 2. Hardcoded credentials ─────────────────────────────────────────
		if m := credentialRe.FindStringSubmatch(line); m != nil {
			issues = append(issues, SecurityIssue{
				Line:        lineNum,
				Severity:    SeverityHigh,
				Description: `hardcoded credential in "` + m[1] + `" — use environment variables or a secrets manager`,
			})
		}
	}

	return SecurityAudit{
		Issues: issues,
		Clean:  len(issues) == 0,
	}
}
