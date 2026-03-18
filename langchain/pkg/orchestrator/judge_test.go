package orchestrator_test

import (
	"context"
	"strings"
	"testing"

	"github.com/khakiem/playground/langchain/pkg/orchestrator"
)

// ─────────────────────────────────────────────────────────────────────────────
// Security audit
// ─────────────────────────────────────────────────────────────────────────────

func TestSecurityAudit_CleanCode(t *testing.T) {
	code := `package main

import "fmt"

func main() {
	fmt.Println("hello")
}
`
	audit := orchestrator.RunSecurityAudit(code)
	if !audit.Clean {
		t.Errorf("expected clean audit, got issues: %+v", audit.Issues)
	}
}

func TestSecurityAudit_DetectsUnsafeImport_SingleLine(t *testing.T) {
	code := `package main

import "unsafe"

func main() {}
`
	audit := orchestrator.RunSecurityAudit(code)
	requireIssue(t, audit.Issues, 3, orchestrator.SeverityHigh, "unsafe")
}

func TestSecurityAudit_DetectsUnsafeImport_BlockImport(t *testing.T) {
	code := `package main

import (
	"fmt"
	"unsafe"
)

func main() { fmt.Println("x") }
`
	audit := orchestrator.RunSecurityAudit(code)
	requireIssue(t, audit.Issues, 5, orchestrator.SeverityHigh, "unsafe")
}

func TestSecurityAudit_DetectsHardcodedPassword(t *testing.T) {
	code := `package main

const dbPassword = "hunter2"

func main() {}
`
	audit := orchestrator.RunSecurityAudit(code)
	requireIssue(t, audit.Issues, 3, orchestrator.SeverityHigh, "hardcoded credential")
}

func TestSecurityAudit_DetectsHardcodedAPIKey(t *testing.T) {
	code := `package main

var apiKey = "AKIAIOSFODNN7EXAMPLE"

func main() {}
`
	audit := orchestrator.RunSecurityAudit(code)
	requireIssue(t, audit.Issues, 3, orchestrator.SeverityHigh, "hardcoded credential")
}

func TestSecurityAudit_DetectsHardcodedSecret(t *testing.T) {
	code := `package main

func connect() string {
	secret := "mysupersecret"
	return secret
}
`
	audit := orchestrator.RunSecurityAudit(code)
	requireIssue(t, audit.Issues, 4, orchestrator.SeverityHigh, "hardcoded credential")
}

func TestSecurityAudit_DetectsHardcodedToken(t *testing.T) {
	code := `package main

var authToken = "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"

func main() {}
`
	audit := orchestrator.RunSecurityAudit(code)
	requireIssue(t, audit.Issues, 3, orchestrator.SeverityHigh, "hardcoded credential")
}

func TestSecurityAudit_MultipleIssues(t *testing.T) {
	code := `package main

import "unsafe"

const password = "admin123"

func main() {}
`
	audit := orchestrator.RunSecurityAudit(code)
	if len(audit.Issues) < 2 {
		t.Errorf("expected at least 2 issues, got %d: %+v", len(audit.Issues), audit.Issues)
	}
}

func TestSecurityAudit_EmptyStringNotFlagged(t *testing.T) {
	// Short/empty strings should not trigger the credential detector.
	code := `package main

var password = ""

func main() {}
`
	audit := orchestrator.RunSecurityAudit(code)
	if !audit.Clean {
		t.Errorf("empty string should not be flagged, got: %+v", audit.Issues)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Correction prompt / error parsing
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildCorrectionPrompt_ParsesLineAndColumn(t *testing.T) {
	errors := []string{
		"main.go:5:2: undefined: fmt",
	}
	code := "package main\n\nfunc main() {\n\tfmt.Println()\n}\n"

	cp := orchestrator.BuildCorrectionPrompt(code, errors, nil)

	if len(cp.Annotations) != 1 {
		t.Fatalf("expected 1 annotation, got %d", len(cp.Annotations))
	}
	a := cp.Annotations[0]
	if a.Line != 5 {
		t.Errorf("want line 5, got %d", a.Line)
	}
	if a.Column != 2 {
		t.Errorf("want col 2, got %d", a.Column)
	}
	if !strings.Contains(a.Message, "undefined") {
		t.Errorf("expected 'undefined' in message, got %q", a.Message)
	}
}

func TestBuildCorrectionPrompt_ParsesRelativePath(t *testing.T) {
	errors := []string{"./main.go:3:1: syntax error: unexpected }"}
	cp := orchestrator.BuildCorrectionPrompt("", errors, nil)
	if len(cp.Annotations) != 1 {
		t.Fatalf("expected 1 annotation, got %d", len(cp.Annotations))
	}
	if cp.Annotations[0].Line != 3 {
		t.Errorf("want line 3, got %d", cp.Annotations[0].Line)
	}
}

func TestBuildCorrectionPrompt_SkipsNonErrorLines(t *testing.T) {
	errors := []string{
		"# sandbox",        // package header line
		"[build failed]",   // summary line
		"main.go:2:1: expected 'package', found 'EOF'",
	}
	cp := orchestrator.BuildCorrectionPrompt("", errors, nil)
	if len(cp.Annotations) != 1 {
		t.Errorf("expected only 1 parsed annotation, got %d", len(cp.Annotations))
	}
}

func TestBuildCorrectionPrompt_MultipleErrors(t *testing.T) {
	errors := []string{
		"main.go:3:5: undefined: x",
		"main.go:7:12: cannot use \"str\" (untyped string) as int",
		"main.go:10:1: syntax error: unexpected EOF",
	}
	cp := orchestrator.BuildCorrectionPrompt("", errors, nil)
	if len(cp.Annotations) != 3 {
		t.Errorf("expected 3 annotations, got %d", len(cp.Annotations))
	}
}

func TestCorrectionPrompt_Format_ContainsRequiredSections(t *testing.T) {
	errors := []string{"main.go:2:1: undefined: fmt"}
	issues := []orchestrator.SecurityIssue{
		{Line: 3, Severity: orchestrator.SeverityHigh, Description: `import "unsafe" detected`},
	}
	code := "package main\n\nfunc main() {}\n"
	cp := orchestrator.BuildCorrectionPrompt(code, errors, issues)
	formatted := cp.Format()

	for _, want := range []string{
		"SECURITY ISSUES",
		"COMPILER ERRORS",
		"ANNOTATED SOURCE",
		"undefined: fmt",
		`import "unsafe"`,
	} {
		if !strings.Contains(formatted, want) {
			t.Errorf("formatted prompt missing expected section/content %q", want)
		}
	}
}

func TestCorrectionPrompt_Format_AnnotatesCorrectLine(t *testing.T) {
	code := "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello\"\n}\n"
	errors := []string{"main.go:6:20: syntax error: unexpected newline in argument list"}
	cp := orchestrator.BuildCorrectionPrompt(code, errors, nil)
	formatted := cp.Format()

	// The caret marker for the error must appear after line 6 in the output.
	if !strings.Contains(formatted, "^ col 20") {
		t.Errorf("expected caret annotation '^ col 20' in formatted output:\n%s", formatted)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// StructuredJudge end-to-end
// ─────────────────────────────────────────────────────────────────────────────

func TestStructuredJudge_Fix_CallsLLMWithFormattedPrompt(t *testing.T) {
	fixedCode := "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"ok\") }\n"
	llm := &orchestrator.MockLLMBackend{Responses: []string{fixedCode}}
	judge := &orchestrator.StructuredJudge{LLM: llm}

	brokenCode := "package main\n\nfunc main() {\n\tfmt.Println(\"hi\")\n}\n"
	errors := []string{"main.go:4:2: undefined: fmt"}

	result, err := judge.Fix(context.Background(), brokenCode, errors)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != fixedCode {
		t.Errorf("want fixed code back, got: %q", result)
	}
	if len(llm.Prompts) != 1 {
		t.Fatalf("expected 1 LLM call, got %d", len(llm.Prompts))
	}
	prompt := llm.Prompts[0]
	// Prompt must contain the annotated source section and the raw error.
	for _, needle := range []string{"ANNOTATED SOURCE", "undefined: fmt", "COMPILER ERRORS"} {
		if !strings.Contains(prompt, needle) {
			t.Errorf("prompt missing %q", needle)
		}
	}
}

func TestStructuredJudge_Fix_IncludesSecurityIssuesInPrompt(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{Responses: []string{"package main\nfunc main(){}"}}
	judge := &orchestrator.StructuredJudge{LLM: llm}

	codeWithCred := "package main\n\nconst password = \"s3cr3t\"\n\nfunc main() {}\n"
	_, err := judge.Fix(context.Background(), codeWithCred, []string{"main.go:5:1: unexpected EOF"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	prompt := llm.Prompts[0]
	if !strings.Contains(prompt, "SECURITY ISSUES") {
		t.Errorf("prompt should surface security issues when audit finds problems:\n%s", prompt)
	}
	if !strings.Contains(prompt, "hardcoded credential") {
		t.Errorf("prompt should name the credential issue:\n%s", prompt)
	}
}

func TestStructuredJudge_Fix_PropagatesLLMError(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{} // no responses → returns error
	judge := &orchestrator.StructuredJudge{LLM: llm}

	_, err := judge.Fix(context.Background(), "package main", []string{"main.go:1:1: foo"})
	if err == nil {
		t.Fatal("expected error from exhausted mock backend, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Common Go syntax errors — parser regression table
// ─────────────────────────────────────────────────────────────────────────────

func TestParseErrors_CommonSyntaxErrors(t *testing.T) {
	// Each entry is a raw compiler line we want to successfully parse.
	cases := []struct {
		name    string
		raw     string
		wantMsg string
		wantL   int
		wantC   int
	}{
		{
			name:    "missing closing paren",
			raw:     "main.go:6:20: syntax error: unexpected newline in argument list; possibly missing comma or )",
			wantMsg: "syntax error: unexpected newline",
			wantL:   6, wantC: 20,
		},
		{
			name:    "undefined identifier",
			raw:     "main.go:4:2: undefined: fmt",
			wantMsg: "undefined: fmt",
			wantL:   4, wantC: 2,
		},
		{
			name:    "type mismatch",
			raw:     "main.go:9:14: cannot use 42 (untyped int constant) as string value",
			wantMsg: "cannot use 42",
			wantL:   9, wantC: 14,
		},
		{
			name:    "declared and not used",
			raw:     "main.go:7:2: x declared and not used",
			wantMsg: "declared and not used",
			wantL:   7, wantC: 2,
		},
		{
			name:    "missing return statement",
			raw:     "main.go:12:1: missing return at end of function",
			wantMsg: "missing return",
			wantL:   12, wantC: 1,
		},
		{
			name:    "unexpected EOF",
			raw:     "main.go:20:1: syntax error: unexpected EOF",
			wantMsg: "unexpected EOF",
			wantL:   20, wantC: 1,
		},
		{
			name:    "relative path prefix",
			raw:     "./main.go:3:5: syntax error: unexpected }",
			wantMsg: "syntax error: unexpected }",
			wantL:   3, wantC: 5,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := orchestrator.BuildCorrectionPrompt("", []string{tc.raw}, nil)
			if len(cp.Annotations) != 1 {
				t.Fatalf("want 1 annotation, got %d", len(cp.Annotations))
			}
			a := cp.Annotations[0]
			if a.Line != tc.wantL {
				t.Errorf("line: want %d, got %d", tc.wantL, a.Line)
			}
			if a.Column != tc.wantC {
				t.Errorf("col: want %d, got %d", tc.wantC, a.Column)
			}
			if !strings.Contains(a.Message, tc.wantMsg) {
				t.Errorf("message: want %q in %q", tc.wantMsg, a.Message)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func requireIssue(t *testing.T, issues []orchestrator.SecurityIssue, wantLine int, wantSev orchestrator.Severity, wantDesc string) {
	t.Helper()
	for _, iss := range issues {
		if iss.Line == wantLine && iss.Severity == wantSev && strings.Contains(iss.Description, wantDesc) {
			return
		}
	}
	t.Errorf("no issue found with line=%d severity=%s desc~=%q\ngot: %+v", wantLine, wantSev, wantDesc, issues)
}
