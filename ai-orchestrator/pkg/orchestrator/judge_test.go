package orchestrator_test

import (
	"context"
	"strings"
	"testing"

	"github.com/khakiem/playground/ai-orchestrator/pkg/orchestrator"
)

// ─────────────────────────────────────────────────────────────────────────────
// Security audit (regex fallback, not the main pipeline)
// ─────────────────────────────────────────────────────────────────────────────

func TestSecurityAudit_CleanCode(t *testing.T) {
	audit := orchestrator.RunSecurityAudit(`package main
import "fmt"
func main() { fmt.Println("hello") }
`)
	if !audit.Clean {
		t.Errorf("expected clean, got: %+v", audit.Issues)
	}
}

func TestSecurityAudit_DetectsUnsafeImport_SingleLine(t *testing.T) {
	audit := orchestrator.RunSecurityAudit("package main\nimport \"unsafe\"\nfunc main() {}")
	requireSecIssue(t, audit.Issues, 2, orchestrator.SeverityHigh, "unsafe")
}

func TestSecurityAudit_DetectsUnsafeImport_BlockImport(t *testing.T) {
	code := "package main\nimport (\n\t\"fmt\"\n\t\"unsafe\"\n)\nfunc main() { fmt.Println() }"
	audit := orchestrator.RunSecurityAudit(code)
	requireSecIssue(t, audit.Issues, 4, orchestrator.SeverityHigh, "unsafe")
}

func TestSecurityAudit_DetectsHardcodedPassword(t *testing.T) {
	audit := orchestrator.RunSecurityAudit("package main\n\nconst dbPassword = \"hunter2\"\nfunc main() {}")
	requireSecIssue(t, audit.Issues, 3, orchestrator.SeverityHigh, "hardcoded credential")
}

func TestSecurityAudit_DetectsHardcodedAPIKey(t *testing.T) {
	audit := orchestrator.RunSecurityAudit("package main\n\nvar apiKey = \"AKIAIOSFODNN7EXAMPLE\"\nfunc main() {}")
	requireSecIssue(t, audit.Issues, 3, orchestrator.SeverityHigh, "hardcoded credential")
}

func TestSecurityAudit_DetectsHardcodedSecret(t *testing.T) {
	code := "package main\nfunc connect() string {\n\tsecret := \"mysupersecret\"\n\treturn secret\n}"
	audit := orchestrator.RunSecurityAudit(code)
	requireSecIssue(t, audit.Issues, 3, orchestrator.SeverityHigh, "hardcoded credential")
}

func TestSecurityAudit_DetectsHardcodedToken(t *testing.T) {
	audit := orchestrator.RunSecurityAudit("package main\n\nvar authToken = \"Bearer eyJhbGciOiJIUzI1NiJ9\"\nfunc main() {}")
	requireSecIssue(t, audit.Issues, 3, orchestrator.SeverityHigh, "hardcoded credential")
}

func TestSecurityAudit_MultipleIssues(t *testing.T) {
	code := "package main\nimport \"unsafe\"\nconst password = \"admin123\"\nfunc main() {}"
	audit := orchestrator.RunSecurityAudit(code)
	if len(audit.Issues) < 2 {
		t.Errorf("expected at least 2 issues, got %d: %+v", len(audit.Issues), audit.Issues)
	}
}

func TestSecurityAudit_EmptyStringNotFlagged(t *testing.T) {
	audit := orchestrator.RunSecurityAudit("package main\nvar password = \"\"\nfunc main() {}")
	if !audit.Clean {
		t.Errorf("empty string should not be flagged: %+v", audit.Issues)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CorrectionPrompt builder
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildCorrectionPrompt_ParsesLineAndColumn(t *testing.T) {
	errors := []string{"main.go:5:2: undefined: fmt"}
	cp := orchestrator.BuildCorrectionPrompt("package main\n\nfunc main() {\n\tfmt.Println()\n}\n", errors, nil, nil)

	if len(cp.Annotations) != 1 {
		t.Fatalf("expected 1 annotation, got %d", len(cp.Annotations))
	}
	a := cp.Annotations[0]
	if a.Line != 5 || a.Column != 2 {
		t.Errorf("want line=5 col=2, got line=%d col=%d", a.Line, a.Column)
	}
	if !strings.Contains(a.Message, "undefined") {
		t.Errorf("expected 'undefined' in message, got %q", a.Message)
	}
}

func TestBuildCorrectionPrompt_ParsesRelativePath(t *testing.T) {
	cp := orchestrator.BuildCorrectionPrompt("", []string{"./main.go:3:1: syntax error: unexpected }"}, nil, nil)
	if len(cp.Annotations) != 1 || cp.Annotations[0].Line != 3 {
		t.Errorf("expected annotation at line 3, got %+v", cp.Annotations)
	}
}

func TestBuildCorrectionPrompt_SkipsNonErrorLines(t *testing.T) {
	errors := []string{"# sandbox", "[build failed]", "main.go:2:1: expected 'package', found 'EOF'"}
	cp := orchestrator.BuildCorrectionPrompt("", errors, nil, nil)
	if len(cp.Annotations) != 1 {
		t.Errorf("expected 1 annotation, got %d", len(cp.Annotations))
	}
}

func TestBuildCorrectionPrompt_MultipleErrors(t *testing.T) {
	errors := []string{
		"main.go:3:5: undefined: x",
		"main.go:7:12: cannot use \"str\" (untyped string) as int",
		"main.go:10:1: syntax error: unexpected EOF",
	}
	cp := orchestrator.BuildCorrectionPrompt("", errors, nil, nil)
	if len(cp.Annotations) != 3 {
		t.Errorf("expected 3 annotations, got %d", len(cp.Annotations))
	}
}

func TestBuildCorrectionPrompt_AttachesFindings(t *testing.T) {
	findings := []orchestrator.Finding{
		{Tool: "gosec", File: "main.go", Line: 3, Severity: orchestrator.SeverityHigh, Rule: "G101", Message: "Potential hardcoded credentials"},
	}
	cp := orchestrator.BuildCorrectionPrompt("package main\nfunc main() {}", nil, findings, nil)
	if len(cp.Findings) != 1 {
		t.Fatalf("expected 1 finding attached, got %d", len(cp.Findings))
	}
	if cp.Findings[0].Rule != "G101" {
		t.Errorf("want rule G101, got %q", cp.Findings[0].Rule)
	}
}

func TestCorrectionPrompt_Format_ContainsRequiredSections(t *testing.T) {
	findings := []orchestrator.Finding{
		{Tool: "gosec", Severity: orchestrator.SeverityHigh, Rule: "G101", Message: "Potential hardcoded credentials", File: "main.go", Line: 3},
	}
	cp := orchestrator.BuildCorrectionPrompt("package main\nfunc main() {}", []string{"main.go:2:1: undefined: fmt"}, findings, nil)
	formatted := cp.Format()

	for _, want := range []string{"TOOL FINDINGS", "COMPILER ERRORS", "ANNOTATED SOURCE", "undefined: fmt", "G101"} {
		if !strings.Contains(formatted, want) {
			t.Errorf("formatted prompt missing %q", want)
		}
	}
}

func TestCorrectionPrompt_Format_AnnotatesCorrectLine(t *testing.T) {
	code := "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello\"\n}\n"
	cp := orchestrator.BuildCorrectionPrompt(code, []string{"main.go:6:20: syntax error: unexpected newline"}, nil, nil)
	if !strings.Contains(cp.Format(), "^ col 20") {
		t.Errorf("expected caret annotation '^ col 20' in formatted output:\n%s", cp.Format())
	}
}

func TestCorrectionPrompt_Format_IncludesSnippet(t *testing.T) {
	findings := []orchestrator.Finding{
		{
			Tool: "gosec", File: "main.go", Line: 3, Severity: orchestrator.SeverityHigh,
			Rule: "G101", Message: "hardcoded cred", Snippet: `const apiKey = "SECRET"`,
		},
	}
	cp := orchestrator.BuildCorrectionPrompt("", nil, findings, nil)
	if !strings.Contains(cp.Format(), `const apiKey = "SECRET"`) {
		t.Error("formatted prompt should include the offending snippet from gosec")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// StructuredJudge.Fix — uses RepairRequest
// ─────────────────────────────────────────────────────────────────────────────

func TestStructuredJudge_Fix_BuildsPromptFromRepairRequest(t *testing.T) {
	fixedCode := "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"ok\") }\n"
	llm := &orchestrator.MockLLMBackend{Responses: []string{fixedCode}}
	judge := &orchestrator.StructuredJudge{LLM: llm}

	req := orchestrator.RepairRequest{
		Code:        "package main\nfunc main() {\n\tfmt.Println(\"hi\")\n}\n",
		BuildErrors: []string{"main.go:3:2: undefined: fmt"},
	}

	result, err := judge.Fix(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != fixedCode {
		t.Errorf("want fixed code, got: %q", result)
	}
	prompt := llm.Prompts[0]
	for _, needle := range []string{"ANNOTATED SOURCE", "undefined: fmt", "COMPILER ERRORS"} {
		if !strings.Contains(prompt, needle) {
			t.Errorf("prompt missing %q", needle)
		}
	}
}

func TestStructuredJudge_Fix_IncludesToolFindingsInPrompt(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{Responses: []string{"package main\nfunc main(){}"}}
	judge := &orchestrator.StructuredJudge{LLM: llm}

	req := orchestrator.RepairRequest{
		Code: "package main\nconst password = \"s3cr3t\"\nfunc main() {}",
		Findings: []orchestrator.Finding{
			{
				Tool: "gosec", File: "main.go", Line: 2, Severity: orchestrator.SeverityHigh,
				Rule: "G101", Message: "Potential hardcoded credentials", Snippet: `const password = "s3cr3t"`,
			},
		},
	}
	_, err := judge.Fix(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	prompt := llm.Prompts[0]
	if !strings.Contains(prompt, "TOOL FINDINGS") {
		t.Errorf("prompt should contain TOOL FINDINGS section:\n%s", prompt)
	}
	if !strings.Contains(prompt, "G101") {
		t.Errorf("prompt should include the gosec rule ID:\n%s", prompt)
	}
	if !strings.Contains(prompt, `const password = "s3cr3t"`) {
		t.Errorf("prompt should include the offending snippet:\n%s", prompt)
	}
}

func TestStructuredJudge_Fix_PropagatesLLMError(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{} // no responses → error
	judge := &orchestrator.StructuredJudge{LLM: llm}

	_, err := judge.Fix(context.Background(), orchestrator.RepairRequest{
		Code:        "package main",
		BuildErrors: []string{"main.go:1:1: foo"},
	})
	if err == nil {
		t.Fatal("expected error from exhausted mock backend")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-agent persona separation: DevAgent + AuditorJudge
// ─────────────────────────────────────────────────────────────────────────────

func TestDevAgent_UsesDevSystemPrompt(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{Responses: []string{"package main\nfunc main(){}"}}
	agent := &orchestrator.DevAgent{LLM: llm}

	_, err := agent.GenerateInitialCode(context.Background(), "print hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(llm.SystemPrompts) == 0 {
		t.Fatal("DevAgent should pass a system prompt")
	}
	sys := llm.SystemPrompts[0]
	for _, want := range []string{"Junior", "package main"} {
		if !strings.Contains(sys, want) {
			t.Errorf("dev system prompt missing %q:\n%s", want, sys)
		}
	}
	if strings.Contains(sys, "Auditor") {
		t.Error("dev system prompt should not contain auditor persona")
	}
}

func TestAuditorJudge_UsesAuditorSystemPrompt(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{Responses: []string{"package main\nfunc main(){}"}}
	judge := &orchestrator.AuditorJudge{LLM: llm}

	req := orchestrator.RepairRequest{
		Code:        "package main\nfunc main() {}",
		BuildErrors: []string{"main.go:1:1: undefined: x"},
	}
	_, err := judge.Fix(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(llm.SystemPrompts) == 0 {
		t.Fatal("AuditorJudge should pass a system prompt")
	}
	sys := llm.SystemPrompts[0]
	for _, want := range []string{"Senior", "Auditor"} {
		if !strings.Contains(sys, want) {
			t.Errorf("auditor system prompt missing %q:\n%s", want, sys)
		}
	}
	if strings.Contains(sys, "Junior") {
		t.Error("auditor system prompt should not contain dev persona")
	}
}

func TestAuditorJudge_UserPromptContainsFindings(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{Responses: []string{"package main\nfunc main(){}"}}
	judge := &orchestrator.AuditorJudge{LLM: llm}

	req := orchestrator.RepairRequest{
		Code: "package main\nconst password = \"s3cr3t\"\nfunc main() {}",
		Findings: []orchestrator.Finding{
			{
				Tool: "gosec", File: "main.go", Line: 2, Severity: orchestrator.SeverityHigh,
				Rule: "G101", Message: "hardcoded credential", Snippet: `const password = "s3cr3t"`,
			},
		},
	}
	_, err := judge.Fix(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	userPrompt := llm.Prompts[0]
	for _, want := range []string{"TOOL FINDINGS", "G101", "hardcoded credential", "ANNOTATED SOURCE"} {
		if !strings.Contains(userPrompt, want) {
			t.Errorf("auditor user prompt missing %q", want)
		}
	}
}

func TestDevAgent_UserPromptContainsRequirement(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{Responses: []string{"package main\nfunc main(){}"}}
	agent := &orchestrator.DevAgent{LLM: llm}

	_, err := agent.GenerateInitialCode(context.Background(), "serve HTTP on port 9090")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(llm.Prompts[0], "serve HTTP on port 9090") {
		t.Errorf("user prompt should contain the requirement, got: %q", llm.Prompts[0])
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// History / anti-flip-flop memory
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildCorrectionPrompt_HistoryAppearsInFormat(t *testing.T) {
	history := []orchestrator.Attempt{
		{Number: 1, Code: "package main\nfunc main() {}", BuildErrors: []string{"main.go:1:1: bad"}},
	}
	cp := orchestrator.BuildCorrectionPrompt("package main\nfunc main() {}", nil, nil, history)
	formatted := cp.Format()
	if !strings.Contains(formatted, "ATTEMPT HISTORY") {
		t.Error("formatted prompt missing ATTEMPT HISTORY section")
	}
	if !strings.Contains(formatted, "Attempt 1") {
		t.Error("formatted prompt missing attempt number")
	}
	if !strings.Contains(formatted, "main.go:1:1: bad") {
		t.Error("formatted prompt missing build error from history")
	}
}

func TestBuildCorrectionPrompt_NoHistoryOmitsSection(t *testing.T) {
	cp := orchestrator.BuildCorrectionPrompt("package main\nfunc main() {}", nil, nil, nil)
	if strings.Contains(cp.Format(), "ATTEMPT HISTORY") {
		t.Error("should not include ATTEMPT HISTORY when history is empty")
	}
}

func TestBuildCorrectionPrompt_HistoryCappedAtThree(t *testing.T) {
	var history []orchestrator.Attempt
	for i := 1; i <= 5; i++ {
		history = append(history, orchestrator.Attempt{
			Number:      i,
			Code:        "package main",
			BuildErrors: []string{"err"},
		})
	}
	cp := orchestrator.BuildCorrectionPrompt("package main", nil, nil, history)
	formatted := cp.Format()
	// Only the last 3 attempts should be in the prompt.
	if strings.Contains(formatted, "Attempt 1") || strings.Contains(formatted, "Attempt 2") {
		t.Error("oldest attempts beyond cap of 3 should be excluded from prompt")
	}
	for _, want := range []string{"Attempt 3", "Attempt 4", "Attempt 5"} {
		if !strings.Contains(formatted, want) {
			t.Errorf("expected recent %s in prompt", want)
		}
	}
}

func TestStructuredJudge_Fix_PassesHistoryToPrompt(t *testing.T) {
	llm := &orchestrator.MockLLMBackend{Responses: []string{"package main\nfunc main(){}"}}
	judge := &orchestrator.StructuredJudge{LLM: llm}

	req := orchestrator.RepairRequest{
		Code:        "package main\nfunc main() {}",
		BuildErrors: []string{"main.go:1:1: err"},
		History: []orchestrator.Attempt{
			{Number: 1, Code: "package main", BuildErrors: []string{"main.go:1:1: previous error"}},
		},
	}
	_, err := judge.Fix(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(llm.Prompts[0], "ATTEMPT HISTORY") {
		t.Error("prompt should contain ATTEMPT HISTORY when history is provided")
	}
	if !strings.Contains(llm.Prompts[0], "previous error") {
		t.Error("prompt should contain error message from prior attempt")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Compiler error parser regression table
// ─────────────────────────────────────────────────────────────────────────────

func TestParseErrors_CommonSyntaxErrors(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantMsg string
		wantL   int
		wantC   int
	}{
		{"missing closing paren", "main.go:6:20: syntax error: unexpected newline in argument list; possibly missing comma or )", "syntax error: unexpected newline", 6, 20},
		{"undefined identifier", "main.go:4:2: undefined: fmt", "undefined: fmt", 4, 2},
		{"type mismatch", "main.go:9:14: cannot use 42 (untyped int constant) as string value", "cannot use 42", 9, 14},
		{"declared and not used", "main.go:7:2: x declared and not used", "declared and not used", 7, 2},
		{"missing return", "main.go:12:1: missing return at end of function", "missing return", 12, 1},
		{"unexpected EOF", "main.go:20:1: syntax error: unexpected EOF", "unexpected EOF", 20, 1},
		{"relative path prefix", "./main.go:3:5: syntax error: unexpected }", "syntax error: unexpected }", 3, 5},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := orchestrator.BuildCorrectionPrompt("", []string{tc.raw}, nil, nil)
			if len(cp.Annotations) != 1 {
				t.Fatalf("want 1 annotation, got %d", len(cp.Annotations))
			}
			a := cp.Annotations[0]
			if a.Line != tc.wantL || a.Column != tc.wantC {
				t.Errorf("want line=%d col=%d, got line=%d col=%d", tc.wantL, tc.wantC, a.Line, a.Column)
			}
			if !strings.Contains(a.Message, tc.wantMsg) {
				t.Errorf("want %q in message, got %q", tc.wantMsg, a.Message)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func requireSecIssue(t *testing.T, issues []orchestrator.SecurityIssue, wantLine int, wantSev orchestrator.Severity, wantDesc string) {
	t.Helper()
	for _, iss := range issues {
		if iss.Line == wantLine && iss.Severity == wantSev && strings.Contains(iss.Description, wantDesc) {
			return
		}
	}
	t.Errorf("no issue found with line=%d severity=%s desc~=%q\ngot: %+v", wantLine, wantSev, wantDesc, issues)
}
