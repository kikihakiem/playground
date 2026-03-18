package orchestrator

import (
	"context"
	"fmt"
	"strings"
)

// ApprovedDep is one pre-vetted external dependency the DevAgent may import.
// Every field is required — the Module + Version pair goes into go.mod, and
// Desc is injected into the enriched requirement so the LLM knows what the
// package provides without having to guess the import path.
type ApprovedDep struct {
	Name    string // human label, e.g. "Google UUID"
	Module  string // Go module path (= import path), e.g. "github.com/google/uuid"
	Version string // pinned semver tag, e.g. "v1.6.0"
	Desc    string // one-line description for LLM prompts
}

// DependencyApprover selects the subset of pre-vetted packages relevant for
// a given requirement.  Called once per RunFromRequirement, before generation.
type DependencyApprover interface {
	ApproveDeps(ctx context.Context, requirement string) ([]ApprovedDep, error)
}

// TextBackend is a narrow LLM interface for non-code completions.
// Unlike LLMBackend, it returns the raw trimmed response without stripping
// preamble or extracting Go source — necessary when the expected output is
// plain text (e.g. a list of module paths).
type TextBackend interface {
	CompleteText(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}

// ── AllowlistApprover ─────────────────────────────────────────────────────────

// AllowlistApprover always returns its full Allowlist.
// No LLM is involved — every dep in the list is pre-approved for any
// requirement.  Use this when the caller has already curated the list for the
// specific task, or when you want the DevAgent to decide which deps to use.
type AllowlistApprover struct {
	Allowlist []ApprovedDep
}

func (a *AllowlistApprover) ApproveDeps(_ context.Context, _ string) ([]ApprovedDep, error) {
	return a.Allowlist, nil
}

// ── LLMDependencyAgent ────────────────────────────────────────────────────────

// LLMDependencyAgent uses an LLM to select the relevant subset of Allowlist
// for a given requirement.  The safety gate is parseDepResponse: the LLM can
// only select packages that are in the Allowlist — hallucinated module paths
// are silently dropped.
type LLMDependencyAgent struct {
	LLM       TextBackend
	Allowlist []ApprovedDep
}

const depSelectorSystemPrompt = `You are a Go dependency selector.
You receive a requirement and a numbered list of approved packages.
Rules:
- Output ONLY the module paths of relevant packages, one per line.
- Do NOT output numbers, explanations, blank lines, or punctuation.
- If no packages are needed, output exactly: NONE
- Do NOT invent module paths that are not in the approved list.`

func (a *LLMDependencyAgent) ApproveDeps(ctx context.Context, requirement string) ([]ApprovedDep, error) {
	userPrompt := buildDepSelectionPrompt(requirement, a.Allowlist)
	raw, err := a.LLM.CompleteText(ctx, depSelectorSystemPrompt, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("llm dependency agent: %w", err)
	}
	return parseDepResponse(raw, a.Allowlist), nil
}

func buildDepSelectionPrompt(requirement string, allowlist []ApprovedDep) string {
	var b strings.Builder
	b.WriteString("REQUIREMENT:\n")
	b.WriteString(requirement)
	b.WriteString("\n\nAPPROVED PACKAGES:\n")
	for i, d := range allowlist {
		b.WriteString(fmt.Sprintf("%d. %s — %s\n", i+1, d.Module, d.Desc))
	}
	b.WriteString("\nOutput the module paths of packages relevant to this requirement, one per line, or NONE:\n")
	return b.String()
}

// parseDepResponse extracts approved deps from a raw LLM response.
// Only module paths present in the allowlist are returned — the allowlist is
// the trust boundary; hallucinated paths are silently dropped.
func parseDepResponse(raw string, allowlist []ApprovedDep) []ApprovedDep {
	allowed := make(map[string]ApprovedDep, len(allowlist))
	for _, d := range allowlist {
		allowed[d.Module] = d
	}

	var result []ApprovedDep
	seen := make(map[string]bool)

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.EqualFold(line, "none") {
			continue
		}
		// Strip a leading "N. " prefix the model may emit despite instructions.
		if idx := strings.Index(line, ". "); idx >= 0 && idx < 4 {
			line = strings.TrimSpace(line[idx+2:])
		}
		// Strip trailing punctuation.
		line = strings.TrimRight(line, ".,;:")
		if d, ok := allowed[line]; ok && !seen[line] {
			result = append(result, d)
			seen[line] = true
		}
	}
	return result
}

// ── MockDependencyApprover ────────────────────────────────────────────────────

// MockDependencyApprover is a deterministic test double for DependencyApprover.
type MockDependencyApprover struct {
	Deps  []ApprovedDep
	Err   error
	Calls []string // requirements passed to ApproveDeps
}

func (m *MockDependencyApprover) ApproveDeps(_ context.Context, req string) ([]ApprovedDep, error) {
	m.Calls = append(m.Calls, req)
	if m.Err != nil {
		return nil, m.Err
	}
	return m.Deps, nil
}

// ── Prompt helpers ────────────────────────────────────────────────────────────

// EnrichRequirement appends dep import hints to the requirement string so the
// DevAgent knows which external packages it may use and their exact import paths.
func EnrichRequirement(requirement string, deps []ApprovedDep) string {
	if len(deps) == 0 {
		return requirement
	}
	var b strings.Builder
	b.WriteString(requirement)
	b.WriteString("\n\nApproved external packages (use these import paths exactly — do not invent others):\n")
	for _, d := range deps {
		b.WriteString(fmt.Sprintf("  import %q  // %s\n", d.Module, d.Desc))
	}
	return b.String()
}

// BuildGoMod returns the contents of a go.mod file for the sandbox module,
// including a require block for any approved external deps.
func BuildGoMod(deps []ApprovedDep) string {
	var b strings.Builder
	b.WriteString("module sandbox\n\ngo 1.25\n")
	if len(deps) > 0 {
		b.WriteString("\nrequire (\n")
		for _, d := range deps {
			b.WriteString(fmt.Sprintf("\t%s %s\n", d.Module, d.Version))
		}
		b.WriteString(")\n")
	}
	return b.String()
}
