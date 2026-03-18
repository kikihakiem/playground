package orchestrator

import (
	"context"
	"fmt"
	"strings"

	"github.com/tmc/langchaingo/llms/ollama"
)

const (
	DefaultModel     = "codellama:7b-instruct"
	DefaultServerURL = "http://localhost:11434"
)

// CodeLlamaBackend implements LLMBackend using a local CodeLlama model via
// Ollama.  It satisfies LLMBackend so it can be dropped directly into
// StructuredJudge without any other changes.
type CodeLlamaBackend struct {
	llm *ollama.LLM
}

// CodeLlamaOption configures the backend at construction time.
type CodeLlamaOption func(*codeLlamaConfig)

type codeLlamaConfig struct {
	model     string
	serverURL string
}

// WithCodeLlamaModel overrides the default model tag (e.g. "codellama:13b").
func WithCodeLlamaModel(model string) CodeLlamaOption {
	return func(c *codeLlamaConfig) { c.model = model }
}

// WithCodeLlamaServerURL overrides the Ollama server URL.
func WithCodeLlamaServerURL(url string) CodeLlamaOption {
	return func(c *codeLlamaConfig) { c.serverURL = url }
}

// NewCodeLlamaBackend creates and validates a CodeLlamaBackend.
// It returns an error if the Ollama server is unreachable or if the model
// is not available locally (run `ollama pull codellama:7b-instruct` first).
func NewCodeLlamaBackend(opts ...CodeLlamaOption) (*CodeLlamaBackend, error) {
	cfg := &codeLlamaConfig{
		model:     DefaultModel,
		serverURL: DefaultServerURL,
	}
	for _, o := range opts {
		o(cfg)
	}

	llm, err := ollama.New(
		ollama.WithModel(cfg.model),
		ollama.WithServerURL(cfg.serverURL),
		// Keep the model resident between calls so the orchestrator loop
		// doesn't pay a cold-start penalty on every retry.
		ollama.WithKeepAlive("10m"),
	)
	if err != nil {
		return nil, fmt.Errorf("create ollama client (model=%s, server=%s): %w",
			cfg.model, cfg.serverURL, err)
	}

	return &CodeLlamaBackend{llm: llm}, nil
}

// Complete sends the prompt to CodeLlama and returns clean Go source.
// Instruct-tuned models often wrap the answer in prose or markdown fences;
// extractGoSource strips that noise before returning.
func (b *CodeLlamaBackend) Complete(ctx context.Context, prompt string) (string, error) {
	response, err := b.llm.Call(ctx, prompt)
	if err != nil {
		return "", fmt.Errorf("codellama completion: %w", err)
	}
	return extractGoSource(strings.TrimSpace(response)), nil
}

// extractGoSource pulls the raw Go source out of a model response that may
// contain markdown fences, explanatory prose, or both.
//
// Priority:
//  1. Content inside a ```go ... ``` or ``` ... ``` fence.
//  2. Everything from the first "package " line onward (handles prose preamble).
//  3. The raw response as-is (last resort — lets the build step surface the error).
func extractGoSource(s string) string {
	// ── 1. Markdown fences ───────────────────────────────────────────────────
	// Strip optional "go" language tag after the opening fence.
	if start := strings.Index(s, "```"); start != -1 {
		inner := s[start+3:]
		// Skip the language tag line (e.g. "go\n")
		if nl := strings.Index(inner, "\n"); nl != -1 {
			inner = inner[nl+1:]
		}
		if end := strings.Index(inner, "```"); end != -1 {
			return strings.TrimSpace(inner[:end])
		}
	}

	// ── 2. Prose preamble before "package" ───────────────────────────────────
	if idx := strings.Index(s, "package "); idx != -1 {
		return strings.TrimSpace(s[idx:])
	}

	// ── 3. Return as-is ──────────────────────────────────────────────────────
	return s
}
