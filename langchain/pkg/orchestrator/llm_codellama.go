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

// CompleteText satisfies TextBackend.  Returns the raw trimmed response without
// extracting Go source — used when the expected output is plain text (e.g.
// a list of module paths from the dependency selector).
func (b *CodeLlamaBackend) CompleteText(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	response, err := b.llm.Call(ctx, formatLlamaPrompt(systemPrompt, userPrompt))
	if err != nil {
		return "", fmt.Errorf("codellama text completion: %w", err)
	}
	return strings.TrimSpace(response), nil
}

// Complete sends systemPrompt + userPrompt to CodeLlama and returns clean Go source.
// The two turns are combined using the Llama instruct template so the model
// treats the system text as a persistent persona rather than part of the task.
// extractGoSource (defined in structured_judge.go) strips any prose preamble
// or markdown fences the instruct model may prepend.
func (b *CodeLlamaBackend) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	response, err := b.llm.Call(ctx, formatLlamaPrompt(systemPrompt, userPrompt))
	if err != nil {
		return "", fmt.Errorf("codellama completion: %w", err)
	}
	return extractGoSource(strings.TrimSpace(response)), nil
}

// formatLlamaPrompt combines system + user text using the CodeLlama instruct
// template.  When no system prompt is provided the [INST] wrapper is still
// applied so the model stays in instruction-following mode.
func formatLlamaPrompt(system, user string) string {
	if system == "" {
		return "[INST] " + user + " [/INST]"
	}
	return "[INST] <<SYS>>\n" + system + "\n<</SYS>>\n\n" + user + " [/INST]"
}
