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
// extractGoSource (defined in structured_judge.go) strips any prose preamble
// or markdown fences the instruct model may prepend.
func (b *CodeLlamaBackend) Complete(ctx context.Context, prompt string) (string, error) {
	response, err := b.llm.Call(ctx, prompt)
	if err != nil {
		return "", fmt.Errorf("codellama completion: %w", err)
	}
	return extractGoSource(strings.TrimSpace(response)), nil
}
