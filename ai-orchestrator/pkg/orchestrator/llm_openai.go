package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	DefaultModel   = "qwen2.5-coder:14b"
	DefaultBaseURL = "http://localhost:11434/v1" // Ollama's OpenAI-compat endpoint
)

// OpenAIBackend implements LLMBackend and TextBackend by talking to any
// OpenAI-compatible /v1/chat/completions endpoint (Ollama, vLLM, llama.cpp, etc.).
// It uses only net/http — no external dependencies.
type OpenAIBackend struct {
	BaseURL    string
	Model      string
	HTTPClient *http.Client
}

// OpenAIOption configures the backend at construction time.
type OpenAIOption func(*OpenAIBackend)

// WithModel overrides the default model tag.
func WithModel(model string) OpenAIOption {
	return func(b *OpenAIBackend) { b.Model = model }
}

// WithBaseURL overrides the API base URL.
func WithBaseURL(url string) OpenAIOption {
	return func(b *OpenAIBackend) { b.BaseURL = url }
}

// NewOpenAIBackend creates a backend that talks to an OpenAI-compatible endpoint.
func NewOpenAIBackend(opts ...OpenAIOption) *OpenAIBackend {
	b := &OpenAIBackend{
		BaseURL: DefaultBaseURL,
		Model:   DefaultModel,
		HTTPClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Complete satisfies LLMBackend. It sends systemPrompt + userPrompt as a chat
// completion request and returns the extracted Go source from the response.
func (b *OpenAIBackend) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	raw, err := b.chatCompletion(ctx, systemPrompt, userPrompt)
	if err != nil {
		return "", err
	}
	return extractGoSource(raw), nil
}

// CompleteText satisfies TextBackend. Same as Complete but returns raw text
// without Go source extraction — used for non-code completions like
// dependency selection.
func (b *OpenAIBackend) CompleteText(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	return b.chatCompletion(ctx, systemPrompt, userPrompt)
}

// ── OpenAI chat completions wire types ──────────────────────────────────────

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// chatCompletion sends a request to the /chat/completions endpoint and returns
// the trimmed response content.
func (b *OpenAIBackend) chatCompletion(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	messages := make([]chatMessage, 0, 2)
	if systemPrompt != "" {
		messages = append(messages, chatMessage{Role: "system", Content: systemPrompt})
	}
	messages = append(messages, chatMessage{Role: "user", Content: userPrompt})

	reqBody := chatRequest{
		Model:       b.Model,
		Messages:    messages,
		Temperature: 0.2,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	url := strings.TrimRight(b.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai completion (%s): %w", b.Model, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai completion (%s): HTTP %d: %s", b.Model, resp.StatusCode, string(respBody))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	if chatResp.Error != nil {
		return "", fmt.Errorf("openai error: %s", chatResp.Error.Message)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("openai completion (%s): empty choices in response", b.Model)
	}

	return strings.TrimSpace(chatResp.Choices[0].Message.Content), nil
}
