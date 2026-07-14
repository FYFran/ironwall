package ai

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

// CostTracker accumulates token usage and computes cost.
type CostTracker struct {
	PromptTokens     int
	CompletionTokens int
	Calls            int
	Errors           int
}

// Add records usage from a single API call.
func (ct *CostTracker) Add(prompt, completion int) {
	ct.PromptTokens += prompt
	ct.CompletionTokens += completion
	ct.Calls++
}

// CostUSD estimates cost in USD using DeepSeek pricing (2026).
func (ct *CostTracker) CostUSD(model string) float64 {
	rates := map[string][2]float64{ // per 1M tokens: [prompt, completion]
		"deepseek-chat":     {0.27, 1.10},
		"deepseek-reasoner": {0.55, 2.19},
	}
	if r, ok := rates[model]; ok {
		return float64(ct.PromptTokens)/1e6*r[0] + float64(ct.CompletionTokens)/1e6*r[1]
	}
	return 0
}

// Summary returns a human-readable summary.
func (ct *CostTracker) Summary(model string) string {
	return fmt.Sprintf("%d calls, %d prompt + %d completion tokens, $%.4f",
		ct.Calls, ct.PromptTokens, ct.CompletionTokens, ct.CostUSD(model))
}

const (
	// DefaultHTTPTimeout is the default HTTP client timeout for AI API calls.
	// Long enough for DeepSeek R1 reasoning (can take 60-180s on complex prompts).
	DefaultHTTPTimeout = 300 * time.Second
	// ShortHTTPTimeout is used for fast API calls (triage/chat models).
	ShortHTTPTimeout = 120 * time.Second
)

// Client is a minimal OpenAI-compatible API client for AI analysis.
type Client struct {
	endpoint   string
	apiKey     string
	model      string
	httpClient *http.Client
	Cost       CostTracker
}

// NewClient creates a new AI client with default timeout (300s).
// endpoint is the API base URL (e.g. "https://api.deepseek.com/v1").
// apiKey is the authentication key.
// model is the model name (e.g. "deepseek-chat", "deepseek-reasoner").
func NewClient(endpoint, apiKey, model string) *Client {
	return NewClientWithTimeout(endpoint, apiKey, model, DefaultHTTPTimeout)
}

// NewOllamaClient creates an AI client for a local Ollama instance.
// Ollama exposes an OpenAI-compatible API at /v1/chat/completions.
// baseURL is the Ollama server URL (e.g. "http://localhost:11434/v1").
// model is the local model name (e.g. "qwen2.5-coder:7b", "llama3.1:8b").
func NewOllamaClient(baseURL, model string) *Client {
	return &Client{
		endpoint: strings.TrimRight(baseURL, "/"),
		apiKey:   "ollama", // Ollama doesn't require auth locally
		model:    model,
		httpClient: &http.Client{
			Timeout: ShortHTTPTimeout, // local models may be slower on CPU
		},
	}
}

// NewClientWithTimeout creates a new AI client with a custom HTTP timeout.
// Use ShortHTTPTimeout (120s) for fast chat models, DefaultHTTPTimeout (300s) for reasoning models.
func NewClientWithTimeout(endpoint, apiKey, model string, timeout time.Duration) *Client {
	return &Client{
		endpoint: strings.TrimRight(endpoint, "/"),
		apiKey:   apiKey,
		model:    model,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// Message represents a chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest is the request body for the chat completions API.
type ChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
}

// ChatResponse is the response from the chat completions API.
type ChatResponse struct {
	ID      string   `json:"id"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

// Choice is a single completion choice.
type Choice struct {
	Index   int     `json:"index"`
	Message Message `json:"message"`
}

// Usage contains token usage statistics.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Chat sends a chat completion request and returns the response text.
func (c *Client) Chat(ctx context.Context, systemPrompt string, userMessage string) (string, error) {
	return c.chatWithTemp(ctx, systemPrompt, userMessage, 0.1, 1024)
}

// ChatWithTemp sends a chat completion with custom temperature and max tokens.
func (c *Client) ChatWithTemp(ctx context.Context, systemPrompt string, userMessage string, temp float64, maxTokens int) (string, error) {
	return c.chatWithTemp(ctx, systemPrompt, userMessage, temp, maxTokens)
}

func (c *Client) chatWithTemp(ctx context.Context, systemPrompt, userMessage string, temp float64, maxTokens int) (string, error) {
	messages := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userMessage},
	}

	reqBody := ChatRequest{
		Model:       c.model,
		Messages:    messages,
		MaxTokens:   maxTokens,
		Temperature: temp,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	url := c.endpoint + "/chat/completions"

	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt)) * time.Second // 1s, 2s, 4s
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(backoff):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return "", fmt.Errorf("create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.apiKey)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("api call failed: %w", err)
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("read response: %w", err)
			continue
		}

		// Retry on rate limit (429) or server error (5xx)
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("api error %d (retry %d): %s", resp.StatusCode, attempt+1, string(respBody[:minInt(len(respBody), 200)]))
			c.Cost.Errors++
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("api error %d: %s", resp.StatusCode, string(respBody))
		}

		// Success — parse response below
		var chatResp ChatResponse
		if err := json.Unmarshal(respBody, &chatResp); err != nil {
			return "", fmt.Errorf("unmarshal response: %w", err)
		}

		c.Cost.Add(chatResp.Usage.PromptTokens, chatResp.Usage.CompletionTokens)

		if len(chatResp.Choices) == 0 {
			return "", fmt.Errorf("no choices in response")
		}

		return chatResp.Choices[0].Message.Content, nil
	}

	return "", fmt.Errorf("all retries exhausted: %w", lastErr)
}

// ChatJSON sends a chat request and unmarshals the response into the given target struct.
// Uses proper JSON unmarshal — not string matching.
func (c *Client) ChatJSON(ctx context.Context, systemPrompt string, userMessage string, target interface{}) error {
	return c.ChatJSONWithMaxTokens(ctx, systemPrompt, userMessage, target, 4096)
}

// ChatJSONWithMaxTokens sends a chat request with custom max_tokens and unmarshals the response.
func (c *Client) ChatJSONWithMaxTokens(ctx context.Context, systemPrompt string, userMessage string, target interface{}, maxTokens int) error {
	response, err := c.chatWithTemp(ctx, systemPrompt, userMessage, 0.1, maxTokens)
	if err != nil {
		return err
	}

	// Extract JSON from response (handle markdown code blocks, embedded JSON)
	jsonStr := extractJSON(response)
	if jsonStr == "" {
		return fmt.Errorf("no JSON found in AI response (len=%d): %s", len(response), truncateStr(response, 300))
	}

	if err := json.Unmarshal([]byte(jsonStr), target); err != nil {
		// Fallback: AI sometimes returns bare array [{...}] instead of {"findings": [...]}
		if strings.HasPrefix(strings.TrimSpace(jsonStr), "[") {
			wrapped := `{"findings":` + jsonStr + `}`
			if err2 := json.Unmarshal([]byte(wrapped), target); err2 == nil {
				return nil
			}
		}
		return fmt.Errorf("unmarshal AI JSON response (len=%d): %w\nJSON: %s", len(jsonStr), err, truncateStr(jsonStr, 500))
	}

	return nil
}

// Available returns true if the client is configured with an API key.
func (c *Client) Available() bool {
	return c.apiKey != ""
}

// Model returns the model name used by this client.
func (c *Client) Model() string {
	return c.model
}

// extractJSON extracts JSON content from an AI response, handling markdown code blocks.
func extractJSON(response string) string {
	response = strings.TrimSpace(response)

	// Strategy 1: Extract from ```json ... ``` block (most common)
	if idx := strings.Index(response, "```json"); idx >= 0 {
		start := idx + len("```json")
		if end := strings.Index(response[start:], "```"); end >= 0 {
			return strings.TrimSpace(response[start : start+end])
		}
	}
	// Strategy 2: ``` ... ``` block (no language tag)
	if idx := strings.Index(response, "```"); idx >= 0 {
		start := idx + len("```")
		if start < len(response) && response[start] == '\n' {
			start++
		}
		if end := strings.Index(response[start:], "```"); end >= 0 {
			return strings.TrimSpace(response[start : start+end])
		}
		// Single backtick: response starts with ```, use findMatchingJSON after it
		return findMatchingJSON(response, start)
	}

	// Strategy 3: Find first { or [ and use bracket matching (handles embedded JSON)
	for i, ch := range response {
		if ch == '{' || ch == '[' {
			result := findMatchingJSON(response, i)
			if result != "" {
				return result
			}
		}
	}

	// Strategy 4: Clean JSON that starts and ends with brackets
	if (strings.HasPrefix(response, "{") || strings.HasPrefix(response, "[")) &&
		(strings.HasSuffix(response, "}") || strings.HasSuffix(response, "]")) {
		return response
	}

	return ""
}

// findMatchingJSON finds the matching closing bracket from start index.
func findMatchingJSON(s string, start int) string {
	if start >= len(s) {
		return ""
	}
	open := s[start]
	var close byte
	if open == '{' {
		close = '}'
	} else {
		close = ']'
	}

	depth := 0
	inString := false
	escaped := false

	for i := start; i < len(s); i++ {
		ch := s[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && inString {
			escaped = true
			continue
		}
		if ch == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		if ch == open {
			depth++
		} else if ch == close {
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
