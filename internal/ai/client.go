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

// Client is a minimal OpenAI-compatible API client for AI analysis.
type Client struct {
	endpoint   string
	apiKey     string
	model      string
	httpClient *http.Client
}

// NewClient creates a new AI client.
// endpoint is the API base URL (e.g. "https://api.deepseek.com/v1").
// apiKey is the authentication key.
// model is the model name (e.g. "deepseek-chat").
func NewClient(endpoint, apiKey, model string) *Client {
	return &Client{
		endpoint: strings.TrimRight(endpoint, "/"),
		apiKey:   apiKey,
		model:    model,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// Message represents a chat message.
type Message struct {
	Role    string `json:"role"`    // "system", "user", or "assistant"
	Content string `json:"content"` // The message text
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
	messages := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userMessage},
	}

	reqBody := ChatRequest{
		Model:       c.model,
		Messages:    messages,
		MaxTokens:   1024,
		Temperature: 0.1, // Low temperature for deterministic security analysis
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	url := c.endpoint + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("api call failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("api error %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp ChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}

	return chatResp.Choices[0].Message.Content, nil
}

// Available returns true if the client is configured with an API key.
func (c *Client) Available() bool {
	return c.apiKey != ""
}
