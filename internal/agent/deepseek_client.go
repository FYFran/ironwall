package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DeepSeekClient implements LLMClient for the DeepSeek API (OpenAI-compatible).
// This is self-contained in the agent package to avoid import cycles with the ai package.
type DeepSeekClient struct {
	endpoint   string
	apiKey     string
	model      string
	httpClient *http.Client
}

// NewDeepSeekClient creates a DeepSeek API client.
func NewDeepSeekClient(apiKey, model string) *DeepSeekClient {
	return &DeepSeekClient{
		endpoint: "https://api.deepseek.com/v1",
		apiKey:   apiKey,
		model:    model,
		httpClient: &http.Client{
			Timeout: 300 * time.Second, // R1 reasoning can take 60-180s per call
		},
	}
}

// Chat sends a chat completion request and returns the response text.
func (c *DeepSeekClient) Chat(ctx context.Context, systemPrompt, userMessage string) (string, error) {
	messages := []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userMessage},
	}

	reqBody := struct {
		Model       string `json:"model"`
		Messages    interface{} `json:"messages"`
		MaxTokens   int    `json:"max_tokens,omitempty"`
		Temperature float64 `json:"temperature,omitempty"`
	}{
		Model:       c.model,
		Messages:    messages,
		MaxTokens:   4096,
		Temperature: 0.1,
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
		return "", fmt.Errorf("api call: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("api error %d: %s", resp.StatusCode, truncateForField(string(respBody), 300))
	}

	var chatResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", fmt.Errorf("unmarshal response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}

	return chatResp.Choices[0].Message.Content, nil
}
