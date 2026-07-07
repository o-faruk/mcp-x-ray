package llmreview

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	DefaultModel    = "qwen2.5-coder:14b"
	DefaultEndpoint = "http://localhost:11434"
)

// Client talks to a local Ollama instance.
type Client struct {
	endpoint string
	model    string
	http     *http.Client
}

func New(endpoint, model string) *Client {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	if model == "" {
		model = DefaultModel
	}
	return &Client{endpoint: endpoint, model: model, http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) Model() string { return c.model }

// Verdict is the model's judgment on one flagged finding.
type Verdict struct {
	Confirmed bool
	Reason    string
}

type generateOptions struct {
	// Verdicts feed directly into which findings get dropped from a
	// security report, so decoding is pinned to near-deterministic rather
	// than left at Ollama's sampling defaults.
	Temperature float64 `json:"temperature"`
	Seed        int     `json:"seed"`
}

type generateRequest struct {
	Model   string          `json:"model"`
	Prompt  string          `json:"prompt"`
	Stream  bool            `json:"stream"`
	Format  string          `json:"format"`
	Options generateOptions `json:"options"`
}

type generateResponse struct {
	Response string `json:"response"`
}

type verdictJSON struct {
	Confirmed bool   `json:"confirmed"`
	Reason    string `json:"reason"`
}

// Review asks the model to judge one flagged finding. title/detail are the
// rule's own output; untrustedText is the exact tool/prompt/resource
// description that triggered it — attacker-controlled, and treated as such
// in the prompt (see package doc).
func (c *Client) Review(ctx context.Context, title, detail, untrustedText string) (Verdict, error) {
	body, err := json.Marshal(generateRequest{
		Model:   c.model,
		Prompt:  buildPrompt(title, detail, untrustedText),
		Stream:  false,
		Format:  "json",
		Options: generateOptions{Temperature: 0, Seed: 42},
	})
	if err != nil {
		return Verdict{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return Verdict{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return Verdict{}, fmt.Errorf("calling ollama: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Verdict{}, fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	var gr generateResponse
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return Verdict{}, fmt.Errorf("decoding ollama response: %w", err)
	}

	var v verdictJSON
	if err := json.Unmarshal([]byte(gr.Response), &v); err != nil {
		return Verdict{}, fmt.Errorf("parsing model verdict %q: %w", gr.Response, err)
	}

	return Verdict{Confirmed: v.Confirmed, Reason: v.Reason}, nil
}

// Ping checks the Ollama endpoint is reachable, so callers can skip
// verification up front rather than timing out on every finding.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/api/tags", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}
	return nil
}
