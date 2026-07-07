// Command benchmark runs mcpxray's static rule engine (and, if Ollama is
// reachable, the --llm-verify pass) against a fixed list of real public MCP
// servers, to measure the false-positive rate docs/findings-report.md
// reports on. Not part of the shipped mcpxray binary — a one-off/rerunnable
// analysis tool, meant to run inside an isolated container (see
// docs/findings-report.md for the exact invocation), not on a bare host.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ofaruk/mcp-x-ray/internal/llmreview"
	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/rules"
)

type target struct {
	Name    string
	Source  string
	Command string
	Args    []string
	Env     map[string]string
}

var targets = []target{
	{Name: "server-everything", Source: "npm:@modelcontextprotocol/server-everything", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-everything"}},
	{Name: "server-filesystem", Source: "npm:@modelcontextprotocol/server-filesystem", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"}},
	{Name: "server-memory", Source: "npm:@modelcontextprotocol/server-memory", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-memory"}},
	{Name: "server-sequential-thinking", Source: "npm:@modelcontextprotocol/server-sequential-thinking", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-sequential-thinking"}},
	{Name: "server-github", Source: "npm:@modelcontextprotocol/server-github", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-github"}, Env: map[string]string{"GITHUB_PERSONAL_ACCESS_TOKEN": "dummy"}},
	{Name: "mcp-server-fetch", Source: "pypi:mcp-server-fetch", Command: "uvx", Args: []string{"mcp-server-fetch"}},
	{Name: "mcp-server-git", Source: "pypi:mcp-server-git", Command: "uvx", Args: []string{"mcp-server-git"}},
	{Name: "server-puppeteer", Source: "npm:@modelcontextprotocol/server-puppeteer", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-puppeteer"}},
	{Name: "server-brave-search", Source: "npm:@modelcontextprotocol/server-brave-search", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-brave-search"}, Env: map[string]string{"BRAVE_API_KEY": "dummy"}},
	{Name: "server-slack", Source: "npm:@modelcontextprotocol/server-slack", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-slack"}, Env: map[string]string{"SLACK_BOT_TOKEN": "dummy", "SLACK_TEAM_ID": "dummy"}},
}

type findingRecord struct {
	ID         string `json:"id"`
	Severity   string `json:"severity"`
	Tool       string `json:"tool"`
	Detail     string `json:"detail"`
	LLMVerdict string `json:"llm_verdict,omitempty"` // "confirmed" | "dismissed" | ""
	LLMReason  string `json:"llm_reason,omitempty"`
}

type serverResult struct {
	Name      string          `json:"name"`
	Source    string          `json:"source"`
	Error     string          `json:"error,omitempty"`
	ToolCount int             `json:"tool_count"`
	Findings  []findingRecord `json:"findings"`
}

func main() {
	// Ollama runs on the host, not inside the container this script is
	// meant to run in; MCPX_LLM_ENDPOINT lets the caller point at it (e.g.
	// http://host.docker.internal:11434 on Docker Desktop for Mac).
	endpoint := os.Getenv("MCPX_LLM_ENDPOINT")
	if endpoint == "" {
		endpoint = llmreview.DefaultEndpoint
	}
	llmClient := llmreview.New(endpoint, llmreview.DefaultModel)
	llmAvailable := llmClient.Ping(context.Background()) == nil
	fmt.Fprintf(os.Stderr, "llm-verify available: %v\n", llmAvailable)

	var results []serverResult

	for _, tg := range targets {
		fmt.Fprintf(os.Stderr, "scanning %s...\n", tg.Name)
		result := serverResult{Name: tg.Name, Source: tg.Source}

		var env []string
		for k, v := range tg.Env {
			env = append(env, k+"="+v)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		manifest, err := parser.FetchManifest(ctx, parser.Target{Command: tg.Command, Args: tg.Args, Env: env})
		cancel()
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}

		result.ToolCount = len(manifest.Tools)
		findings := rules.Default().Run(manifest)

		verdicts := map[string]llmreview.Verdict{}
		if llmAvailable && len(findings) > 0 {
			verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 120*time.Second)
			for _, f := range findings {
				if !llmreview.Reviewable[f.ID] {
					continue
				}
				text, ok := describedText(manifest, f.Location.Tool)
				if !ok {
					continue
				}
				v, err := llmClient.Review(verifyCtx, f.Title, f.Detail, text)
				if err == nil {
					verdicts[f.ID+"|"+f.Location.Tool] = v
				}
			}
			verifyCancel()
		}

		for _, f := range findings {
			rec := findingRecord{
				ID:       f.ID,
				Severity: string(f.Severity),
				Tool:     f.Location.Tool,
				Detail:   f.Detail,
			}
			if v, ok := verdicts[f.ID+"|"+f.Location.Tool]; ok {
				if v.Confirmed {
					rec.LLMVerdict = "confirmed"
				} else {
					rec.LLMVerdict = "dismissed"
				}
				rec.LLMReason = v.Reason
			}
			result.Findings = append(result.Findings, rec)
		}

		results = append(results, result)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(results)
}

func describedText(m *parser.Manifest, toolName string) (string, bool) {
	for _, t := range m.Tools {
		if t.Name == toolName {
			return t.Description, true
		}
	}
	return "", false
}
