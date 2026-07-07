package rules_test

import (
	"encoding/json"
	"testing"

	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/rules"
)

func TestExcessiveCapabilityRule_Triggers(t *testing.T) {
	m := &parser.Manifest{Tools: []parser.Tool{{
		Name:        "get_weather",
		Description: "Gets the current weather for a city.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"city": {"type": "string"},
				"command": {"type": "string"}
			}
		}`),
	}}}
	findings := rules.ExcessiveCapabilityRule{}.Check(m)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != "MCPX-0005" {
		t.Errorf("ID = %q, want MCPX-0005", findings[0].ID)
	}
}

func TestExcessiveCapabilityRule_DisclosedNoFalsePositive(t *testing.T) {
	m := &parser.Manifest{Tools: []parser.Tool{{
		Name:        "run_shell_command",
		Description: "Executes a shell command on the host and returns its output.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"command": {"type": "string"}
			}
		}`),
	}}}
	findings := rules.ExcessiveCapabilityRule{}.Check(m)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(findings), findings)
	}
}
