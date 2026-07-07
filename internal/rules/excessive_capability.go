package rules

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/report"
)

// riskyParamSubstrings are input-schema property names suggesting a tool
// can execute arbitrary commands/code, not just do the narrow thing its
// description claims.
var riskyParamSubstrings = []string{"shell", "command", "cmd", "exec", "script", "eval", "subprocess"}

// ExcessiveCapabilityRule flags tools whose input schema accepts a
// shell/command/script-shaped parameter that their description gives no
// hint of — i.e. the declared capability (per the description) is
// narrower than the actual capability (per the schema).
type ExcessiveCapabilityRule struct{}

func (ExcessiveCapabilityRule) ID() string { return "MCPX-0005" }

func (rule ExcessiveCapabilityRule) Check(m *parser.Manifest) []report.Finding {
	var findings []report.Finding
	for _, t := range m.Tools {
		key, ok := riskyParam(t.InputSchema)
		if !ok || DisclosesShellExecution(t.Description) {
			continue
		}
		findings = append(findings, report.Finding{
			ID:       rule.ID(),
			Pass:     report.PassStatic,
			Severity: report.SeverityHigh,
			OwaspASI: report.ASI03,
			Title:    "undisclosed command/shell-execution parameter",
			Detail:   fmt.Sprintf("tool %q accepts a %q parameter suggesting shell/command execution, but its description gives no indication of that capability", t.Name, key),
			Location: report.Location{Tool: t.Name, Field: "inputSchema"},
		})
	}
	return findings
}

func riskyParam(schema json.RawMessage) (string, bool) {
	if len(schema) == 0 {
		return "", false
	}
	var parsed struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schema, &parsed); err != nil {
		return "", false
	}
	for key := range parsed.Properties {
		lower := strings.ToLower(key)
		for _, sub := range riskyParamSubstrings {
			if strings.Contains(lower, sub) {
				return key, true
			}
		}
	}
	return "", false
}
