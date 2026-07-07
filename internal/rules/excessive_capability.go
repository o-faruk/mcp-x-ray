package rules

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/report"
)

// riskyParamWords are input-schema property name words suggesting a tool
// can execute arbitrary commands/code, not just do the narrow thing its
// description claims. Matched as whole words after tokenizing camelCase/
// snake_case, not as substrings — a naive substring check flags a
// perfectly ordinary "description" property, which contains "script" as a
// literal substring (caught by the Phase 3 public-server benchmark).
var riskyParamWords = map[string]bool{
	"shell": true, "command": true, "cmd": true, "exec": true,
	"execute": true, "script": true, "eval": true, "subprocess": true,
}

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
		for _, word := range tokenizeParamName(key) {
			if riskyParamWords[word] {
				return key, true
			}
		}
	}
	return "", false
}

// tokenizeParamName splits a property name on underscores/hyphens/dots and
// camelCase boundaries into lowercase words, e.g. "shellCommand" and
// "shell_command" both become ["shell", "command"].
func tokenizeParamName(name string) []string {
	var b strings.Builder
	runes := []rune(name)
	for i, r := range runes {
		switch {
		case r == '_' || r == '-' || r == '.':
			b.WriteRune(' ')
		case i > 0 && unicode.IsUpper(r) && (unicode.IsLower(runes[i-1]) || unicode.IsDigit(runes[i-1])):
			b.WriteRune(' ')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return strings.Fields(strings.ToLower(b.String()))
}
