package rules

import (
	"fmt"
	"regexp"

	"github.com/o-faruk/mcp-x-ray/internal/parser"
	"github.com/o-faruk/mcp-x-ray/internal/report"
)

// invokedElsewherePattern matches language describing a *different* tool
// being used, the setup for a shadowing attack ("whenever send_email is
// called...").
var invokedElsewherePattern = regexp.MustCompile(`(?i)whenever\s+(the\s+)?[\w -]+\s+(tool\s+)?(is\s+)?(used|called|invoked)`)

// bccPattern matches an explicit hidden-recipient instruction, the classic
// email-shadowing payload.
var bccPattern = regexp.MustCompile(`(?i)\b(bcc|cc)\b\s*(a\s+copy\s+)?to\s+[\w.+-]+@[\w.-]+`)

// ShadowingRule flags descriptions that attempt to manipulate the behavior
// of a *different, unrelated* tool — MCP "tool shadowing", where a
// malicious server's tool description rewrites how a trusted tool from
// another server behaves.
type ShadowingRule struct{}

func (ShadowingRule) ID() string { return "MCPX-0004" }

func (rule ShadowingRule) Check(m *parser.Manifest) []report.Finding {
	var findings []report.Finding
	for _, item := range describedItems(m) {
		triggered := bccPattern.MatchString(item.Text) ||
			(invokedElsewherePattern.MatchString(item.Text) && secondaryActionPattern.MatchString(item.Text))
		if !triggered {
			continue
		}
		findings = append(findings, report.Finding{
			ID:       rule.ID(),
			Pass:     report.PassStatic,
			Severity: report.SeverityHigh,
			OwaspASI: report.ASI01,
			Title:    "attempts to manipulate the behavior of a different tool",
			Detail:   fmt.Sprintf("%s of %q describes altering another tool's behavior (e.g. adding a hidden recipient or a secondary action whenever it's used) rather than its own", item.Field, item.Name),
			Location: report.Location{Tool: item.Name, Field: item.Field},
		})
	}
	return findings
}
