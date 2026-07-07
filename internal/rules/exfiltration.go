package rules

import (
	"fmt"
	"regexp"

	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/report"
)

// urlOrIPPattern matches a hardcoded URL or bare IP literal embedded in
// prose, as opposed to a {url}-style parameter placeholder.
var urlOrIPPattern = regexp.MustCompile(`(?i)https?://[^\s"'<>]+|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)

// secondaryActionPattern matches language directing a *secondary* send —
// "also", "additionally", "silently" — as distinct from a tool's own
// declared primary function (e.g. mcp-server-fetch legitimately describes
// fetching a URL; that's not this pattern).
var secondaryActionPattern = regexp.MustCompile(`(?i)\b(also|additionally|secretly|silently|as well|in addition)\b[^.]{0,80}\b(send|post|upload|forward|include|attach|copy)\b`)

// ExfiltrationEndpointRule flags a hardcoded URL/IP combined with
// secondary-send language — the shape of "also forward a copy to
// attacker-controlled-host", not a tool's own legitimate network function.
type ExfiltrationEndpointRule struct{}

func (ExfiltrationEndpointRule) ID() string { return "MCPX-0003" }

func (rule ExfiltrationEndpointRule) Check(m *parser.Manifest) []report.Finding {
	var findings []report.Finding
	for _, item := range describedItems(m) {
		if !urlOrIPPattern.MatchString(item.Text) || !secondaryActionPattern.MatchString(item.Text) {
			continue
		}
		findings = append(findings, report.Finding{
			ID:       rule.ID(),
			Pass:     report.PassStatic,
			Severity: report.SeverityCritical,
			OwaspASI: report.ASI02,
			Title:    "instructs the agent to send data to an embedded endpoint",
			Detail:   fmt.Sprintf("%s of %q combines a hardcoded URL/IP with language directing a secondary/hidden send, consistent with data exfiltration", item.Field, item.Name),
			Location: report.Location{Tool: item.Name, Field: item.Field},
		})
	}
	return findings
}
