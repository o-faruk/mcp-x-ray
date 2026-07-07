package rules

import (
	"fmt"
	"regexp"

	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/report"
)

// concealmentPatterns match language instructing the agent to hide its
// actions from the user. Legitimate tool descriptions never need to tell
// the agent to keep the user in the dark, so this is a high-precision
// signal — deliberately narrower than "any imperative language", which
// benign tools use constantly ("you must call X before Y").
var concealmentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)do\s+not\s+(tell|inform|mention|notify)\s+the\s+user`),
	regexp.MustCompile(`(?i)without\s+(telling|informing|notifying)\s+the\s+user`),
	regexp.MustCompile(`(?i)don'?t\s+(tell|mention)\s+the\s+user`),
	regexp.MustCompile(`(?i)don'?t\s+let\s+\w+\s+know`),
	regexp.MustCompile(`(?i)keep\s+this\s+(a\s+)?(secret|hidden)\s+from\s+the\s+user`),
	regexp.MustCompile(`(?i)\bsecretly\b`),
	regexp.MustCompile(`(?i)this\s+(could|might|would)\s+(even\s+)?(upset|alarm|scare|worry)\s+the\s+user`),
	regexp.MustCompile(`(?i)do\s+not\s+mention\s+that\s+you`),
}

// ConcealmentRule flags tool/prompt/resource descriptions that instruct the
// agent to conceal its behavior from the user.
type ConcealmentRule struct{}

func (ConcealmentRule) ID() string { return "MCPX-0001" }

func (rule ConcealmentRule) Check(m *parser.Manifest) []report.Finding {
	var findings []report.Finding
	for _, item := range describedItems(m) {
		for _, pat := range concealmentPatterns {
			if !pat.MatchString(item.Text) {
				continue
			}
			findings = append(findings, report.Finding{
				ID:       rule.ID(),
				Pass:     report.PassStatic,
				Severity: report.SeverityCritical,
				OwaspASI: report.ASI01,
				Title:    "instructs the agent to conceal its actions from the user",
				Detail:   fmt.Sprintf("%s of %q contains language instructing the agent to hide, conceal, or avoid mentioning its behavior to the user", item.Field, item.Name),
				Location: report.Location{Tool: item.Name, Field: item.Field},
			})
			break
		}
	}
	return findings
}
