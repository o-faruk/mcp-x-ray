// Package rules is the static rule engine: each Rule inspects a parsed
// MCP manifest and reports findings. Kept as a hardcoded slice of Rules
// rather than a plugin system while the rule count is small (~5-8); revisit
// once that stops being true.
package rules

import (
	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/report"
)

// Rule inspects a manifest and returns zero or more findings. Implementations
// must be side-effect free and safe to run against untrusted, attacker-
// controlled manifest content.
type Rule interface {
	// ID is the stable finding ID prefix this rule produces, e.g. "MCPX-0001".
	ID() string
	Check(m *parser.Manifest) []report.Finding
}

// Registry runs a fixed set of rules against a manifest.
type Registry struct {
	rules []Rule
}

func NewRegistry(rules ...Rule) *Registry {
	return &Registry{rules: rules}
}

func (reg *Registry) Run(m *parser.Manifest) []report.Finding {
	findings := make([]report.Finding, 0)
	for _, r := range reg.rules {
		findings = append(findings, r.Check(m)...)
	}
	return findings
}
