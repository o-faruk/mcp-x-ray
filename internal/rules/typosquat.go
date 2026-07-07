package rules

import (
	"fmt"

	"github.com/o-faruk/mcp-x-ray/internal/parser"
	"github.com/o-faruk/mcp-x-ray/internal/registry"
	"github.com/o-faruk/mcp-x-ray/internal/report"
)

// typosquatMaxDistance is the maximum edit distance still considered a
// plausible typosquat rather than an unrelated name.
const typosquatMaxDistance = 2

// TyposquatRule flags a package reference that is suspiciously close to,
// but not exactly, a known-good MCP package name.
type TyposquatRule struct{}

func (TyposquatRule) ID() string { return "MCPX-0006" }

func (rule TyposquatRule) Check(m *parser.Manifest) []report.Finding {
	ref := m.PackageRef
	if ref == "" || registry.IsKnown(ref) {
		return nil
	}

	for _, known := range registry.KnownPackages {
		if lengthsTooDifferent(ref, known) {
			continue
		}
		d := levenshtein(ref, known)
		if d > 0 && d <= typosquatMaxDistance {
			return []report.Finding{{
				ID:       rule.ID(),
				Pass:     report.PassStatic,
				Severity: report.SeverityHigh,
				OwaspASI: report.ASI05,
				Title:    "package name closely resembles a known MCP server",
				Detail:   fmt.Sprintf("%q is %d edit(s) away from the known package %q; verify this isn't a typosquat before installing", ref, d, known),
				Location: report.Location{Tool: ref, Field: "package"},
			}}
		}
	}
	return nil
}

func lengthsTooDifferent(a, b string) bool {
	diff := len(a) - len(b)
	if diff < 0 {
		diff = -diff
	}
	return diff > typosquatMaxDistance
}
