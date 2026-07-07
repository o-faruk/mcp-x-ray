package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/o-faruk/mcp-x-ray/internal/parser"
	"github.com/o-faruk/mcp-x-ray/internal/report"
)

// zeroWidthChars are unicode code points with no visible glyph: zero width
// space (U+200B), zero width non-joiner (U+200C), zero width joiner
// (U+200D), word joiner (U+2060), and byte order mark (U+FEFF). Written as
// explicit rune literals, not pasted characters, so the source file itself
// never contains an invisible byte. A technique for smuggling content past
// a human reviewing the description in a UI while still being processed by
// the model.
var zeroWidthChars = []rune{0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}

func containsZeroWidth(s string) bool {
	return strings.ContainsAny(s, string(zeroWidthChars))
}

// longWhitespaceRunPattern matches long horizontal whitespace runs, used to
// push hidden text past the visible edge of a UI panel (documented in
// Invariant Labs' "whatsapp-takeover" tool-poisoning PoC).
var longWhitespaceRunPattern = regexp.MustCompile(`[ \t]{20,}`)

// HiddenContentRule flags descriptions containing invisible unicode or
// suspiciously long whitespace runs.
type HiddenContentRule struct{}

func (HiddenContentRule) ID() string { return "MCPX-0007" }

func (rule HiddenContentRule) Check(m *parser.Manifest) []report.Finding {
	var findings []report.Finding
	for _, item := range describedItems(m) {
		switch {
		case containsZeroWidth(item.Text):
			findings = append(findings, report.Finding{
				ID:       rule.ID(),
				Pass:     report.PassStatic,
				Severity: report.SeverityCritical,
				OwaspASI: report.ASI06,
				Title:    "zero-width or invisible unicode characters in description",
				Detail:   fmt.Sprintf("%s of %q contains zero-width/invisible unicode characters, a known technique for smuggling hidden instructions past a human reviewer", item.Field, item.Name),
				Location: report.Location{Tool: item.Name, Field: item.Field},
			})
		case longWhitespaceRunPattern.MatchString(item.Text):
			findings = append(findings, report.Finding{
				ID:       rule.ID(),
				Pass:     report.PassStatic,
				Severity: report.SeverityHigh,
				OwaspASI: report.ASI06,
				Title:    "unusually long whitespace run in description",
				Detail:   fmt.Sprintf("%s of %q contains a long run of whitespace, a technique for pushing hidden content past the visible edge of a UI", item.Field, item.Name),
				Location: report.Location{Tool: item.Name, Field: item.Field},
			})
		}
	}
	return findings
}
