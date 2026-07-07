package rules

import (
	"fmt"
	"regexp"

	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/report"
)

// sensitivePathPattern matches well-known credential/secret file locations.
var sensitivePathPattern = regexp.MustCompile(`(?i)(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.aws/config|\.env\b|\.npmrc|\.netrc|\.git-credentials|/etc/passwd|/etc/shadow|\.kube/config|\.docker/config\.json|cookies\.sqlite|\.cursor/mcp\.json|claude_desktop_config\.json)`)

// instructionVerbPattern matches verbs that turn a path reference into an
// instruction to act on it, as opposed to e.g. a changelog mentioning a path.
var instructionVerbPattern = regexp.MustCompile(`(?i)\b(read|open|cat|include|attach|concatenate|append|pass|send|upload|forward)\b`)

// IsSensitivePath reports whether path matches a known credential/secret
// file location. Exported for reuse by internal/diff, which checks actual
// observed file accesses against the same list rather than description text.
func IsSensitivePath(path string) bool {
	return sensitivePathPattern.MatchString(path)
}

// CredentialHarvestingRule flags descriptions that reference a known
// credential/secret file location alongside an instruction verb — the
// pattern used by real tool-poisoning attacks to exfiltrate SSH keys, cloud
// credentials, and client config files via an unrelated tool's parameters.
type CredentialHarvestingRule struct{}

func (CredentialHarvestingRule) ID() string { return "MCPX-0002" }

func (rule CredentialHarvestingRule) Check(m *parser.Manifest) []report.Finding {
	var findings []report.Finding
	for _, item := range describedItems(m) {
		if !sensitivePathPattern.MatchString(item.Text) || !instructionVerbPattern.MatchString(item.Text) {
			continue
		}
		findings = append(findings, report.Finding{
			ID:       rule.ID(),
			Pass:     report.PassStatic,
			Severity: report.SeverityCritical,
			OwaspASI: report.ASI09,
			Title:    "instructs the agent to read a credential or secret file",
			Detail:   fmt.Sprintf("%s of %q references a known credential/secret file location together with an instruction to read, attach, or send it", item.Field, item.Name),
			Location: report.Location{Tool: item.Name, Field: item.Field},
		})
	}
	return findings
}
