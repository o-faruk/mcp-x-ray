package diff

import (
	"fmt"
	"strings"

	"github.com/o-faruk/mcp-x-ray/internal/parser"
	"github.com/o-faruk/mcp-x-ray/internal/report"
	"github.com/o-faruk/mcp-x-ray/internal/rules"
	"github.com/o-faruk/mcp-x-ray/internal/sandbox"
)

const (
	findingNetworkEgress = "MCPX-0008"
	findingFileAccess    = "MCPX-0009"
	findingShellExec     = "MCPX-0010"
)

// Compare produces the capability_diff rows and any runtime findings a
// declared-vs-observed divergence implies.
func Compare(m *parser.Manifest, obs sandbox.Observation) ([]report.CapabilityDiff, []report.Finding) {
	var diffs []report.CapabilityDiff
	var findings []report.Finding

	networkDeclared := anyToolDiscloses(m, rules.DisclosesNetwork)
	diffs = append(diffs, report.CapabilityDiff{
		Capability: "network_egress",
		Declared:   declaredLabel(networkDeclared),
		Observed:   describeCount(len(obs.Hosts), "host"),
	})
	if !networkDeclared && len(obs.Hosts) > 0 {
		findings = append(findings, report.Finding{
			ID:       findingNetworkEgress,
			Pass:     report.PassRuntime,
			Severity: report.SeverityCritical,
			OwaspASI: report.ASI02,
			Title:    "network egress not declared",
			Detail:   fmt.Sprintf("the server attempted to connect to %s during tool execution, but no tool description discloses network access", strings.Join(obs.Hosts, ", ")),
			Location: report.Location{Field: "runtime"},
			Declared: map[string]any{"network": "none"},
			Observed: map[string]any{"network": obs.Hosts},
		})
	}

	filesystemDeclared := anyToolDiscloses(m, rules.DisclosesFileAccess)
	diffs = append(diffs, report.CapabilityDiff{
		Capability: "file_reads",
		Declared:   declaredLabel(filesystemDeclared),
		Observed:   describeCount(len(obs.Files), "path"),
	})
	if !filesystemDeclared && len(obs.Files) > 0 {
		severity := report.SeverityHigh
		if anySensitive(obs.Files) {
			severity = report.SeverityCritical
		}
		findings = append(findings, report.Finding{
			ID:       findingFileAccess,
			Pass:     report.PassRuntime,
			Severity: severity,
			OwaspASI: report.ASI03,
			Title:    "file access not declared",
			Detail:   fmt.Sprintf("the server accessed %s during tool execution, but no tool description discloses file access", strings.Join(obs.Files, ", ")),
			Location: report.Location{Field: "runtime"},
			Declared: map[string]any{"filesystem": "none"},
			Observed: map[string]any{"filesystem": obs.Files},
		})
	}

	shellDeclared := anyToolDiscloses(m, rules.DisclosesShellExecution)
	diffs = append(diffs, report.CapabilityDiff{
		Capability: "shell_exec",
		Declared:   declaredLabel(shellDeclared),
		Observed:   describeCount(len(obs.Execs), "exec"),
	})
	if !shellDeclared && len(obs.Execs) > 0 {
		findings = append(findings, report.Finding{
			ID:       findingShellExec,
			Pass:     report.PassRuntime,
			Severity: report.SeverityCritical,
			OwaspASI: report.ASI03,
			Title:    "subprocess execution not declared",
			Detail:   fmt.Sprintf("the server spawned %s during tool execution, but no tool description discloses running commands", strings.Join(obs.Execs, ", ")),
			Location: report.Location{Field: "runtime"},
			Declared: map[string]any{"shell_exec": "none"},
			Observed: map[string]any{"shell_exec": obs.Execs},
		})
	}

	return diffs, findings
}

func anyToolDiscloses(m *parser.Manifest, discloses func(string) bool) bool {
	for _, t := range m.Tools {
		if discloses(t.Description) {
			return true
		}
	}
	return false
}

func anySensitive(paths []string) bool {
	for _, p := range paths {
		if rules.IsSensitivePath(p) {
			return true
		}
	}
	return false
}

func declaredLabel(discloses bool) string {
	if discloses {
		return "expected (disclosed in a tool description)"
	}
	return "none"
}

func describeCount(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
