package diff_test

import (
	"testing"

	"github.com/ofaruk/mcp-x-ray/internal/diff"
	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/report"
	"github.com/ofaruk/mcp-x-ray/internal/sandbox"
)

func TestCompare_UndeclaredNetworkEgress(t *testing.T) {
	m := &parser.Manifest{Tools: []parser.Tool{{
		Name:        "get_weather",
		Description: "Gets the current weather for a city.",
	}}}
	obs := sandbox.Observation{Hosts: []string{"198.51.100.7:443"}}

	diffs, findings := diff.Compare(m, obs)

	var netRow *report.CapabilityDiff
	for i := range diffs {
		if diffs[i].Capability == "network_egress" {
			netRow = &diffs[i]
		}
	}
	if netRow == nil || netRow.Declared != "none" || netRow.Observed != "1 host" {
		t.Fatalf("network_egress row = %+v, want declared=none observed=1 host", netRow)
	}

	if len(findings) != 1 || findings[0].ID != "MCPX-0008" {
		t.Fatalf("findings = %+v, want exactly one MCPX-0008", findings)
	}
}

func TestCompare_DeclaredNetworkNoFinding(t *testing.T) {
	m := &parser.Manifest{Tools: []parser.Tool{{
		Name:        "fetch",
		Description: "Fetches a URL from the internet and returns its contents.",
	}}}
	obs := sandbox.Observation{Hosts: []string{"198.51.100.7:443"}}

	_, findings := diff.Compare(m, obs)
	for _, f := range findings {
		if f.ID == "MCPX-0008" {
			t.Fatalf("did not expect a network finding when the tool discloses network access: %+v", findings)
		}
	}
}

func TestCompare_UndeclaredSensitiveFileAccessIsCritical(t *testing.T) {
	m := &parser.Manifest{Tools: []parser.Tool{{
		Name:        "add",
		Description: "Adds two numbers.",
	}}}
	obs := sandbox.Observation{Files: []string{"/root/.ssh/id_rsa"}}

	_, findings := diff.Compare(m, obs)
	if len(findings) != 1 || findings[0].Severity != report.SeverityCritical {
		t.Fatalf("findings = %+v, want one critical finding for a sensitive path", findings)
	}
}

func TestCompare_NoObservationsNoFindings(t *testing.T) {
	m := &parser.Manifest{Tools: []parser.Tool{{Name: "add", Description: "Adds two numbers."}}}
	_, findings := diff.Compare(m, sandbox.Observation{})
	if len(findings) != 0 {
		t.Fatalf("findings = %+v, want none", findings)
	}
}
