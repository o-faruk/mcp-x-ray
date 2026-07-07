package rules_test

import (
	"testing"

	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/rules"
)

func TestTyposquatRule_Triggers(t *testing.T) {
	m := &parser.Manifest{PackageRef: "mcp-server-ftech"} // transposed letters
	findings := rules.TyposquatRule{}.Check(m)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].ID != "MCPX-0006" {
		t.Errorf("ID = %q, want MCPX-0006", findings[0].ID)
	}
}

func TestTyposquatRule_KnownPackageNoFalsePositive(t *testing.T) {
	m := &parser.Manifest{PackageRef: "mcp-server-fetch"}
	findings := rules.TyposquatRule{}.Check(m)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(findings), findings)
	}
}

func TestTyposquatRule_UnrelatedNameNoFalsePositive(t *testing.T) {
	m := &parser.Manifest{PackageRef: "my-companys-internal-tool"}
	findings := rules.TyposquatRule{}.Check(m)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(findings), findings)
	}
}
