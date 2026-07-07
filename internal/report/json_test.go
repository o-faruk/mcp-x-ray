package report_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/o-faruk/mcp-x-ray/internal/report"
)

func TestWriteJSON_EmptyFindingsAreArrayNotNull(t *testing.T) {
	rpt := &report.Report{
		Findings:       []report.Finding{},
		CapabilityDiff: []report.CapabilityDiff{},
	}

	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, rpt); err != nil {
		t.Fatal(err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded["findings"]) != "[]" {
		t.Errorf("findings = %s, want []", decoded["findings"])
	}
	if string(decoded["capability_diff"]) != "[]" {
		t.Errorf("capability_diff = %s, want []", decoded["capability_diff"])
	}
}
