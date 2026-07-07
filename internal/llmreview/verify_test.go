package llmreview_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ofaruk/mcp-x-ray/internal/llmreview"
	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/report"
)

// verdictServer replies with a fixed verdict for every request, keyed by
// the tool name embedded in the untrusted-text section of the prompt.
func verdictServer(t *testing.T, verdicts map[string]bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Prompt string `json:"prompt"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		for tool, confirmed := range verdicts {
			if strings.Contains(req.Prompt, tool) {
				json.NewEncoder(w).Encode(map[string]string{
					"response": `{"confirmed": ` + boolStr(confirmed) + `, "reason": "test reason for ` + tool + `"}`,
				})
				return
			}
		}
		t.Fatalf("no verdict configured for prompt: %s", req.Prompt)
	}))
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestVerify_FiltersDismissedKeepsConfirmedAndIneligible(t *testing.T) {
	srv := verdictServer(t, map[string]bool{
		"confirmed-tool": true,
		"dismissed-tool": false,
	})
	defer srv.Close()

	manifest := &parser.Manifest{Tools: []parser.Tool{
		{Name: "confirmed-tool", Description: "confirmed-tool description text"},
		{Name: "dismissed-tool", Description: "dismissed-tool description text"},
	}}

	findings := []report.Finding{
		{ID: "MCPX-0001", Location: report.Location{Tool: "confirmed-tool", Field: "description"}},
		{ID: "MCPX-0002", Location: report.Location{Tool: "dismissed-tool", Field: "description"}},
		{ID: "MCPX-0005", Location: report.Location{Tool: "confirmed-tool", Field: "inputSchema"}}, // not reviewable
	}

	client := llmreview.New(srv.URL, "test-model")
	var audit bytes.Buffer
	kept, summary := llmreview.Verify(context.Background(), client, findings, manifest, &audit)

	if len(kept) != 2 {
		t.Fatalf("kept = %+v, want 2 findings (confirmed + ineligible)", kept)
	}
	if summary.Reviewed != 2 || summary.Confirmed != 1 || summary.Dismissed != 1 {
		t.Errorf("summary = %+v, want reviewed=2 confirmed=1 dismissed=1", summary)
	}

	var sawConfirmed, sawIneligible bool
	for _, f := range kept {
		if f.ID == "MCPX-0001" {
			sawConfirmed = true
			if f.LLMReview == nil || !f.LLMReview.Confirmed {
				t.Errorf("MCPX-0001 should carry a confirmed LLMReview, got %+v", f.LLMReview)
			}
		}
		if f.ID == "MCPX-0005" {
			sawIneligible = true
			if f.LLMReview != nil {
				t.Errorf("MCPX-0005 is not reviewable, should have no LLMReview, got %+v", f.LLMReview)
			}
		}
		if f.ID == "MCPX-0002" {
			t.Errorf("dismissed finding MCPX-0002 should have been filtered out")
		}
	}
	if !sawConfirmed || !sawIneligible {
		t.Fatalf("missing expected findings in kept: %+v", kept)
	}

	if !strings.Contains(audit.String(), "MCPX-0002") {
		t.Errorf("audit log should mention the dismissed finding, got: %s", audit.String())
	}
}

func TestVerify_FailsOpenOnReviewError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	manifest := &parser.Manifest{Tools: []parser.Tool{{Name: "add", Description: "adds two numbers"}}}
	findings := []report.Finding{{ID: "MCPX-0001", Location: report.Location{Tool: "add", Field: "description"}}}

	client := llmreview.New(srv.URL, "test-model")
	var audit bytes.Buffer
	kept, summary := llmreview.Verify(context.Background(), client, findings, manifest, &audit)

	if len(kept) != 1 {
		t.Fatalf("kept = %+v, want the finding preserved when the model call errors", kept)
	}
	if summary.Reviewed != 0 {
		t.Errorf("summary.Reviewed = %d, want 0 (a failed call doesn't count as reviewed)", summary.Reviewed)
	}
	if !strings.Contains(audit.String(), "review failed") {
		t.Errorf("audit log should record the failure, got: %s", audit.String())
	}
}
