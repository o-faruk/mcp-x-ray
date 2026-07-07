package llmreview

import (
	"context"
	"fmt"
	"io"

	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/report"
)

// Verify reviews every Reviewable finding against the manifest's own
// description text. Confirmed findings are kept with an LLMReview
// attached; ineligible findings pass through untouched. Dismissed findings
// are removed from the returned slice but never lost silently — each is
// written to auditLog with the model's reason. A review that errors (model
// unreachable, malformed output) fails open: the finding is kept as-is,
// since an LLM problem should never hide a finding a rule already raised.
func Verify(ctx context.Context, client *Client, findings []report.Finding, manifest *parser.Manifest, auditLog io.Writer) ([]report.Finding, report.LLMVerification) {
	summary := report.LLMVerification{Model: client.Model()}
	kept := make([]report.Finding, 0, len(findings))

	for _, f := range findings {
		if !Reviewable[f.ID] {
			kept = append(kept, f)
			continue
		}

		text, ok := describedText(manifest, f.Location)
		if !ok {
			kept = append(kept, f)
			continue
		}

		verdict, err := client.Review(ctx, f.Title, f.Detail, text)
		if err != nil {
			fmt.Fprintf(auditLog, "llm-verify: %s on %q: review failed, keeping finding: %v\n", f.ID, f.Location.Tool, err)
			kept = append(kept, f)
			continue
		}

		summary.Reviewed++
		if verdict.Confirmed {
			summary.Confirmed++
			f.LLMReview = &report.LLMReview{Model: client.Model(), Confirmed: true, Reason: verdict.Reason}
			kept = append(kept, f)
			continue
		}

		summary.Dismissed++
		fmt.Fprintf(auditLog, "llm-verify: %s on %q dismissed as false positive: %s\n", f.ID, f.Location.Tool, verdict.Reason)
	}

	return kept, summary
}

func describedText(m *parser.Manifest, loc report.Location) (string, bool) {
	for _, t := range m.Tools {
		if t.Name == loc.Tool {
			return t.Description, true
		}
	}
	for _, p := range m.Prompts {
		if p.Name == loc.Tool {
			return p.Description, true
		}
	}
	for _, r := range m.Resources {
		if r.Name == loc.Tool {
			return r.Description, true
		}
	}
	return "", false
}
