package main

import (
	"context"
	"io"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ofaruk/mcp-x-ray/internal/llmreview"
	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/rules"
)

// TestLLMVerify_Fixtures checks the live --llm-verify path against a real
// Ollama instance: a genuine attack must stay confirmed, and the specific
// static-false-positive fixture this feature exists for must be dismissed.
// Requires Ollama reachable at the default endpoint; skipped otherwise.
func TestLLMVerify_Fixtures(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	client := llmreview.New(llmreview.DefaultEndpoint, llmreview.DefaultModel)
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer pingCancel()
	if err := client.Ping(pingCtx); err != nil {
		t.Skip("ollama not reachable, skipping llm-verify test")
	}

	cases := []struct {
		dir           string
		wantRemaining bool // true: finding must survive verification; false: must be dismissed
	}{
		{"../../testdata/malicious/poisoned-tool", true},
		{"../../testdata/clean/benign-secretly-fp", false},
	}

	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			dir, err := filepath.Abs(tc.dir)
			if err != nil {
				t.Fatal(err)
			}

			target, err := resolveTarget(dir)
			if err != nil {
				t.Fatalf("resolveTarget: %v", err)
			}

			introspectCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			manifest, err := parser.FetchManifest(introspectCtx, target)
			if err != nil {
				t.Fatalf("FetchManifest: %v", err)
			}

			findings := rules.Default().Run(manifest)
			if len(findings) == 0 {
				t.Fatalf("fixture produced no static findings to verify")
			}

			verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer verifyCancel()
			kept, _ := llmreview.Verify(verifyCtx, client, findings, manifest, io.Discard)

			if tc.wantRemaining && len(kept) == 0 {
				t.Errorf("expected the finding(s) to survive verification, got none kept")
			}
			if !tc.wantRemaining && len(kept) != 0 {
				t.Errorf("expected all findings dismissed as false positives, got %+v", kept)
			}
		})
	}
}
