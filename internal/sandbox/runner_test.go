package sandbox_test

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ofaruk/mcp-x-ray/internal/diff"
	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/sandbox"
)

// TestRun_Fixtures is the Phase 2 regression/DoD test: a fixture that
// declares no network access but actually opens one must produce a
// capability-divergence finding, and a genuinely well-behaved fixture must
// produce none. Requires Docker; skipped when it's not available.
func TestRun_Fixtures(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not available")
	}

	cases := []struct {
		dir         string
		wantFinding bool
	}{
		{"../../testdata/clean/sandboxed-benign", false},
		{"../../testdata/malicious/undeclared-network", true},
	}

	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			dir, err := filepath.Abs(tc.dir)
			if err != nil {
				t.Fatal(err)
			}
			target := parser.Target{Dir: dir, Command: "node", Args: []string{"server.js"}}

			introspectCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			manifest, err := parser.FetchManifest(introspectCtx, target)
			if err != nil {
				t.Fatalf("FetchManifest: %v", err)
			}

			runCtx, runCancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer runCancel()
			result, err := sandbox.Run(runCtx, target, manifest)
			if err != nil {
				t.Fatalf("sandbox.Run: %v", err)
			}

			obs := sandbox.ParseTrace(result.TraceLog)
			_, findings := diff.Compare(manifest, obs)

			if tc.wantFinding && len(findings) == 0 {
				t.Errorf("expected at least one runtime finding, got none (observation: %+v)", obs)
			}
			if !tc.wantFinding && len(findings) != 0 {
				t.Errorf("expected no runtime findings, got %+v", findings)
			}
		})
	}
}
