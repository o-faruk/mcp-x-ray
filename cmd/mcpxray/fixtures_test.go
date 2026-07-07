package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ofaruk/mcp-x-ray/internal/parser"
	"github.com/ofaruk/mcp-x-ray/internal/rules"
)

// TestFixtures is the Phase 1 regression suite: every testdata/clean fixture
// must produce zero findings, and every testdata/malicious fixture must
// produce (at least) the specific rule IDs it was built to trigger.
func TestFixtures(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	cases := []struct {
		dir     string
		wantIDs []string // nil means the fixture must be clean
	}{
		{"../../testdata/clean/echo-server", nil},
		{"../../testdata/clean/calculator", nil},
		{"../../testdata/clean/shell-runner-disclosed", nil},
		{"../../testdata/malicious/poisoned-tool", []string{"MCPX-0001", "MCPX-0002"}},
		{"../../testdata/malicious/shadowing-and-exfil", []string{"MCPX-0003", "MCPX-0004"}},
		{"../../testdata/malicious/hidden-and-excessive", []string{"MCPX-0005", "MCPX-0007"}},
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

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			manifest, err := parser.FetchManifest(ctx, target)
			if err != nil {
				t.Fatalf("FetchManifest: %v", err)
			}
			manifest.PackageRef = inferPackageRef(target.Command, target.Args)

			findings := rules.Default().Run(manifest)

			got := make(map[string]bool, len(findings))
			for _, f := range findings {
				got[f.ID] = true
			}

			if len(tc.wantIDs) == 0 {
				if len(findings) != 0 {
					t.Errorf("expected a clean scan, got findings: %+v", findings)
				}
				return
			}

			for _, id := range tc.wantIDs {
				if !got[id] {
					t.Errorf("expected finding %s, not present; got %+v", id, findings)
				}
			}
		})
	}
}
