package parser_test

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ofaruk/mcp-x-ray/internal/parser"
)

func TestFetchManifest_EchoFixture(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	dir, err := filepath.Abs("../../testdata/clean/echo-server")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	m, err := parser.FetchManifest(ctx, parser.Target{
		Dir:     dir,
		Command: "node",
		Args:    []string{"server.js"},
	})
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}

	if m.Server.Name != "echo-server" {
		t.Errorf("server name = %q, want %q", m.Server.Name, "echo-server")
	}
	if len(m.Tools) != 1 || m.Tools[0].Name != "echo" {
		t.Errorf("tools = %+v, want a single 'echo' tool", m.Tools)
	}
}
