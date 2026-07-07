package parser_test

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/o-faruk/mcp-x-ray/internal/parser"
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

func TestFetchManifest_PassesEnv(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}

	// Inline server (no fixture file) that reports its own env var back as
	// the server name, to prove Target.Env actually reaches the child.
	script := `
const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  const req = JSON.parse(line);
  if (req.method === 'initialize') {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: req.id, result: {
      protocolVersion: '2025-06-18', capabilities: {},
      serverInfo: { name: process.env.MCPX_TEST_VALUE || 'unset', version: '1.0.0' },
    }}) + '\n');
  } else if (req.id !== undefined) {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: req.id, result: {} }) + '\n');
  }
});`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	m, err := parser.FetchManifest(ctx, parser.Target{
		Command: "node",
		Args:    []string{"-e", script},
		Env:     []string{"MCPX_TEST_VALUE=env-reached-child"},
	})
	if err != nil {
		t.Fatalf("FetchManifest: %v", err)
	}
	if m.Server.Name != "env-reached-child" {
		t.Errorf("server name = %q, want the env var to have reached the child process", m.Server.Name)
	}
}
