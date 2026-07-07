package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/o-faruk/mcp-x-ray/internal/parser"
)

// fixtureManifest is the convention a local testdata directory uses to
// declare how to launch itself, e.g.:
//
//	{"command": "node", "args": ["server.js"]}
type fixtureManifest struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

const fixtureManifestName = "mcpx.json"

// resolveTarget turns a scan positional argument into a launchable Target.
// For now it only supports local fixture directories containing mcpx.json;
// scanning a live npm/PyPI package name or a multi-server client config file
// is a follow-up, not needed for the Phase 1 static MVP.
func resolveTarget(path string) (parser.Target, error) {
	info, err := os.Stat(path)
	if err != nil {
		return parser.Target{}, fmt.Errorf("target %q: %w", path, err)
	}
	if !info.IsDir() {
		return parser.Target{}, fmt.Errorf("target %q: not a directory (expected a fixture directory containing %s)", path, fixtureManifestName)
	}

	manifestPath := filepath.Join(path, fixtureManifestName)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return parser.Target{}, fmt.Errorf("target %q: %w", path, err)
	}

	var fm fixtureManifest
	if err := json.Unmarshal(data, &fm); err != nil {
		return parser.Target{}, fmt.Errorf("parsing %s: %w", manifestPath, err)
	}
	if fm.Command == "" {
		return parser.Target{}, fmt.Errorf("%s: missing required \"command\" field", manifestPath)
	}

	return parser.Target{Dir: path, Command: fm.Command, Args: fm.Args}, nil
}

// inferPackageRef makes a best-effort guess at the installed package name
// from a launcher command's own arguments — e.g. for `npx -y <pkg>` or
// `uvx <pkg>`, the package name a developer would have typed (and could
// have mistyped) when adding this server.
func inferPackageRef(command string, args []string) string {
	switch filepath.Base(command) {
	case "npx", "uvx":
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				return a
			}
		}
	}
	return ""
}
