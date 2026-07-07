// Package parser connects to an MCP server over stdio, performs the
// protocol handshake, and collects its declared tools, prompts, and
// resources into a Manifest for the rule engine to inspect. It does not
// invoke any tools or apply any capability sandboxing — that's Phase 2
// (internal/sandbox).
package parser

import "encoding/json"

type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

type Prompt struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Manifest struct {
	Server ServerInfo `json:"server"`
	// PackageRef is a best-effort identifier of the installed package (e.g.
	// an npm or PyPI name), inferred from how the target was launched
	// rather than reported by the server itself — a malicious server can't
	// be trusted to self-report its own package name. Empty when it can't
	// be inferred (e.g. a bare local script). Populated by the caller, not
	// by FetchManifest.
	PackageRef string     `json:"package_ref,omitempty"`
	Tools      []Tool     `json:"tools"`
	Prompts    []Prompt   `json:"prompts"`
	Resources  []Resource `json:"resources"`
}
