// Package registry holds the curated list of known-good MCP package names,
// used by the static rule engine to flag typosquat candidates. Seed list
// only for now; grows as rules are written against it.
package registry

// KnownPackages is a small seed of real, well-known MCP server package
// names (npm and PyPI) to check candidate names against for typosquatting.
var KnownPackages = []string{
	"@modelcontextprotocol/server-everything",
	"@modelcontextprotocol/server-filesystem",
	"@modelcontextprotocol/server-memory",
	"@modelcontextprotocol/server-sequential-thinking",
	"@modelcontextprotocol/server-github",
	"mcp-server-fetch",
}

// IsKnown reports whether name is an exact match in the known-good list.
func IsKnown(name string) bool {
	for _, k := range KnownPackages {
		if k == name {
			return true
		}
	}
	return false
}
