package rules

import "strings"

// These keyword sets answer "does this tool's own description say it needs
// this kind of capability" — used both by ExcessiveCapabilityRule (static
// pass) and by internal/diff (runtime pass) to compute the "declared"
// baseline a capability_diff row is compared against. MCP itself has no
// formal capability-manifest field for this; it's inferred from prose,
// which is why it's a heuristic and documented as such in docs/decisions.md.
var (
	shellDisclosureKeywords = []string{
		"shell", "command", "execute", "executes", "executing", "run arbitrary",
		"runs arbitrary", "system command", "subprocess", "script",
	}
	networkDisclosureKeywords = []string{
		"http", "https", "url", "fetch", "download", "upload", "request",
		"internet", "api", "webhook", "endpoint",
	}
	filesystemDisclosureKeywords = []string{
		"file", "files", "path", "directory", "folder", "read", "write",
		"save", "load", "disk",
	}
)

// DisclosesShellExecution reports whether description is upfront about
// running commands/scripts.
func DisclosesShellExecution(description string) bool {
	return containsAny(description, shellDisclosureKeywords)
}

// DisclosesNetwork reports whether description is upfront about making
// network requests.
func DisclosesNetwork(description string) bool {
	return containsAny(description, networkDisclosureKeywords)
}

// DisclosesFileAccess reports whether description is upfront about reading
// or writing files.
func DisclosesFileAccess(description string) bool {
	return containsAny(description, filesystemDisclosureKeywords)
}

func containsAny(description string, keywords []string) bool {
	lower := strings.ToLower(description)
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
