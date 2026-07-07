// Package diff compares a manifest's declared capabilities — inferred from
// Phase 1's disclosure-keyword heuristics, since MCP has no formal
// capability-manifest field — against what internal/sandbox observed at
// runtime, producing the report's capability_diff rows and any runtime
// findings a divergence implies.
package diff
