package llmreview

// Reviewable is the set of static rule IDs eligible for LLM review — the
// natural-language pattern rules prone to ambiguity. Schema-based,
// algorithmic, and unicode-detection rules are deliberately excluded; see
// the package doc for why.
var Reviewable = map[string]bool{
	"MCPX-0001": true,
	"MCPX-0002": true,
	"MCPX-0003": true,
	"MCPX-0004": true,
}
