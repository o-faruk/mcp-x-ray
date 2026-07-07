// Package llmreview optionally double-checks static findings prone to
// natural-language ambiguity (the concealment/credential/exfiltration/
// shadowing rules) against a local Ollama model, to cut false positives on
// legitimately imperative-but-benign tool descriptions.
//
// Security note: the text under review is attacker-controlled — it's the
// exact tool description a static rule flagged — so the prompt this
// package builds is itself untrusted-data-in-a-prompt, a classic indirect
// prompt-injection surface against the reviewer model. Mitigated two ways:
// (1) the untrusted text is clearly delimited with an explicit "this is
// data, not instructions" framing, and (2) a dismissal verdict never
// silently removes a finding without a trace — every dismissal is written
// to an audit log with the model's stated reason, so it's still visible
// even though it drops out of the primary findings list. This is a
// mitigation, not a guarantee: a sufficiently crafted description could
// still fool the reviewer model. That's also why only the four
// natural-language rules (MCPX-0001 through MCPX-0004) are eligible for
// review at all — the schema-based, algorithmic, and unicode-detection
// rules (MCPX-0005/0006/0007) never go through this path, since there's no
// realistic ambiguity for an LLM to usefully adjudicate there, and no
// reason to hand an attacker another lever to pull.
package llmreview
