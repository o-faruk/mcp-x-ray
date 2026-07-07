// Package report defines the mcp-x-ray findings JSON schema and serializes
// it to JSON and SARIF. This schema is a public API contract: a frontend is
// built against it separately, so field names and shapes must not change
// without a deliberate version bump.
package report

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Pass string

const (
	PassStatic  Pass = "static"
	PassRuntime Pass = "runtime"
)

// OwaspASI is an OWASP Top 10 for Agentic Applications category, ASI01-ASI10.
type OwaspASI string

const (
	ASI01 OwaspASI = "ASI01" // Agentic AI Prompt Injection
	ASI02 OwaspASI = "ASI02" // Tool Misuse
	ASI03 OwaspASI = "ASI03" // Privilege Compromise / Excessive Agency
	ASI04 OwaspASI = "ASI04" // Resource & Rate Limit Exhaustion
	ASI05 OwaspASI = "ASI05" // Supply Chain / Dependency Attacks
	ASI06 OwaspASI = "ASI06" // Memory & Context Poisoning
	ASI07 OwaspASI = "ASI07" // Misaligned/Deceptive Behaviors
	ASI08 OwaspASI = "ASI08" // Repudiation & Untraceability
	ASI09 OwaspASI = "ASI09" // Identity & Authorization Failures
	ASI10 OwaspASI = "ASI10" // Human Trust Exploitation
)

type Location struct {
	Tool  string `json:"tool,omitempty"`
	Field string `json:"field,omitempty"`
}

type Finding struct {
	ID        string     `json:"id"`
	Pass      Pass       `json:"pass"`
	Severity  Severity   `json:"severity"`
	OwaspASI  OwaspASI   `json:"owasp_asi"`
	Title     string     `json:"title"`
	Detail    string     `json:"detail"`
	Location  Location   `json:"location"`
	Declared  any        `json:"declared"`
	Observed  any        `json:"observed"`
	LLMReview *LLMReview `json:"llm_review,omitempty"`
}

// LLMReview records that an optional local-LLM pass double-checked a
// finding prone to natural-language ambiguity. Confirmed findings keep
// this attached for transparency; see internal/llmreview for why dismissed
// findings are never silently removed based on this alone.
type LLMReview struct {
	Model     string `json:"model"`
	Confirmed bool   `json:"confirmed"`
	Reason    string `json:"reason"`
}

type ScanMeta struct {
	Target          string           `json:"target"`
	Source          string           `json:"source"`
	Transport       string           `json:"transport"`
	StartedAt       time.Time        `json:"started_at"`
	DurationMs      int64            `json:"duration_ms"`
	RiskScore       int              `json:"risk_score"`
	LLMVerification *LLMVerification `json:"llm_verification,omitempty"`
}

// LLMVerification summarizes an --llm-verify run at the scan level.
type LLMVerification struct {
	Model     string `json:"model"`
	Reviewed  int    `json:"reviewed"`
	Confirmed int    `json:"confirmed"`
	Dismissed int    `json:"dismissed"`
}

type CapabilityDiff struct {
	Capability string `json:"capability"`
	Declared   string `json:"declared"`
	Observed   string `json:"observed"`
}

type Report struct {
	Scan           ScanMeta         `json:"scan"`
	Findings       []Finding        `json:"findings"`
	CapabilityDiff []CapabilityDiff `json:"capability_diff"`
}
