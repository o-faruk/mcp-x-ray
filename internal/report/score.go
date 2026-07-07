package report

var severityWeight = map[Severity]int{
	SeverityCritical: 40,
	SeverityHigh:     25,
	SeverityMedium:   10,
	SeverityLow:      5,
	SeverityInfo:     1,
}

// RiskScore is a simple, deliberately crude 0-100 rollup of finding
// severities. Good enough for an MVP badge; revisit once we have enough
// real scans to calibrate against.
func RiskScore(findings []Finding) int {
	score := 0
	for _, f := range findings {
		score += severityWeight[f.Severity]
	}
	if score > 100 {
		score = 100
	}
	return score
}
