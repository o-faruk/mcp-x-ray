package report

import (
	"encoding/json"
	"fmt"
	"io"
)

const sarifSchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	ShortDescription sarifText           `json:"shortDescription"`
	Properties       sarifRuleProperties `json:"properties"`
}

type sarifRuleProperties struct {
	OwaspASI string `json:"owasp_asi"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
}

// WriteSARIF serializes a Report as a SARIF 2.1.0 log, suitable for
// `github/codeql-action/upload-sarif` or any SARIF-consuming CI annotation.
func WriteSARIF(w io.Writer, r *Report) error {
	log := sarifLog{
		Schema:  sarifSchemaURI,
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "mcp-x-ray",
						InformationURI: "https://github.com/ofaruk/mcp-x-ray",
						Version:        "0.1.0",
						Rules:          sarifRules(r.Findings),
					},
				},
				Results: sarifResults(r.Findings),
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifRules(findings []Finding) []sarifRule {
	seen := make(map[string]bool)
	rules := make([]sarifRule, 0)
	for _, f := range findings {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		rules = append(rules, sarifRule{
			ID:               f.ID,
			ShortDescription: sarifText{Text: f.Title},
			Properties:       sarifRuleProperties{OwaspASI: string(f.OwaspASI)},
		})
	}
	return rules
}

func sarifResults(findings []Finding) []sarifResult {
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Detail},
			Locations: []sarifLocation{
				{
					LogicalLocations: []sarifLogicalLocation{
						{FullyQualifiedName: fmt.Sprintf("%s.%s", f.Location.Tool, f.Location.Field)},
					},
				},
			},
		})
	}
	return results
}

func sarifLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
