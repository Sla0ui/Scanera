package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/Sla0ui/scanera/internal/models"
)

// Minimal SARIF 2.1.0 structures (https://sarifweb.azurewebsites.net/).
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
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       sarifRuleProps `json:"properties,omitempty"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// GenerateSARIF writes all findings across every result as a SARIF 2.1.0 file,
// suitable for CI code-scanning ingestion.
func (r *Reporter) GenerateSARIF(outputPath string) error {
	rulesByID := make(map[string]sarifRule)
	// SARIF requires "results" to be an array, so never emit null.
	results := []sarifResult{}

	for _, res := range r.results {
		for _, f := range res.Findings {
			if _, ok := rulesByID[f.ID]; !ok {
				help := ""
				if len(f.References) > 0 {
					help = f.References[0]
				}
				rulesByID[f.ID] = sarifRule{
					ID:               f.ID,
					Name:             f.Title,
					ShortDescription: sarifText{Text: nonEmpty(f.Title, f.ID)},
					HelpURI:          help,
					Properties: sarifRuleProps{
						Tags:             f.Tags,
						SecuritySeverity: securityScore(f.Severity),
					},
				}
			}

			loc := f.Location
			if loc == "" {
				loc = res.Domain
			}
			results = append(results, sarifResult{
				RuleID:  f.ID,
				Level:   sarifLevel(f.Severity),
				Message: sarifText{Text: sarifMessage(res.Domain, f)},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: loc}},
				}},
				Properties: map[string]any{
					"severity": string(f.Severity.Normalize()),
					"source":   f.Source,
					"domain":   res.Domain,
				},
			})
		}
	}

	// Map iteration order is random; sort so identical scans produce
	// identical files, then point each result at its rule.
	rules := make([]sarifRule, 0, len(rulesByID))
	for _, rule := range rulesByID {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	ruleIndex := make(map[string]int, len(rules))
	for i, rule := range rules {
		ruleIndex[rule.ID] = i
	}
	for i := range results {
		results[i].RuleIndex = ruleIndex[results[i].RuleID]
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Scanera",
				InformationURI: "https://github.com/Sla0ui/scanera",
				Version:        Version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SARIF: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write SARIF file: %w", err)
	}
	return nil
}

func sarifLevel(s models.Severity) string {
	switch s.Normalize() {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func securityScore(s models.Severity) string {
	switch s.Normalize() {
	case models.SeverityCritical:
		return "9.5"
	case models.SeverityHigh:
		return "8.0"
	case models.SeverityMedium:
		return "5.5"
	case models.SeverityLow:
		return "3.0"
	default:
		return "0.0"
	}
}

func sarifMessage(domain string, f models.Finding) string {
	msg := fmt.Sprintf("[%s] %s on %s", f.Severity, f.Title, domain)
	if f.Evidence != "" {
		msg += " (evidence: " + f.Evidence + ")"
	}
	return msg
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
