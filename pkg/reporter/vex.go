package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/matanlivne/exploint/pkg/models"
)

// VEXGenerator generates CycloneDX VEX JSON
type VEXGenerator struct {
	report *models.Report
}

// NewVEXGenerator creates a new VEX generator
func NewVEXGenerator(report *models.Report) *VEXGenerator {
	return &VEXGenerator{
		report: report,
	}
}

// VEXDocument represents a simplified VEX document structure
type VEXDocument struct {
	BOMFormat    string                 `json:"bomFormat"`
	SpecVersion  string                 `json:"specVersion"`
	Version      int                    `json:"version"`
	SerialNumber string                 `json:"serialNumber,omitempty"`
	Metadata     VEXMetadata            `json:"metadata"`
	Vulnerabilities []VEXVulnerability  `json:"vulnerabilities"`
}

// VEXMetadata represents metadata in VEX document
type VEXMetadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     VEXTools `json:"tools"`
}

// VEXTools represents tools used
type VEXTools struct {
	Components []VEXComponent `json:"components"`
}

// VEXComponent represents a component in tools
type VEXComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// VEXVulnerability represents a vulnerability in VEX
type VEXVulnerability struct {
	ID          string                  `json:"id"`
	Description string                 `json:"description,omitempty"`
	Recommendation string               `json:"recommendation,omitempty"`
	Affects     []VEXAffect            `json:"affects"`
	Analysis    VEXAnalysis            `json:"analysis"`
	Ratings     []VEXRating            `json:"ratings,omitempty"`
}

// VEXAffect represents affected components
type VEXAffect struct {
	Ref string `json:"ref"`
}

// VEXAnalysis represents vulnerability analysis
type VEXAnalysis struct {
	State         string   `json:"state"` // "not_affected", "affected", "under_investigation"
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

// VEXRating represents vulnerability rating
type VEXRating struct {
	Score    *float64 `json:"score,omitempty"`
	Severity string   `json:"severity,omitempty"` // "critical", "high", "medium", "low", "none", "unknown"
	Method   string   `json:"method,omitempty"`
}

// Generate generates a VEX document
func (v *VEXGenerator) Generate(outputPath string) error {
	doc := VEXDocument{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: VEXMetadata{
			Timestamp: time.Now().Format(time.RFC3339),
			Tools: VEXTools{
				Components: []VEXComponent{
					{
						Name:    "exploint",
						Version: "1.0.0",
					},
				},
			},
		},
		Vulnerabilities: []VEXVulnerability{},
	}
	
	// Convert findings to VEX vulnerabilities
	for _, finding := range v.report.Findings {
		vexVuln := v.findingToVEX(finding)
		doc.Vulnerabilities = append(doc.Vulnerabilities, vexVuln)
	}
	
	// Serialize to JSON
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal VEX: %w", err)
	}
	
	// Write to file
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write VEX file: %w", err)
	}
	
	return nil
}

// findingToVEX converts a finding to a VEX vulnerability
func (v *VEXGenerator) findingToVEX(finding *models.Finding) VEXVulnerability {
	// Handle nil Vulnerability
	vulnID := "Unknown"
	vulnDescription := ""
	vulnCVSSScore := 0.0
	
	if finding.Vulnerability != nil {
		vulnID = finding.Vulnerability.ID
		vulnDescription = finding.Vulnerability.Description
		vulnCVSSScore = finding.Vulnerability.CVSSScore
	}
	
	vuln := VEXVulnerability{
		ID:          vulnID,
		Description: vulnDescription,
		Recommendation: finding.Recommendation,
	}
	
	// Determine VEX state
	var state string
	var justification string
	
	switch finding.Score {
	case models.ScoreNotExploitable:
		state = "not_affected"
		justification = "Component not exploitable in this context"
	case models.ScoreLow:
		state = "affected"
		justification = "Low exploitability risk"
	case models.ScoreMedium:
		state = "affected"
		justification = "Medium exploitability risk"
	case models.ScoreHigh:
		state = "affected"
		justification = "High exploitability risk"
	case models.ScoreCritical:
		state = "affected"
		justification = "Critical exploitability risk"
	default:
		state = "under_investigation"
		justification = "Assessment in progress"
	}
	
	// Create affected component - handle nil Component
	var purl string
	if finding.Component != nil {
		purl = finding.Component.PURL
		if purl == "" {
			// Generate PURL if not present
			purl = fmt.Sprintf("pkg:%s/%s@%s", finding.Component.Type, finding.Component.Name, finding.Component.Version)
		}
	} else {
		// Component not found - use a placeholder
		purl = "pkg:unknown/component@unknown"
	}
	
	vuln.Affects = []VEXAffect{
		{Ref: purl},
	}
	
	// Add analysis
	vuln.Analysis = VEXAnalysis{
		State:         state,
		Justification: justification,
		Response:      []string{},
		Detail:        finding.Assessment,
	}
	
	// Add ratings
	if vulnCVSSScore > 0 {
		severity := v.scoreToSeverity(finding.Score)
		score := vulnCVSSScore
		rating := VEXRating{
			Score:    &score,
			Severity: severity,
			Method:   "CVSSv3",
		}
		vuln.Ratings = []VEXRating{rating}
	}
	
	return vuln
}

// scoreToSeverity converts exploitability score to severity
func (v *VEXGenerator) scoreToSeverity(score models.ExploitabilityScore) string {
	switch score {
	case models.ScoreCritical:
		return "critical"
	case models.ScoreHigh:
		return "high"
	case models.ScoreMedium:
		return "medium"
	case models.ScoreLow:
		return "low"
	case models.ScoreNotExploitable:
		return "none"
	default:
		return "unknown"
	}
}
