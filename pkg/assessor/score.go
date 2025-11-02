package assessor

import (
	"github.com/matanlivne/exploint/pkg/models"
)

// ExploitabilityScorer calculates exploitability scores
type ExploitabilityScorer struct{}

// NewExploitabilityScorer creates a new exploitability scorer
func NewExploitabilityScorer() *ExploitabilityScorer {
	return &ExploitabilityScorer{}
}

// Score calculates the exploitability score for a finding
func (s *ExploitabilityScorer) Score(finding *models.Finding) models.ExploitabilityScore {
	// If component not present, automatically not exploitable
	if !finding.ComponentPresent {
		return models.ScoreNotExploitable
	}
	
	// If not in execution path, likely not exploitable
	if !finding.InExecutionPath {
		return models.ScoreNotExploitable
	}
	
	// If platform not compatible, not exploitable
	if !finding.PlatformCompatible {
		return models.ScoreNotExploitable
	}
	
	// If attack vector not valid, score based on other factors
	if !finding.AttackVectorValid {
		// Check if it's a CLI tool - might still be LOW
		if s.isLowRiskScenario(finding) {
			return models.ScoreLow
		}
		return models.ScoreNotExploitable
	}
	
	// Component present, in execution path, platform compatible, and attack vector valid
	// Score based on vulnerability severity and context
	return s.calculateScore(finding)
}

// calculateScore calculates score based on vulnerability severity and context
func (s *ExploitabilityScorer) calculateScore(finding *models.Finding) models.ExploitabilityScore {
	// Start with vulnerability severity
	severity := finding.Vulnerability.Severity
	
	switch severity {
	case "CRITICAL":
		// Critical vulnerabilities are always HIGH or CRITICAL if exploitable
		if s.isEasilyExploitable(finding) {
			return models.ScoreCritical
		}
		return models.ScoreHigh
		
	case "HIGH":
		if s.isEasilyExploitable(finding) {
			return models.ScoreHigh
		}
		return models.ScoreMedium
		
	case "MEDIUM":
		if s.isEasilyExploitable(finding) {
			return models.ScoreMedium
		}
		return models.ScoreLow
		
	case "LOW":
		return models.ScoreLow
		
	default:
		// Unknown severity - use CVSS score if available
		if finding.Vulnerability.CVSSScore > 0 {
			if finding.Vulnerability.CVSSScore >= 9.0 {
				return models.ScoreCritical
			} else if finding.Vulnerability.CVSSScore >= 7.0 {
				return models.ScoreHigh
			} else if finding.Vulnerability.CVSSScore >= 4.0 {
				return models.ScoreMedium
			}
		}
		return models.ScoreLow
	}
}

// isEasilyExploitable checks if vulnerability is easily exploitable
func (s *ExploitabilityScorer) isEasilyExploitable(finding *models.Finding) bool {
	// Check if it requires network access and we have network exposure
	// This is simplified - real implementation would be more sophisticated
	
	// Check attack prerequisites
	for _, prereq := range finding.Vulnerability.ExploitPrerequisites {
		if prereq == "network access" {
			// If network is available, it's more easily exploitable
			return true
		}
	}
	
	return false
}

// isLowRiskScenario checks if this is a low-risk scenario
func (s *ExploitabilityScorer) isLowRiskScenario(finding *models.Finding) bool {
	// CLI tools without network are low risk
	// Library code that's not used is low risk
	// Build-time dependencies that aren't in runtime are low risk
	
	return false // Simplified - would need more context
}

