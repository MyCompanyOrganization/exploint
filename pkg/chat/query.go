package chat

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/matanlivne/exploint/pkg/models"
)

// QueryEngine processes natural language queries
type QueryEngine struct {
	report *models.Report
}

// NewQueryEngine creates a new query engine
func NewQueryEngine(reportPath string) (*QueryEngine, error) {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read report: %w", err)
	}
	
	var report models.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse report: %w", err)
	}
	
	return &QueryEngine{
		report: &report,
	}, nil
}

// BuildContext builds a context string from the report for LLM
func (q *QueryEngine) BuildContext() string {
	var sb strings.Builder
	
	sb.WriteString("Vulnerability Analysis Report\n")
	sb.WriteString("============================\n\n")
	
	sb.WriteString(fmt.Sprintf("Target: %s (%s)\n", q.report.Target, q.report.TargetType))
	sb.WriteString(fmt.Sprintf("Total Findings: %d\n", len(q.report.Findings)))
	sb.WriteString(fmt.Sprintf("Total Components: %d\n\n", len(q.report.Components)))
	
	sb.WriteString("Findings Summary:\n")
	scoreCounts := make(map[string]int)
	for _, finding := range q.report.Findings {
		scoreCounts[string(finding.Score)]++
	}
	
	for score, count := range scoreCounts {
		sb.WriteString(fmt.Sprintf("  %s: %d\n", score, count))
	}
	
	sb.WriteString("\nDetailed Findings:\n")
	for i, finding := range q.report.Findings {
		sb.WriteString(fmt.Sprintf("\n%d. %s (%s)\n", i+1, finding.Vulnerability.ID, finding.Vulnerability.Title))
		sb.WriteString(fmt.Sprintf("   Component: %s@%s\n", finding.Component.Name, finding.Component.Version))
		sb.WriteString(fmt.Sprintf("   Score: %s\n", finding.Score))
		sb.WriteString(fmt.Sprintf("   Assessment: %s\n", finding.Assessment))
		
		if finding.LLMInsights != "" {
			sb.WriteString(fmt.Sprintf("   LLM Insights: %s\n", finding.LLMInsights))
		}
	}
	
	return sb.String()
}

// ExtractCVEFromQuestion extracts CVE ID from a question if present
func (q *QueryEngine) ExtractCVEFromQuestion(question string) string {
	// Try CVE first
	if strings.Contains(strings.ToUpper(question), "CVE-") {
		// Simple extraction - look for CVE- followed by numbers
		parts := strings.Fields(question)
		for _, part := range parts {
			if strings.HasPrefix(strings.ToUpper(part), "CVE-") {
				return strings.ToUpper(part)
			}
		}
	}
	
	// Try GHSA
	if strings.Contains(strings.ToUpper(question), "GHSA-") {
		parts := strings.Fields(question)
		for _, part := range parts {
			if strings.HasPrefix(strings.ToUpper(part), "GHSA-") {
				return strings.ToUpper(part)
			}
		}
	}
	
	return ""
}

// FindFindingByCVE finds a finding by CVE ID
func (q *QueryEngine) FindFindingByCVE(cveID string) *models.Finding {
	for _, finding := range q.report.Findings {
		if finding.Vulnerability.ID == cveID {
			return finding
		}
	}
	return nil
}

// GetFindingsByScore returns findings filtered by score
func (q *QueryEngine) GetFindingsByScore(score models.ExploitabilityScore) []*models.Finding {
	var results []*models.Finding
	for _, finding := range q.report.Findings {
		if finding.Score == score {
			results = append(results, finding)
		}
	}
	return results
}

// GetExploitableFindings returns all exploitable findings (not NOT_EXPLOITABLE)
func (q *QueryEngine) GetExploitableFindings() []*models.Finding {
	var results []*models.Finding
	for _, finding := range q.report.Findings {
		if finding.Score != models.ScoreNotExploitable {
			results = append(results, finding)
		}
	}
	return results
}

