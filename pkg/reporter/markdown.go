package reporter

import (
	"fmt"
	"os"
	"time"

	"github.com/matanlivne/exploint/pkg/models"
)

// MarkdownReporter generates markdown reports
type MarkdownReporter struct {
	report *models.Report
}

// NewMarkdownReporter creates a new markdown reporter
func NewMarkdownReporter(report *models.Report) *MarkdownReporter {
	return &MarkdownReporter{
		report: report,
	}
}

// Generate generates a markdown report
func (r *MarkdownReporter) Generate(outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer file.Close()
	
	// Write header
	r.writeHeader(file)
	
	// Write executive summary
	r.writeExecutiveSummary(file)
	
	// Write component inventory
	r.writeComponentInventory(file)
	
	// Write detailed findings
	r.writeDetailedFindings(file)
	
	// Write recommendations
	r.writeRecommendations(file)
	
	return nil
}

// writeHeader writes the report header
func (r *MarkdownReporter) writeHeader(file *os.File) {
	fmt.Fprintf(file, "# Vulnerability Exploitability Analysis Report\n\n")
	fmt.Fprintf(file, "**Generated:** %s\n\n", r.report.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(file, "**Target:** %s (%s)\n\n", r.report.Target, r.report.TargetType)
	fmt.Fprintf(file, "---\n\n")
}

// writeExecutiveSummary writes the executive summary
func (r *MarkdownReporter) writeExecutiveSummary(file *os.File) {
	fmt.Fprintf(file, "## Executive Summary\n\n")
	
	summary := r.report.Summary
	if summary == nil {
		summary = r.buildSummary()
	}
	
	fmt.Fprintf(file, "This analysis identified **%d** vulnerabilities across **%d** components.\n\n", 
		summary.TotalFindings, summary.TotalComponents)
	
	fmt.Fprintf(file, "### Exploitability Breakdown\n\n")
	fmt.Fprintf(file, "| Score | Count |\n")
	fmt.Fprintf(file, "|-------|-------|\n")
	
	scoreOrder := []models.ExploitabilityScore{
		models.ScoreCritical,
		models.ScoreHigh,
		models.ScoreMedium,
		models.ScoreLow,
		models.ScoreNotExploitable,
	}
	
	for _, score := range scoreOrder {
		count := summary.ByScore[string(score)]
		if count > 0 {
			fmt.Fprintf(file, "| %s | %d |\n", score, count)
		}
	}
	
	fmt.Fprintf(file, "\n")
	fmt.Fprintf(file, "- **Exploitable:** %d vulnerabilities\n", summary.ExploitableCount)
	fmt.Fprintf(file, "- **Not Exploitable:** %d vulnerabilities\n\n", summary.NotExploitableCount)
	fmt.Fprintf(file, "---\n\n")
}

// writeComponentInventory writes the component inventory
func (r *MarkdownReporter) writeComponentInventory(file *os.File) {
	fmt.Fprintf(file, "## Component Inventory\n\n")
	
	fmt.Fprintf(file, "| Component | Version | Type | Source | Location |\n")
	fmt.Fprintf(file, "|-----------|---------|------|--------|----------|\n")
	
	for _, comp := range r.report.Components {
		fmt.Fprintf(file, "| %s | %s | %s | %s | %s |\n",
			comp.Name,
			comp.Version,
			comp.Type,
			comp.Source,
			comp.Location,
		)
	}
	
	fmt.Fprintf(file, "\n---\n\n")
}

// writeDetailedFindings writes detailed findings
func (r *MarkdownReporter) writeDetailedFindings(file *os.File) {
	fmt.Fprintf(file, "## Detailed Findings\n\n")
	
	for i, finding := range r.report.Findings {
		r.writeFinding(file, finding, i+1)
		fmt.Fprintf(file, "\n")
	}
}

// writeFinding writes a single finding
func (r *MarkdownReporter) writeFinding(file *os.File, finding *models.Finding, index int) {
	fmt.Fprintf(file, "### %d. %s\n\n", index, finding.Vulnerability.ID)
	
	if finding.Vulnerability.Title != "" {
		fmt.Fprintf(file, "**Title:** %s\n\n", finding.Vulnerability.Title)
	}
	
	fmt.Fprintf(file, "**Component:** %s@%s\n\n", finding.Component.Name, finding.Component.Version)
	fmt.Fprintf(file, "**Exploitability Score:** `%s`\n\n", finding.Score)
	
	if finding.Vulnerability.Severity != "" {
		fmt.Fprintf(file, "**Severity:** %s\n\n", finding.Vulnerability.Severity)
	}
	
	if finding.Vulnerability.CVSSScore > 0 {
		fmt.Fprintf(file, "**CVSS Score:** %.1f\n\n", finding.Vulnerability.CVSSScore)
	}
	
	if finding.Vulnerability.Description != "" {
		fmt.Fprintf(file, "**Description:**\n\n%s\n\n", finding.Vulnerability.Description)
	}
	
	fmt.Fprintf(file, "**Assessment:**\n\n%s\n\n", finding.Assessment)
	
	// Assessment details
	fmt.Fprintf(file, "**Assessment Details:**\n\n")
	fmt.Fprintf(file, "- Component Present: %v\n", finding.ComponentPresent)
	fmt.Fprintf(file, "- In Execution Path: %v\n", finding.InExecutionPath)
	fmt.Fprintf(file, "- Platform Compatible: %v\n", finding.PlatformCompatible)
	fmt.Fprintf(file, "- Attack Vector Valid: %v\n\n", finding.AttackVectorValid)
	
	if finding.LLMInsights != "" {
		fmt.Fprintf(file, "**LLM-Enhanced Insights:**\n\n%s\n\n", finding.LLMInsights)
	}
	
	if finding.Recommendation != "" {
		fmt.Fprintf(file, "**Recommendation:**\n\n%s\n\n", finding.Recommendation)
	}
	
	if len(finding.Vulnerability.AttackVectors) > 0 {
		fmt.Fprintf(file, "**Attack Vectors:**\n\n")
		for _, vector := range finding.Vulnerability.AttackVectors {
			fmt.Fprintf(file, "- %s\n", vector)
		}
		fmt.Fprintf(file, "\n")
	}
	
	if len(finding.Vulnerability.ExploitPrerequisites) > 0 {
		fmt.Fprintf(file, "**Exploitation Prerequisites:**\n\n")
		for _, prereq := range finding.Vulnerability.ExploitPrerequisites {
			fmt.Fprintf(file, "- %s\n", prereq)
		}
		fmt.Fprintf(file, "\n")
	}
}

// writeRecommendations writes recommendations
func (r *MarkdownReporter) writeRecommendations(file *os.File) {
	fmt.Fprintf(file, "## Recommendations\n\n")
	
	summary := r.report.Summary
	if summary == nil {
		summary = r.buildSummary()
	}
	
	if len(summary.Recommendations) > 0 {
		for i, rec := range summary.Recommendations {
			fmt.Fprintf(file, "%d. %s\n", i+1, rec)
		}
	} else {
		fmt.Fprintf(file, "1. Address all exploitable vulnerabilities (scores: CRITICAL, HIGH, MEDIUM, LOW)\n")
		fmt.Fprintf(file, "2. Review components marked as NOT_EXPLOITABLE to confirm assessment\n")
		fmt.Fprintf(file, "3. Keep dependencies up to date\n")
		fmt.Fprintf(file, "4. Implement security scanning in CI/CD pipeline\n")
	}
	
	fmt.Fprintf(file, "\n")
}

// buildSummary builds a summary from findings
func (r *MarkdownReporter) buildSummary() *models.Summary {
	summary := &models.Summary{
		TotalFindings:   len(r.report.Findings),
		TotalComponents: len(r.report.Components),
		ByScore:         make(map[string]int),
	}
	
	for _, finding := range r.report.Findings {
		score := string(finding.Score)
		summary.ByScore[score]++
		
		if finding.Score != models.ScoreNotExploitable {
			summary.ExploitableCount++
		} else {
			summary.NotExploitableCount++
		}
	}
	
	return summary
}

