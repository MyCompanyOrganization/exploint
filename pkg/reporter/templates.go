package reporter

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/matanlivne/exploint/pkg/models"
)

// TemplateSystem provides customizable report templates
type TemplateSystem struct{}

// NewTemplateSystem creates a new template system
func NewTemplateSystem() *TemplateSystem {
	return &TemplateSystem{}
}

// Format represents output format
type Format string

const (
	FormatMarkdown Format = "md"
	FormatJSON     Format = "json"
	FormatVEX      Format = "vex"
	FormatBoth     Format = "both"
)

// GenerateReport generates a report in the specified format(s)
func (t *TemplateSystem) GenerateReport(report *models.Report, outputPath string, format Format) error {
	switch format {
	case FormatMarkdown:
		reporter := NewMarkdownReporter(report)
		return reporter.Generate(outputPath)
		
	case FormatJSON:
		return t.generateJSON(report, outputPath)
		
	case FormatVEX:
		generator := NewVEXGenerator(report)
		return generator.Generate(outputPath)
		
	case FormatBoth:
		// Generate both markdown and JSON
		mdPath := fmt.Sprintf("%s.md", outputPath)
		jsonPath := fmt.Sprintf("%s.json", outputPath)
		
		mdReporter := NewMarkdownReporter(report)
		if err := mdReporter.Generate(mdPath); err != nil {
			return fmt.Errorf("failed to generate markdown: %w", err)
		}
		
		if err := t.generateJSON(report, jsonPath); err != nil {
			return fmt.Errorf("failed to generate JSON: %w", err)
		}
		
		return nil
		
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// generateJSON generates a JSON report
func (t *TemplateSystem) generateJSON(report *models.Report, outputPath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}
	
	return nil
}

