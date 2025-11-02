package llm

import (
	"context"
	"fmt"

	"github.com/matanlivne/exploint/pkg/models"
)

// Analyzer provides context-aware analysis enhancement using LLM
type Analyzer struct {
	provider Provider
}

// NewAnalyzer creates a new analyzer instance
func NewAnalyzer(provider Provider) *Analyzer {
	return &Analyzer{
		provider: provider,
	}
}

// AnalyzeExploitability analyzes exploitability with code context
func (a *Analyzer) AnalyzeExploitability(ctx context.Context, finding *models.Finding, codeContext string) (string, error) {
	// Build context string
	context := fmt.Sprintf(`Component: %s (version: %s)
Location: %s
Component Present: %v
In Execution Path: %v
Platform Compatible: %v

Code Context:
%s`, finding.Component.Name, finding.Component.Version,
		finding.Component.Location, finding.ComponentPresent,
		finding.InExecutionPath, finding.PlatformCompatible,
		codeContext)

	insights, err := a.provider.AnalyzeContext(ctx, finding.Vulnerability, context)
	if err != nil {
		return "", fmt.Errorf("failed to analyze exploitability: %w", err)
	}

	return insights, nil
}

// EnhanceFinding enhances a finding with LLM insights
func (a *Analyzer) EnhanceFinding(ctx context.Context, finding *models.Finding, codeContext string) error {
	insights, err := a.AnalyzeExploitability(ctx, finding, codeContext)
	if err != nil {
		return err
	}

	finding.LLMInsights = insights
	return nil
}
