package llm

import (
	"context"

	"github.com/matanlivne/exploint/pkg/models"
)

// Provider defines the interface for LLM providers
type Provider interface {
	// EnrichCVE enriches a CVE with detailed information
	EnrichCVE(ctx context.Context, cveID string) (*models.Vulnerability, error)

	// AnalyzeContext analyzes code context for exploitability
	AnalyzeContext(ctx context.Context, vuln *models.Vulnerability, context string) (string, error)

	// AnswerQuestion answers a question about analysis results
	AnswerQuestion(ctx context.Context, question string, context string, history []*models.ChatMessage) (string, error)

	// Name returns the provider name
	Name() string
}
