package llm

import (
	"context"
	"fmt"

	"github.com/matanlivne/exploint/pkg/models"
)

// CursorProvider implements the Provider interface for Cursor IDE LLM integration
// Instead of calling LLM APIs, it returns structured prompts that Cursor's LLM can process
type CursorProvider struct{}

// NewCursorProvider creates a new Cursor provider
func NewCursorProvider() (*CursorProvider, error) {
	return &CursorProvider{}, nil
}

// Name returns the provider name
func (p *CursorProvider) Name() string {
	return "cursor"
}

// EnrichCVE returns a structured prompt for Cursor's LLM to enrich a CVE
// The prompt is returned as a special format that Cursor can process
func (p *CursorProvider) EnrichCVE(ctx context.Context, cveID string) (*models.Vulnerability, error) {
	// Return a vulnerability with a special prompt in the description
	// This prompt will be processed by Cursor's LLM when it sees the tool results
	prompt := fmt.Sprintf(`[CURSOR_LLM_PROMPT:ENRICH_CVE]
Please provide detailed information about %s including:
1. Vulnerability description
2. Affected components and version ranges
3. Attack vectors
4. Exploitation prerequisites
5. CVSS score and severity (if known)
6. Any platform-specific requirements

Format your response as structured information that can be used for security analysis.
CVE ID: %s`, cveID, cveID)

	// Return a vulnerability object with the prompt that Cursor will process
	// The actual enrichment will happen when Cursor's LLM processes this
	return &models.Vulnerability{
		ID:          cveID,
		Type:        "cve",
		Description: prompt,
		Title:       fmt.Sprintf("%s (Cursor LLM enrichment needed)", cveID),
	}, nil
}

// AnalyzeContext returns a structured prompt for Cursor's LLM to analyze exploitability
func (p *CursorProvider) AnalyzeContext(ctx context.Context, vuln *models.Vulnerability, context string) (string, error) {
	// Return an analysis prompt that Cursor's LLM will process
	prompt := fmt.Sprintf(`[CURSOR_LLM_PROMPT:ANALYZE_CONTEXT]
Analyze if %s (%s) is exploitable in the following context:

Vulnerability Details:
- Description: %s
- Attack Vectors: %s
- Prerequisites: %s

Code/Container Context:
%s

Provide an analysis that includes:
1. Is the vulnerable component present and in use?
2. Is it in the execution path?
3. Are the attack vectors viable in this context?
4. Platform/architecture compatibility
5. Overall exploitability assessment

Be specific and reference the code context provided.`, 
		vuln.ID, 
		vuln.Title, 
		vuln.Description,
		joinStrings(vuln.AttackVectors),
		joinStrings(vuln.ExploitPrerequisites),
		context)

	return prompt, nil
}

// AnswerQuestion returns a structured prompt for Cursor's LLM to answer questions
func (p *CursorProvider) AnswerQuestion(ctx context.Context, question string, context string, history []*models.ChatMessage) (string, error) {
	// Build conversation context
	historyText := ""
	for _, msg := range history {
		historyText += fmt.Sprintf("\n%s: %s", msg.Role, msg.Content)
	}

	prompt := fmt.Sprintf(`[CURSOR_LLM_PROMPT:ANSWER_QUESTION]
You are a security expert helping analyze vulnerability exploitability.

Analysis Context:
%s

Conversation History:%s

Question: %s

Please provide a detailed answer based on the analysis context and conversation history.`, 
		context, 
		historyText, 
		question)

	return prompt, nil
}

// joinStrings joins a slice of strings with commas
func joinStrings(strs []string) string {
	if len(strs) == 0 {
		return "None specified"
	}
	result := ""
	for i, s := range strs {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}

