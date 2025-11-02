package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/matanlivne/exploint/pkg/models"
	"github.com/sashabaranov/go-openai"
)

// OpenAIProvider implements the Provider interface using OpenAI API
type OpenAIProvider struct {
	client *openai.Client
	model  string
}

// NewOpenAIProvider creates a new OpenAI provider
func NewOpenAIProvider(apiKey string, model string) (*OpenAIProvider, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("OpenAI API key is required")
	}

	if model == "" {
		model = openai.GPT4 // Default model
	}

	client := openai.NewClient(apiKey)

	return &OpenAIProvider{
		client: client,
		model:  model,
	}, nil
}

// Name returns the provider name
func (p *OpenAIProvider) Name() string {
	return "openai"
}

// EnrichCVE enriches a CVE with detailed information from the LLM
func (p *OpenAIProvider) EnrichCVE(ctx context.Context, cveID string) (*models.Vulnerability, error) {
	prompt := fmt.Sprintf(`Provide detailed information about %s including:
1. Vulnerability description
2. Affected components and version ranges
3. Attack vectors
4. Exploitation prerequisites
5. CVSS score and severity
6. Any platform-specific requirements

Format the response as JSON with the following structure:
{
  "description": "...",
  "affected_versions": ["..."],
  "attack_vectors": ["..."],
  "exploit_prerequisites": ["..."],
  "cvss_score": 0.0,
  "severity": "..."
}`, cveID)

	resp, err := p.client.CreateChatCompletion(
		ctx,
		openai.ChatCompletionRequest{
			Model: p.model,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: prompt,
				},
			},
			Temperature: 0.3, // Lower temperature for more factual responses
		},
	)

	if err != nil {
		return nil, fmt.Errorf("failed to call OpenAI API: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("no response from OpenAI")
	}

	content := resp.Choices[0].Message.Content

	// Parse JSON response
	var enrichment struct {
		Description          string   `json:"description"`
		AffectedVersions     []string `json:"affected_versions"`
		AttackVectors        []string `json:"attack_vectors"`
		ExploitPrerequisites []string `json:"exploit_prerequisites"`
		CVSSScore            float64  `json:"cvss_score"`
		Severity             string   `json:"severity"`
	}

	// Try to extract JSON from markdown code blocks if present
	if strings.Contains(content, "```json") {
		start := strings.Index(content, "```json") + 7
		end := strings.Index(content[start:], "```")
		if end > 0 {
			content = content[start : start+end]
		}
	} else if strings.Contains(content, "```") {
		start := strings.Index(content, "```") + 3
		end := strings.Index(content[start:], "```")
		if end > 0 {
			content = content[start : start+end]
		}
	}

	if err := json.Unmarshal([]byte(content), &enrichment); err != nil {
		// If JSON parsing fails, use the raw content as description
		vuln := &models.Vulnerability{
			ID:          cveID,
			Type:        "cve",
			Description: content,
		}
		if strings.HasPrefix(cveID, "GHSA-") {
			vuln.Type = "ghsa"
		}
		return vuln, nil
	}

	vuln := &models.Vulnerability{
		ID:                   cveID,
		Type:                 "cve",
		Description:          enrichment.Description,
		AffectedVersions:     enrichment.AffectedVersions,
		AttackVectors:        enrichment.AttackVectors,
		ExploitPrerequisites: enrichment.ExploitPrerequisites,
		CVSSScore:            enrichment.CVSSScore,
		Severity:             enrichment.Severity,
	}

	if strings.HasPrefix(cveID, "GHSA-") {
		vuln.Type = "ghsa"
	}

	return vuln, nil
}

// AnalyzeContext analyzes code context for exploitability
func (p *OpenAIProvider) AnalyzeContext(ctx context.Context, vuln *models.Vulnerability, context string) (string, error) {
	prompt := fmt.Sprintf(`Analyze if %s (%s) is exploitable in the following context:

Vulnerability Details:
- Description: %s
- Attack Vectors: %s
- Prerequisites: %s

Code Context:
%s

Provide an analysis that includes:
1. Is the vulnerable component present and in use?
2. Is it in the execution path?
3. Are the attack vectors viable in this context?
4. Platform/architecture compatibility
5. Overall exploitability assessment

Be specific and reference the code context.`, vuln.ID, vuln.Title, vuln.Description,
		strings.Join(vuln.AttackVectors, ", "),
		strings.Join(vuln.ExploitPrerequisites, ", "),
		context)

	resp, err := p.client.CreateChatCompletion(
		ctx,
		openai.ChatCompletionRequest{
			Model: p.model,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: prompt,
				},
			},
			Temperature: 0.3,
		},
	)

	if err != nil {
		return "", fmt.Errorf("failed to call OpenAI API: %w", err)
	}

	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("no response from OpenAI")
	}

	return resp.Choices[0].Message.Content, nil
}

// AnswerQuestion answers a question about analysis results
func (p *OpenAIProvider) AnswerQuestion(ctx context.Context, question string, context string, history []*models.ChatMessage) (string, error) {
	messages := []openai.ChatCompletionMessage{
		{
			Role:    openai.ChatMessageRoleSystem,
			Content: "You are a security expert helping analyze vulnerability exploitability. Use the provided analysis context to answer questions accurately.",
		},
	}

	// Add conversation history
	for _, msg := range history {
		role := openai.ChatMessageRoleUser
		if msg.Role == "assistant" {
			role = openai.ChatMessageRoleAssistant
		}
		messages = append(messages, openai.ChatCompletionMessage{
			Role:    role,
			Content: msg.Content,
		})
	}

	// Add current question with context
	userMessage := fmt.Sprintf(`Analysis Context:
%s

Question: %s`, context, question)

	messages = append(messages, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleUser,
		Content: userMessage,
	})

	resp, err := p.client.CreateChatCompletion(
		ctx,
		openai.ChatCompletionRequest{
			Model:       p.model,
			Messages:    messages,
			Temperature: 0.7,
		},
	)

	if err != nil {
		return "", fmt.Errorf("failed to call OpenAI API: %w", err)
	}

	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("no response from OpenAI")
	}

	return resp.Choices[0].Message.Content, nil
}
