package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/matanlivne/exploint/pkg/analyzer/container"
	"github.com/matanlivne/exploint/pkg/analyzer/golang"
	"github.com/matanlivne/exploint/pkg/assessor"
	"github.com/matanlivne/exploint/pkg/llm"
	"github.com/matanlivne/exploint/pkg/models"
	"github.com/matanlivne/exploint/pkg/scanner"
)

// MCPRequest represents an MCP JSON-RPC request
type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// MCPResponse represents an MCP JSON-RPC response
type MCPResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

// MCPError represents an MCP error
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ToolCall represents an MCP tool call
type ToolCall struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// ToolResult represents the result of a tool execution with LLM prompts
type ToolResult struct {
	Report    interface{}            `json:"report"`
	LLMPrompts map[string]interface{} `json:"llm_prompts,omitempty"`
}

// AnalysisResult wraps the full analysis result
type AnalysisResult struct {
	Success     bool                   `json:"success"`
	Report      *models.Report         `json:"report"`
	LLMPrompts  map[string]interface{} `json:"llm_prompts,omitempty"`
	Message     string                 `json:"message,omitempty"`
}

func main() {
	// Set MCP_SERVER environment variable for auto-detection
	os.Setenv("MCP_SERVER", "1")
	
	decoder := json.NewDecoder(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	
	// Initialize the server
	initialize(encoder)
	
	// Process requests
	for {
		var req MCPRequest
		if err := decoder.Decode(&req); err != nil {
			break // EOF or invalid JSON
		}
		
		resp := handleRequest(&req)
		if resp != nil {
			encoder.Encode(resp)
		}
	}
}

func initialize(encoder *json.Encoder) {
	// Send initialize response
	resp := MCPResponse{
		JSONRPC: "2.0",
		ID:      1,
		Result: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]interface{}{
				"name":    "exploint-mcp",
				"version": "1.0.0",
			},
		},
	}
	encoder.Encode(resp)
	
	// Send initialized notification
	notif := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	encoder.Encode(notif)
}

func handleRequest(req *MCPRequest) *MCPResponse {
	switch req.Method {
	case "tools/list":
		return handleToolsList(req)
	case "tools/call":
		return handleToolCall(req)
	default:
		if req.Method != "" && !strings.HasPrefix(req.Method, "notifications/") {
			return &MCPResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &MCPError{
					Code:    -32601,
					Message: fmt.Sprintf("Method not found: %s", req.Method),
				},
			}
		}
	}
	return nil
}

func handleToolsList(req *MCPRequest) *MCPResponse {
	tools := []map[string]interface{}{
		{
			"name":        "analyze_repository",
			"description": "Analyze a Go repository for vulnerability exploitability",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Path to the Go repository",
					},
					"scan": map[string]interface{}{
						"type":        "boolean",
						"description": "Run Trivy scan (default: true)",
						"default":     true,
					},
					"use_cursor_llm": map[string]interface{}{
						"type":        "boolean",
						"description": "Use Cursor's LLM for enrichment (default: true)",
						"default":     true,
					},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "analyze_image",
			"description": "Analyze a Docker image for vulnerability exploitability",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"image": map[string]interface{}{
						"type":        "string",
						"description": "Docker image name/tag",
					},
					"scan": map[string]interface{}{
						"type":        "boolean",
						"description": "Run Trivy scan (default: true)",
						"default":     true,
					},
					"use_cursor_llm": map[string]interface{}{
						"type":        "boolean",
						"description": "Use Cursor's LLM for enrichment (default: true)",
						"default":     true,
					},
				},
				"required": []string{"image"},
			},
		},
		{
			"name":        "analyze_cves",
			"description": "Analyze specific CVEs for a repository or image",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"cves": map[string]interface{}{
						"type":        "string",
						"description": "Comma-separated list of CVE IDs",
					},
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Path to repository (optional if image provided)",
					},
					"image": map[string]interface{}{
						"type":        "string",
						"description": "Docker image name (optional if path provided)",
					},
					"use_cursor_llm": map[string]interface{}{
						"type":        "boolean",
						"description": "Use Cursor's LLM for enrichment (default: true)",
						"default":     true,
					},
				},
				"required": []string{"cves"},
			},
		},
	}
	
	return &MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"tools": tools,
		},
	}
}

func handleToolCall(req *MCPRequest) *MCPResponse {
	var call ToolCall
	if err := json.Unmarshal(req.Params, &call); err != nil {
		return &MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &MCPError{
				Code:    -32602,
				Message: fmt.Sprintf("Invalid params: %v", err),
			},
		}
	}
	
	ctx := context.Background()
	var result *AnalysisResult
	var err error
	
	switch call.Name {
	case "analyze_repository":
		path := getStringArg(call.Arguments, "path")
		useCursorLLM := getBoolArg(call.Arguments, "use_cursor_llm", true)
		scanFlag := getBoolArg(call.Arguments, "scan", true)
		result, err = analyzeRepository(ctx, path, scanFlag, useCursorLLM)
		
	case "analyze_image":
		image := getStringArg(call.Arguments, "image")
		useCursorLLM := getBoolArg(call.Arguments, "use_cursor_llm", true)
		scanFlag := getBoolArg(call.Arguments, "scan", true)
		result, err = analyzeImage(ctx, image, scanFlag, useCursorLLM)
		
	case "analyze_cves":
		cvesStr := getStringArg(call.Arguments, "cves")
		path := getStringArg(call.Arguments, "path")
		image := getStringArg(call.Arguments, "image")
		useCursorLLM := getBoolArg(call.Arguments, "use_cursor_llm", true)
		result, err = analyzeCVEs(ctx, cvesStr, path, image, useCursorLLM)
		
	default:
		return &MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &MCPError{
				Code:    -32601,
				Message: fmt.Sprintf("Unknown tool: %s", call.Name),
			},
		}
	}
	
	if err != nil {
		return &MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &MCPError{
				Code:    -32000,
				Message: err.Error(),
			},
		}
	}
	
	return &MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

func analyzeRepository(ctx context.Context, path string, scan bool, useCursorLLM bool) (*AnalysisResult, error) {
	// Set provider to cursor if requested
	if useCursorLLM {
		os.Setenv("EXPLOINT_LLM_PROVIDER", "cursor")
	}
	
	var vulnerabilities []*models.Vulnerability
	var components []*models.Component
	var err error
	
	// Scan if requested
	if scan {
		trivyScanner := scanner.NewTrivyScanner()
		if trivyScanner.IsAvailable() {
			vulnerabilities, components, err = trivyScanner.ScanFilesystem(path)
			if err != nil {
				return nil, fmt.Errorf("trivy scan failed: %w", err)
			}
		}
	}
	
	// Analyze Go code dependencies
	depParser := golang.NewDependencyParser(path)
	deps, err := depParser.Parse()
	if err == nil {
		components = append(components, deps...)
	}
	
	// Assess exploitability
	findings := assessExploitability(ctx, vulnerabilities, components, path, "repository", useCursorLLM)
	
	// Build report
	report := buildReport(path, "repository", findings, components)
	
	// Collect LLM prompts if using Cursor LLM
	llmPrompts := collectLLMPrompts(findings, useCursorLLM)
	
	return &AnalysisResult{
		Success:    true,
		Report:     report,
		LLMPrompts: llmPrompts,
		Message:    fmt.Sprintf("Analyzed %d vulnerabilities in repository", len(findings)),
	}, nil
}

func analyzeImage(ctx context.Context, image string, scan bool, useCursorLLM bool) (*AnalysisResult, error) {
	if useCursorLLM {
		os.Setenv("EXPLOINT_LLM_PROVIDER", "cursor")
	}
	
	var vulnerabilities []*models.Vulnerability
	var components []*models.Component
	var err error
	
	if scan {
		trivyScanner := scanner.NewTrivyScanner()
		if trivyScanner.IsAvailable() {
			vulnerabilities, components, err = trivyScanner.ScanImage(image)
			if err != nil {
				return nil, fmt.Errorf("trivy scan failed: %w", err)
			}
		}
	}
	
	// Analyze container image (returns vulnerabilities and components)
	imageAnalyzer := container.NewImageAnalyzer()
	imageVulns, imageComponents, err := imageAnalyzer.AnalyzeImage(image)
	if err == nil {
		vulnerabilities = append(vulnerabilities, imageVulns...)
		components = append(components, imageComponents...)
	}
	
	findings := assessExploitability(ctx, vulnerabilities, components, image, "image", useCursorLLM)
	report := buildReport(image, "image", findings, components)
	llmPrompts := collectLLMPrompts(findings, useCursorLLM)
	
	return &AnalysisResult{
		Success:    true,
		Report:     report,
		LLMPrompts: llmPrompts,
		Message:    fmt.Sprintf("Analyzed %d vulnerabilities in image", len(findings)),
	}, nil
}

func analyzeCVEs(ctx context.Context, cvesStr, path, image string, useCursorLLM bool) (*AnalysisResult, error) {
	if useCursorLLM {
		os.Setenv("EXPLOINT_LLM_PROVIDER", "cursor")
	}
	
	manualScanner := scanner.NewManualScanner()
	vulnerabilities, err := manualScanner.ParseCVEsFromString(cvesStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CVEs: %w", err)
	}
	
	var components []*models.Component
	var target string
	var targetType string
	
	if path != "" {
		target = path
		targetType = "repository"
		depParser := golang.NewDependencyParser(path)
		deps, _ := depParser.Parse()
		components = append(components, deps...)
	} else if image != "" {
		target = image
		targetType = "image"
		imageAnalyzer := container.NewImageAnalyzer()
		_, imageComponents, _ := imageAnalyzer.AnalyzeImage(image)
		components = append(components, imageComponents...)
	} else {
		target = "manual"
		targetType = "manual"
	}
	
	findings := assessExploitability(ctx, vulnerabilities, components, target, targetType, useCursorLLM)
	report := buildReport(target, targetType, findings, components)
	llmPrompts := collectLLMPrompts(findings, useCursorLLM)
	
	return &AnalysisResult{
		Success:    true,
		Report:     report,
		LLMPrompts: llmPrompts,
		Message:    fmt.Sprintf("Analyzed %d CVEs", len(findings)),
	}, nil
}

func assessExploitability(ctx context.Context, vulnerabilities []*models.Vulnerability, components []*models.Component, target, targetType string, useCursorLLM bool) []*models.Finding {
	presenceVerifier := assessor.NewPresenceVerifier()
	pathAnalyzer := assessor.NewExecutionPathAnalyzer()
	vectorAssessor := assessor.NewAttackVectorAssessor()
	scorer := assessor.NewExploitabilityScorer()
	
	var findings []*models.Finding
	
	for _, vuln := range vulnerabilities {
		matchingComponents := presenceVerifier.FindMatchingComponents(vuln, components)
		
		if len(matchingComponents) == 0 {
			findings = append(findings, &models.Finding{
				Vulnerability:      vuln,
				Component:          nil,
				Score:              models.ScoreNotExploitable,
				Assessment:         "Component not found in codebase/container",
				ComponentPresent:   false,
				InExecutionPath:    false,
				AttackVectorValid:  false,
				PlatformCompatible: true,
				AnalyzedAt:         time.Now(),
			})
			continue
		}
		
		for _, comp := range matchingComponents {
			present, _ := presenceVerifier.VerifyComponentPresence(vuln, []*models.Component{comp})
			inPath, reason := pathAnalyzer.AnalyzeExecutionPath(comp, nil)
			context := map[string]interface{}{
				"platform": "linux",
			}
			vectorValid, vectorReason := vectorAssessor.AnalyzeAttackVector(vuln, comp, context)
			
			finding := &models.Finding{
				Vulnerability:      vuln,
				Component:          comp,
				Assessment:         fmt.Sprintf("%s. %s", reason, vectorReason),
				ComponentPresent:   present,
				InExecutionPath:    inPath,
				AttackVectorValid:  vectorValid,
				PlatformCompatible: true,
				AnalyzedAt:         time.Now(),
			}
			
			finding.Score = scorer.Score(finding)
			
			// If using Cursor LLM, generate prompt for context analysis
			if useCursorLLM {
				cursorProvider, _ := llm.NewCursorProvider()
				codeContext := fmt.Sprintf("Component: %s, Location: %s", comp.Name, comp.Location)
				prompt, err := cursorProvider.AnalyzeContext(ctx, vuln, codeContext)
				if err == nil {
					finding.LLMInsights = prompt // Store prompt for Cursor to process
				}
			}
			
			findings = append(findings, finding)
		}
	}
	
	return findings
}

func buildReport(target, targetType string, findings []*models.Finding, components []*models.Component) *models.Report {
	summary := &models.Summary{
		TotalFindings:   len(findings),
		TotalComponents: len(components),
		ByScore:         make(map[string]int),
	}
	
	for _, finding := range findings {
		score := string(finding.Score)
		summary.ByScore[score]++
		if finding.Score != models.ScoreNotExploitable {
			summary.ExploitableCount++
		} else {
			summary.NotExploitableCount++
		}
	}
	
	return &models.Report{
		GeneratedAt: time.Now(),
		Target:       target,
		TargetType:   targetType,
		Findings:     findings,
		Components:   components,
		Summary:      summary,
	}
}

func collectLLMPrompts(findings []*models.Finding, useCursorLLM bool) map[string]interface{} {
	if !useCursorLLM {
		return nil
	}
	
	prompts := map[string]interface{}{
		"enrichment_prompts": []map[string]string{},
		"analysis_prompts":   []map[string]interface{}{},
	}
	
	cvesNeedingEnrichment := make(map[string]bool)
	analysisPrompts := []map[string]interface{}{}
	
	for _, finding := range findings {
		if finding.Vulnerability != nil {
			// Check if CVE needs enrichment
			if finding.Vulnerability.Description != "" && 
			   strings.Contains(finding.Vulnerability.Description, "[CURSOR_LLM_PROMPT:ENRICH_CVE]") {
				cvesNeedingEnrichment[finding.Vulnerability.ID] = true
			}
			
			// Collect analysis prompts
			if finding.LLMInsights != "" {
				analysisPrompts = append(analysisPrompts, map[string]interface{}{
					"finding_id": finding.Vulnerability.ID,
					"component":   getComponentName(finding.Component),
					"prompt":      finding.LLMInsights,
				})
			}
		}
	}
	
	// Build enrichment prompts
	enrichmentPrompts := []map[string]string{}
	for cveID := range cvesNeedingEnrichment {
		cursorProvider, _ := llm.NewCursorProvider()
		vuln, _ := cursorProvider.EnrichCVE(context.Background(), cveID)
		if vuln != nil {
			enrichmentPrompts = append(enrichmentPrompts, map[string]string{
				"cve":    cveID,
				"prompt": vuln.Description,
			})
		}
	}
	
	prompts["enrichment_prompts"] = enrichmentPrompts
	prompts["analysis_prompts"] = analysisPrompts
	
	return prompts
}

func getComponentName(comp *models.Component) string {
	if comp == nil {
		return "Unknown"
	}
	return comp.Name
}

func getStringArg(args map[string]interface{}, key string) string {
	if val, ok := args[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getBoolArg(args map[string]interface{}, key string, defaultValue bool) bool {
	if val, ok := args[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return defaultValue
}

