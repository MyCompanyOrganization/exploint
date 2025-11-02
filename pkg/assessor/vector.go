package assessor

import (
	"fmt"
	"strings"

	"github.com/matanlivne/exploint/pkg/models"
)

// AttackVectorAssessor analyzes attack vectors for vulnerabilities
type AttackVectorAssessor struct{}

// NewAttackVectorAssessor creates a new attack vector assessor
func NewAttackVectorAssessor() *AttackVectorAssessor {
	return &AttackVectorAssessor{}
}

// AnalyzeAttackVector analyzes if an attack vector is viable
func (a *AttackVectorAssessor) AnalyzeAttackVector(vuln *models.Vulnerability, component *models.Component, context map[string]interface{}) (bool, string) {
	// Check platform compatibility first
	if !a.isPlatformCompatible(vuln, component, context) {
		return false, "Platform mismatch - vulnerability not applicable"
	}
	
	// Analyze based on attack vectors from vulnerability
	for _, vector := range vuln.AttackVectors {
		viable, reason := a.checkVectorViability(vector, component, context)
		if viable {
			return true, reason
		}
	}
	
	// Default: check if network exposure exists
	if a.hasNetworkExposure(context) {
		return true, "Network-exposed component"
	}
	
	// Check if it's a CLI tool without network (less exploitable)
	if a.isCLITool(context) {
		return false, "CLI tool without network exposure - low attack surface"
	}
	
	return false, "Attack vector not viable in current context"
}

// isPlatformCompatible checks platform compatibility
func (a *AttackVectorAssessor) isPlatformCompatible(vuln *models.Vulnerability, component *models.Component, context map[string]interface{}) bool {
	// Extract platform from context
	platform := ""
	if p, ok := context["platform"].(string); ok {
		platform = strings.ToLower(p)
	}
	
	// Check vulnerability description for platform-specific mentions
	desc := strings.ToLower(vuln.Description)
	
	// Windows-specific vulnerabilities
	if strings.Contains(desc, "windows") || strings.Contains(desc, "win32") {
		if !strings.Contains(platform, "windows") {
			return false
		}
	}
	
	// Linux-specific vulnerabilities
	if strings.Contains(desc, "linux-only") || strings.Contains(desc, "unix") {
		if strings.Contains(platform, "windows") {
			return false
		}
	}
	
	// Check component type
	if component.Type == "apk" || component.Type == "apt" {
		// These are Linux package managers
		if strings.Contains(platform, "windows") {
			return false
		}
	}
	
	return true
}

// checkVectorViability checks if a specific attack vector is viable
func (a *AttackVectorAssessor) checkVectorViability(vector string, component *models.Component, context map[string]interface{}) (bool, string) {
	vectorLower := strings.ToLower(vector)
	
	// Network-based attacks
	if strings.Contains(vectorLower, "network") || strings.Contains(vectorLower, "remote") {
		if a.hasNetworkExposure(context) {
			return true, fmt.Sprintf("Network attack vector viable: %s", vector)
		}
		return false, "Network attack vector not viable - no network exposure"
	}
	
	// Local attacks
	if strings.Contains(vectorLower, "local") {
		return true, fmt.Sprintf("Local attack vector viable: %s", vector)
	}
	
	// Authentication-based
	if strings.Contains(vectorLower, "authenticated") || strings.Contains(vectorLower, "login") {
		if a.requiresAuth(context) {
			return true, fmt.Sprintf("Authenticated attack vector viable: %s", vector)
		}
		return false, "Authentication required but not present"
	}
	
	return true, fmt.Sprintf("Attack vector viable: %s", vector)
}

// hasNetworkExposure checks if there's network exposure
func (a *AttackVectorAssessor) hasNetworkExposure(context map[string]interface{}) bool {
	// Check for HTTP server indicators
	if httpServer, ok := context["http_server"].(bool); ok && httpServer {
		return true
	}
	
	// Check for listening ports
	if ports, ok := context["ports"].([]int); ok && len(ports) > 0 {
		return true
	}
	
	// Check for network libraries in Go
	if imports, ok := context["imports"].([]string); ok {
		networkImports := []string{"net/http", "net", "http"}
		for _, imp := range imports {
			for _, netImp := range networkImports {
				if strings.Contains(imp, netImp) {
					return true
				}
			}
		}
	}
	
	return false
}

// isCLITool checks if the application is a CLI tool
func (a *AttackVectorAssessor) isCLITool(context map[string]interface{}) bool {
	// Check if it's explicitly marked as CLI
	if cli, ok := context["cli_tool"].(bool); ok && cli {
		return true
	}
	
	// Check for main function without HTTP server
	if hasMain, ok := context["has_main"].(bool); ok && hasMain {
		if !a.hasNetworkExposure(context) {
			return true
		}
	}
	
	return false
}

// requiresAuth checks if authentication is required
func (a *AttackVectorAssessor) requiresAuth(context map[string]interface{}) bool {
	// This would need more sophisticated analysis
	if auth, ok := context["requires_auth"].(bool); ok {
		return auth
	}
	
	return false
}

