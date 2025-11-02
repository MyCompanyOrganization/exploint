package assessor

import (
	"strings"

	"github.com/matanlivne/exploint/pkg/models"
)

// ExecutionPathAnalyzer determines if vulnerable code is in execution path
type ExecutionPathAnalyzer struct{}

// NewExecutionPathAnalyzer creates a new execution path analyzer
func NewExecutionPathAnalyzer() *ExecutionPathAnalyzer {
	return &ExecutionPathAnalyzer{}
}

// AnalyzeExecutionPath determines if a component is in the execution path
func (a *ExecutionPathAnalyzer) AnalyzeExecutionPath(component *models.Component, usageInfo interface{}) (bool, string) {
	// Check component source and type
	switch component.Source {
	case "go.mod":
		// For Go dependencies, check if it's direct and used in code
		if component.Direct {
			return true, "Direct dependency, likely in execution path"
		}
		// Indirect dependencies may still be used
		if usageInfo != nil {
			if info, ok := usageInfo.(*ExecutionPathInfo); ok {
				return info.InExecutionPath, info.Reason
			}
		}
		return false, "Indirect dependency, verify usage in code"
		
	case "dockerfile", "trivy", "container":
		// For container components, check if they're runtime vs build-time
		if a.isRuntimeComponent(component) {
			return true, "Runtime component in container"
		}
		return false, "Build-time component, not in runtime execution path"
		
	default:
		return true, "Component present, assume in execution path"
	}
}

// ExecutionPathInfo contains execution path analysis information
type ExecutionPathInfo struct {
	InExecutionPath bool
	Reason          string
	Files           []string
}

// isRuntimeComponent checks if a component is used at runtime
func (a *ExecutionPathAnalyzer) isRuntimeComponent(component *models.Component) bool {
	// Build-time tools typically have these patterns
	buildTimePatterns := []string{
		"build-", "compile", "make", "gcc", "clang",
		"python-dev", "build-essential", "git", "mercurial",
	}
	
	name := strings.ToLower(component.Name)
	for _, pattern := range buildTimePatterns {
		if strings.Contains(name, pattern) {
			return false
		}
	}
	
	// Python setuptools, pip are typically build-time unless used at runtime
	if component.Type == "pip" {
		buildTools := []string{"setuptools", "pip", "wheel", "build"}
		for _, tool := range buildTools {
			if name == tool {
				return false
			}
		}
	}
	
	return true
}

// AnalyzeDependencyChain analyzes whether a dependency is used directly or indirectly
func (a *ExecutionPathAnalyzer) AnalyzeDependencyChain(component *models.Component) (string, error) {
	if component.Source != "go.mod" {
		return "N/A", nil
	}
	
	if component.Direct {
		return "Direct dependency", nil
	}
	
	return "Indirect dependency", nil
}

