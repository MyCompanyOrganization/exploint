package golang

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/matanlivne/exploint/pkg/models"
)

// ASTAnalyzer analyzes Go code using AST to find component usage
type ASTAnalyzer struct {
	modulePath string
	fileSet    *token.FileSet
}

// NewASTAnalyzer creates a new AST analyzer
func NewASTAnalyzer(modulePath string) *ASTAnalyzer {
	return &ASTAnalyzer{
		modulePath: modulePath,
		fileSet:    token.NewFileSet(),
	}
}

// UsageInfo contains information about component usage in code
type UsageInfo struct {
	Component     *models.Component
	Files         []string       // Files where component is used
	Functions     []FunctionCall // Functions that use the component
	InMainPath    bool           // Whether used in main execution path
	ExecutionPath []string       // Execution path graph
}

// FunctionCall represents a function call involving a component
type FunctionCall struct {
	File     string
	Function string
	Line     int
	Type     string // "import", "call", "type"
}

// AnalyzeComponentUsage analyzes where a component is used in the codebase
func (a *ASTAnalyzer) AnalyzeComponentUsage(componentName string) (*UsageInfo, error) {
	usage := &UsageInfo{
		Component: &models.Component{
			Name: componentName,
			Type: "go",
		},
		Files:         []string{},
		Functions:     []FunctionCall{},
		ExecutionPath: []string{},
	}

	// Walk through all .go files
	err := filepath.Walk(a.modulePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			// Skip vendor and hidden directories
			if info.Name() == "vendor" || strings.HasPrefix(info.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		// Parse file
		fileInfo, err := a.parseFile(path)
		if err != nil {
			// Skip files with parse errors
			return nil
		}

		// Check for component usage
		if used, calls := a.checkComponentUsage(fileInfo, componentName); used {
			usage.Files = append(usage.Files, path)
			usage.Functions = append(usage.Functions, calls...)

			// Check if it's in main execution path
			if a.isMainExecutionPath(fileInfo, path) {
				usage.InMainPath = true
			}
		}

		return nil
	})

	return usage, err
}

// parseFile parses a Go file and returns its AST
func (a *ASTAnalyzer) parseFile(path string) (*ast.File, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return parser.ParseFile(a.fileSet, path, src, parser.ParseComments)
}

// checkComponentUsage checks if a component is used in a file
func (a *ASTAnalyzer) checkComponentUsage(file *ast.File, componentName string) (bool, []FunctionCall) {
	var calls []FunctionCall
	used := false

	// Check imports
	for _, imp := range file.Imports {
		impPath := strings.Trim(imp.Path.Value, "\"")
		if strings.Contains(impPath, componentName) {
			used = true
			pos := a.fileSet.Position(imp.Pos())
			calls = append(calls, FunctionCall{
				File:     pos.Filename,
				Function: "import",
				Line:     pos.Line,
				Type:     "import",
			})
		}
	}

	// Check function calls and type usage
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok {
					if strings.Contains(id.Name, componentName) ||
						strings.Contains(fmt.Sprintf("%v", sel), componentName) {
						used = true
						pos := a.fileSet.Position(n.Pos())
						calls = append(calls, FunctionCall{
							File:     pos.Filename,
							Function: fmt.Sprintf("%v", sel),
							Line:     pos.Line,
							Type:     "call",
						})
					}
				}
			}
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok {
				if strings.Contains(id.Name, componentName) ||
					strings.Contains(fmt.Sprintf("%v", x), componentName) {
					used = true
					pos := a.fileSet.Position(n.Pos())
					calls = append(calls, FunctionCall{
						File:     pos.Filename,
						Function: fmt.Sprintf("%v", x),
						Line:     pos.Line,
						Type:     "type",
					})
				}
			}
		}
		return true
	})

	return used, calls
}

// isMainExecutionPath checks if a file is part of the main execution path
func (a *ASTAnalyzer) isMainExecutionPath(file *ast.File, path string) bool {
	// Check if it's main.go or contains main function
	if strings.HasSuffix(path, "main.go") {
		return true
	}

	// Check for main function
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			if fn.Name.Name == "main" {
				return true
			}
		}
	}

	return false
}

// BuildExecutionPath builds an execution path graph
func (a *ASTAnalyzer) BuildExecutionPath(componentName string) ([]string, error) {
	// Simplified execution path analysis
	// Full implementation would require more sophisticated call graph analysis
	usage, err := a.AnalyzeComponentUsage(componentName)
	if err != nil {
		return nil, err
	}

	var path []string
	for _, file := range usage.Files {
		path = append(path, file)
	}

	return path, nil
}
