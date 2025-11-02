package golang

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/matanlivne/exploint/pkg/models"
)

// DependencyParser parses Go module dependencies
type DependencyParser struct {
	modulePath string
}

// NewDependencyParser creates a new dependency parser
func NewDependencyParser(modulePath string) *DependencyParser {
	return &DependencyParser{
		modulePath: modulePath,
	}
}

// Parse parses go.mod and go.sum to extract dependencies
func (p *DependencyParser) Parse() ([]*models.Component, error) {
	// Find go.mod file
	goModPath := filepath.Join(p.modulePath, "go.mod")
	if _, err := os.Stat(goModPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("go.mod not found in %s", p.modulePath)
	}

	// Parse go.mod
	components, err := p.parseGoMod(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.mod: %w", err)
	}

	// Parse go.sum to verify checksums (optional)
	goSumPath := filepath.Join(p.modulePath, "go.sum")
	if _, err := os.Stat(goSumPath); err == nil {
		// go.sum exists, but we don't need to parse it for dependency extraction
		// It's used for checksum verification which is handled by Go itself
	}

	return components, nil
}

// parseGoMod parses a go.mod file
func (p *DependencyParser) parseGoMod(path string) ([]*models.Component, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var components []*models.Component

	// Regex patterns for require statements
	requireDirect := regexp.MustCompile(`^\s*require\s+`)
	requireBlock := regexp.MustCompile(`^\s*require\s+\(`)
	inRequireBlock := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// Check for require block start
		if requireBlock.MatchString(line) {
			inRequireBlock = true
			continue
		}

		// Check for require block end
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		// Parse require line
		if requireDirect.MatchString(line) || inRequireBlock {
			comp := p.parseRequireLine(line)
			if comp != nil {
				components = append(components, comp)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return components, nil
}

// parseRequireLine parses a require line from go.mod
func (p *DependencyParser) parseRequireLine(line string) *models.Component {
	// Remove "require" keyword
	line = strings.TrimSpace(line)
	line = regexp.MustCompile(`^\s*require\s+`).ReplaceAllString(line, "")
	line = strings.TrimSpace(line)

	// Handle // indirect comments
	isDirect := true
	if strings.Contains(line, "// indirect") {
		isDirect = false
		line = strings.Split(line, "//")[0]
		line = strings.TrimSpace(line)
	}

	// Split module path and version
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	modulePath := parts[0]
	version := parts[1]

	// Remove version prefix if present (e.g., "v1.2.3" or "v0.0.0-20231201-abc123")
	version = strings.TrimPrefix(version, "v")

	// Extract package name from module path
	moduleParts := strings.Split(modulePath, "/")
	packageName := moduleParts[len(moduleParts)-1]

	// Generate PURL
	purl := fmt.Sprintf("pkg:golang/%s@%s", modulePath, version)

	return &models.Component{
		Name:     packageName,
		Version:  version,
		Type:     "go",
		PURL:     purl,
		Direct:   isDirect,
		Source:   "go.mod",
		Location: modulePath,
	}
}

// GetModuleInfo extracts module information from go.mod
func (p *DependencyParser) GetModuleInfo() (string, string, error) {
	goModPath := filepath.Join(p.modulePath, "go.mod")
	file, err := os.Open(goModPath)
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	moduleRegex := regexp.MustCompile(`^module\s+(.+)$`)
	goVersionRegex := regexp.MustCompile(`^go\s+(.+)$`)

	var moduleName, goVersion string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if matches := moduleRegex.FindStringSubmatch(line); len(matches) > 1 {
			moduleName = matches[1]
		}
		if matches := goVersionRegex.FindStringSubmatch(line); len(matches) > 1 {
			goVersion = matches[1]
		}
	}

	return moduleName, goVersion, scanner.Err()
}
