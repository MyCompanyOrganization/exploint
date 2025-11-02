package container

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/matanlivne/exploint/pkg/models"
)

// DockerfileParser parses Dockerfiles to extract components
type DockerfileParser struct {
	dockerfilePath string
}

// NewDockerfileParser creates a new Dockerfile parser
func NewDockerfileParser(dockerfilePath string) *DockerfileParser {
	return &DockerfileParser{
		dockerfilePath: dockerfilePath,
	}
}

// Parse parses a Dockerfile and extracts components
func (p *DockerfileParser) Parse() ([]*models.Component, string, error) {
	data, err := os.ReadFile(p.dockerfilePath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read Dockerfile: %w", err)
	}
	
	lines := strings.Split(string(data), "\n")
	var components []*models.Component
	var baseImage string
	
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Parse FROM directive for base image
		if strings.HasPrefix(line, "FROM ") {
			baseImage = p.parseFrom(line)
			if baseImage != "" {
				comp := &models.Component{
					Name:     baseImage,
					Type:     "docker",
					Source:   "dockerfile",
					Location: fmt.Sprintf("Dockerfile:%d", i+1),
				}
				components = append(components, comp)
			}
		}
		
		// Parse package installation commands
		comp := p.parsePackageInstall(line, i+1)
		if comp != nil {
			components = append(components, comp)
		}
	}
	
	return components, baseImage, nil
}

// parseFrom parses a FROM directive
func (p *DockerfileParser) parseFrom(line string) string {
	// FROM [--platform=...] image[:tag] [AS name]
	parts := strings.Fields(line)
	for i, part := range parts {
		if part == "FROM" && i+1 < len(parts) {
			next := parts[i+1]
			// Skip --platform flag
			if strings.HasPrefix(next, "--") {
				if i+2 < len(parts) {
					return parts[i+2]
				}
				return ""
			}
			return next
		}
	}
	return ""
}

// parsePackageInstall parses package installation commands
func (p *DockerfileParser) parsePackageInstall(line string, lineNum int) *models.Component {
	// APK (Alpine)
	if strings.HasPrefix(line, "RUN apk add") || strings.HasPrefix(line, "RUN apk install") {
		return p.parseApkInstall(line, lineNum)
	}
	
	// APT (Debian/Ubuntu)
	if strings.HasPrefix(line, "RUN apt-get install") || strings.HasPrefix(line, "RUN apt install") {
		return p.parseAptInstall(line, lineNum)
	}
	
	// PIP (Python)
	if strings.Contains(line, "pip install") {
		return p.parsePipInstall(line, lineNum)
	}
	
	// NPM (Node.js)
	if strings.Contains(line, "npm install") {
		return p.parseNpmInstall(line, lineNum)
	}
	
	return nil
}

// parseApkInstall parses apk add commands
func (p *DockerfileParser) parseApkInstall(line string, lineNum int) *models.Component {
	// Extract package names from: RUN apk add package1 package2
	re := regexp.MustCompile(`apk\s+(?:add|install)\s+(.+)`)
	matches := re.FindStringSubmatch(line)
	if len(matches) < 2 {
		return nil
	}
	
	packages := strings.Fields(matches[1])
	if len(packages) == 0 {
		return nil
	}
	
	// Take first package as example (simplified)
	pkg := packages[0]
	
	return &models.Component{
		Name:     pkg,
		Type:     "apk",
		Source:   "dockerfile",
		Location: fmt.Sprintf("Dockerfile:%d", lineNum),
	}
}

// parseAptInstall parses apt-get install commands
func (p *DockerfileParser) parseAptInstall(line string, lineNum int) *models.Component {
	re := regexp.MustCompile(`apt(?:-get)?\s+install\s+(.+)`)
	matches := re.FindStringSubmatch(line)
	if len(matches) < 2 {
		return nil
	}
	
	packages := strings.Fields(matches[1])
	if len(packages) == 0 {
		return nil
	}
	
	pkg := packages[0]
	
	return &models.Component{
		Name:     pkg,
		Type:     "apt",
		Source:   "dockerfile",
		Location: fmt.Sprintf("Dockerfile:%d", lineNum),
	}
}

// parsePipInstall parses pip install commands
func (p *DockerfileParser) parsePipInstall(line string, lineNum int) *models.Component {
	re := regexp.MustCompile(`pip\s+install\s+(.+)`)
	matches := re.FindStringSubmatch(line)
	if len(matches) < 2 {
		return nil
	}
	
	// Extract package name (may include version)
	pkgSpec := strings.TrimSpace(matches[1])
	// Remove flags
	pkgSpec = regexp.MustCompile(`\s+--.*$`).ReplaceAllString(pkgSpec, "")
	
	// Extract package name (before version specifiers)
	pkgParts := regexp.MustCompile(`[<>=!]`).Split(pkgSpec, 2)
	pkg := strings.TrimSpace(pkgParts[0])
	
	return &models.Component{
		Name:     pkg,
		Type:     "pip",
		Source:   "dockerfile",
		Location: fmt.Sprintf("Dockerfile:%d", lineNum),
	}
}

// parseNpmInstall parses npm install commands
func (p *DockerfileParser) parseNpmInstall(line string, lineNum int) *models.Component {
	re := regexp.MustCompile(`npm\s+install\s+(.+)`)
	matches := re.FindStringSubmatch(line)
	if len(matches) < 2 {
		return nil
	}
	
	pkgSpec := strings.TrimSpace(matches[1])
	pkgParts := strings.Fields(pkgSpec)
	if len(pkgParts) == 0 {
		return nil
	}
	
	pkg := pkgParts[0]
	
	return &models.Component{
		Name:     pkg,
		Type:     "npm",
		Source:   "dockerfile",
		Location: fmt.Sprintf("Dockerfile:%d", lineNum),
	}
}

