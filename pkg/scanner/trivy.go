package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/matanlivne/exploint/pkg/models"
)

// TrivyScanner integrates with Trivy for vulnerability scanning
type TrivyScanner struct {
	trivyPath string
}

// NewTrivyScanner creates a new Trivy scanner instance
func NewTrivyScanner() *TrivyScanner {
	return &TrivyScanner{
		trivyPath: "trivy", // Default: expect trivy in PATH
	}
}

// NewTrivyScannerWithPath creates a Trivy scanner with a specific trivy binary path
func NewTrivyScannerWithPath(path string) *TrivyScanner {
	return &TrivyScanner{
		trivyPath: path,
	}
}

// Name returns the scanner name
func (t *TrivyScanner) Name() string {
	return "trivy"
}

// TrivyReport represents the structure of Trivy JSON output
type TrivyReport struct {
	Results []TrivyResult `json:"Results"`
}

// TrivyResult represents a result in Trivy output
type TrivyResult struct {
	Target          string         `json:"Target"`
	Class           string         `json:"Class"`
	Type            string         `json:"Type"`
	Vulnerabilities []TrivyVuln    `json:"Vulnerabilities"`
	Packages        []TrivyPackage `json:"Packages,omitempty"`
}

// TrivyVuln represents a vulnerability in Trivy output
type TrivyVuln struct {
	VulnerabilityID  string                 `json:"VulnerabilityID"`
	PkgName          string                 `json:"PkgName"`
	PkgPath          string                 `json:"PkgPath,omitempty"`
	InstalledVersion string                 `json:"InstalledVersion"`
	FixedVersion     string                 `json:"FixedVersion,omitempty"`
	Severity         string                 `json:"Severity"`
	Title            string                 `json:"Title,omitempty"`
	Description      string                 `json:"Description,omitempty"`
	CVSS             map[string]interface{} `json:"CVSS,omitempty"`
}

// TrivyPackage represents a package in Trivy output
type TrivyPackage struct {
	Name    string `json:"Name"`
	Version string `json:"Version"`
	Path    string `json:"Path,omitempty"`
	Type    string `json:"Type,omitempty"`
}

// ScanFilesystem scans a filesystem path using Trivy
func (t *TrivyScanner) ScanFilesystem(path string) ([]*models.Vulnerability, []*models.Component, error) {
	// Check if trivy is available
	if _, err := exec.LookPath(t.trivyPath); err != nil {
		return nil, nil, fmt.Errorf("trivy not found in PATH: %w", err)
	}

	// Run trivy scan
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	cmd := exec.Command(t.trivyPath, "fs", "--format", "json", "--scanners", "vuln", absPath)
	output, err := cmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("trivy scan failed: %w", err)
	}

	return t.parseTrivyOutput(output)
}

// ScanImage scans a container image using Trivy
func (t *TrivyScanner) ScanImage(image string) ([]*models.Vulnerability, []*models.Component, error) {
	// Check if trivy is available
	if _, err := exec.LookPath(t.trivyPath); err != nil {
		return nil, nil, fmt.Errorf("trivy not found in PATH: %w", err)
	}

	// Run trivy scan
	cmd := exec.Command(t.trivyPath, "image", "--format", "json", "--scanners", "vuln", image)
	output, err := cmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("trivy scan failed: %w", err)
	}

	return t.parseTrivyOutput(output)
}

// parseTrivyOutput parses Trivy JSON output into our models
func (t *TrivyScanner) parseTrivyOutput(output []byte) ([]*models.Vulnerability, []*models.Component, error) {
	var report TrivyReport
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	vulnMap := make(map[string]*models.Vulnerability)
	componentMap := make(map[string]*models.Component)

	for _, result := range report.Results {
		for _, trivyVuln := range result.Vulnerabilities {
			// Create or update vulnerability
			vuln, exists := vulnMap[trivyVuln.VulnerabilityID]
			if !exists {
				vuln = &models.Vulnerability{
					ID:          trivyVuln.VulnerabilityID,
					Type:        "cve",
					Title:       trivyVuln.Title,
					Description: trivyVuln.Description,
					Severity:    trivyVuln.Severity,
				}

				// Extract CVSS score if available
				if cvss, ok := trivyVuln.CVSS["nvd"].(map[string]interface{}); ok {
					if score, ok := cvss["V3Score"].(float64); ok {
						vuln.CVSSScore = score
					}
				}

				vulnMap[trivyVuln.VulnerabilityID] = vuln
			}

			// Create component
			compKey := fmt.Sprintf("%s:%s:%s", trivyVuln.PkgName, trivyVuln.InstalledVersion, result.Type)
			comp, exists := componentMap[compKey]
			if !exists {
				comp = &models.Component{
					Name:     trivyVuln.PkgName,
					Version:  trivyVuln.InstalledVersion,
					Type:     result.Type,
					Location: trivyVuln.PkgPath,
					Source:   "trivy",
				}
				componentMap[compKey] = comp
			}
		}

		// Also extract packages without vulnerabilities for component inventory
		for _, pkg := range result.Packages {
			compKey := fmt.Sprintf("%s:%s:%s", pkg.Name, pkg.Version, result.Type)
			if _, exists := componentMap[compKey]; !exists {
				componentMap[compKey] = &models.Component{
					Name:     pkg.Name,
					Version:  pkg.Version,
					Type:     result.Type,
					Location: pkg.Path,
					Source:   "trivy",
				}
			}
		}
	}

	// Convert maps to slices
	var vulns []*models.Vulnerability
	for _, vuln := range vulnMap {
		vulns = append(vulns, vuln)
	}

	var components []*models.Component
	for _, comp := range componentMap {
		components = append(components, comp)
	}

	return vulns, components, nil
}

// IsAvailable checks if Trivy is available in the system
func (t *TrivyScanner) IsAvailable() bool {
	_, err := exec.LookPath(t.trivyPath)
	return err == nil
}
