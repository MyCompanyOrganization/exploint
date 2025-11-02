package scanner

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/matanlivne/exploint/pkg/models"
	"gopkg.in/yaml.v3"
)

// ManualScanner handles manual CVE input from various sources
type ManualScanner struct{}

// NewManualScanner creates a new manual scanner instance
func NewManualScanner() *ManualScanner {
	return &ManualScanner{}
}

// Name returns the scanner name
func (m *ManualScanner) Name() string {
	return "manual"
}

// ScanFilesystem is not applicable for manual scanner
func (m *ManualScanner) ScanFilesystem(path string) ([]*models.Vulnerability, []*models.Component, error) {
	return nil, nil, fmt.Errorf("manual scanner does not support filesystem scanning")
}

// ScanImage is not applicable for manual scanner
func (m *ManualScanner) ScanImage(image string) ([]*models.Vulnerability, []*models.Component, error) {
	return nil, nil, fmt.Errorf("manual scanner does not support image scanning")
}

// ParseCVEsFromString parses comma-separated CVE list
func (m *ManualScanner) ParseCVEsFromString(cveList string) ([]*models.Vulnerability, error) {
	if cveList == "" {
		return nil, nil
	}

	cves := strings.Split(cveList, ",")
	var vulns []*models.Vulnerability

	for _, cve := range cves {
		cve = strings.TrimSpace(cve)
		if cve == "" {
			continue
		}

		vuln := &models.Vulnerability{
			ID:   cve,
			Type: "cve",
		}

		// Infer type from prefix
		if strings.HasPrefix(cve, "GHSA-") {
			vuln.Type = "ghsa"
		}

		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// CVEFileInput represents the structure for CVE input files
type CVEFileInput struct {
	CVEs []string `json:"cves" yaml:"cves"`
}

// ParseCVEsFromJSONFile parses CVEs from a JSON file
func (m *ManualScanner) ParseCVEsFromJSONFile(path string) ([]*models.Vulnerability, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read JSON file: %w", err)
	}

	var input CVEFileInput
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	var vulns []*models.Vulnerability
	for _, cve := range input.CVEs {
		vuln := &models.Vulnerability{
			ID:   cve,
			Type: "cve",
		}

		if strings.HasPrefix(cve, "GHSA-") {
			vuln.Type = "ghsa"
		}

		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// ParseCVEsFromYAMLFile parses CVEs from a YAML file
func (m *ManualScanner) ParseCVEsFromYAMLFile(path string) ([]*models.Vulnerability, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read YAML file: %w", err)
	}

	var input CVEFileInput
	if err := yaml.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	var vulns []*models.Vulnerability
	for _, cve := range input.CVEs {
		vuln := &models.Vulnerability{
			ID:   cve,
			Type: "cve",
		}

		if strings.HasPrefix(cve, "GHSA-") {
			vuln.Type = "ghsa"
		}

		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// ParseCVEsFromCSVFile parses CVEs from a CSV file
func (m *ManualScanner) ParseCVEsFromCSVFile(path string) ([]*models.Vulnerability, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open CSV file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV: %w", err)
	}

	var vulns []*models.Vulnerability

	// Assume first row might be headers, first column contains CVEs
	for i, record := range records {
		if len(record) == 0 {
			continue
		}

		cve := strings.TrimSpace(record[0])
		if cve == "" || (i == 0 && strings.ToUpper(cve) == "CVE" || strings.ToUpper(cve) == "CVE_ID") {
			// Skip header row
			continue
		}

		vuln := &models.Vulnerability{
			ID:   cve,
			Type: "cve",
		}

		if strings.HasPrefix(cve, "GHSA-") {
			vuln.Type = "ghsa"
		}

		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// ParseCVEsFromFile auto-detects file format and parses CVEs
func (m *ManualScanner) ParseCVEsFromFile(path string) ([]*models.Vulnerability, error) {
	lowerPath := strings.ToLower(path)

	if strings.HasSuffix(lowerPath, ".json") {
		return m.ParseCVEsFromJSONFile(path)
	} else if strings.HasSuffix(lowerPath, ".yaml") || strings.HasSuffix(lowerPath, ".yml") {
		return m.ParseCVEsFromYAMLFile(path)
	} else if strings.HasSuffix(lowerPath, ".csv") {
		return m.ParseCVEsFromCSVFile(path)
	}

	return nil, fmt.Errorf("unsupported file format for CVE input: %s (supported: .json, .yaml, .yml, .csv)", path)
}
