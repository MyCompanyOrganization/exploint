package scanner

import (
	"github.com/matanlivne/exploint/pkg/models"
)

// Scanner defines the interface for vulnerability scanners
type Scanner interface {
	// ScanFilesystem scans a filesystem path for vulnerabilities
	ScanFilesystem(path string) ([]*models.Vulnerability, []*models.Component, error)

	// ScanImage scans a container image for vulnerabilities
	ScanImage(image string) ([]*models.Vulnerability, []*models.Component, error)

	// Name returns the scanner name
	Name() string
}

// FilterOptions contains filtering criteria for vulnerabilities
type FilterOptions struct {
	CVEs       []string // Specific CVE IDs to include
	Severities []string // Severity levels to include (CRITICAL, HIGH, etc.)
	Components []string // Component names to filter by
}

// FilterVulnerabilities filters vulnerabilities based on the provided options
func FilterVulnerabilities(vulns []*models.Vulnerability, opts FilterOptions) []*models.Vulnerability {
	if len(opts.CVEs) == 0 && len(opts.Severities) == 0 && len(opts.Components) == 0 {
		return vulns
	}

	var filtered []*models.Vulnerability

	for _, vuln := range vulns {
		// Filter by CVE IDs
		if len(opts.CVEs) > 0 {
			matched := false
			for _, cve := range opts.CVEs {
				if vuln.ID == cve {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		// Filter by severity
		if len(opts.Severities) > 0 {
			matched := false
			for _, severity := range opts.Severities {
				if vuln.Severity == severity {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		filtered = append(filtered, vuln)
	}

	return filtered
}
