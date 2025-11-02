package assessor

import (
	"strings"

	"github.com/matanlivne/exploint/pkg/models"
)

// PresenceVerifier verifies if a component is present in the codebase or container
type PresenceVerifier struct{}

// NewPresenceVerifier creates a new presence verifier
func NewPresenceVerifier() *PresenceVerifier {
	return &PresenceVerifier{}
}

// VerifyComponentPresence checks if a vulnerable component is present
func (p *PresenceVerifier) VerifyComponentPresence(vuln *models.Vulnerability, components []*models.Component) (bool, *models.Component) {
	// Match by component name (various strategies)
	for _, comp := range components {
		if p.matchesComponent(vuln, comp) {
			// Verify version range if specified
			if p.versionInRange(comp, vuln.AffectedVersions) {
				return true, comp
			}
		}
	}
	
	return false, nil
}

// matchesComponent checks if a component matches the vulnerability
func (p *PresenceVerifier) matchesComponent(vuln *models.Vulnerability, comp *models.Component) bool {
	// Check if component name appears in vulnerability description or affected versions
	vulnText := strings.ToLower(vuln.Description + " " + strings.Join(vuln.AffectedVersions, " "))
	compName := strings.ToLower(comp.Name)
	
	// Direct match
	if strings.Contains(vulnText, compName) {
		return true
	}
	
	// Check package path (for Go modules)
	if comp.Location != "" {
		if strings.Contains(vulnText, comp.Location) {
			return true
		}
	}
	
	// Check PURL if available
	if comp.PURL != "" {
		if strings.Contains(vulnText, comp.PURL) {
			return true
		}
	}
	
	return false
}

// versionInRange checks if a component version is in the affected range
func (p *PresenceVerifier) versionInRange(comp *models.Component, affectedVersions []string) bool {
	if len(affectedVersions) == 0 {
		// No version range specified, assume all versions affected
		return true
	}
	
	compVersion := comp.Version
	
	// Simple version matching - full implementation would parse semantic versions
	for _, affected := range affectedVersions {
		if strings.Contains(affected, compVersion) || strings.Contains(compVersion, affected) {
			return true
		}
	}
	
	// If no explicit match, assume version is in range (conservative)
	return true
}

// FindMatchingComponents finds all components that might match a vulnerability
func (p *PresenceVerifier) FindMatchingComponents(vuln *models.Vulnerability, components []*models.Component) []*models.Component {
	var matches []*models.Component
	
	for _, comp := range components {
		if p.matchesComponent(vuln, comp) {
			if p.versionInRange(comp, vuln.AffectedVersions) {
				matches = append(matches, comp)
			}
		}
	}
	
	return matches
}

