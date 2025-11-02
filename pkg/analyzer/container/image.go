package container

import (
	"fmt"

	"github.com/matanlivne/exploint/pkg/models"
	"github.com/matanlivne/exploint/pkg/scanner"
)

// ImageAnalyzer analyzes container images
type ImageAnalyzer struct {
	trivyScanner *scanner.TrivyScanner
}

// NewImageAnalyzer creates a new image analyzer
func NewImageAnalyzer() *ImageAnalyzer {
	return &ImageAnalyzer{
		trivyScanner: scanner.NewTrivyScanner(),
	}
}

// AnalyzeImage analyzes a container image using Trivy
// This prefers deep image inspection over Dockerfile analysis
func (a *ImageAnalyzer) AnalyzeImage(image string) ([]*models.Vulnerability, []*models.Component, error) {
	if !a.trivyScanner.IsAvailable() {
		return nil, nil, fmt.Errorf("trivy is not available for image analysis")
	}

	// Use Trivy scanner which performs deep image inspection
	vulns, components, err := a.trivyScanner.ScanImage(image)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to scan image with Trivy: %w", err)
	}

	return vulns, components, nil
}

// GetImageInfo extracts basic information about the image
func (a *ImageAnalyzer) GetImageInfo(image string) (map[string]string, error) {
	// This would ideally inspect the image metadata
	// For now, we rely on Trivy for detailed analysis
	info := make(map[string]string)
	info["image"] = image

	// Trivy scan provides component information which includes image details
	_, components, err := a.trivyScanner.ScanImage(image)
	if err != nil {
		return info, err
	}

	// Extract OS and architecture from components if available
	for _, comp := range components {
		if comp.Type != "" {
			info["type"] = comp.Type
		}
	}

	return info, nil
}
