package models

// Component represents a software component (package, library, binary)
type Component struct {
	Name     string `json:"name" yaml:"name"`
	Version  string `json:"version,omitempty" yaml:"version,omitempty"`
	Type     string `json:"type,omitempty" yaml:"type,omitempty"`         // "go", "python", "npm", "apk", etc.
	PURL     string `json:"purl,omitempty" yaml:"purl,omitempty"`         // Package URL
	Location string `json:"location,omitempty" yaml:"location,omitempty"` // File path or container layer
	Direct   bool   `json:"direct" yaml:"direct"`                         // Direct vs indirect dependency
	Source   string `json:"source,omitempty" yaml:"source,omitempty"`     // "go.mod", "container", "dockerfile", etc.
}
