package models

import "time"

// Report represents a collection of findings and analysis results
type Report struct {
	GeneratedAt time.Time              `json:"generated_at" yaml:"generated_at"`
	Target      string                 `json:"target" yaml:"target"`           // Repository path or container image
	TargetType  string                 `json:"target_type" yaml:"target_type"` // "repository", "image", "dockerfile"
	Findings    []*Finding             `json:"findings" yaml:"findings"`
	Components  []*Component           `json:"components" yaml:"components"`
	Summary     *Summary               `json:"summary" yaml:"summary"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// Summary provides a high-level overview of the analysis
type Summary struct {
	TotalFindings       int            `json:"total_findings" yaml:"total_findings"`
	TotalComponents     int            `json:"total_components" yaml:"total_components"`
	ByScore             map[string]int `json:"by_score" yaml:"by_score"`
	ExploitableCount    int            `json:"exploitable_count" yaml:"exploitable_count"`
	NotExploitableCount int            `json:"not_exploitable_count" yaml:"not_exploitable_count"`
	Recommendations     []string       `json:"recommendations,omitempty" yaml:"recommendations,omitempty"`
}
