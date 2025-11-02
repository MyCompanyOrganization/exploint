package models

import "time"

// ExploitabilityScore represents the exploitability assessment
type ExploitabilityScore string

const (
	ScoreNotExploitable ExploitabilityScore = "NOT_EXPLOITABLE"
	ScoreLow            ExploitabilityScore = "LOW"
	ScoreMedium         ExploitabilityScore = "MEDIUM"
	ScoreHigh           ExploitabilityScore = "HIGH"
	ScoreCritical       ExploitabilityScore = "CRITICAL"
)

// Finding represents a vulnerability assessment for a specific component
type Finding struct {
	Vulnerability      *Vulnerability      `json:"vulnerability" yaml:"vulnerability"`
	Component          *Component          `json:"component" yaml:"component"`
	Score              ExploitabilityScore `json:"score" yaml:"score"`
	Assessment         string              `json:"assessment" yaml:"assessment"` // Detailed explanation
	ComponentPresent   bool                `json:"component_present" yaml:"component_present"`
	InExecutionPath    bool                `json:"in_execution_path" yaml:"in_execution_path"`
	AttackVectorValid  bool                `json:"attack_vector_valid" yaml:"attack_vector_valid"`
	PlatformCompatible bool                `json:"platform_compatible" yaml:"platform_compatible"`
	Recommendation     string              `json:"recommendation,omitempty" yaml:"recommendation,omitempty"`
	LLMInsights        string              `json:"llm_insights,omitempty" yaml:"llm_insights,omitempty"`
	AnalyzedAt         time.Time           `json:"analyzed_at" yaml:"analyzed_at"`
}
