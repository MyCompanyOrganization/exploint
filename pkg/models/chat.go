package models

import "time"

// ChatMessage represents a single message in a conversation
type ChatMessage struct {
	Role      string    `json:"role" yaml:"role"` // "user" or "assistant"
	Content   string    `json:"content" yaml:"content"`
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
}

// Conversation represents a chat session with analysis results
type Conversation struct {
	ID            string        `json:"id" yaml:"id"`
	ReportPath    string        `json:"report_path,omitempty" yaml:"report_path,omitempty"`
	Messages      []ChatMessage `json:"messages" yaml:"messages"`
	StartedAt     time.Time     `json:"started_at" yaml:"started_at"`
	LastUpdatedAt time.Time     `json:"last_updated_at" yaml:"last_updated_at"`
}
