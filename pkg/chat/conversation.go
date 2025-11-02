package chat

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/matanlivne/exploint/pkg/models"
)

// ConversationManager manages chat conversations
type ConversationManager struct {
	conversationDir string
}

// NewConversationManager creates a new conversation manager
func NewConversationManager() (*ConversationManager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}
	
	convDir := filepath.Join(homeDir, ".exploint", "conversations")
	if err := os.MkdirAll(convDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create conversations directory: %w", err)
	}
	
	return &ConversationManager{
		conversationDir: convDir,
	}, nil
}

// LoadConversation loads a conversation from file
func (m *ConversationManager) LoadConversation(id string) (*models.Conversation, error) {
	convFile := filepath.Join(m.conversationDir, fmt.Sprintf("%s.json", id))
	
	data, err := os.ReadFile(convFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("conversation not found: %s", id)
		}
		return nil, fmt.Errorf("failed to read conversation: %w", err)
	}
	
	var conv models.Conversation
	if err := json.Unmarshal(data, &conv); err != nil {
		return nil, fmt.Errorf("failed to parse conversation: %w", err)
	}
	
	return &conv, nil
}

// SaveConversation saves a conversation to file
func (m *ConversationManager) SaveConversation(conv *models.Conversation) error {
	convFile := filepath.Join(m.conversationDir, fmt.Sprintf("%s.json", conv.ID))
	
	data, err := json.MarshalIndent(conv, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal conversation: %w", err)
	}
	
	if err := os.WriteFile(convFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write conversation: %w", err)
	}
	
	return nil
}

// NewConversation creates a new conversation
func (m *ConversationManager) NewConversation(reportPath string) (*models.Conversation, error) {
	conv := &models.Conversation{
		ID:            generateConversationID(),
		ReportPath:    reportPath,
		Messages:      []models.ChatMessage{},
		StartedAt:     time.Now(),
		LastUpdatedAt: time.Now(),
	}
	
	return conv, nil
}

// AddMessage adds a message to a conversation
func (m *ConversationManager) AddMessage(conv *models.Conversation, role, content string) {
	msg := models.ChatMessage{
		Role:      role,
		Content:   content,
		Timestamp: time.Now(),
	}
	
	conv.Messages = append(conv.Messages, msg)
	conv.LastUpdatedAt = time.Now()
}

// ExportToMarkdown exports a conversation to markdown
func (m *ConversationManager) ExportToMarkdown(conv *models.Conversation, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create markdown file: %w", err)
	}
	defer file.Close()
	
	fmt.Fprintf(file, "# Conversation: %s\n\n", conv.ID)
	fmt.Fprintf(file, "Started: %s\n", conv.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(file, "Report: %s\n\n", conv.ReportPath)
	fmt.Fprintf(file, "---\n\n")
	
	for _, msg := range conv.Messages {
		fmt.Fprintf(file, "## %s\n\n", msg.Role)
		fmt.Fprintf(file, "%s\n\n", msg.Content)
		fmt.Fprintf(file, "*%s*\n\n", msg.Timestamp.Format(time.RFC3339))
		fmt.Fprintf(file, "---\n\n")
	}
	
	return nil
}

// generateConversationID generates a unique conversation ID
func generateConversationID() string {
	return fmt.Sprintf("conv_%d", time.Now().UnixNano())
}

