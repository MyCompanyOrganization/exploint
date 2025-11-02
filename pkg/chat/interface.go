package chat

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/matanlivne/exploint/pkg/llm"
	"github.com/matanlivne/exploint/pkg/models"
)

// ChatInterface provides an interactive REPL for Q&A
type ChatInterface struct {
	queryEngine   *QueryEngine
	conversation  *models.Conversation
	convManager   *ConversationManager
	llmProvider   llm.Provider
}

// NewChatInterface creates a new chat interface
func NewChatInterface(reportPath string, provider llm.Provider) (*ChatInterface, error) {
	queryEngine, err := NewQueryEngine(reportPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create query engine: %w", err)
	}
	
	convManager, err := NewConversationManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create conversation manager: %w", err)
	}
	
	conv, err := convManager.NewConversation(reportPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create conversation: %w", err)
	}
	
	return &ChatInterface{
		queryEngine:  queryEngine,
		conversation: conv,
		convManager:  convManager,
		llmProvider:  provider,
	}, nil
}

// Start starts the interactive chat session
func (c *ChatInterface) Start(ctx context.Context) error {
	fmt.Println("Exploint Interactive Chat")
	fmt.Println("=========================")
	fmt.Println("Ask questions about the vulnerability analysis results.")
	fmt.Println("Type 'exit' or 'quit' to end the session.")
	fmt.Println("Type 'help' for available commands.\n")
	
	contextStr := c.queryEngine.BuildContext()
	
	scanner := bufio.NewScanner(os.Stdin)
	
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		
		question := strings.TrimSpace(scanner.Text())
		if question == "" {
			continue
		}
		
		// Handle commands
		if question == "exit" || question == "quit" {
			fmt.Println("Goodbye!")
			c.convManager.SaveConversation(c.conversation)
			break
		}
		
		if question == "help" {
			c.printHelp()
			continue
		}
		
		// Process question
		answer, err := c.processQuestion(ctx, question, contextStr)
		if err != nil {
			fmt.Printf("Error: %v\n\n", err)
			continue
		}
		
		fmt.Printf("\n%s\n\n", answer)
		
		// Save conversation
		c.convManager.AddMessage(c.conversation, "user", question)
		c.convManager.AddMessage(c.conversation, "assistant", answer)
		c.convManager.SaveConversation(c.conversation)
	}
	
	return scanner.Err()
}

// processQuestion processes a user question
func (c *ChatInterface) processQuestion(ctx context.Context, question string, contextStr string) (string, error) {
	// Build conversation history
	history := make([]*models.ChatMessage, len(c.conversation.Messages))
	for i := range c.conversation.Messages {
		history[i] = &c.conversation.Messages[i]
	}
	
	// Get answer from LLM
	answer, err := c.llmProvider.AnswerQuestion(ctx, question, contextStr, history)
	if err != nil {
		return "", fmt.Errorf("failed to get answer: %w", err)
	}
	
	return answer, nil
}

// printHelp prints help information
func (c *ChatInterface) printHelp() {
	fmt.Println("\nAvailable commands:")
	fmt.Println("  exit, quit - Exit the chat session")
	fmt.Println("  help       - Show this help message")
	fmt.Println("\nExample questions:")
	fmt.Println("  - Is CVE-2025-47273 exploitable?")
	fmt.Println("  - What components are vulnerable?")
	fmt.Println("  - Why is setuptools not exploitable?")
	fmt.Println("  - How can I fix CVE-2025-0913?")
	fmt.Println()
}

