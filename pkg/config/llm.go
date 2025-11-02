package config

import (
	"fmt"
	"os"
)

// LLMProviderConfig holds LLM provider-specific configuration
type LLMProviderConfig struct {
	Provider string
	APIKey   string
	Model    string
}

// GetLLMConfig retrieves LLM configuration from environment and config
func GetLLMConfig(provider, apiKey string) (*LLMProviderConfig, error) {
	cfg := &LLMProviderConfig{
		Provider: provider,
		APIKey:   apiKey,
	}

	// Override with environment variables if not provided via flags
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("EXPLOINT_LLM_API_KEY")
	}

	if cfg.Provider == "" {
		cfg.Provider = os.Getenv("EXPLOINT_LLM_PROVIDER")
		if cfg.Provider == "" {
			cfg.Provider = "openai" // Default
		}
	}

	if cfg.APIKey == "" {
		return nil, fmt.Errorf("LLM API key is required. Set EXPLOINT_LLM_API_KEY environment variable or use --llm-api-key flag")
	}

	return cfg, nil
}

// ValidateAPIKey checks if API key is present and warns if insecure
func ValidateAPIKey(apiKey string, source string) {
	if apiKey == "" {
		return
	}

	if source == "flag" {
		fmt.Fprintf(os.Stderr, "Warning: Passing API key via command-line flag is insecure. Consider using environment variable EXPLOINT_LLM_API_KEY instead.\n")
	}
}
