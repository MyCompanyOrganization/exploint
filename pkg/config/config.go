package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	LLM LLMConfig `mapstructure:"llm"`
}

// LLMConfig contains LLM provider settings
type LLMConfig struct {
	Provider string `mapstructure:"provider"` // "openai", "anthropic"
	APIKey   string `mapstructure:"api_key"`
	Model    string `mapstructure:"model,omitempty"` // Optional model override
	Enabled  bool   `mapstructure:"enabled"`
}

// LoadConfig loads configuration from file, environment variables, and flags
func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	// Add config path: ~/.exploint/
	homeDir, err := os.UserHomeDir()
	if err == nil {
		configDir := filepath.Join(homeDir, ".exploint")
		viper.AddConfigPath(configDir)
	}

	// Also look in current directory
	viper.AddConfigPath(".")

	// Environment variables
	viper.SetEnvPrefix("EXPLOINT")
	viper.AutomaticEnv()

	// Defaults
	viper.SetDefault("llm.provider", "openai")
	viper.SetDefault("llm.enabled", true)

	// Read config file (optional, won't error if not found)
	_ = viper.ReadInConfig()

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Override with environment variables if set
	if apiKey := os.Getenv("EXPLOINT_LLM_API_KEY"); apiKey != "" {
		config.LLM.APIKey = apiKey
	}
	if provider := os.Getenv("EXPLOINT_LLM_PROVIDER"); provider != "" {
		config.LLM.Provider = provider
	}

	return &config, nil
}

// GetConfigDir returns the configuration directory path
func GetConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".exploint"), nil
}
