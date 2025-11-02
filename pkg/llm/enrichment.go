package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/matanlivne/exploint/pkg/models"
)

// Cache manages caching of LLM enrichment responses
type Cache struct {
	cacheDir string
	mu       sync.RWMutex
}

// NewCache creates a new cache instance
func NewCache() (*Cache, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	cacheDir := filepath.Join(homeDir, ".exploint", "cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &Cache{
		cacheDir: cacheDir,
	}, nil
}

// Get retrieves a cached vulnerability enrichment
func (c *Cache) Get(cveID string) (*models.Vulnerability, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cacheFile := filepath.Join(c.cacheDir, fmt.Sprintf("%s.json", sanitizeFilename(cveID)))

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Not cached
		}
		return nil, fmt.Errorf("failed to read cache: %w", err)
	}

	var vuln models.Vulnerability
	if err := json.Unmarshal(data, &vuln); err != nil {
		return nil, fmt.Errorf("failed to parse cache: %w", err)
	}

	return &vuln, nil
}

// Set stores a vulnerability enrichment in cache
func (c *Cache) Set(vuln *models.Vulnerability) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	vuln.EnrichedAt = &now

	cacheFile := filepath.Join(c.cacheDir, fmt.Sprintf("%s.json", sanitizeFilename(vuln.ID)))

	data, err := json.MarshalIndent(vuln, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache: %w", err)
	}

	if err := os.WriteFile(cacheFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache: %w", err)
	}

	return nil
}

// sanitizeFilename sanitizes a CVE ID for use as a filename
func sanitizeFilename(cveID string) string {
	// Replace characters that are not safe for filenames
	result := cveID
	for _, char := range []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"} {
		result = strings.ReplaceAll(result, char, "_")
	}
	return result
}

// Enricher handles CVE enrichment with caching
type Enricher struct {
	provider Provider
	cache    *Cache
}

// NewEnricher creates a new enricher instance
func NewEnricher(provider Provider) (*Enricher, error) {
	cache, err := NewCache()
	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}

	return &Enricher{
		provider: provider,
		cache:    cache,
	}, nil
}

// EnrichCVE enriches a CVE, using cache if available
func (e *Enricher) EnrichCVE(ctx context.Context, cveID string) (*models.Vulnerability, error) {
	// Check cache first
	if cached, err := e.cache.Get(cveID); err == nil && cached != nil {
		return cached, nil
	}

	// Enrich from LLM
	vuln, err := e.provider.EnrichCVE(ctx, cveID)
	if err != nil {
		return nil, fmt.Errorf("failed to enrich CVE: %w", err)
	}

	// Store in cache
	if err := e.cache.Set(vuln); err != nil {
		// Log error but don't fail the enrichment
		fmt.Fprintf(os.Stderr, "Warning: failed to cache enrichment: %v\n", err)
	}

	return vuln, nil
}

// EnrichMultiple enriches multiple CVEs in parallel
func (e *Enricher) EnrichMultiple(ctx context.Context, cveIDs []string) (map[string]*models.Vulnerability, error) {
	result := make(map[string]*models.Vulnerability)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, cveID := range cveIDs {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()

			vuln, err := e.EnrichCVE(ctx, id)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to enrich %s: %v\n", id, err)
				return
			}

			mu.Lock()
			result[id] = vuln
			mu.Unlock()
		}(cveID)
	}

	wg.Wait()
	return result, nil
}
