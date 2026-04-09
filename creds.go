// Package mcpcreds provides zero-trust credential loading for MCP servers.
//
// Vault Agent renders secrets to /run/secrets/<mcp-name>/.env (tmpfs).
// This package reads from those files on every call — rotation is automatic,
// no restart needed. Credentials never enter the LLM context window.
package mcpcreds

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ── Redaction patterns ────────────────────────────────────────────────────────
// Applied to ALL strings returned from tool handlers before they reach the
// LLM context window.

var redactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(token|key|password|secret|pass|pwd|api[_-]?key)\s*[=:]\s*\S+`),
	regexp.MustCompile(`s\.[A-Za-z0-9]{20,}`),                                        // Vault token
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*`),                         // Bearer
	regexp.MustCompile(`(?i)basic\s+[A-Za-z0-9+/]+=*`),                               // Basic auth
	regexp.MustCompile(`-----BEGIN [A-Z ]+KEY-----[\s\S]+?-----END [A-Z ]+KEY-----`), // PEM key
	regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),                                        // GitHub PAT
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-]+`),                                  // Slack token
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                                           // AWS key ID
}

// Sanitize strips credential-like patterns from s before it is returned
// to a tool result (and thus into the LLM context window).
// Call this on every string your tool handler returns.
func Sanitize(s string) string {
	for _, p := range redactPatterns {
		s = p.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

// ── Credential store ──────────────────────────────────────────────────────────

// Store reads secrets from a Vault-Agent-rendered .env file.
// It re-reads the file on every Get/Require call so credential rotation
// takes effect immediately without restarting the MCP server.
type Store struct {
	mu          sync.RWMutex
	name        string
	secretsPath string

	// cache: reduce syscalls under high call rate
	cache     map[string]string
	cacheTime time.Time
	cacheTTL  time.Duration
}

// secretsBaseDir is the root where Vault Agent renders secrets.
// Override via MCP_SECRETS_DIR env var.
func secretsBaseDir() string {
	if d := os.Getenv("MCP_SECRETS_DIR"); d != "" {
		return d
	}
	return "/run/secrets"
}

// New creates a Store for the given MCP server name.
// name must match the directory under MCP_SECRETS_DIR, e.g. "jenkins".
func New(name string) *Store {
	return &Store{
		name:        name,
		secretsPath: filepath.Join(secretsBaseDir(), name, ".env"),
		cacheTTL:    2 * time.Second, // re-read at most every 2s under load
	}
}

// load reads and parses the .env file. Caller holds mu.
func (s *Store) load() (map[string]string, error) {
	f, err := os.Open(s.secretsPath)
	if err != nil {
		return nil, fmt.Errorf("[%s] secrets file not found at %s — is Vault Agent running? (%w)",
			s.name, s.secretsPath, err)
	}
	defer f.Close()

	result := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		result[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return result, scanner.Err()
}

// cached returns the in-memory cache, refreshing if stale.
func (s *Store) cached() (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cache != nil && time.Since(s.cacheTime) < s.cacheTTL {
		return s.cache, nil
	}
	m, err := s.load()
	if err != nil {
		return nil, err
	}
	s.cache = m
	s.cacheTime = time.Now()
	return m, nil
}

// Get returns the value for key, or def if not found.
// Returns an error if the secrets file is unreadable.
func (s *Store) Get(key, def string) (string, error) {
	m, err := s.cached()
	if err != nil {
		return "", err
	}
	if v, ok := m[key]; ok {
		return v, nil
	}
	return def, nil
}

// Require returns the value for key or returns an error if missing.
// The error message is safe to surface — it never contains the secret value.
func (s *Store) Require(key string) (string, error) {
	m, err := s.cached()
	if err != nil {
		return "", err
	}
	v, ok := m[key]
	if !ok || v == "" {
		return "", fmt.Errorf("[%s] required secret %q not found — check Vault policy and template", s.name, key)
	}
	return v, nil
}

// MustRequire is like Require but panics on error.
// Use only in init() or startup checks, never inside a hot path.
func (s *Store) MustRequire(key string) string {
	v, err := s.Require(key)
	if err != nil {
		panic(err)
	}
	return v
}

// Keys returns the list of available secret keys (not their values).
// Safe to log — no credential values are returned.
func (s *Store) Keys() ([]string, error) {
	m, err := s.cached()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys, nil
}

// Invalidate clears the cache, forcing a fresh file read on the next call.
// Call this after receiving SIGHUP if you want instant re-read.
func (s *Store) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache = nil
}

// ── Health check ──────────────────────────────────────────────────────────────

// HealthCheck verifies all registered stores can read their secrets files.
// Call this at startup and expose via /healthz.
func HealthCheck(stores ...*Store) error {
	for _, s := range stores {
		if _, err := s.Keys(); err != nil {
			return err
		}
	}
	return nil
}
