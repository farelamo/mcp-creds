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

	// ── Database & connection string patterns ─────────────────────────────
	// Generic URL with embedded credentials: scheme://user:pass@host
	// Covers mongodb(+srv), postgres, mysql, redis, amqp, nats, couchdb, etc.
	regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://[^\s"']*@[^\s"']+`),
	// Go-style DSN: user:pass@tcp(host:port)/db?params
	regexp.MustCompile(`[A-Za-z0-9_\-]+:[A-Za-z0-9_\-]+@tcp\([^\)]+\)[^\s"']*`),
	// JDBC connection strings: jdbc:subprotocol://host:port/db?user=x&password=y
	regexp.MustCompile(`(?i)jdbc:[A-Za-z0-9:]+//[^\s"']+`),
	// libpq / psql key-value DSN: host=... password=...
	regexp.MustCompile(`(?i)(?:host|server)\s*=\s*\S+[^;]*(?:password|pwd)\s*=\s*\S+`),
	// Data Source / Server= style (SQL Server, Oracle, ODBC):
	//   Server=host;Database=db;User Id=x;Password=y
	regexp.MustCompile(`(?i)(?:Data Source|Server)\s*=[^;]+;[^;]*(?:Password|Pwd)\s*=[^\s;]+`),

	// ── CI/CD build log patterns ──────────────────────────────────────────
	// Elastic ApiKey header value: ApiKey <base64>
	regexp.MustCompile(`(?i)apikey\s+[A-Za-z0-9\-._~+/]+=*`),
	// Webhook URLs with tokens/keys in query params
	regexp.MustCompile(`https?://[^\s"']*[?&](key|token|secret|password|credential|auth)[=][^\s"'&]*`),
	// Vault HTTP API paths (leak secret mount paths)
	regexp.MustCompile(`(?i)X-Vault-Token\s*[=:]\s*\S+`),

	// ── Jenkins patterns ──────────────────────────────────────────────────
	// Jenkins crumb header: Jenkins-Crumb: <value>
	regexp.MustCompile(`(?i)Jenkins-Crumb\s*[=:]\s*\S+`),
	// Jenkins API token in URL: http://user:token@jenkins/...
	regexp.MustCompile(`(?i)https?://[A-Za-z0-9._\-]+:[A-Za-z0-9._\-]+@[^\s"']+`),
	// Jenkins CLI auth header: -auth user:token
	regexp.MustCompile(`(?i)-auth\s+\S+:\S+`),
	// Groovy credentials() binding leaked in console: password=****
	regexp.MustCompile(`(?i)(?:password|passwd|credentials?)\s*=\s*\S+`),
	// Webhook URLs (Google Chat, Slack, etc.) — full URL with path
	regexp.MustCompile(`https://chat\.googleapis\.com/v1/spaces/[^\s"']+`),
	regexp.MustCompile(`https://hooks\.slack\.com/services/[^\s"']+`),
	// withCredentials / sshagent credential IDs in console output
	regexp.MustCompile(`(?i)(?:credentialsId|credentials)\s*[=:(]\s*['"]?[A-Za-z0-9_\-]+['"]?`),
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

// ── Build log sanitization ────────────────────────────────────────────────────

// envBlockHeader matches the "environment:" key in a Docker Compose YAML file.
var envBlockHeader = regexp.MustCompile(`^(\s*)environment\s*:\s*$`)

// envListItem matches YAML list items: "  - KEY=value" or "  - KEY"
var envListItem = regexp.MustCompile(`^(\s*-\s*)([A-Za-z_]\w*)\s*[=:]\s*(.+)$`)

// envMappingItem matches YAML mapping items: "  KEY: value"
var envMappingItem = regexp.MustCompile(`^(\s+)([A-Za-z_]\w*)\s*:\s*(.+)$`)

// redactDockerComposeEnv walks the text line-by-line and redacts the value
// of every KEY=value / KEY: value entry inside Docker Compose environment:
// blocks. It uses indentation to detect block boundaries — once a line at
// the same or lesser indent as "environment:" appears, the block ends.
func redactDockerComposeEnv(s string) string {
	lines := strings.Split(s, "\n")
	inEnvBlock := false
	envIndent := 0 // indentation level of the "environment:" line

	for i, line := range lines {
		if m := envBlockHeader.FindStringSubmatch(line); m != nil {
			inEnvBlock = true
			envIndent = len(m[1])
			continue
		}

		if !inEnvBlock {
			continue
		}

		trimmed := strings.TrimRight(line, " \t\r")
		// blank line — keep inside block
		if trimmed == "" {
			continue
		}

		// comment line — keep inside block
		stripped := strings.TrimLeft(trimmed, " \t")
		if strings.HasPrefix(stripped, "#") {
			continue
		}

		// measure current indent
		lineIndent := len(trimmed) - len(stripped)

		// if indent <= envIndent, we've left the environment block
		if lineIndent <= envIndent {
			inEnvBlock = false
			continue
		}

		// inside the block — redact value in list or mapping form
		if m := envListItem.FindStringSubmatch(line); m != nil {
			lines[i] = m[1] + m[2] + "=[REDACTED]"
		} else if m := envMappingItem.FindStringSubmatch(line); m != nil {
			lines[i] = m[1] + m[2] + ": [REDACTED]"
		}
	}
	return strings.Join(lines, "\n")
}

// ── Dockerfile ENV / ARG redaction ────────────────────────────────────────────

// dockerfileEnvAssign matches KEY=value pairs inside ENV/ARG lines.
// Handles unquoted, double-quoted, and single-quoted values.
var dockerfileEnvAssign = regexp.MustCompile(`([A-Za-z_]\w*)=("[^"]*"|'[^']*'|[^\s]+)`)

// dockerfileEnvSpace matches the legacy single-key form: ENV KEY value
var dockerfileEnvSpace = regexp.MustCompile(`(?i)^(\s*ENV\s+)([A-Za-z_]\w*)\s+(.+)$`)

// redactDockerfileEnv redacts values in Dockerfile ENV and ARG directives.
// Covers all forms:
//
//	ENV KEY=value
//	ENV KEY=value KEY2=value2
//	ENV KEY value          (legacy space-separated, single key only)
//	ARG KEY=default
func redactDockerfileEnv(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)

		// Only process lines starting with ENV or ARG
		if !strings.HasPrefix(upper, "ENV ") && !strings.HasPrefix(upper, "ARG ") {
			continue
		}

		// Try KEY=value form first (works for both ENV and ARG, supports multi-key)
		if dockerfileEnvAssign.MatchString(line) {
			lines[i] = dockerfileEnvAssign.ReplaceAllString(line, "${1}=[REDACTED]")
			continue
		}

		// Legacy space-separated form: ENV KEY value (ENV only, single key)
		if m := dockerfileEnvSpace.FindStringSubmatch(line); m != nil {
			lines[i] = m[1] + m[2] + " [REDACTED]"
		}
	}
	return strings.Join(lines, "\n")
}

// SanitizeBuildLog performs build-log-specific redaction on top of the
// standard Sanitize pass. It walks Docker Compose environment: blocks and
// Dockerfile ENV/ARG directives, redacting every value, then applies all
// standard credential patterns.
func SanitizeBuildLog(s string) string {
	// First pass: redact all values inside Docker Compose environment: blocks.
	s = redactDockerComposeEnv(s)
	// Second pass: redact Dockerfile ENV and ARG directives.
	s = redactDockerfileEnv(s)
	// Third pass: apply all standard credential patterns.
	s = Sanitize(s)
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
