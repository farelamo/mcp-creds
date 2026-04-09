# MCP-CREDS

Zero-trust credential loading for MCP servers, designed to work with HashiCorp Vault Agent.

For the Vault Agent sidecar setup, see [github.com/farelamo/mcp-creds-agent](https://github.com/farelamo/mcp-creds-agent).

## How It Works

Vault Agent renders secrets to `.env` files on a tmpfs volume (`/run/secrets/<service>/.env`). This package reads those files on every call — credential rotation is automatic with no restart required. Credentials never enter the LLM context window.

```
Vault Agent  ──renders──▶  /run/secrets/jenkins/.env  ──read by──▶  mcpcreds.Store
                           /run/secrets/ssh/.env
                           /run/secrets/grafana/.env
```

## Install

```bash
go get github.com/farelamo/mcp-creds@latest
```

## Usage

```go
package main

import (
    "log"
    "github.com/farelamo/mcp-creds"
)

func main() {
    jenkins := mcpcreds.New("jenkins")

    // Get with a default fallback
    url, err := jenkins.Get("JENKINS_URL", "http://localhost:8080")

    // Require (error if missing)
    token, err := jenkins.Require("JENKINS_TOKEN")

    // Startup health check
    if err := mcpcreds.HealthCheck(jenkins); err != nil {
        log.Fatal(err)
    }

    // Watch for Vault Agent SIGHUP to refresh cache instantly
    go mcpcreds.WatchReload(jenkins)
}
```

## Credential Redaction

All tool handler output should be sanitized before reaching the LLM context window:

```go
result := doSomething()
return mcpcreds.Sanitize(result) // strips tokens, keys, PEM blocks, etc.
```

Detected patterns include Vault tokens, Bearer/Basic auth, PEM keys, GitHub PATs, Slack tokens, and AWS key IDs.

## API

| Function / Method | Description |
|---|---|
| `New(name)` | Create a store for a service (reads from `/run/secrets/<name>/.env`) |
| `Store.Get(key, default)` | Get a value with fallback |
| `Store.Require(key)` | Get a value or error if missing |
| `Store.MustRequire(key)` | Like Require but panics — use only at startup |
| `Store.Keys()` | List available keys (no values) |
| `Store.Invalidate()` | Clear cache, forcing a fresh read |
| `HealthCheck(stores...)` | Verify all stores can read their secrets |
| `WatchReload(stores...)` | Listen for SIGHUP and invalidate caches |
| `Sanitize(s)` | Strip credential patterns from a string |

## Configuration

| Env Var | Default | Description |
|---|---|---|
| `MCP_SECRETS_DIR` | `/run/secrets` | Root directory where Vault Agent renders secrets |

## Cache Behavior

The store caches parsed `.env` contents for 2 seconds to reduce syscalls under load. Cache is automatically cleared on SIGHUP from Vault Agent via `WatchReload`.
