package mcpcreds

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

// WatchReload listens for SIGHUP and invalidates the cache on all provided
// stores. Vault Agent sends SIGHUP to your MCP server process after re-rendering
// secrets — this ensures the next credential read is always fresh.
//
// Call once at startup in a goroutine:
//
//	go mcpcreds.WatchReload(mcpcreds.Jenkins, mcpcreds.SSH)
func WatchReload(stores ...*Store) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)

	for range ch {
		log.Println("[mcpcreds] SIGHUP received — invalidating credential cache")
		for _, s := range stores {
			s.Invalidate()
		}
		log.Println("[mcpcreds] credential cache cleared — next call reads fresh secrets")
	}
}
