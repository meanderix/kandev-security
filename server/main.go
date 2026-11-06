// Command kandev-security runs the supervised security reports plugin.
package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kdlbs/kandev/pluginsdk"
	"kandev-security/internal/reports"
)

func main() {
	dir := os.Getenv("KANDEV_PLUGIN_DATA_DIR")
	if dir == "" {
		log.Fatal("KANDEV_PLUGIN_DATA_DIR is required")
	}
	store, err := reports.Open(filepath.Join(dir, "security.db"))
	if err != nil {
		log.Fatalf("initialize security reports: %v", err)
	}
	defer store.Close()
	ctx, cancel := context.WithCancel(context.Background())
	var worker sync.WaitGroup
	worker.Add(1)
	go func() { defer worker.Done(); runRetentionWorker(ctx, store) }()
	defer func() { cancel(); worker.Wait() }()
	pluginsdk.Serve(&securityPlugin{store: store})
}

func runRetentionWorker(ctx context.Context, store *reports.Store) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err := store.RunAllRetention(runCtx)
		cancel()
		if err != nil && ctx.Err() == nil {
			log.Printf("security report retention: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
