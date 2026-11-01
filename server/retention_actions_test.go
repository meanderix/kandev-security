package main

import (
	"context"
	"testing"
)

func TestRetentionActionsAuthorizationAndRevisionSafety(t *testing.T) {
	p := testPlugin(t)
	raw := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Scanner"}},"results":[]}]}`)
	r, _, err := p.store.Import(context.Background(), "ws", "actor", "scan.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := invoke(t, p, "reports.pin", "other", map[string]any{"id": r.ID, "pinned": true}); status != 404 {
		t.Fatal(status)
	}
	if status, result := invoke(t, p, "reports.pin", "ws", map[string]any{"id": r.ID, "pinned": true}); status != 200 || result["pinned"] != true || result["retained"] != true {
		t.Fatal(status, result)
	}
	for _, key := range []string{"retention.get", "retention.preview", "retention.save", "retention.run", "reports.pin", "reports.purged.list"} {
		if status, _ := invoke(t, p, key, "ws", map[string]any{"workspace_id": "other"}); status != 400 {
			t.Fatal(key, status)
		}
	}
	config := map[string]any{"enabled": true, "default": map[string]any{"max_reports": 1, "max_age_days": 0}, "overrides": []any{}}
	status, result := invoke(t, p, "retention.preview", "ws", map[string]any{"config": config})
	if status != 200 || result["pinned_reports"] != float64(1) {
		t.Fatal(status, result)
	}
	status, result = invoke(t, p, "retention.save", "ws", map[string]any{"expected_revision": 0, "config": config})
	if status != 200 || result["settings"].(map[string]any)["revision"] != float64(1) {
		t.Fatal(status, result)
	}
	if status, _ = invoke(t, p, "retention.save", "ws", map[string]any{"expected_revision": 0, "config": config}); status != 409 {
		t.Fatal("stale save", status)
	}
	if status, _ = invoke(t, p, "reports.pin", "ws", map[string]any{"id": r.ID}); status != 400 {
		t.Fatal("missing pin bool", status)
	}
	config["enabled"] = false
	if status, _ = invoke(t, p, "retention.save", "ws", map[string]any{"expected_revision": 1, "config": config, "actor_id": "spoof"}); status != 400 {
		t.Fatal("spoofed actor", status)
	}
	status, result = invoke(t, p, "retention.get", "other", map[string]any{})
	if status != 200 || result["revision"] != float64(0) {
		t.Fatal("foreign settings", status, result)
	}
}
