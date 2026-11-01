package main

import (
	"context"
	"testing"
)

func TestStatusFilteringForFindingAndIssueActions(t *testing.T) {
	p := testPlugin(t)
	id, _ := auditFixture(t, p, "ws")
	auditFixture(t, p, "private")
	f, err := p.store.Finding(context.Background(), "ws", id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.store.SetIssueStatus(context.Background(), "ws", "actor", f.Finding.IssueID, "closed", "Reviewed"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"findings.list", "issues.list"} {
		for _, status := range []string{"", "open", "closed"} {
			code, data := invoke(t, p, key, "ws", map[string]any{"status": status})
			want := float64(1)
			if status == "" {
				want = 2
			}
			if code != 200 || data["total"] != want {
				t.Fatal(key, status, code, data)
			}
		}
		code, data := invoke(t, p, key, "ws", map[string]any{"status": "open", "severity": "critical"})
		if code != 200 || data["total"] != float64(0) || data["severity_counts"].(map[string]any)["critical"] != float64(0) {
			t.Fatal(key, code, data)
		}
		if code, _ = invoke(t, p, key, "ws", map[string]any{"status": "bad"}); code != 400 {
			t.Fatal(key, code)
		}
	}
}
