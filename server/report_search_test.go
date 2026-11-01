package main

import "testing"

func TestReportSearchActionUsesFilenameAndWorkspace(t *testing.T) {
	p := testPlugin(t)
	auditFixture(t, p, "ws")
	auditFixture(t, p, "private")
	for _, entry := range []struct {
		search string
		want   float64
	}{{"SCAN.SAR", 1}, {"Critical finding", 0}, {"' OR 1=1 --", 0}} {
		status, result := invoke(t, p, "reports.list", "ws", map[string]any{"search": entry.search, "tool": "Scanner", "status": "all"})
		if status != 200 || result["total"] != entry.want || result["status_counts"].(map[string]any)["all"] != entry.want {
			t.Fatal(entry, status, result)
		}
	}
}
