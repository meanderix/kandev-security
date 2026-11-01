package main

import (
	"context"
	"testing"
)

func TestArchiveActionsAndMCPDiscovery(t *testing.T) {
	p := testPlugin(t)
	p.SetHost(taskTestHost{workflows: &taskTestWorkflows{}, tasks: &taskTestReader{workspace: "ws"}})
	id, _ := auditFixture(t, p, "ws")
	for _, body := range []map[string]any{{"id": id}, {"id": id, "archived": nil}, {"id": id, "archived": true, "workspace_id": "other"}, {"id": id, "archived": "true"}} {
		if status, _ := invoke(t, p, "reports.archive", "ws", body); status != 400 {
			t.Fatal(body, status)
		}
	}
	if status, _ := invoke(t, p, "reports.archive", "other", map[string]any{"id": id, "archived": true}); status != 404 {
		t.Fatal(status)
	}
	if status, _ := invoke(t, p, "reports.archive", "", map[string]any{"id": id, "archived": true}); status != 403 {
		t.Fatal(status)
	}
	status, result := invoke(t, p, "reports.archive", "ws", map[string]any{"id": id, "archived": true})
	if status != 200 || result["report"].(map[string]any)["archived_by"] != "actor" {
		t.Fatal(status, result)
	}
	for visibility, want := range map[string]int{"active": 0, "archived": 1, "all": 1} {
		status, result = invoke(t, p, "reports.list", "ws", map[string]any{"status": visibility})
		if status != 200 || len(result["items"].([]any)) != want {
			t.Fatal(visibility, status, result)
		}
		listed := toolData(t, p, "list_reports", map[string]any{"status": visibility})
		if listed["total"] != float64(want) {
			t.Fatal(visibility, listed)
		}
	}
	if listed := toolData(t, p, "list_reports", nil); listed["total"] != float64(0) {
		t.Fatal(listed)
	}
	if status, _ = invoke(t, p, "reports.list", "ws", map[string]any{"status": "invalid"}); status != 400 {
		t.Fatal(status)
	}
	report := toolData(t, p, "get_report", map[string]any{"report_id": id})
	if report["report"].(map[string]any)["archived_at"] == nil {
		t.Fatal(report)
	}
	summary := toolData(t, p, "get_audit_summary", map[string]any{"report_ids": []string{id}})
	if summary["finding_count"] != float64(2) {
		t.Fatal(summary)
	}
	finding := toolData(t, p, "get_finding", map[string]any{"report_id": id, "ordinal": 0})
	if finding["report"].(map[string]any)["archived_at"] == nil {
		t.Fatal(finding)
	}
	// Task creation can still explicitly inspect an archived finding.
	status, result = invoke(t, p, "tasks.prepare", "ws", map[string]any{"id": id, "ordinal": 0, "preset_id": "investigate"})
	if status != 200 {
		t.Fatal(status, result)
	}
	if _, err := p.store.SetReportArchived(context.Background(), "ws", "actor", id, false); err != nil {
		t.Fatal(err)
	}
	if listed := toolData(t, p, "list_reports", nil); listed["total"] != float64(1) {
		t.Fatal(listed)
	}
}
