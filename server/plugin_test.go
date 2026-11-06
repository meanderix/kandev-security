package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/kdlbs/kandev/pluginsdk"
	"kandev-security/internal/reports"
)

func testPlugin(t *testing.T) *securityPlugin {
	t.Helper()
	s, err := reports.Open(filepath.Join(t.TempDir(), "security.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return &securityPlugin{store: s}
}

func TestAdvisoryWorkspaceActions(t *testing.T) {
	p := testPlugin(t)
	raw := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Scanner"}},"results":[{"ruleId":"CVE-2026-12345","message":{"text":"Package A"}},{"ruleId":"CVE-2026-12345","message":{"text":"Package B"}},{"ruleId":"10027","message":{"text":"Ordinary rule"}}]}]}`)
	if _, _, err := p.store.Import(context.Background(), "ws", "actor", "scan.sarif", raw); err != nil {
		t.Fatal(err)
	}
	status, list := invoke(t, p, "advisories.list", "ws", map[string]any{})
	if status != 200 || list["total"] != float64(1) || list["finding_count"] != float64(2) {
		t.Fatal(status, list)
	}
	key := list["items"].([]any)[0].(map[string]any)["key"]
	status, members := invoke(t, p, "advisories.findings", "ws", map[string]any{"id": key})
	if status != 200 || members["total"] != float64(2) {
		t.Fatal(status, members)
	}
	if status, _ = invoke(t, p, "advisories.findings", "other", map[string]any{"id": key}); status != 404 {
		t.Fatal("foreign advisory", status)
	}
	if status, _ = invoke(t, p, "advisories.list", "ws", map[string]any{"workspace_id": "other"}); status != 400 {
		t.Fatal("authority override", status)
	}
	if status, _ = invoke(t, p, "advisories.findings", "ws", map[string]any{"id": key, "severity": "high"}); status != 400 {
		t.Fatal("ambiguous severity filter", status)
	}
}
func invoke(t *testing.T, p *securityPlugin, key, ws string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	response, err := p.HandleAction(context.Background(), &pluginsdk.PluginActionRequest{ActionKey: key, Context: pluginsdk.VerifiedActionContext{WorkspaceID: ws, ActorID: "actor"}, Body: raw})
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal(response.Body, &value); err != nil {
		t.Fatal(err)
	}
	return response.Status, value
}
func TestWorkspaceActions(t *testing.T) {
	p := testPlugin(t)
	if status, _ := invoke(t, p, "imports.start", "", map[string]any{"filename": "x", "size": 1}); status != 403 {
		t.Fatal(status)
	}
	// A body cannot override the authenticated workspace.
	if status, _ := invoke(t, p, "reports.list", "ws", map[string]any{"workspace_id": "other"}); status != 400 {
		t.Fatal(status)
	}
	raw := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Scanner"}},"results":[]}]}`)
	status, value := invoke(t, p, "imports.start", "ws", map[string]any{"filename": "scan.sarif", "size": len(raw)})
	if status != 200 {
		t.Fatal(value)
	}
	id := value["id"].(string)
	if status, _ := invoke(t, p, "imports.append", "other", map[string]any{"id": id, "data": base64.StdEncoding.EncodeToString(raw)}); status != 404 {
		t.Fatal(status)
	}
	if status, _ := invoke(t, p, "imports.append", "ws", map[string]any{"id": id, "data": "invalid base64"}); status != 400 {
		t.Fatal(status)
	}
	if status, value = invoke(t, p, "imports.append", "ws", map[string]any{"id": id, "data": base64.StdEncoding.EncodeToString(raw)}); status != 200 {
		t.Fatal(value)
	}
	status, value = invoke(t, p, "imports.complete", "ws", map[string]any{"id": id})
	if status != 200 {
		t.Fatal(value)
	}
	report := value["report"].(map[string]any)
	if report["workspace_id"] != "ws" || report["actor_id"] != "actor" {
		t.Fatal(report)
	}
	for _, key := range []string{"reports.get", "reports.source", "reports.delete"} {
		if status, _ := invoke(t, p, key, "other", map[string]any{"id": report["id"]}); status != 404 {
			t.Fatalf("%s: %d", key, status)
		}
	}
	if status, _ := invoke(t, p, "reports.get", "ws", map[string]any{"id": report["id"]}); status != 200 {
		t.Fatal(status)
	}
	if status, _ := invoke(t, p, "reports.delete", "ws", map[string]any{"id": report["id"]}); status != 200 {
		t.Fatal(status)
	}
}
func TestActionValidation(t *testing.T) {
	p := testPlugin(t)
	for _, raw := range []string{`{`, `{} {}`, `{"offset":-1}`, `{"search":"x","level":"bogus"}`} {
		key := "reports.list"
		if raw == `{"search":"x","level":"bogus"}` {
			key = "reports.get"
		}
		resp, err := p.HandleAction(context.Background(), &pluginsdk.PluginActionRequest{ActionKey: key, Context: pluginsdk.VerifiedActionContext{WorkspaceID: "ws"}, Body: []byte(raw)})
		if err != nil || resp.Status != 400 {
			t.Fatalf("%s: %+v %v", raw, resp, err)
		}
	}
	if status, _ := invoke(t, p, "unknown", "ws", nil); status != 404 {
		t.Fatal(status)
	}
	resp, err := p.HandleAction(context.Background(), nil)
	if err != nil || resp.Status != 403 {
		t.Fatal(resp, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.HandleAction(ctx, &pluginsdk.PluginActionRequest{Context: pluginsdk.VerifiedActionContext{WorkspaceID: "ws"}}); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestAggregateActionsAreWorkspaceScoped(t *testing.T) {
	p := testPlugin(t)
	raw := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"PrivateTool"}},"results":[{"ruleId":"RULE","level":"error","message":{"text":"Private finding"}}]}]}`)
	if _, _, err := p.store.Import(context.Background(), "private", "actor", "private.sarif", raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"findings.list", "findings.facets"} {
		body := map[string]any{}
		if key == "findings.facets" {
			body["facet"] = "tool"
		}
		status, value := invoke(t, p, key, "other", body)
		if status != 200 || len(value["items"].([]any)) != 0 {
			t.Fatalf("%s leaked findings: %+v", key, value)
		}
		if status, _ := invoke(t, p, key, "", body); status != 403 {
			t.Fatal("missing workspace accepted")
		}
	}
	if status, _ := invoke(t, p, "findings.list", "private", map[string]any{"sort": "DROP TABLE"}); status != 400 {
		t.Fatal("unknown sort accepted")
	}
	status, value := invoke(t, p, "findings.list", "private", map[string]any{"tool": "PrivateTool", "severity": "high", "sort": "newest"})
	if status != 200 || value["total"] != float64(1) {
		t.Fatal(value)
	}
}

func TestFindingDetailActionAuthority(t *testing.T) {
	p := testPlugin(t)
	raw := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Scanner"}},"results":[{"message":{"text":"A"}},{"message":{"text":"B"}}]}]}`)
	r, _, err := p.store.Import(context.Background(), "ws", "actor", "scan.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ws     string
		body   map[string]any
		status int
	}{
		{"ws", map[string]any{"id": r.ID}, 400}, {"ws", map[string]any{"id": r.ID, "ordinal": -1}, 400},
		{"ws", map[string]any{"id": r.ID, "ordinal": 2}, 404}, {"other", map[string]any{"id": r.ID, "ordinal": 1}, 404},
		{"", map[string]any{"id": r.ID, "ordinal": 1}, 403}, {"ws", map[string]any{"id": r.ID, "ordinal": 1}, 200},
	} {
		status, value := invoke(t, p, "findings.get", tc.ws, tc.body)
		if status != tc.status {
			t.Fatalf("%+v: %d %+v", tc, status, value)
		}
		if status == 200 && value["finding"].(map[string]any)["message"] != "B" {
			t.Fatal(value)
		}
	}
}

func TestIssueActionsAndReadOnlyAgentHistory(t *testing.T) {
	p := testPlugin(t)
	reportID, _ := auditFixture(t, p, "ws")
	status, list := invoke(t, p, "issues.list", "ws", map[string]any{})
	if status != 200 || list["total"] != float64(2) {
		t.Fatal(status, list)
	}
	issueID := list["items"].([]any)[0].(map[string]any)["issue_id"].(string)
	for _, key := range []string{"issues.get", "issues.set_status"} {
		status, _ = invoke(t, p, key, "foreign", map[string]any{"id": issueID, "status": "closed", "reason": "Reviewed"})
		if status != 404 {
			t.Fatal("workspace leak", key, status)
		}
	}
	status, _ = invoke(t, p, "issues.set_status", "ws", map[string]any{"id": issueID, "status": "closed", "reason": "Reviewed", "actor": "spoof"})
	if status != 400 {
		t.Fatal("actor override accepted")
	}
	status, _ = invoke(t, p, "issues.set_status", "ws", map[string]any{"id": issueID, "status": "closed", "reason": "Reviewed"})
	if status != 200 {
		t.Fatal(status)
	}
	status, d := invoke(t, p, "issues.get", "ws", map[string]any{"id": issueID})
	if status != 200 || d["issue"].(map[string]any)["status"] != "closed" || d["history"].([]any)[0].(map[string]any)["actor"] != "actor" {
		t.Fatal(status, d)
	}
	read := toolData(t, p, "get_issue", map[string]any{"issue_id": issueID})
	if read["total"] != float64(1) {
		t.Fatal(read)
	}
	req := auditRequest("get_issue", map[string]any{"issue_id": issueID})
	req.Context.WorkspaceID = "foreign"
	result, err := p.InvokeAgentTool(context.Background(), req)
	if err != nil || !result.IsError {
		t.Fatal("native issue workspace leak", result, err)
	}
	native := toolData(t, p, "get_finding", map[string]any{"report_id": reportID, "ordinal": 0})
	if native["finding"].(map[string]any)["issue_id"] != issueID {
		t.Fatal("native identity absent", native)
	}
}
