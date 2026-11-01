package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"kandev-security/internal/reports"
)

func draftToolSpec(id string) map[string]any {
	return map[string]any{"client_report_id": id, "title": "Audit request handling", "instructions": "Inspect SQL queries.", "scope": []any{"src/handlers"}, "repository": "https://example.com/repo", "revision": "abc123", "branch": "main"}
}
func draftToolFinding(id string) map[string]any {
	return map[string]any{"finding_id": id, "title": "Unsafe query", "description": "Input reaches SQL execution.", "severity": "critical", "confidence": "medium", "evidence": "db.Query concatenates input.", "remediation": "Use query parameters.", "uri": "src/db.go", "line": 12, "rule_id": "CWE-89", "snippet": "db.Query(query+input)"}
}
func TestAgentDraftWorkflowAndErrors(t *testing.T) {
	p := testPlugin(t)
	d := toolData(t, p, "start_report", draftToolSpec("audit"))
	id := d["id"].(string)
	if d["revision"] != float64(0) {
		t.Fatal(d)
	}
	d = toolData(t, p, "submit_finding", map[string]any{"draft_id": id, "expected_revision": 0, "finding": draftToolFinding("query")})
	if d["revision"] != float64(1) {
		t.Fatal(d)
	}
	if toolData(t, p, "list_reports", nil)["total"] != float64(0) {
		t.Fatal("unpublished draft visible")
	}
	list := toolData(t, p, "list_report_drafts", map[string]any{"status": "draft"})
	if list["total"] != float64(1) {
		t.Fatal(list)
	}
	detail := toolData(t, p, "get_report_draft", map[string]any{"draft_id": id})
	if len(detail["items"].([]any)) != 1 {
		t.Fatal(detail)
	}
	for _, tc := range []struct {
		name string
		args map[string]any
		code string
	}{
		{"submit_finding", map[string]any{"draft_id": id, "finding": draftToolFinding("missing-revision")}, "invalid_arguments"},
		{"submit_finding", map[string]any{"draft_id": id, "expected_revision": 0, "finding": draftToolFinding("stale")}, "conflict"},
		{"complete_report", map[string]any{"draft_id": id, "expected_revision": 1, "completion": map[string]any{"summary": "Done"}}, "invalid_arguments"},
		{"start_report", map[string]any{"workspace_id": "foreign"}, "invalid_arguments"},
		{"get_report_draft", map[string]any{"draft_id": id, "task_id": "task"}, "invalid_arguments"},
	} {
		r, err := p.InvokeAgentTool(context.Background(), auditRequest(tc.name, tc.args))
		if err != nil || !r.IsError || r.StructuredContent["error"].(map[string]any)["code"] != tc.code {
			t.Fatal(tc.name, r, err)
		}
	}
	for _, name := range []string{"get_report_draft", "submit_finding", "complete_report", "cancel_report"} {
		req := auditRequest(name, map[string]any{"draft_id": id, "expected_revision": 1})
		if name == "get_report_draft" {
			delete(req.Arguments, "expected_revision")
		}
		if name == "submit_finding" {
			req.Arguments["finding"] = draftToolFinding("foreign")
		}
		if name == "complete_report" {
			req.Arguments["completion"] = map[string]any{"summary": "Done", "coverage": "Handlers"}
		}
		req.Context.TaskID = "other-task"
		result, err := p.InvokeAgentTool(context.Background(), req)
		if err != nil || !result.IsError || result.StructuredContent["error"].(map[string]any)["code"] != "not_found" {
			t.Fatal("task binding lost", name, result, err)
		}
	}
	args := map[string]any{"draft_id": id, "expected_revision": 1, "completion": map[string]any{"summary": "One finding.", "coverage": "Inspected SQL handlers.", "limitations": []string{"No runtime tests."}}}
	result := toolData(t, p, "complete_report", args)
	report := result["report"].(map[string]any)
	reportID := report["id"].(string)
	again := toolData(t, p, "complete_report", args)
	if again["report"].(map[string]any)["id"] != reportID {
		t.Fatal("retry created new report")
	}
	finding := toolData(t, p, "get_finding", map[string]any{"report_id": reportID, "ordinal": 0})
	if finding["finding"].(map[string]any)["confidence"] != "medium" || finding["run"].(map[string]any)["agent_audit"].(map[string]any)["task_id"] != "task" {
		t.Fatal("attribution missing", finding)
	}
}
func TestDraftToolResultBudgetsAndStrictNestedAuthority(t *testing.T) {
	p := testPlugin(t)
	a := reports.DraftAuthority{WorkspaceID: "ws", TaskID: "task", SessionID: "session", InvocationID: "invocation"}
	for n := 0; n < 25; n++ {
		spec := reports.AgentReportSpec{ClientReportID: string(rune('a' + n)), Title: "Audit", Instructions: strings.Repeat("x", 4096), Scope: []string{strings.Repeat("s", 256)}}
		for n := 0; n < 23; n++ {
			spec.Scope = append(spec.Scope, strings.Repeat("s", 256))
		}
		spec.Repository = "https://example.com/" + strings.Repeat("r", 700)
		d, err := p.store.StartReport(context.Background(), a, spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = p.store.CompleteReport(context.Background(), a, d.ID, 0, reports.AgentCompletion{Summary: strings.Repeat("x", 2048), Coverage: strings.Repeat("c", 4096), Limitations: []string{strings.Repeat("l", 256), strings.Repeat("l", 256), strings.Repeat("l", 256), strings.Repeat("l", 256), strings.Repeat("l", 256), strings.Repeat("l", 256), strings.Repeat("l", 256)}}); err != nil {
			t.Fatal(err)
		}
	}
	total := 0
	offset := 0
	pages := 0
	for {
		r, err := p.InvokeAgentTool(context.Background(), auditRequest("list_report_drafts", map[string]any{"offset": offset}))
		if err != nil || r.IsError || len(r.Text) > maxAgentJSONBytes {
			t.Fatal(r, err)
		}
		v := r.StructuredContent["data"].(map[string]any)
		pages++
		total += len(v["items"].([]any))
		next := int(v["next_offset"].(float64))
		if next == 0 {
			break
		}
		if next <= offset {
			t.Fatal("paging stopped")
		}
		offset = next
	}
	if total != 25 || pages < 2 {
		t.Fatal("drafts skipped", total)
	}
	d := toolData(t, p, "start_report", draftToolSpec("nested"))
	finding := draftToolFinding("f")
	finding["session_id"] = "spoof"
	r, err := p.InvokeAgentTool(context.Background(), auditRequest("submit_finding", map[string]any{"draft_id": d["id"], "expected_revision": 0, "finding": finding}))
	if err != nil || !r.IsError {
		t.Fatal("accepted nested authority", r, err)
	}
	for _, field := range []string{"workspace", "task", "session", "invocation", "surface"} {
		req := auditRequest("start_report", draftToolSpec("forbidden"))
		switch field {
		case "workspace":
			req.Context.WorkspaceID = ""
		case "task":
			req.Context.TaskID = ""
		case "session":
			req.Context.SessionID = ""
		case "invocation":
			req.InvocationID = ""
		case "surface":
			req.Context.Surface = "external"
		}
		r, err = p.InvokeAgentTool(context.Background(), req)
		if err != nil || !r.IsError {
			t.Fatal("missing authority accepted", field)
		}
	}
	// Check the returned text and structured representations have identical data.
	response, err := p.InvokeAgentTool(context.Background(), auditRequest("get_report_draft", map[string]any{"draft_id": d["id"]}))
	if err != nil || response.IsError {
		t.Fatal(err)
	}
	var fallback map[string]any
	if err = json.Unmarshal([]byte(response.Text), &fallback); err != nil || fallback["source"] != response.StructuredContent["source"] {
		t.Fatal("fallback mismatch", err)
	}
}
