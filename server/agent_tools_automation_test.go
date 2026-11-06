package main

import (
	"context"
	"testing"

	"github.com/kdlbs/kandev/pluginsdk"
)

func TestAutomationToolsPreserveAuthorityBoundaries(t *testing.T) {
	p := testPlugin(t)
	request := func(name string, args map[string]any) *pluginsdk.AgentToolRequest {
		req := auditRequest(name, args)
		req.Context.Surface = "automation"
		return req
	}
	call := func(req *pluginsdk.AgentToolRequest, code string) *pluginsdk.AgentToolResult {
		t.Helper()
		result, err := p.InvokeAgentTool(context.Background(), req)
		if err != nil || result == nil {
			t.Fatalf("invoke: %+v %v", result, err)
		}
		if code == "" {
			if result.IsError {
				t.Fatal(result)
			}
		} else if !result.IsError || result.StructuredContent["error"].(map[string]any)["code"] != code {
			t.Fatalf("expected %s: %+v", code, result)
		}
		return result
	}
	id, _ := auditFixture(t, p, "ws")
	foreignID, _ := auditFixture(t, p, "private")
	foreign, err := p.store.Finding(context.Background(), "private", foreignID, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"get_report", map[string]any{"report_id": foreignID}},
		{"get_finding", map[string]any{"report_id": foreignID, "ordinal": 0}},
		{"get_issue", map[string]any{"issue_id": foreign.Finding.IssueID}},
		{"list_findings", map[string]any{"report_ids": []string{id, foreignID}}},
		{"get_audit_summary", map[string]any{"report_ids": []string{foreignID}}},
		{"list_filter_values", map[string]any{"report_ids": []string{foreignID}, "facet": "rule"}},
		{"set_issue_status", map[string]any{"issue_id": foreign.Finding.IssueID, "status": "closed", "reason": "Foreign review"}},
	} {
		t.Run(tc.name, func(t *testing.T) { call(request(tc.name, tc.args), "not_found") })
	}
	start := call(request("start_report", draftToolSpec("automation-owned")), "")
	draftID := start.StructuredContent["data"].(map[string]any)["id"]
	for _, name := range []string{"get_report_draft", "submit_finding", "complete_report", "cancel_report"} {
		args := map[string]any{"draft_id": draftID}
		if name != "get_report_draft" {
			args["expected_revision"] = 0
		}
		if name == "submit_finding" {
			args["finding"] = draftToolFinding("foreign-task")
		}
		if name == "complete_report" {
			args["completion"] = map[string]any{"summary": "Done", "coverage": "Handlers"}
		}
		for _, authority := range []string{"task", "workspace"} {
			req := request(name, args)
			if authority == "task" {
				req.Context.TaskID = "another-run-task"
			} else {
				req.Context.WorkspaceID = "private"
			}
			call(req, "not_found")
		}
	}
	resume := request("get_report_draft", map[string]any{"draft_id": draftID})
	resume.Context.SessionID = "continued-session"
	call(resume, "")
	for _, name := range []string{"list_reports", "start_report", "set_issue_status"} {
		for _, field := range []string{"workspace", "task", "session", "invocation"} {
			req := request(name, nil)
			switch field {
			case "workspace":
				req.Context.WorkspaceID = ""
			case "task":
				req.Context.TaskID = ""
			case "session":
				req.Context.SessionID = ""
			case "invocation":
				req.InvocationID = ""
			}
			call(req, "forbidden")
		}
		for _, surface := range []string{"external", "coordinator", "configuration", "managed-conversation", ""} {
			req := request(name, nil)
			req.Context.Surface = surface
			call(req, "forbidden")
		}
	}
	for _, field := range []string{"workspace_id", "task_id", "session_id", "invocation_id"} {
		call(request("list_reports", map[string]any{field: "spoofed"}), "invalid_arguments")
	}
}
