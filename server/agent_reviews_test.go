package main

import (
	"context"
	"testing"
)

func TestIssueReviewToolReasonOnlyTransitionsAndVerifiedAttribution(t *testing.T) {
	p := testPlugin(t)
	id, _ := auditFixture(t, p, "ws")
	f, err := p.store.Finding(context.Background(), "ws", id, 0)
	if err != nil {
		t.Fatal(err)
	}
	issueID := f.Finding.IssueID
	request := auditRequest("set_issue_status", map[string]any{"issue_id": issueID, "status": "open", "reason": "Needs runtime verification"})
	result, err := p.InvokeAgentTool(context.Background(), request)
	if err != nil || result.IsError || result.StructuredContent["source"] != "issue_review" {
		t.Fatal(result, err)
	}
	data := result.StructuredContent["data"].(map[string]any)
	issue := data["issue"].(map[string]any)
	if data["changed"] != true || issue["status"] != "open" || issue["status_reason"] != "Needs runtime verification" || issue["status_actor"] != "agent:task:task" {
		t.Fatal(data)
	}
	history := toolData(t, p, "get_issue", map[string]any{"issue_id": issueID})["history"].([]any)
	change := history[0].(map[string]any)
	if change["kind"] != "reason_updated" || change["task_id"] != "task" || change["session_id"] != "session" || change["invocation_id"] != "invocation" {
		t.Fatal(change)
	}
	request.InvocationID = "office-review"
	request.Context.Surface = "office-task"
	request.Arguments["status"] = "closed"
	request.Arguments["reason"] = "Reviewed evidence"
	result, err = p.InvokeAgentTool(context.Background(), request)
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	if result.StructuredContent["data"].(map[string]any)["issue"].(map[string]any)["status"] != "closed" {
		t.Fatal(result)
	}
	request.InvocationID = "reason-expanded"
	request.Arguments["reason"] = "Expanded evidence for closure"
	result, err = p.InvokeAgentTool(context.Background(), request)
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	// The original retry returns current state without rolling back later reviews.
	request.InvocationID = "invocation"
	request.Arguments["status"] = "open"
	request.Arguments["reason"] = "Needs runtime verification"
	result, err = p.InvokeAgentTool(context.Background(), request)
	if err != nil || result.IsError {
		t.Fatal(result, err)
	}
	data = result.StructuredContent["data"].(map[string]any)
	if data["replayed"] != true || data["changed"] != false || data["issue"].(map[string]any)["status"] != "closed" {
		t.Fatal(data)
	}
	request.Arguments["reason"] = "Changed replay"
	result, err = p.InvokeAgentTool(context.Background(), request)
	if err != nil || !result.IsError || result.StructuredContent["error"].(map[string]any)["code"] != "conflict" {
		t.Fatal(result, err)
	}
}
func TestIssueReviewToolRejectsSpoofedAuthorityAndMissingFields(t *testing.T) {
	p := testPlugin(t)
	id, _ := auditFixture(t, p, "private")
	foreign, err := p.store.Finding(context.Background(), "private", id, 0)
	if err != nil {
		t.Fatal(err)
	}
	request := auditRequest("set_issue_status", map[string]any{"issue_id": foreign.Finding.IssueID, "status": "closed", "reason": "Review"})
	result, err := p.InvokeAgentTool(context.Background(), request)
	if err != nil || !result.IsError || result.StructuredContent["error"].(map[string]any)["code"] != "not_found" {
		t.Fatal(result, err)
	}
	id, _ = auditFixture(t, p, "ws")
	own, err := p.store.Finding(context.Background(), "ws", id, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"workspace_id", "actor_id", "task_id", "session_id", "invocation_id"} {
		args := map[string]any{"issue_id": own.Finding.IssueID, "status": "closed", "reason": "Review", field: "spoofed"}
		result, err = p.InvokeAgentTool(context.Background(), auditRequest("set_issue_status", args))
		if err != nil || !result.IsError {
			t.Fatal(field, result, err)
		}
	}
	for _, field := range []string{"issue_id", "status", "reason"} {
		args := map[string]any{"issue_id": own.Finding.IssueID, "status": "closed", "reason": "Review"}
		delete(args, field)
		result, err = p.InvokeAgentTool(context.Background(), auditRequest("set_issue_status", args))
		if err != nil || !result.IsError {
			t.Fatal(field, result, err)
		}
	}
	for _, field := range []string{"workspace", "task", "session", "invocation", "surface"} {
		req := auditRequest("set_issue_status", map[string]any{"issue_id": own.Finding.IssueID, "status": "closed", "reason": "Review"})
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
		result, err = p.InvokeAgentTool(context.Background(), req)
		if err != nil || !result.IsError {
			t.Fatal(field, result, err)
		}
	}
	d, err := p.store.Issue(context.Background(), "ws", own.Finding.IssueID, 0, 0)
	if err != nil || d.Issue.Status != "open" || len(d.History) != 0 {
		t.Fatal(d, err)
	}
}
