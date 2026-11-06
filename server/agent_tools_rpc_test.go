package main

import (
	"context"
	"net"
	"testing"

	"github.com/kdlbs/kandev/pluginsdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// Hide HostSetter: these tools use plugin storage and need no Host
// calls. Exercise real SDK protobuf conversion and dispatch over in-memory gRPC.
type auditRPCHandler struct{ plugin *securityPlugin }

func (p *auditRPCHandler) OnEvent(ctx context.Context, e *pluginsdk.Event) error {
	return p.plugin.OnEvent(ctx, e)
}
func (p *auditRPCHandler) HandleWebhook(ctx context.Context, r *pluginsdk.WebhookRequest) (*pluginsdk.WebhookResponse, error) {
	return p.plugin.HandleWebhook(ctx, r)
}
func (p *auditRPCHandler) InvokeAgentTool(ctx context.Context, r *pluginsdk.AgentToolRequest) (*pluginsdk.AgentToolResult, error) {
	return p.plugin.InvokeAgentTool(ctx, r)
}
func TestAuditAgentToolSDKRoundTrip(t *testing.T) {
	for _, surface := range []string{"kanban-task", "office-task", "automation"} {
		t.Run(surface, func(t *testing.T) { testAuditAgentToolSDKRoundTrip(t, surface) })
	}
}
func testAuditAgentToolSDKRoundTrip(t *testing.T, surface string) {
	request := func(name string, args map[string]any) *pluginsdk.AgentToolRequest {
		req := auditRequest(name, args)
		req.Context.Surface = surface
		return req
	}
	p := testPlugin(t)
	id, _ := auditFixture(t, p, "ws")
	listener := bufconn.Listen(1 << 20)
	defer listener.Close()
	server := grpc.NewServer()
	defer server.Stop()
	sdk := &pluginsdk.GRPCPlugin{Impl: &auditRPCHandler{plugin: p}}
	if err := sdk.GRPCServer(nil, server); err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener)
	conn, err := grpc.NewClient("passthrough:///audit", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := sdk.GRPCClient(context.Background(), nil, conn)
	if err != nil {
		t.Fatal(err)
	}
	remote := raw.(*pluginsdk.RemotePlugin)
	for _, tc := range []struct {
		name string
		args map[string]any
	}{{"get_audit_summary", nil}, {"list_findings", nil}, {"list_filter_values", map[string]any{"facet": "rule"}}} {
		response, err := remote.InvokeAgentTool(context.Background(), request(tc.name, tc.args))
		if err != nil || response.IsError {
			t.Fatal("default report scope RPC", tc.name, response, err)
		}
		data := response.StructuredContent["data"].(map[string]any)
		if data["report_scope"] != "active_workspace" || data["report_count"] != float64(1) || data["reports"].([]any)[0].(map[string]any)["report_id"] != id {
			t.Fatal("default scope lost across RPC", data)
		}
	}
	for _, ids := range []any{nil, []any{}} {
		response, err := remote.InvokeAgentTool(context.Background(), request("list_findings", map[string]any{"report_ids": ids}))
		if err != nil || !response.IsError || response.StructuredContent["error"].(map[string]any)["code"] != "invalid_arguments" {
			t.Fatal("invalid explicit scope widened across RPC", ids, response, err)
		}
	}
	req := request("get_finding", map[string]any{"report_id": id, "ordinal": 0})
	result, err := remote.InvokeAgentTool(context.Background(), req)
	if err != nil || result.IsError {
		t.Fatalf("SDK invocation: %+v %v", result, err)
	}
	data := result.StructuredContent["data"].(map[string]any)
	if data["finding"].(map[string]any)["message"] != "Critical finding" {
		t.Fatal("wrong finding after RPC")
	}
	// Common evidence survives the public protobuf/StructuredContent boundary.
	web, _, err := p.store.Import(context.Background(), "ws", "actor", "web.sarif", []byte(`{"version":"2.1.0","runs":[{"automationDetails":{"id":"web/staging"},"tool":{"driver":{"name":"Generic web scanner"}},"results":[{"message":{"text":"Review response"},"webRequest":{"method":"GET","target":"https://example.test/","headers":{"Authorization":"private"}},"webResponse":{"statusCode":403,"body":{"text":"<html>Evidence</html>"}}}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	webResult, err := remote.InvokeAgentTool(context.Background(), request("get_finding", map[string]any{"report_id": web.ID, "ordinal": 0}))
	if err != nil || webResult.IsError {
		t.Fatal(webResult, err)
	}
	webData := webResult.StructuredContent["data"].(map[string]any)
	http := webData["http"].(map[string]any)
	if webData["context"].(map[string]any)["automation_id"] != "web/staging" || http["response"].(map[string]any)["status_code"] != float64(403) || http["request"].(map[string]any)["headers"].(map[string]any)["Authorization"] != "[redacted]" {
		t.Fatal("common evidence RPC", webData)
	}
	issueID := data["finding"].(map[string]any)["issue_id"]
	issueReq := request("get_issue", map[string]any{"issue_id": issueID})
	issueResult, err := remote.InvokeAgentTool(context.Background(), issueReq)
	if err != nil || issueResult.IsError || issueResult.StructuredContent["data"].(map[string]any)["total"] != float64(1) {
		t.Fatal("issue RPC", issueResult, err)
	}
	// Review writes and attribution survive the public SDK/protobuf path too.
	reviewReq := request("set_issue_status", map[string]any{"issue_id": issueID, "status": "open", "reason": "RPC review needs validation"})
	reviewResult, err := remote.InvokeAgentTool(context.Background(), reviewReq)
	if err != nil || reviewResult.IsError || reviewResult.StructuredContent["source"] != "issue_review" {
		t.Fatal("review RPC", reviewResult, err)
	}
	issueResult, err = remote.InvokeAgentTool(context.Background(), issueReq)
	if err != nil || issueResult.IsError {
		t.Fatal(issueResult, err)
	}
	reviewHistory := issueResult.StructuredContent["data"].(map[string]any)["history"].([]any)
	reviewChange := reviewHistory[0].(map[string]any)
	if reviewChange["kind"] != "reason_updated" || reviewChange["task_id"] != "task" || reviewChange["session_id"] != "session" {
		t.Fatal(reviewChange)
	}
	// Exercise authoring through the same public SDK/protobuf path.
	start, err := remote.InvokeAgentTool(context.Background(), request("start_report", draftToolSpec("rpc-audit")))
	if err != nil || start.IsError {
		t.Fatal(start, err)
	}
	draftID := start.StructuredContent["data"].(map[string]any)["id"]
	submit, err := remote.InvokeAgentTool(context.Background(), request("submit_finding", map[string]any{"draft_id": draftID, "expected_revision": 0, "finding": draftToolFinding("rpc-finding")}))
	if err != nil || submit.IsError {
		t.Fatal(submit, err)
	}
	resume := request("get_report_draft", map[string]any{"draft_id": draftID})
	resume.Context.SessionID = "later-session"
	draft, err := remote.InvokeAgentTool(context.Background(), resume)
	if err != nil || draft.IsError || len(draft.StructuredContent["data"].(map[string]any)["items"].([]any)) != 1 {
		t.Fatal("resumed draft RPC", draft, err)
	}
	published, err := remote.InvokeAgentTool(context.Background(), request("complete_report", map[string]any{"draft_id": draftID, "expected_revision": 1, "completion": map[string]any{"summary": "One risk", "coverage": "Inspected database calls", "limitations": []any{"No runtime verification"}}}))
	if err != nil || published.IsError {
		t.Fatal("publication RPC", published, err)
	}
	reportID := published.StructuredContent["data"].(map[string]any)["report"].(map[string]any)["id"]
	read, err := remote.InvokeAgentTool(context.Background(), request("get_finding", map[string]any{"report_id": reportID, "ordinal": 0}))
	if err != nil || read.IsError || read.StructuredContent["data"].(map[string]any)["finding"].(map[string]any)["severity"] != "critical" {
		t.Fatal("generated finding RPC", read, err)
	}
	req.Context.WorkspaceID = "other"
	result, err = remote.InvokeAgentTool(context.Background(), req)
	if err != nil || !result.IsError {
		t.Fatal("workspace binding lost across RPC")
	}
}
