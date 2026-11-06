package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kdlbs/kandev/pluginsdk"
	"kandev-security/internal/reports"
)

type testWorkspaceHost struct {
	pluginsdk.Host
	reader pluginsdk.WorkspaceReader
}

func (h testWorkspaceHost) Workspaces() pluginsdk.WorkspaceReader { return h.reader }

type testWorkspaceReader struct {
	fail    bool
	missing bool
}

func (r testWorkspaceReader) List(ctx context.Context, page pluginsdk.Page) ([]pluginsdk.Workspace, *pluginsdk.PageInfo, error) {
	if r.fail {
		return nil, nil, errors.New("host unavailable")
	}
	if r.missing {
		return nil, &pluginsdk.PageInfo{}, nil
	}
	if page.Cursor == "" {
		return []pluginsdk.Workspace{{ID: "other"}}, &pluginsdk.PageInfo{HasMore: true, NextCursor: "next"}, nil
	}
	return []pluginsdk.Workspace{{ID: "ws"}}, &pluginsdk.PageInfo{}, nil
}

const webhookSample = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Scanner"}},"results":[{"ruleId":"R","level":"error","message":{"text":"Finding"}}]}]}`

func webhookCall(t *testing.T, p *securityPlugin, secret, body string, headers map[string]string) *pluginsdk.WebhookResponse {
	t.Helper()
	if headers == nil {
		headers = map[string]string{"Content-Type": "application/sarif+json", "X-Security-Token": secret, "X-Security-Filename": "scan.sarif"}
	}
	resp, err := p.HandleWebhook(context.Background(), &pluginsdk.WebhookRequest{WebhookKey: "upload", Method: "POST", Headers: headers, Body: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
func TestDirectWebhookUploadAndRevocation(t *testing.T) {
	p := testPlugin(t)
	p.SetHost(testWorkspaceHost{reader: testWorkspaceReader{}})
	status, value := invoke(t, p, "tokens.create", "ws", map[string]any{"name": "CI scanner"})
	if status != 200 {
		t.Fatal(value)
	}
	secret := value["secret"].(string)
	tokenID := value["token"].(map[string]any)["id"].(string)
	resp := webhookCall(t, p, secret, webhookSample, nil)
	if resp.Status != 200 {
		t.Fatalf("upload: %s", resp.Body)
	}
	var imported reports.ImportResult
	if err := json.Unmarshal(resp.Body, &imported); err != nil {
		t.Fatal(err)
	}
	if imported.Report.WorkspaceID != "ws" || imported.Report.ActorID != "actor" || imported.Report.Filename != "scan.sarif" {
		t.Fatalf("attribution: %+v", imported.Report)
	}
	resp = webhookCall(t, p, secret, webhookSample, nil)
	if resp.Status != 200 {
		t.Fatal(string(resp.Body))
	}
	status, list := invoke(t, p, "tokens.list", "ws", nil)
	if status != 200 {
		t.Fatal(list)
	}
	encoded, _ := json.Marshal(list)
	if string(encoded) == "" {
		t.Fatal("missing token listing")
	}
	for _, entry := range list["items"].([]any) {
		if _, ok := entry.(map[string]any)["secret"]; ok {
			t.Fatal("list exposed secret")
		}
	}
	if status, _ = invoke(t, p, "tokens.revoke", "other", map[string]any{"id": tokenID}); status != 404 {
		t.Fatal("cross workspace revoke")
	}
	if status, _ = invoke(t, p, "tokens.revoke", "ws", map[string]any{"id": tokenID}); status != 200 {
		t.Fatal(status)
	}
	if resp = webhookCall(t, p, secret, webhookSample, nil); resp.Status != 401 {
		t.Fatal("revoked token accepted")
	}
}
func TestWebhookRejectsMissingTokensAndInvalidInputs(t *testing.T) {
	p := testPlugin(t)
	p.SetHost(testWorkspaceHost{reader: testWorkspaceReader{}})
	token, err := p.store.CreateUploadToken(context.Background(), "ws", "issuer", "CI")
	if err != nil {
		t.Fatal(err)
	}
	if r := webhookCall(t, p, "", webhookSample, nil); r.Status != 401 {
		t.Fatal("missing token")
	}
	if r := webhookCall(t, p, "kandev_pat_example", webhookSample, nil); r.Status != 401 {
		t.Fatal("PAT accepted as plugin token")
	}
	if r := webhookCall(t, p, token.Secret, "bad SARIF", nil); r.Status != 400 {
		t.Fatal("bad report accepted")
	}
	headers := map[string]string{"x-security-token": token.Secret, "content-type": "application/json; charset=utf-8"}
	if r := webhookCall(t, p, token.Secret, webhookSample, headers); r.Status != 200 {
		t.Fatalf("case-insensitive headers: %s", r.Body)
	}
	headers["content-type"] = "multipart/form-data; boundary=abc"
	if r := webhookCall(t, p, token.Secret, webhookSample, headers); r.Status != 415 {
		t.Fatal("unsupported multipart accepted")
	}
	resp, err := p.HandleWebhook(context.Background(), &pluginsdk.WebhookRequest{WebhookKey: "upload", Method: "GET"})
	if err != nil || resp.Status != 405 {
		t.Fatal("GET accepted")
	}
	resp, err = p.HandleWebhook(context.Background(), &pluginsdk.WebhookRequest{WebhookKey: "unknown", Method: "POST"})
	if err != nil || resp.Status != 404 {
		t.Fatal("unknown hook accepted")
	}
	resp, err = p.HandleWebhook(context.Background(), &pluginsdk.WebhookRequest{WebhookKey: "upload", Method: "POST", Query: "workspaceId=other", Headers: map[string]string{"X-Security-Token": token.Secret, "Content-Type": "application/json"}, Body: []byte(webhookSample)})
	if err != nil || resp.Status != 400 {
		t.Fatal("workspace override query accepted")
	}
}
func TestWebhookWorkspaceCheckFailsClosed(t *testing.T) {
	p := testPlugin(t)
	token, err := p.store.CreateUploadToken(context.Background(), "ws", "issuer", "CI")
	if err != nil {
		t.Fatal(err)
	}
	if r := webhookCall(t, p, token.Secret, webhookSample, nil); r.Status != 503 {
		t.Fatal("missing host accepted")
	}
	p.SetHost(testWorkspaceHost{reader: testWorkspaceReader{fail: true}})
	if r := webhookCall(t, p, token.Secret, webhookSample, nil); r.Status != 503 {
		t.Fatal("failed workspace check accepted")
	}
	p.SetHost(testWorkspaceHost{reader: testWorkspaceReader{missing: true}})
	if r := webhookCall(t, p, token.Secret, webhookSample, nil); r.Status != 403 {
		t.Fatal("deleted workspace accepted")
	}
	page, err := p.store.List(context.Background(), "ws", 0)
	if err != nil || len(page.Items) != 0 {
		t.Fatal("failed workspace authorization stored data")
	}
}

func TestWebhookAccepts16MiBAndRejectsLargerBody(t *testing.T) {
	p := testPlugin(t)
	p.SetHost(testWorkspaceHost{reader: testWorkspaceReader{}})
	token, err := p.store.CreateUploadToken(context.Background(), "ws", "issuer", "Boundary")
	if err != nil {
		t.Fatal(err)
	}
	req := &pluginsdk.WebhookRequest{WebhookKey: "upload", Method: "POST", Headers: map[string]string{"X-Security-Token": token.Secret, "Content-Type": "application/sarif+json"}, Body: make([]byte, reports.MaxWebhookBytes+1)}
	response, err := p.HandleWebhook(context.Background(), req)
	if err != nil || response.Status != 413 {
		t.Fatalf("over limit: %+v %v", response, err)
	}
	prefix := webhookSample[:len(webhookSample)-1] + `,"padding":"`
	suffix := `"}`
	req.Body = []byte(prefix + strings.Repeat("x", reports.MaxWebhookBytes-len(prefix)-len(suffix)) + suffix)
	response, err = p.HandleWebhook(context.Background(), req)
	if err != nil || response.Status != 200 {
		t.Fatalf("exact limit: %s %v", response.Body, err)
	}
}
