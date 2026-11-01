package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime"
	"path"
	"strings"
	"time"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"kandev-security/internal/reports"
)

// Kandev authenticates the caller without forwarding their credentials. The
// plugin-owned token independently binds upload authority to one workspace;
// caller-supplied workspace selectors are never authority for this endpoint.
func (p *securityPlugin) HandleWebhook(ctx context.Context, req *pluginsdk.WebhookRequest) (*pluginsdk.WebhookResponse, error) {
	if req == nil {
		return webhookJSON(400, map[string]string{"error": "An upload request is required."})
	}
	if req.WebhookKey != "upload" {
		return webhookJSON(404, map[string]string{"error": "Unknown webhook."})
	}
	if req.Method != "POST" {
		response, err := webhookJSON(405, map[string]string{"error": "Use POST to upload SARIF."})
		response.Headers["Allow"] = "POST"
		return response, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if p.store == nil {
		return webhookJSON(503, map[string]string{"error": "Report storage is unavailable."})
	}
	secret := webhookHeader(req.Headers, "X-Security-Token")
	token, err := p.store.AuthenticateUploadToken(ctx, secret)
	if err != nil {
		return webhookFailure(err)
	}
	if len(req.Body) > reports.MaxWebhookBytes {
		return webhookFailure(reports.ErrTooLarge)
	}
	if req.Query != "" {
		return webhookJSON(400, map[string]string{"error": "Upload does not accept query parameters. Workspace ownership comes from the upload token."})
	}
	contentType, _, err := mime.ParseMediaType(webhookHeader(req.Headers, "Content-Type"))
	if err != nil || (contentType != "application/sarif+json" && contentType != "application/json") {
		return webhookJSON(415, map[string]string{"error": "Send raw SARIF with Content-Type: application/sarif+json or application/json."})
	}
	exists, err := p.uploadWorkspaceExists(ctx, token.WorkspaceID)
	if err != nil {
		return webhookJSON(503, map[string]string{"error": "Workspace verification is unavailable. Please try again."})
	}
	if !exists {
		return webhookJSON(403, map[string]string{"error": "The upload token's workspace no longer exists."})
	}
	filename := strings.TrimSpace(webhookHeader(req.Headers, "X-Security-Filename"))
	if filename == "" {
		filename = "report.sarif"
	}
	filename = path.Base(strings.ReplaceAll(filename, `\`, "/"))
	if filename == "." || filename == ".." {
		return webhookJSON(400, map[string]string{"error": "Invalid report filename."})
	}
	result, err := p.store.ImportWithToken(ctx, secret, filename, req.Body)
	if err != nil {
		return webhookFailure(err)
	}
	return webhookJSON(200, result)
}
func webhookHeader(headers map[string]string, name string) string {
	value := ""
	found := false
	for key, item := range headers {
		if strings.EqualFold(key, name) {
			if found {
				return ""
			}
			value = item
			found = true
		}
	}
	return value
}
func (p *securityPlugin) uploadWorkspaceExists(ctx context.Context, id string) (bool, error) {
	host := p.Host()
	if host == nil {
		return false, fmt.Errorf("host unavailable")
	}
	page := pluginsdk.Page{Limit: 100}
	seen := map[string]bool{}
	for {
		workspaces, info, err := host.Workspaces().List(ctx, page)
		if err != nil {
			return false, err
		}
		for _, workspace := range workspaces {
			if workspace.ID == id {
				return true, nil
			}
		}
		if info == nil || !info.HasMore {
			return false, nil
		}
		if info.NextCursor == "" || seen[info.NextCursor] {
			return false, fmt.Errorf("invalid workspace pagination")
		}
		seen[info.NextCursor] = true
		page.Cursor = info.NextCursor
	}
}
func webhookJSON(status int, value any) (*pluginsdk.WebhookResponse, error) {
	body, err := json.Marshal(value)
	return &pluginsdk.WebhookResponse{Status: int32(status), Body: body, Headers: map[string]string{"Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store"}}, err
}
func webhookFailure(err error) (*pluginsdk.WebhookResponse, error) {
	status := 500
	message := "Report storage failed. Please try again."
	switch {
	case errors.Is(err, reports.ErrUnauthorized):
		status = 401
		message = "A valid X-Security-Token upload token is required."
	case errors.Is(err, reports.ErrTooLarge):
		status = 413
		message = "Direct uploads are limited to 16 MiB (16777216 bytes)."
	case errors.Is(err, reports.ErrInvalid):
		status = 400
		message = err.Error()
	case errors.Is(err, context.DeadlineExceeded):
		status = 504
		message = "The upload timed out. Retry the same report safely."
	case errors.Is(err, context.Canceled):
		status = 503
		message = "The upload was cancelled."
	default:
		log.Printf("security webhook storage error: %v", err)
	}
	return webhookJSON(status, map[string]string{"error": message})
}
