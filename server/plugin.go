package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"kandev-security/internal/reports"
)

type securityPlugin struct {
	pluginsdk.UnimplementedPlugin
	store *reports.Store
}

var _ pluginsdk.ActionHandler = (*securityPlugin)(nil)

// Workspace authority comes exclusively from Kandev's verified action context.
func (p *securityPlugin) HandleAction(ctx context.Context, req *pluginsdk.PluginActionRequest) (*pluginsdk.PluginActionResponse, error) {
	if req == nil || req.Context.WorkspaceID == "" {
		return actionJSON(403, map[string]string{"error": "A verified workspace is required."})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.store == nil {
		return actionJSON(503, map[string]string{"error": "Report storage is unavailable."})
	}
	if isTaskAction(req.ActionKey) {
		return p.handleTaskAction(ctx, req)
	}
	if isRetentionAction(req.ActionKey) {
		return p.handleRetentionAction(ctx, req)
	}
	if req.ActionKey == "reports.archive" {
		return p.handleArchiveAction(ctx, req)
	}
	var input struct {
		HistoryOffset int    `json:"history_offset"`
		Status        string `json:"status"`
		Reason        string `json:"reason"`
		ID            string `json:"id"`
		Ordinal       *int   `json:"ordinal"`
		Name          string `json:"name"`
		Filename      string `json:"filename"`
		Size          int    `json:"size"`
		Offset        int    `json:"offset"`
		Data          string `json:"data"`
		Level         string `json:"level"`
		Search        string `json:"search"`
		Language      string `json:"language"`
		Tool          string `json:"tool"`
		Rule          string `json:"rule"`
		Severity      string `json:"severity"`
		Sort          string `json:"sort"`
		Facet         string `json:"facet"`
	}
	if len(req.Body) > 1<<20 {
		return actionFailure(reports.ErrInvalid)
	}
	raw := req.Body
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return actionFailure(reports.ErrInvalid)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return actionFailure(reports.ErrInvalid)
	}
	workspace := req.Context.WorkspaceID
	var result any
	var err error
	switch req.ActionKey {
	case "advisories.list":
		result, err = p.store.Advisories(ctx, workspace, reports.AggregateQuery{Language: input.Language, Tool: input.Tool, Rule: input.Rule, Severity: input.Severity, Search: input.Search, Sort: input.Sort, Offset: input.Offset})
	case "advisories.findings":
		result, err = p.store.AdvisoryFindings(ctx, workspace, input.ID, reports.AggregateQuery{Language: input.Language, Tool: input.Tool, Rule: input.Rule, Severity: input.Severity, Search: input.Search, Sort: input.Sort, Offset: input.Offset})
	case "tokens.create":
		result, err = p.store.CreateUploadToken(ctx, workspace, req.Context.ActorID, input.Name)
	case "tokens.list":
		result, err = p.store.ListUploadTokens(ctx, workspace, input.Offset)
	case "tokens.revoke":
		err = p.store.RevokeUploadToken(ctx, workspace, req.Context.ActorID, input.ID)
		result = map[string]bool{"revoked": true}
	case "imports.start":
		result, err = p.store.StartUpload(ctx, workspace, req.Context.ActorID, input.Filename, input.Size)
	case "imports.append":
		var chunk []byte
		chunk, err = base64.StdEncoding.DecodeString(input.Data)
		if err != nil {
			err = reports.ErrInvalid
			break
		}
		var offset int
		offset, err = p.store.AppendUpload(ctx, workspace, input.ID, input.Offset, chunk)
		result = map[string]int{"offset": offset}
	case "imports.complete":
		result, err = p.store.CompleteUpload(ctx, workspace, input.ID)
	case "imports.cancel":
		err = p.store.CancelUpload(ctx, workspace, input.ID)
		result = map[string]bool{"cancelled": true}
	case "issues.list":
		result, err = p.store.Issues(ctx, workspace, reports.IssueQuery{AggregateQuery: reports.AggregateQuery{Language: input.Language, Tool: input.Tool, Rule: input.Rule, Severity: input.Severity, Search: input.Search, Sort: input.Sort, Offset: input.Offset}, Status: input.Status})
	case "issues.get":
		result, err = p.store.Issue(ctx, workspace, input.ID, input.Offset, input.HistoryOffset)
	case "issues.set_status":
		err = p.store.SetIssueStatus(ctx, workspace, req.Context.ActorID, input.ID, input.Status, input.Reason)
		result = map[string]bool{"updated": true}
	case "findings.get":
		if input.Ordinal == nil {
			err = reports.ErrInvalid
			break
		}
		result, err = p.store.Finding(ctx, workspace, input.ID, *input.Ordinal)
	case "findings.list":
		result, err = p.store.AggregateWithStatus(ctx, workspace, reports.AggregateQuery{Language: input.Language, Tool: input.Tool, Rule: input.Rule, Severity: input.Severity, Search: input.Search, Sort: input.Sort, Offset: input.Offset}, input.Status)
	case "findings.facets":
		result, err = p.store.Facets(ctx, workspace, input.Facet, input.Search, input.Offset)
	case "reports.list":
		result, err = p.store.QueryReports(ctx, workspace, reports.ReportQuery{Offset: input.Offset, Status: input.Status, Tool: input.Tool, Search: input.Search})
	case "reports.tools":
		result, err = p.store.ReportTools(ctx, workspace, input.Search, input.Offset)
	case "reports.get":
		result, err = p.store.Detail(ctx, workspace, input.ID, reports.FindingQuery{Offset: input.Offset, Level: input.Level, Search: input.Search})
	case "reports.source":
		result, err = p.store.Source(ctx, workspace, input.ID, input.Offset)
	case "reports.delete":
		err = p.store.Delete(ctx, workspace, input.ID)
		result = map[string]bool{"deleted": true}
	default:
		return actionJSON(404, map[string]string{"error": "Unknown report action."})
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return actionFailure(err)
	}
	return actionJSON(200, result)
}
func actionJSON(status int, value any) (*pluginsdk.PluginActionResponse, error) {
	body, err := json.Marshal(value)
	return &pluginsdk.PluginActionResponse{Status: status, Body: body, Headers: map[string]string{"Cache-Control": "no-store"}}, err
}
func actionFailure(err error) (*pluginsdk.PluginActionResponse, error) {
	status := 500
	message := "Report storage failed. Please try again."
	switch {
	case errors.Is(err, reports.ErrInvalid):
		status = 400
		message = err.Error()
	case errors.Is(err, reports.ErrNotFound):
		status = 404
		message = "Report, finding, or import not found in this workspace."
	case errors.Is(err, reports.ErrConflict):
		status = 409
		message = err.Error()
	default:
		log.Printf("security storage error: %v", err)
	}
	return actionJSON(status, map[string]string{"error": message})
}
