package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"kandev-security/internal/reports"
)

func isRetentionAction(key string) bool {
	switch key {
	case "retention.get", "retention.save", "retention.preview", "retention.run", "reports.pin", "reports.purged.list":
		return true
	}
	return false
}
func (p *securityPlugin) handleRetentionAction(ctx context.Context, req *pluginsdk.PluginActionRequest) (*pluginsdk.PluginActionResponse, error) {
	var input struct {
		Config           *reports.RetentionConfig `json:"config"`
		ExpectedRevision *int                     `json:"expected_revision"`
		ID               string                   `json:"id"`
		Pinned           *bool                    `json:"pinned"`
		Offset           int                      `json:"offset"`
	}
	raw := req.Body
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if len(raw) > 128<<10 {
		return actionFailure(reports.ErrInvalid)
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
	case "retention.get":
		result, err = p.store.RetentionSettings(ctx, workspace)
	case "retention.save":
		if input.Config == nil || input.ExpectedRevision == nil {
			return actionFailure(reports.ErrInvalid)
		}
		result, err = p.store.SaveRetention(ctx, workspace, req.Context.ActorID, *input.ExpectedRevision, *input.Config)
	case "retention.preview":
		if input.Config == nil {
			return actionFailure(reports.ErrInvalid)
		}
		result, err = p.store.PreviewRetention(ctx, workspace, *input.Config)
	case "retention.run":
		result, err = p.store.RunRetention(ctx, workspace, req.Context.ActorID)
	case "reports.pin":
		if input.Pinned == nil {
			return actionFailure(reports.ErrInvalid)
		}
		result, err = p.store.SetReportPinned(ctx, workspace, req.Context.ActorID, input.ID, *input.Pinned)
	case "reports.purged.list":
		result, err = p.store.PurgedReports(ctx, workspace, input.Offset)
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return actionFailure(err)
	}
	return actionJSON(200, result)
}
