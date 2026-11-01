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

func (p *securityPlugin) handleArchiveAction(ctx context.Context, req *pluginsdk.PluginActionRequest) (*pluginsdk.PluginActionResponse, error) {
	var input struct {
		ID       string `json:"id"`
		Archived *bool  `json:"archived"`
	}
	if len(req.Body) > 1024 {
		return actionFailure(reports.ErrInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(req.Body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return actionFailure(reports.ErrInvalid)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || input.Archived == nil {
		return actionFailure(reports.ErrInvalid)
	}
	r, err := p.store.SetReportArchived(ctx, req.Context.WorkspaceID, req.Context.ActorID, input.ID, *input.Archived)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return actionFailure(err)
	}
	return actionJSON(200, map[string]any{"report": r})
}
