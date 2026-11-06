package main

import (
	"context"
	"encoding/json"

	"github.com/kdlbs/kandev/pluginsdk"
	"kandev-security/internal/reports"
)

// Only explicitly declared tools can write drafts. No tool forwards arbitrary
// actions or accepts workspace/task/session authority in its arguments.
func (p *securityPlugin) invokeDraftTool(ctx context.Context, req *pluginsdk.AgentToolRequest, raw []byte) (any, error) {
	a := reports.DraftAuthority{WorkspaceID: req.Context.WorkspaceID, TaskID: req.Context.TaskID, SessionID: req.Context.SessionID, InvocationID: req.InvocationID}
	switch req.Name {
	case "start_report":
		var args reports.AgentReportSpec
		if err := decodeToolArgs(raw, &args); err != nil {
			return nil, err
		}
		return p.store.StartReport(ctx, a, args)
	case "list_report_drafts":
		var args struct {
			Status string `json:"status"`
			Offset int    `json:"offset"`
		}
		if err := decodeToolArgs(raw, &args); err != nil {
			return nil, err
		}
		page, err := p.store.Drafts(ctx, a, args.Status, args.Offset)
		for err == nil && len(page.Items) > 1 {
			v, _ := json.Marshal(page)
			if len(v) <= maxAgentJSONBytes-4096 {
				break
			}
			page.Items = page.Items[:len(page.Items)/2]
			page.NextOffset = args.Offset + len(page.Items)
		}
		return page, err
	case "get_report_draft":
		var args struct {
			DraftID string `json:"draft_id"`
			Offset  int    `json:"offset"`
		}
		if err := decodeToolArgs(raw, &args); err != nil {
			return nil, err
		}
		page, err := p.store.Draft(ctx, a, args.DraftID, args.Offset)
		for err == nil && len(page.Items) > 1 {
			v, _ := json.Marshal(page)
			if len(v) <= maxAgentJSONBytes-4096 {
				break
			}
			page.Items = page.Items[:len(page.Items)/2]
			page.NextOffset = args.Offset + len(page.Items)
		}
		return page, err
	case "submit_finding":
		var args struct {
			DraftID          string               `json:"draft_id"`
			ExpectedRevision *int                 `json:"expected_revision"`
			Finding          reports.AgentFinding `json:"finding"`
		}
		if err := decodeToolArgs(raw, &args); err != nil {
			return nil, err
		}
		if args.ExpectedRevision == nil {
			return nil, reports.ErrInvalid
		}
		return p.store.SubmitFinding(ctx, a, args.DraftID, *args.ExpectedRevision, args.Finding)
	case "complete_report":
		var args struct {
			DraftID          string                  `json:"draft_id"`
			ExpectedRevision *int                    `json:"expected_revision"`
			Completion       reports.AgentCompletion `json:"completion"`
		}
		if err := decodeToolArgs(raw, &args); err != nil {
			return nil, err
		}
		if args.ExpectedRevision == nil {
			return nil, reports.ErrInvalid
		}
		return p.store.CompleteReport(ctx, a, args.DraftID, *args.ExpectedRevision, args.Completion)
	case "cancel_report":
		var args struct {
			DraftID          string `json:"draft_id"`
			ExpectedRevision *int   `json:"expected_revision"`
		}
		if err := decodeToolArgs(raw, &args); err != nil {
			return nil, err
		}
		if args.ExpectedRevision == nil {
			return nil, reports.ErrInvalid
		}
		return p.store.CancelReport(ctx, a, args.DraftID, *args.ExpectedRevision)
	}
	return nil, reports.ErrInvalid
}
