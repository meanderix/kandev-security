package main

import (
	"context"
	"errors"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"kandev-security/internal/reports"
)

type taskLaunchStep struct {
	ID     string         `json:"id"`
	Title  string         `json:"title"`
	Events map[string]any `json:"events"`
}
type taskLaunch struct {
	WorkspaceID   string           `json:"workspace_id"`
	IssueID       string           `json:"issue_id"`
	PresetID      string           `json:"preset_id"`
	Title         string           `json:"title"`
	Description   string           `json:"description"`
	WorkflowID    string           `json:"workflow_id"`
	DefaultStepID string           `json:"default_step_id"`
	Steps         []taskLaunchStep `json:"steps"`
}
type linkedTask struct {
	reports.IssueTaskLink
	Title       string `json:"title,omitempty"`
	State       string `json:"state,omitempty"`
	Unavailable bool   `json:"unavailable"`
}

var errTaskHostUnavailable = errors.New("Kandev task services are unavailable; please retry")

func isTaskAction(key string) bool {
	switch key {
	case "task_presets.get", "task_presets.save", "task_presets.reset", "tasks.prepare", "tasks.link", "tasks.list":
		return true
	}
	return false
}
func (p *securityPlugin) handleTaskAction(ctx context.Context, req *pluginsdk.PluginActionRequest) (*pluginsdk.PluginActionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var in struct {
		ID               string               `json:"id"`
		Ordinal          *int                 `json:"ordinal"`
		IssueID          string               `json:"issue_id"`
		TaskID           string               `json:"task_id"`
		PresetID         string               `json:"preset_id"`
		Offset           int                  `json:"offset"`
		ExpectedRevision *int                 `json:"expected_revision"`
		Presets          []reports.TaskPreset `json:"presets"`
	}
	raw := req.Body
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if len(raw) > 64<<10 {
		return actionFailure(reports.ErrInvalid)
	}
	if err := decodeToolArgs(raw, &in); err != nil {
		return actionFailure(err)
	}
	ws := req.Context.WorkspaceID
	var result any
	var err error
	switch req.ActionKey {
	case "task_presets.get":
		result, err = p.store.TaskPresets(ctx, ws)
	case "task_presets.save", "task_presets.reset":
		if in.ExpectedRevision == nil {
			return actionFailure(reports.ErrInvalid)
		}
		result, err = p.store.SaveTaskPresets(ctx, ws, req.Context.ActorID, *in.ExpectedRevision, in.Presets, req.ActionKey == "task_presets.reset")
	case "tasks.prepare":
		if in.Ordinal == nil {
			return actionFailure(reports.ErrInvalid)
		}
		result, err = p.prepareTask(ctx, ws, in.ID, *in.Ordinal, in.PresetID)
	case "tasks.link":
		if in.TaskID == "" || len(in.TaskID) > 128 || in.PresetID == "" || len(in.PresetID) > 128 || req.Context.ActorID == "" {
			return actionFailure(reports.ErrInvalid)
		}
		// A native dialog creates the task. Verify its actual workspace before
		// recording a relationship; caller-supplied task IDs are not authority.
		if _, err = p.store.IssueTasks(ctx, ws, in.IssueID, 0); err != nil {
			break
		}
		host := p.Host()
		if host == nil {
			err = errTaskHostUnavailable
			break
		}
		var task *pluginsdk.Task
		task, err = host.Tasks().Get(ctx, in.TaskID)
		if err != nil {
			if status.Code(err) == codes.NotFound || status.Code(err) == codes.PermissionDenied || status.Code(err) == codes.Unauthenticated {
				err = reports.ErrNotFound
			} else {
				err = errTaskHostUnavailable
			}
			break
		}
		if task == nil || task.ID != in.TaskID || task.WorkspaceID != ws {
			err = reports.ErrNotFound
			break
		}
		err = p.store.LinkIssueTask(ctx, ws, req.Context.ActorID, in.IssueID, in.TaskID, in.PresetID)
		result = map[string]bool{"linked": true}
	case "tasks.list":
		var page reports.IssueTaskPage
		page, err = p.store.IssueTasks(ctx, ws, in.IssueID, in.Offset)
		if err != nil {
			break
		}
		host := p.Host()
		if host == nil {
			err = errTaskHostUnavailable
			break
		}
		items := []linkedTask{}
		for _, l := range page.Items {
			item := linkedTask{IssueTaskLink: l, Unavailable: true}
			task, readErr := host.Tasks().Get(ctx, l.TaskID)
			if readErr == nil && task != nil && task.ID == l.TaskID && task.WorkspaceID == ws {
				item.Title = clipTitle(task.Title, 512)
				item.State = clipTitle(task.State, 80)
				item.Unavailable = false
			}
			items = append(items, item)
		}
		result = struct {
			Items      []linkedTask `json:"items"`
			Total      int          `json:"total"`
			NextOffset int          `json:"next_offset"`
		}{items, page.Total, page.NextOffset}
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		if errors.Is(err, errTaskHostUnavailable) {
			return actionJSON(503, map[string]string{"error": err.Error()})
		}
		return actionFailure(err)
	}
	return actionJSON(200, result)
}
func clipTitle(v string, n int) string {
	if len(v) <= n {
		return v
	}
	v = v[:n]
	for !utf8.ValidString(v) {
		v = v[:len(v)-1]
	}
	return v
}
func (p *securityPlugin) prepareTask(ctx context.Context, workspace, id string, ordinal int, presetID string) (taskLaunch, error) {
	launch := taskLaunch{WorkspaceID: workspace}
	detail, err := p.store.Finding(ctx, workspace, id, ordinal)
	if err != nil {
		return launch, err
	}
	settings, err := p.store.TaskPresets(ctx, workspace)
	if err != nil {
		return launch, err
	}
	var preset *reports.TaskPreset
	for i := range settings.Presets {
		if settings.Presets[i].ID == presetID {
			preset = &settings.Presets[i]
			break
		}
	}
	if preset == nil {
		return launch, reports.ErrNotFound
	}
	launch.Title, launch.Description, err = reports.BuildFindingTask(*preset, detail)
	if err != nil {
		return launch, err
	}
	launch.IssueID = detail.Finding.IssueID
	launch.PresetID = presetID
	host := p.Host()
	if host == nil {
		return launch, errTaskHostUnavailable
	}
	workflows := []pluginsdk.Workflow{}
	page := pluginsdk.Page{Limit: 100}
	seen := map[string]bool{}
	for attempts := 0; attempts < 10; attempts++ {
		items, info, err := host.Workflows().List(ctx, workspace, page)
		if err != nil {
			return launch, errTaskHostUnavailable
		}
		for _, wf := range items {
			if wf.WorkspaceID == workspace {
				workflows = append(workflows, wf)
			}
		}
		if info == nil || !info.HasMore {
			break
		}
		if info.NextCursor == "" || seen[info.NextCursor] || attempts == 9 {
			return launch, errTaskHostUnavailable
		}
		seen[info.NextCursor] = true
		page.Cursor = info.NextCursor
	}
	sort.Slice(workflows, func(i, j int) bool {
		if workflows[i].SortOrder == workflows[j].SortOrder {
			return workflows[i].ID < workflows[j].ID
		}
		return workflows[i].SortOrder < workflows[j].SortOrder
	})
	for _, wf := range workflows {
		steps, err := host.Workflows().ListSteps(ctx, wf.ID)
		if err != nil {
			return launch, errTaskHostUnavailable
		}
		valid := []pluginsdk.WorkflowStep{}
		for _, s := range steps {
			if s.WorkflowID == wf.ID {
				valid = append(valid, s)
			}
		}
		if len(valid) == 0 {
			continue
		}
		sort.Slice(valid, func(i, j int) bool {
			if valid[i].Position == valid[j].Position {
				return valid[i].ID < valid[j].ID
			}
			return valid[i].Position < valid[j].Position
		})
		launch.WorkflowID = wf.ID
		launch.DefaultStepID = valid[0].ID
		launch.Steps = []taskLaunchStep{}
		for _, step := range valid {
			if step.IsStartStep {
				launch.DefaultStepID = step.ID
			}
			onEnter := []map[string]any{}
			for _, kind := range step.OnEnterActionTypes {
				onEnter = append(onEnter, map[string]any{"type": kind})
			}
			launch.Steps = append(launch.Steps, taskLaunchStep{step.ID, step.Name, map[string]any{"on_enter": onEnter}})
		}
		return launch, nil
	}
	return launch, errors.Join(reports.ErrConflict, errors.New("this workspace needs a workflow with at least one step before starting a task"))
}
