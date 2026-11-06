package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kdlbs/kandev/pluginsdk"
)

type taskTestHost struct {
	pluginsdk.Host
	workflows pluginsdk.WorkflowReader
	tasks     pluginsdk.TaskReader
}

func (h taskTestHost) Workflows() pluginsdk.WorkflowReader { return h.workflows }
func (h taskTestHost) Tasks() pluginsdk.TaskReader         { return h.tasks }

type taskTestWorkflows struct {
	pluginsdk.WorkflowReader
	fail  bool
	empty bool
	seen  []string
}

func (w *taskTestWorkflows) List(ctx context.Context, workspace string, p pluginsdk.Page) ([]pluginsdk.Workflow, *pluginsdk.PageInfo, error) {
	if w.fail {
		return nil, nil, errors.New("offline")
	}
	if w.empty {
		return []pluginsdk.Workflow{}, nil, nil
	}
	return []pluginsdk.Workflow{{ID: "empty", WorkspaceID: workspace}, {ID: "main", WorkspaceID: workspace, SortOrder: 1}, {ID: "foreign", WorkspaceID: "other"}}, nil, nil
}
func (w *taskTestWorkflows) ListSteps(ctx context.Context, id string) ([]pluginsdk.WorkflowStep, error) {
	w.seen = append(w.seen, id)
	if id == "empty" {
		return nil, nil
	}
	return []pluginsdk.WorkflowStep{{ID: "start", WorkflowID: id, Name: "Start", IsStartStep: true, Position: 1, OnEnterActionTypes: []string{"auto_start_agent"}}, {ID: "first", WorkflowID: id, Name: "Plan", Position: 0}}, nil
}

type taskTestReader struct {
	pluginsdk.TaskReader
	workspace string
	fail      bool
}

func (r *taskTestReader) Get(ctx context.Context, id string) (*pluginsdk.Task, error) {
	if r.fail {
		return nil, errors.New("offline")
	}
	return &pluginsdk.Task{ID: id, WorkspaceID: r.workspace, Title: "Investigate security risk", State: "in_progress"}, nil
}
func TestWorkspacePresetActionsAndNativeTaskAssociation(t *testing.T) {
	p := testPlugin(t)
	w := &taskTestWorkflows{}
	reader := &taskTestReader{workspace: "ws"}
	p.SetHost(taskTestHost{workflows: w, tasks: reader})
	reportID, _ := auditFixture(t, p, "ws")
	status, value := invoke(t, p, "task_presets.get", "ws", nil)
	if status != 200 || len(value["presets"].([]any)) != 3 {
		t.Fatal(status, value)
	}
	presets := value["presets"].([]any)
	presets[0].(map[string]any)["label"] = "Team investigate"
	status, value = invoke(t, p, "task_presets.save", "ws", map[string]any{"expected_revision": 0, "presets": presets})
	if status != 200 || value["updated_by"] != "actor" {
		t.Fatal(status, value)
	}
	if status, _ = invoke(t, p, "task_presets.save", "ws", map[string]any{"expected_revision": 0, "presets": presets}); status != 409 {
		t.Fatal("stale save", status)
	}
	if status, _ = invoke(t, p, "task_presets.save", "ws", map[string]any{"workspace_id": "other", "expected_revision": 1, "presets": presets}); status != 400 {
		t.Fatal("authority override", status)
	}
	if status, _ = invoke(t, p, "tasks.prepare", "foreign", map[string]any{"id": reportID, "ordinal": 0, "preset_id": "investigate"}); status != 404 {
		t.Fatal("foreign source", status)
	}
	status, launch := invoke(t, p, "tasks.prepare", "ws", map[string]any{"id": reportID, "ordinal": 0, "preset_id": "investigate"})
	if status != 200 || launch["workflow_id"] != "main" || launch["default_step_id"] != "start" || !strings.Contains(launch["description"].(string), reportID) {
		t.Fatal(status, launch)
	}
	for _, id := range w.seen {
		if id == "foreign" {
			t.Fatal("read foreign steps")
		}
	}
	body := map[string]any{"issue_id": launch["issue_id"], "task_id": "native-task", "preset_id": "investigate"}
	reader.workspace = "other"
	if status, _ = invoke(t, p, "tasks.link", "ws", body); status != 404 {
		t.Fatal("cross-workspace task link", status)
	}
	reader.workspace = "ws"
	for i := 0; i < 2; i++ {
		if status, value = invoke(t, p, "tasks.link", "ws", body); status != 200 {
			t.Fatal(status, value)
		}
	}
	status, list := invoke(t, p, "tasks.list", "ws", map[string]any{"issue_id": launch["issue_id"]})
	if status != 200 || list["total"] != float64(1) || list["items"].([]any)[0].(map[string]any)["title"] != "Investigate security risk" {
		t.Fatal(status, list)
	}
	reader.workspace = "other"
	status, list = invoke(t, p, "tasks.list", "ws", map[string]any{"issue_id": launch["issue_id"]})
	if status != 200 {
		t.Fatal(status)
	}
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), "Investigate security risk") || list["items"].([]any)[0].(map[string]any)["unavailable"] != true {
		t.Fatal("foreign task metadata leaked", list)
	}
	reader.fail = true
	if status, _ = invoke(t, p, "tasks.link", "ws", body); status != 503 {
		t.Fatal("host failure did not fail closed", status)
	}
	w.empty = true
	if status, _ = invoke(t, p, "tasks.prepare", "ws", map[string]any{"id": reportID, "ordinal": 0, "preset_id": "investigate"}); status != 409 {
		t.Fatal("empty workflow not explained", status)
	}
}
