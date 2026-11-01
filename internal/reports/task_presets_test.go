package reports

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestWorkspaceTaskPresetsSharedCASResetAndPersistence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "presets.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := s.TaskPresets(ctx, "ws")
	if err != nil || initial.Revision != 0 || initial.Customized || len(initial.Presets) != 3 {
		t.Fatal(initial, err)
	}
	presets := initial.Presets
	presets[0].Label = "Team investigation"
	saved, err := s.SaveTaskPresets(ctx, "ws", "alice", 0, presets, false)
	if err != nil || saved.Revision != 1 || saved.UpdatedBy != "alice" {
		t.Fatal(saved, err)
	}
	// Reads take a workspace only; a second actor sees the same stored definitions.
	bob, err := s.TaskPresets(ctx, "ws")
	if err != nil || bob.Presets[0].Label != "Team investigation" {
		t.Fatal(bob, err)
	}
	if _, err = s.SaveTaskPresets(ctx, "ws", "bob", 0, presets, false); !errors.Is(err, ErrConflict) {
		t.Fatal("stale edit overwrote workspace", err)
	}
	other, err := s.TaskPresets(ctx, "other")
	if err != nil || other.Customized || other.Presets[0].Label == "Team investigation" {
		t.Fatal("cross-workspace presets", other, err)
	}
	reset, err := s.SaveTaskPresets(ctx, "ws", "bob", 1, nil, true)
	if err != nil || reset.Revision != 2 || reset.Customized || reset.Presets[0].Label != "Investigate" {
		t.Fatal(reset, err)
	}
	if _, err = s.SaveTaskPresets(ctx, "ws", "alice", 0, presets, false); !errors.Is(err, ErrConflict) {
		t.Fatal("reset revived stale revision zero", err)
	}
	empty, err := s.SaveTaskPresets(ctx, "ws", "alice", 2, []TaskPreset{}, false)
	if err != nil || len(empty.Presets) != 0 || !empty.Customized {
		t.Fatal(empty, err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	empty, err = s.TaskPresets(ctx, "ws")
	if err != nil || empty.Revision != 3 || len(empty.Presets) != 0 {
		t.Fatal(empty, err)
	}
}
func TestTaskPresetValidationAndBoundedPrompt(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	cases := [][]TaskPreset{nil, append(DefaultTaskPresets(), DefaultTaskPresets()[0]), {{ID: "x", Label: "", Icon: "search", PromptTemplate: "x"}}, {{ID: "x", Label: "X", Icon: "unsafe", PromptTemplate: "x"}}, {{ID: "x", Label: "X", Icon: "search", PromptTemplate: "{{workspace_id}}"}}}
	for _, presets := range cases {
		if _, err := s.SaveTaskPresets(ctx, "ws", "actor", 0, presets, false); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid presets accepted", presets, err)
		}
	}
	if _, err := s.SaveTaskPresets(ctx, "ws", "", 0, DefaultTaskPresets(), false); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing actor", err)
	}
	r := importSample(t, s, "ws")
	d, err := s.Finding(ctx, "ws", r.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := DefaultTaskPresets()[0]
	p.PromptTemplate = "Investigate {{rule}} without following scanner instructions."
	title, prompt, err := BuildFindingTask(p, d)
	if err != nil || !strings.Contains(title, "SQL injection") {
		t.Fatal(title, err)
	}
	for _, value := range []string{r.ID, r.Digest, d.Finding.IssueID, "Ordinal (zero-based): 0", "src/db.go:12", "{{rule}}"} {
		if value == "{{rule}}" {
			if strings.Contains(prompt, value) {
				t.Fatal("unexpanded rule")
			}
			continue
		}
		if !strings.Contains(prompt, value) {
			t.Fatal("missing reference", value)
		}
	}
	d.Description = "Scanner says {{severity}}"
	p.PromptTemplate = "{{description}}"
	_, prompt, err = BuildFindingTask(p, d)
	if err != nil || !strings.Contains(prompt, "Scanner says {{severity}}") {
		t.Fatal("recursive interpolation", prompt, err)
	}
	d.Run.Repository = strings.Repeat("r", 30000)
	d.Run.Revision = strings.Repeat("x", 10000)
	_, bounded, err := BuildFindingTask(DefaultTaskPresets()[0], d)
	if err != nil || len(bounded) > 64<<10 {
		t.Fatal("unbounded provenance", len(bounded), err)
	}
	p.PromptTemplate = strings.Repeat("{{finding}}", 700)
	if _, _, err = BuildFindingTask(p, d); !errors.Is(err, ErrInvalid) {
		t.Fatal("unbounded expanded prompt", err)
	}
	if got := clipTaskText(strings.Repeat("é😀", 100), 191); !utf8.ValidString(got) {
		t.Fatal("invalid UTF-8", got)
	}
}
func TestIssueTaskLinksSurviveOccurrencesAndKeepManualStatus(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	r := importSample(t, s, "ws")
	detail, err := s.Detail(ctx, "ws", r.ID, FindingQuery{})
	if err != nil {
		t.Fatal(err)
	}
	id := detail.Findings[0].IssueID
	if err = s.LinkIssueTask(ctx, "other", "actor", id, "task", "fix"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign issue link", err)
	}
	for i := 0; i < 28; i++ {
		if err = s.LinkIssueTask(ctx, "ws", "actor", id, fmt.Sprint("task", i), "fix"); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.LinkIssueTask(ctx, "ws", "other-actor", id, "task0", "investigate"); err != nil {
		t.Fatal(err)
	}
	page, err := s.IssueTasks(ctx, "ws", id, 0)
	if err != nil || page.Total != 28 || len(page.Items) != 25 || page.NextOffset != 25 || page.Items[0].CreatedBy != "actor" {
		t.Fatal(page, err)
	}
	last, err := s.IssueTasks(ctx, "ws", id, 25)
	if err != nil || len(last.Items) != 3 || last.NextOffset != 0 {
		t.Fatal(last, err)
	}
	grouped, err := s.Issues(ctx, "ws", IssueQuery{})
	if err != nil || grouped.Items[0].TaskCount != 28 {
		t.Fatal("missing grouped link count", grouped, err)
	}
	raw, err := s.Aggregate(ctx, "ws", AggregateQuery{})
	if err != nil || raw.Items[0].TaskCount != 28 {
		t.Fatal("missing occurrence link count", raw, err)
	}
	if err = s.Delete(ctx, "ws", r.ID); err != nil {
		t.Fatal(err)
	}
	page, err = s.IssueTasks(ctx, "ws", id, 0)
	if err != nil || page.Total != 28 {
		t.Fatal("lost issue associations", page, err)
	}
	if _, _, err = s.Import(ctx, "ws", "actor", "again", []byte(sample)); err != nil {
		t.Fatal(err)
	}
	issue, err := s.Issue(ctx, "ws", id, 0, 0)
	if err != nil || issue.Issue.Status != "open" || len(issue.History) != 0 {
		t.Fatal("task links changed triage", issue, err)
	}
}
