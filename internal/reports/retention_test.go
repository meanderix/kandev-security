package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"strings"
	"testing"
	"time"
)

func retentionFixture(t *testing.T, s *Store, workspace string, tools []string, n int) (Report, []byte) {
	t.Helper()
	var runs []any
	for _, tool := range tools {
		runs = append(runs, map[string]any{"tool": map[string]any{"driver": map[string]any{"name": tool}}, "results": []any{map[string]any{"ruleId": "CVE-2026-12345", "level": "warning", "message": map[string]any{"text": fmt.Sprintf("Sensitive evidence %d", n)}, "locations": []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": "file:///app/main.go"}, "region": map[string]any{"snippet": map[string]any{"text": "shared source context"}}}}}}}})
	}
	raw, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": runs})
	r, _, err := s.Import(context.Background(), workspace, "actor", fmt.Sprintf("scan-%d.sarif", n), raw)
	if err != nil {
		t.Fatal(err)
	}
	return r, raw
}
func ageReport(t *testing.T, s *Store, r Report, days int) Report {
	t.Helper()
	r.CreatedAt = time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339Nano)
	r.UpdatedAt = r.CreatedAt
	if _, err := s.db.Exec("UPDATE reports SET created_at=?,updated_at=? WHERE id=?", r.CreatedAt, r.UpdatedAt, r.ID); err != nil {
		t.Fatal(err)
	}
	return r
}
func saveRetention(t *testing.T, s *Store, workspace string, c RetentionConfig) RetentionSaveResult {
	t.Helper()
	d, err := s.RetentionSettings(context.Background(), workspace)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.SaveRetention(context.Background(), workspace, "owner", d.Revision, c)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestRetentionDefaultsDisabledAndPreviewIsReadOnly(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	r, _ := retentionFixture(t, s, "ws", []string{"Tool"}, 1)
	d, err := s.RetentionSettings(ctx, "ws")
	if err != nil || d.Config.Enabled || d.Config.Default.MaxReports != 0 || d.Revision != 0 || len(d.Scanners) != 1 {
		t.Fatal(d, err)
	}
	ageReport(t, s, r, 60)
	config := RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxAgeDays: 30}}
	p, err := s.PreviewRetention(ctx, "ws", config)
	if err != nil || p.EligibleReports != 1 || p.EligibleBytes != int64(r.Size) {
		t.Fatal(p, err)
	}
	if _, err = s.Detail(ctx, "ws", r.ID, FindingQuery{}); err != nil {
		t.Fatal("preview mutated source", err)
	}
	if err = s.RunAllRetention(ctx); err != nil {
		t.Fatal(err)
	}
	list, _ := s.List(ctx, "ws", 0)
	if len(list.Items) != 1 {
		t.Fatal("default cleanup enabled")
	}
}
func TestRetentionPerScannerCountOverridesAndWorkspaceIsolation(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for _, tool := range []string{"A", "B", "Tool, with comma"} {
		for i := 0; i < 3; i++ {
			r, _ := retentionFixture(t, s, "ws", []string{tool}, i)
			ageReport(t, s, r, 3-i)
		}
	}
	other, _ := retentionFixture(t, s, "private", []string{"A"}, 1)
	ageReport(t, s, other, 90)
	result := saveRetention(t, s, "ws", RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxReports: 1}, Overrides: []ScannerRetention{{Tool: "B", RetentionPolicy: RetentionPolicy{MaxReports: 0}}}})
	if result.PurgedCount != 4 {
		t.Fatal(result)
	}
	list, err := s.List(ctx, "ws", 0)
	if err != nil || len(list.Items) != 5 {
		t.Fatal(list, err)
	}
	if _, err = s.Detail(ctx, "private", other.ID, FindingQuery{}); err != nil {
		t.Fatal("foreign report removed", err)
	}
	archives, err := s.PurgedReports(ctx, "ws", 0)
	if err != nil || len(archives.Items) != 4 || archives.Items[0].PurgedBy != "owner" {
		t.Fatal(archives, err)
	}
	foreign, err := s.PurgedReports(ctx, "other", 0)
	if err != nil || len(foreign.Items) != 0 {
		t.Fatal("archive leak", foreign, err)
	}
}
func TestRetentionPinsAreExemptAndUnpinAppliesPolicy(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	old, _ := retentionFixture(t, s, "ws", []string{"A"}, 1)
	ageReport(t, s, old, 60)
	retentionFixture(t, s, "ws", []string{"A"}, 2)
	retentionFixture(t, s, "ws", []string{"A"}, 3)
	if _, err := s.SetReportPinned(ctx, "ws", "actor", old.ID, true); err != nil {
		t.Fatal(err)
	}
	preview, err := s.PreviewRetention(ctx, "ws", RetentionConfig{})
	if err != nil || preview.PinnedReports != 1 || preview.EligibleReports != 0 {
		t.Fatal(preview, err)
	}
	r := saveRetention(t, s, "ws", RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxReports: 1, MaxAgeDays: 30}})
	if r.PurgedCount != 1 {
		t.Fatal(r)
	}
	list, err := s.List(ctx, "ws", 0)
	if err != nil || len(list.Items) != 2 {
		t.Fatal(list, err)
	}
	detail, err := s.Detail(ctx, "ws", old.ID, FindingQuery{})
	if err != nil || !detail.Report.Pinned {
		t.Fatal(detail.Report, err)
	}
	if _, err = s.SetReportPinned(ctx, "other", "actor", old.ID, false); !errors.Is(err, ErrNotFound) {
		t.Fatal("pin scope", err)
	}
	p, err := s.SetReportPinned(ctx, "ws", "actor", old.ID, false)
	if err != nil || p.PurgedCount != 1 || p.Retained || p.Pinned {
		t.Fatal(p, err)
	}
	if _, err = s.Source(ctx, "ws", old.ID, 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("source retained", err)
	}
}
func TestRetentionMixedScannerReportsRequireEveryPolicy(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	mixed, _ := retentionFixture(t, s, "ws", []string{"A", "B"}, 1)
	ageReport(t, s, mixed, 10)
	retentionFixture(t, s, "ws", []string{"A"}, 2)
	r := saveRetention(t, s, "ws", RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxReports: 1}, Overrides: []ScannerRetention{{Tool: "B"}}})
	if r.PurgedCount != 0 {
		t.Fatal("mixed source removed", r)
	}
	retentionFixture(t, s, "ws", []string{"B"}, 3)
	r = saveRetention(t, s, "ws", RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxReports: 1}})
	if r.PurgedCount != 1 {
		t.Fatal(r)
	}
	if _, err := s.Detail(ctx, "ws", mixed.ID, FindingQuery{}); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
func TestRetentionPreservesIssueDecisionsTasksAndCompactProvenance(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	old, _ := retentionFixture(t, s, "ws", []string{"A"}, 1)
	old = ageReport(t, s, old, 60)
	newer, _ := retentionFixture(t, s, "ws", []string{"A"}, 2)
	d, err := s.Finding(ctx, "ws", old.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	id := d.Finding.IssueID
	if err = s.SetIssueStatus(ctx, "ws", "reviewer", id, "closed", "Reviewed separately from report lifecycle"); err != nil {
		t.Fatal(err)
	}
	if err = s.LinkIssueTask(ctx, "ws", "reviewer", id, "task", "fix"); err != nil {
		t.Fatal(err)
	}
	saveRetention(t, s, "ws", RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxAgeDays: 30}})
	issue, err := s.Issue(ctx, "ws", id, 0, 0)
	if err != nil || issue.Total != 2 || issue.PurgedCount != 1 || issue.Issue.Status != "closed" || len(issue.History) != 1 {
		t.Fatal(issue, err)
	}
	links, err := s.IssueTasks(ctx, "ws", id, 0)
	if err != nil || links.Total != 1 {
		t.Fatal(links, err)
	}
	for _, o := range issue.Occurrences {
		if o.ReportID == old.ID && (o.PurgedAt == "" || o.SHA256 != old.Digest || o.Message != "" || o.URI != "file:///app/main.go") {
			t.Fatal("bad compact source", o)
		}
	}
	p, err := s.Aggregate(ctx, "ws", AggregateQuery{})
	if err != nil || p.Total != 1 || p.Items[0].ReportID != newer.ID {
		t.Fatal("purged source still aggregated", p, err)
	}
	advisories, err := s.Advisories(ctx, "ws", AggregateQuery{})
	if err != nil || advisories.FindingCount != 1 {
		t.Fatal(advisories, err)
	}
}
func TestRetentionAgeUsesFirstImportAndOldReimportsStayOld(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	r, raw := retentionFixture(t, s, "ws", []string{"A"}, 1)
	r = ageReport(t, s, r, 40)
	saveRetention(t, s, "ws", RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxAgeDays: 30}})
	retry, duplicate, err := s.Import(ctx, "ws", "new-actor", "renamed.sarif", raw)
	if err != nil || !duplicate || retry.ID != r.ID || retry.CreatedAt != r.CreatedAt || retry.Filename != r.Filename || retry.ActorID != r.ActorID || retry.PurgedAt == "" {
		t.Fatal(retry, duplicate, err)
	}
	p, err := s.List(ctx, "ws", 0)
	if err != nil || len(p.Items) != 0 {
		t.Fatal("old evidence revived", p, err)
	}
	history, err := s.PurgedReports(ctx, "ws", 0)
	if err != nil || len(history.Items) != 1 {
		t.Fatal("reimport duplicated history", history, err)
	}
	saveRetention(t, s, "ws", RetentionConfig{})
	restored, duplicate, err := s.Import(ctx, "ws", "new-actor", "renamed.sarif", raw)
	if err != nil || !duplicate || restored.PurgedAt != "" || restored.CreatedAt != r.CreatedAt || restored.ID != r.ID {
		t.Fatal(restored, duplicate, err)
	}
	history, err = s.PurgedReports(ctx, "ws", 0)
	if err != nil || len(history.Items) != 0 {
		t.Fatal("restored source still marked unavailable", history, err)
	}
}
func TestRetentionImportEnforcementAndLostCompletionReceipts(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	r, raw := retentionFixture(t, s, "other", []string{"A"}, 1)
	u, err := s.StartUpload(ctx, "ws", "actor", "scan.sarif", len(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AppendUpload(ctx, "ws", u.ID, 0, raw); err != nil {
		t.Fatal(err)
	}
	first, err := s.CompleteUpload(ctx, "ws", u.ID)
	if err != nil {
		t.Fatal(err)
	}
	ageReport(t, s, first.Report, 60)
	saveRetention(t, s, "ws", RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxAgeDays: 30}})
	receipt, err := s.CompleteUpload(ctx, "ws", u.ID)
	if err != nil || !receipt.Duplicate || receipt.Report.PurgedAt == "" || receipt.Report.Digest != r.Digest {
		t.Fatal(receipt, err)
	}
	saveRetention(t, s, "other", RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxReports: 1}})
	retentionFixture(t, s, "other", []string{"A"}, 2)
	p, err := s.List(ctx, "other", 0)
	if err != nil || len(p.Items) != 1 {
		t.Fatal("imports did not enforce count", p, err)
	}
}
func TestRetentionPublishedDraftReceiptSurvivesPurge(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a := draftAuthority()
	d := startDraft(t, s, a)
	if _, err := s.SubmitFinding(ctx, a, d.ID, 0, draftFinding("finding")); err != nil {
		t.Fatal(err)
	}
	published, err := s.CompleteReport(ctx, a, d.ID, 1, draftCompletion())
	if err != nil {
		t.Fatal(err)
	}
	ageReport(t, s, published.Report, 60)
	saveRetention(t, s, "ws", RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxAgeDays: 30}})
	receipt, err := s.CompleteReport(ctx, a, d.ID, 1, draftCompletion())
	if err != nil || receipt.Report.ID != published.Report.ID || receipt.Report.PurgedAt == "" {
		t.Fatal(receipt, err)
	}
	detail, err := s.Draft(ctx, a, d.ID, 0)
	if err != nil || detail.Draft.ReportAvailable {
		t.Fatal(detail, err)
	}
}
func TestRetentionValidationRevisionChecksAndBackgroundSweeps(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for _, c := range []RetentionConfig{{Default: RetentionPolicy{MaxReports: -1}}, {Default: RetentionPolicy{MaxAgeDays: 36501}}, {Overrides: []ScannerRetention{{Tool: "A"}, {Tool: "A"}}}, {Overrides: []ScannerRetention{{Tool: " "}}}} {
		if _, err := s.SaveRetention(ctx, "ws", "actor", 0, c); !errors.Is(err, ErrInvalid) {
			t.Fatal(c, err)
		}
	}
	r, _ := retentionFixture(t, s, "ws", []string{"A"}, 1)
	saveRetention(t, s, "ws", RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxAgeDays: 30}})
	if _, err := s.SaveRetention(ctx, "ws", "actor", 0, RetentionConfig{}); !errors.Is(err, ErrConflict) {
		t.Fatal("stale save", err)
	}
	ageReport(t, s, r, 60)
	if err := s.RunAllRetention(ctx); err != nil {
		t.Fatal(err)
	}
	p, err := s.PurgedReports(ctx, "ws", 0)
	if err != nil || len(p.Items) != 1 || p.Items[0].PurgedBy != "system:retention" {
		t.Fatal(p, err)
	}
	settings, err := s.RetentionSettings(ctx, "ws")
	if err != nil || settings.LastRunAt == "" || settings.LastPurgedCount != 1 || settings.Revision != 1 {
		t.Fatal(settings, err)
	}
}
func TestRetentionHistoryPaginationAndZeroFindingReports(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	var issueID string
	for i := 0; i < 30; i++ {
		r, _ := retentionFixture(t, s, "ws", []string{"A"}, i)
		if i == 0 {
			detail, err := s.Finding(ctx, "ws", r.ID, 0)
			if err != nil {
				t.Fatal(err)
			}
			issueID = detail.Finding.IssueID
		}
		ageReport(t, s, r, 60)
	}
	raw := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"A"}},"results":[]}]}`)
	r, _, err := s.Import(ctx, "ws", "actor", "zero.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	ageReport(t, s, r, 60)
	raw = []byte(`{"version":"2.1.0","runs":[]}`)
	r, _, err = s.Import(ctx, "ws", "actor", "no-runs.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	ageReport(t, s, r, 60)
	result := saveRetention(t, s, "ws", RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxAgeDays: 30}})
	if result.PurgedCount != 32 {
		t.Fatal(result)
	}
	p, err := s.PurgedReports(ctx, "ws", 0)
	if err != nil || len(p.Items) != 25 || p.NextOffset != 25 {
		t.Fatal(p, err)
	}
	last, err := s.PurgedReports(ctx, "ws", p.NextOffset)
	if err != nil || len(last.Items) != 7 || last.NextOffset != 0 {
		t.Fatal(last, err)
	}
	issues, err := s.Issues(ctx, "ws", IssueQuery{})
	if err != nil || issues.Total != 0 {
		t.Fatal(issues, err)
	}
	orphan, err := s.Issue(ctx, "ws", issueID, 0, 0)
	if err != nil || orphan.Total != 30 || orphan.PurgedCount != 30 || len(orphan.Occurrences) != 25 || orphan.NextOffset != 25 || orphan.Issue.Status != "open" {
		t.Fatal("orphaned issue history unavailable", orphan, err)
	}
	remaining, err := s.Issue(ctx, "ws", issueID, orphan.NextOffset, 0)
	if err != nil || len(remaining.Occurrences) != 5 || remaining.NextOffset != 0 {
		t.Fatal(remaining, err)
	}
}

func TestRetentionFailureRollsBackPolicyAndPartialCleanup(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	var reports []Report
	for i := 0; i < 3; i++ {
		r, _ := retentionFixture(t, s, "ws", []string{"A"}, i)
		ageReport(t, s, r, 60+i)
		reports = append(reports, r)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_second_retention_delete BEFORE DELETE ON reports WHEN EXISTS(SELECT 1 FROM purged_reports WHERE id<>OLD.id) BEGIN SELECT RAISE(ABORT,'injected retention failure'); END;`); err != nil {
		t.Fatal(err)
	}
	_, err := s.SaveRetention(ctx, "ws", "actor", 0, RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxAgeDays: 30}})
	if err == nil {
		t.Fatal("cleanup unexpectedly succeeded")
	}
	settings, err := s.RetentionSettings(ctx, "ws")
	if err != nil || settings.Revision != 0 || settings.Config.Enabled {
		t.Fatal("failed cleanup changed settings", settings, err)
	}
	archive, err := s.PurgedReports(ctx, "ws", 0)
	if err != nil || len(archive.Items) != 0 {
		t.Fatal("partial history published", archive, err)
	}
	for _, r := range reports {
		if _, err := s.Source(ctx, "ws", r.ID, 0); err != nil {
			t.Fatal("partial cleanup deleted source", err)
		}
	}
}

func TestRetentionIssueHistoryFitsHostResponseBudget(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	var issueID string
	for i := 0; i < 30; i++ {
		r, _ := retentionFixture(t, s, "ws", []string{"A"}, i)
		if i == 0 {
			d, err := s.Finding(ctx, "ws", r.ID, 0)
			if err != nil {
				t.Fatal(err)
			}
			issueID = d.Finding.IssueID
		}
		ageReport(t, s, r, 60)
	}
	saveRetention(t, s, "ws", RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxAgeDays: 30}})
	// Maximal escaped source fields and decision reasons must still page safely.
	value, _ := json.Marshal(Finding{Tool: strings.Repeat("<", 256), RuleID: strings.Repeat("<", 1024), URI: strings.Repeat("<", 2048)})
	if _, err := s.db.Exec("UPDATE issue_purged_occurrences SET value_json=?", string(value)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE purged_reports SET reason=?", strings.Repeat("<", 2048)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		status := "closed"
		if i%2 == 1 {
			status = "open"
		}
		if err := s.SetIssueStatus(ctx, "ws", "reviewer", issueID, status, strings.Repeat("<", 2000)); err != nil {
			t.Fatal(err)
		}
	}
	d, err := s.Issue(ctx, "ws", issueID, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(d)
	if len(encoded) > 850<<10 || d.Total != 30 || d.NextOffset != len(d.Occurrences) || d.HistoryNextOffset != len(d.History) {
		t.Fatal("unbounded or unpageable history", len(encoded), d.NextOffset, d.HistoryNextOffset)
	}
}
