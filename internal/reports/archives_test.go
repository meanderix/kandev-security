package reports

import (
	"context"
	"encoding/base64"
	"errors"

	"testing"
)

func TestArchiveVisibilityEvidenceAndRestore(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	r, raw := retentionFixture(t, s, "ws", []string{"Scanner"}, 1)
	original, err := s.Aggregate(ctx, "ws", AggregateQuery{})
	if err != nil || original.Total != 1 {
		t.Fatal(original, err)
	}
	issueID := original.Items[0].IssueID
	if err = s.LinkIssueTask(ctx, "ws", "owner", issueID, "task", "fix"); err != nil {
		t.Fatal(err)
	}
	if err = s.SetIssueStatus(ctx, "ws", "reviewer", issueID, "closed", "Verified mitigation"); err != nil {
		t.Fatal(err)
	}
	archived, err := s.SetReportArchived(ctx, "ws", "owner", r.ID, true)
	if err != nil || archived.ArchivedAt == "" || archived.ArchivedBy != "owner" || archived.CreatedAt != r.CreatedAt || archived.UpdatedAt != r.UpdatedAt {
		t.Fatal(archived, err)
	}
	again, err := s.SetReportArchived(ctx, "ws", "another", r.ID, true)
	if err != nil || again.ArchivedAt != archived.ArchivedAt || again.ArchivedBy != "owner" {
		t.Fatal("idempotence", again, err)
	}
	if _, err = s.SetReportArchived(ctx, "other", "owner", r.ID, false); !errors.Is(err, ErrNotFound) {
		t.Fatal("scope", err)
	}
	if _, err = s.SetReportArchived(ctx, "ws", "", r.ID, true); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	for status, want := range map[string]int{"": 0, "active": 0, "archived": 1, "all": 1} {
		p, err := s.ListReports(ctx, "ws", 0, status)
		if err != nil || len(p.Items) != want {
			t.Fatal(status, p, err)
		}
		a, err := s.AuditReportsByStatus(ctx, "ws", 0, status)
		if err != nil || a.Total != want || len(a.Items) != want {
			t.Fatal(status, a, err)
		}
	}
	if _, err = s.ListReports(ctx, "ws", 0, "invalid"); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	aggregate, err := s.Aggregate(ctx, "ws", AggregateQuery{})
	if err != nil || aggregate.Total != 0 || aggregate.LatestImportAt != "" || aggregate.SeverityCounts["medium"] != 0 {
		t.Fatal(aggregate, err)
	}
	issues, err := s.Issues(ctx, "ws", IssueQuery{})
	if err != nil || issues.Total != 0 || issues.LatestImportAt != "" {
		t.Fatal(issues, err)
	}
	advisories, err := s.Advisories(ctx, "ws", AggregateQuery{})
	if err != nil || advisories.Total != 0 || advisories.FindingCount != 0 {
		t.Fatal(advisories, err)
	}
	for _, facet := range []string{"language", "tool", "rule"} {
		p, err := s.Facets(ctx, "ws", facet, "", 0)
		if err != nil || len(p.Items) != 0 {
			t.Fatal(facet, p, err)
		}
	}
	detail, err := s.Detail(ctx, "ws", r.ID, FindingQuery{})
	if err != nil || len(detail.Findings) != 1 || detail.Report.ArchivedAt != archived.ArchivedAt {
		t.Fatal(detail, err)
	}
	finding, err := s.Finding(ctx, "ws", r.ID, 0)
	if err != nil || finding.Report.ArchivedBy != "owner" {
		t.Fatal(finding, err)
	}
	source, err := s.Source(ctx, "ws", r.ID, 0)
	decoded, _ := base64.StdEncoding.DecodeString(source.Data)
	if err != nil || string(decoded) != string(raw) {
		t.Fatal("source changed", err)
	}
	audit, err := s.AuditSummary(ctx, "ws", []string{r.ID})
	if err != nil || audit.FindingCount != 1 || audit.Reports[0].ArchivedAt == "" {
		t.Fatal(audit, err)
	}
	history, err := s.Issue(ctx, "ws", issueID, 0, 0)
	if err != nil || history.Total != 1 || history.Issue.Status != "closed" || history.Occurrences[0].ArchivedBy != "owner" {
		t.Fatal(history, err)
	}
	duplicate, wasDuplicate, err := s.Import(ctx, "ws", "uploader", "duplicate.sarif", raw)
	if err != nil || !wasDuplicate || duplicate.ID != r.ID || duplicate.ArchivedAt != archived.ArchivedAt {
		t.Fatal(duplicate, wasDuplicate, err)
	}
	links, err := s.IssueTasks(ctx, "ws", issueID, 0)
	if err != nil || links.Total != 1 || links.Items[0].TaskID != "task" {
		t.Fatal("archive removed task link", links, err)
	}
	restored, err := s.SetReportArchived(ctx, "ws", "owner", r.ID, false)
	if err != nil || restored.ArchivedAt != "" || restored.ArchivedBy != "" {
		t.Fatal(restored, err)
	}
	aggregate, err = s.Aggregate(ctx, "ws", AggregateQuery{})
	if err != nil || aggregate.Total != 1 || aggregate.Items[0].IssueID != issueID {
		t.Fatal(aggregate, err)
	}
	history, err = s.Issue(ctx, "ws", issueID, 0, 0)
	if err != nil || history.Issue.Status != "closed" {
		t.Fatal("restore changed manual status", history, err)
	}
	links, err = s.IssueTasks(ctx, "ws", issueID, 0)
	if err != nil || links.Total != 1 {
		t.Fatal("restore removed task link", links, err)
	}
}

func TestArchiveRepresentativeAndAdvisoryCounts(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a := advisoryFixture(t, s, "ws", "A", "CVE-2026-12345", "error", "pkg-a", true)
	b := advisoryFixture(t, s, "ws", "B", "CVE-2026-12345", "note", "pkg-b", true)
	before, _ := s.Advisories(ctx, "ws", AggregateQuery{})
	key := before.Items[0].Key
	if _, err := s.SetReportArchived(ctx, "ws", "owner", a.ID, true); err != nil {
		t.Fatal(err)
	}
	after, err := s.Advisories(ctx, "ws", AggregateQuery{})
	if err != nil || after.Total != 1 || after.FindingCount != 1 || after.Items[0].ReportCount != 1 || after.Items[0].Severity != "low" {
		t.Fatal(after, err)
	}
	members, err := s.AdvisoryFindings(ctx, "ws", key, AggregateQuery{})
	if err != nil || members.Total != 1 || members.Items[0].ReportID != b.ID {
		t.Fatal(members, err)
	}
	// Two occurrences of the same persistent issue: only active occurrences count.
	raw := identityFixture(t, nil)
	first, _, err := s.Import(ctx, "shared", "owner", "first", raw)
	if err != nil {
		t.Fatal(err)
	}
	raw2 := identityFixture(t, func(_ map[string]any, result map[string]any) {
		result["message"] = map[string]any{"text": "Updated wording"}
	})
	second, _, err := s.Import(ctx, "shared", "owner", "second", raw2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetReportArchived(ctx, "shared", "owner", second.ID, true); err != nil {
		t.Fatal(err)
	}
	issues, err := s.Issues(ctx, "shared", IssueQuery{})
	if err != nil || issues.Total != 1 || issues.Items[0].OccurrenceCount != 1 || issues.Items[0].ReportID != first.ID {
		t.Fatal(issues, err)
	}
	history, err := s.Issue(ctx, "shared", issues.Items[0].Issue.ID, 0, 0)
	if err != nil || history.Total != 2 {
		t.Fatal(history, err)
	}
}

func TestArchiveRetentionAndReimport(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	old, raw := retentionFixture(t, s, "ws", []string{"Scanner"}, 1)
	old = ageReport(t, s, old, 60)
	archived, err := s.SetReportArchived(ctx, "ws", "owner", old.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetReportPinned(ctx, "ws", "owner", old.ID, true); err != nil {
		t.Fatal(err)
	}
	preview, err := s.PreviewRetention(ctx, "ws", RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxAgeDays: 30}})
	if err != nil || preview.EligibleReports != 0 || preview.PinnedReports != 1 {
		t.Fatal(preview, err)
	}
	saveRetention(t, s, "ws", RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxAgeDays: 30}})
	if _, err = s.SetReportPinned(ctx, "ws", "owner", old.ID, false); err != nil {
		t.Fatal(err)
	}
	history, err := s.PurgedReports(ctx, "ws", 0)
	if err != nil || len(history.Items) != 1 || history.Items[0].ArchivedAt != archived.ArchivedAt {
		t.Fatal(history, err)
	}
	// Disabling cleanup permits restoring the exact original bytes; visibility is preserved.
	saveRetention(t, s, "ws", RetentionConfig{})
	restored, _, err := s.Import(ctx, "ws", "actor", "again.sarif", raw)
	if err != nil || restored.ID != old.ID || restored.CreatedAt != old.CreatedAt || restored.ArchivedAt != archived.ArchivedAt || restored.ArchivedBy != "owner" {
		t.Fatal(restored, err)
	}
	active, _ := s.List(ctx, "ws", 0)
	if len(active.Items) != 0 {
		t.Fatal("reimport reactivated archive", active)
	}
	// Archived reports count toward per-scanner limits too.
	ageReport(t, s, restored, 60)
	retentionFixture(t, s, "ws", []string{"Scanner"}, 2)
	saved := saveRetention(t, s, "ws", RetentionConfig{Enabled: true, Default: RetentionPolicy{MaxReports: 1}})
	if saved.PurgedCount != 1 {
		t.Fatal(saved)
	}
}

func TestArchiveUploadRetryPreservesVisibility(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, err := s.StartUpload(ctx, "ws", "actor", "scan.sarif", len(sample))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AppendUpload(ctx, "ws", u.ID, 0, []byte(sample)); err != nil {
		t.Fatal(err)
	}
	result, err := s.CompleteUpload(ctx, "ws", u.ID)
	if err != nil {
		t.Fatal(err)
	}
	archived, err := s.SetReportArchived(ctx, "ws", "owner", result.Report.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := s.CompleteUpload(ctx, "ws", u.ID)
	if err != nil || !receipt.Duplicate || receipt.Report.ArchivedAt != archived.ArchivedAt || receipt.Report.ArchivedBy != "owner" {
		t.Fatal(receipt, err)
	}
}
