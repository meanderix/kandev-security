package reports

import (
	"context"
	"errors"
	"testing"
)

func TestReviewStatusFiltersGroupedAndOccurrenceCounts(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	first, _, err := s.Import(ctx, "ws", "actor", "first.sarif", identityFixture(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.Import(ctx, "ws", "actor", "second.sarif", identityFixture(t, func(_ map[string]any, result map[string]any) {
		result["message"] = map[string]any{"text": "Repeated injection evidence"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	importFixture(t, s, "ws", "Scanner", "LOW", "note", "src/note.go", "", nil)
	importFixture(t, s, "other", "Scanner", "SQL001", "error", "src/db.go", "", 9.8)
	d, err := s.Detail(ctx, "ws", first.ID, FindingQuery{})
	if err != nil {
		t.Fatal(err)
	}
	id := d.Findings[0].IssueID
	if err = s.SetIssueStatus(ctx, "ws", "reviewer", id, "closed", "Reviewed evidence"); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"", "open", "closed"} {
		raw, err := s.AggregateWithStatus(ctx, "ws", AggregateQuery{}, status)
		wantRaw, wantIssues := 3, 2
		if status == "open" {
			wantRaw, wantIssues = 1, 1
		}
		if status == "closed" {
			wantRaw, wantIssues = 2, 1
		}
		if err != nil || raw.Total != wantRaw || len(raw.Items) != wantRaw {
			t.Fatal(status, raw, err)
		}
		grouped, err := s.Issues(ctx, "ws", IssueQuery{Status: status})
		if err != nil || grouped.Total != wantIssues {
			t.Fatal(status, grouped, err)
		}
		if status == "open" && (raw.SeverityCounts["high"] != 0 || raw.SeverityCounts["low"] != 1) {
			t.Fatal(raw)
		}
		if status == "closed" && (raw.SeverityCounts["high"] != 2 || grouped.SeverityCounts["high"] != 1 || raw.SeverityCounts["low"] != 0) {
			t.Fatal(raw, grouped)
		}
	}
	q := AggregateQuery{Tool: "Scanner", Rule: "SQL001", Language: "Go", Search: "injection", Severity: "low", Sort: "oldest"}
	filtered, err := s.AggregateWithStatus(ctx, "ws", q, "closed")
	if err != nil || filtered.Total != 0 || filtered.SeverityCounts["high"] != 2 {
		t.Fatal(filtered, err)
	}
	q.Severity = "high"
	filtered, err = s.AggregateWithStatus(ctx, "ws", q, "closed")
	if err != nil || filtered.Total != 2 {
		t.Fatal(filtered, err)
	}
	q.Offset = 1
	filtered, err = s.AggregateWithStatus(ctx, "ws", q, "closed")
	if err != nil || filtered.Total != 2 || len(filtered.Items) != 1 {
		t.Fatal(filtered, err)
	}
	if _, err = s.AggregateWithStatus(ctx, "ws", AggregateQuery{}, "invalid"); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err = s.SetReportArchived(ctx, "ws", "actor", first.ID, true); err != nil {
		t.Fatal(err)
	}
	filtered, err = s.AggregateWithStatus(ctx, "ws", AggregateQuery{}, "closed")
	if err != nil || filtered.Total != 1 {
		t.Fatal(filtered, err)
	}
}
