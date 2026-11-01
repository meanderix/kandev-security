package reports

import (
	"context"
	"errors"
	"testing"
)

func TestReportQueryToolsStatusCountsAndPagination(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for i := 0; i < 30; i++ {
		r, _ := retentionFixture(t, s, "ws", []string{"Scanner A"}, i)
		if i < 2 {
			if _, err := s.SetReportArchived(ctx, "ws", "owner", r.ID, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	retentionFixture(t, s, "ws", []string{"Scanner A", "Scanner, B"}, 31)
	raw := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Scanner, B"}},"results":[]}]}`)
	empty, _, err := s.Import(ctx, "ws", "actor", "empty.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetReportArchived(ctx, "ws", "owner", empty.ID, true); err != nil {
		t.Fatal(err)
	}
	retentionFixture(t, s, "private", []string{"Private scanner"}, 1)
	page, err := s.QueryReports(ctx, "ws", ReportQuery{Status: "all"})
	if err != nil || page.Total != 32 || len(page.Items) != 25 || page.NextOffset != 25 || page.StatusCounts["active"] != 29 || page.StatusCounts["archived"] != 3 {
		t.Fatal(page, err)
	}
	next, err := s.QueryReports(ctx, "ws", ReportQuery{Status: "all", Offset: page.NextOffset})
	if err != nil || next.Total != 32 || len(next.Items) != 7 || next.NextOffset != 0 {
		t.Fatal(next, err)
	}
	ids := map[string]bool{}
	for _, r := range append(page.Items, next.Items...) {
		if ids[r.ID] {
			t.Fatal("duplicate page member")
		}
		ids[r.ID] = true
	}
	a, err := s.QueryReports(ctx, "ws", ReportQuery{Tool: "Scanner A", Status: "archived"})
	if err != nil || a.Total != 2 || len(a.Items) != 2 || a.StatusCounts["all"] != 31 || a.StatusCounts["active"] != 29 {
		t.Fatal(a, err)
	}
	b, err := s.QueryReports(ctx, "ws", ReportQuery{Tool: "Scanner, B"})
	if err != nil || b.Total != 1 || b.StatusCounts["all"] != 2 || b.StatusCounts["archived"] != 1 {
		t.Fatal(b, err)
	}
	archived, err := s.QueryReports(ctx, "ws", ReportQuery{Tool: "Scanner, B", Status: "archived"})
	if err != nil || archived.Total != 1 || archived.Items[0].FindingCount != 0 || archived.Items[0].ID != empty.ID {
		t.Fatal(archived, err)
	}
	tools, err := s.ReportTools(ctx, "ws", "scanner", 0)
	if err != nil || len(tools.Items) != 2 || tools.Items[0] != "Scanner A" || tools.Items[1] != "Scanner, B" {
		t.Fatal(tools, err)
	}
	partial, err := s.QueryReports(ctx, "ws", ReportQuery{Tool: "Scanner"})
	if err != nil || partial.Total != 0 {
		t.Fatal("tool matching is not exact", partial, err)
	}
	for _, q := range []ReportQuery{{Offset: -1}, {Status: "invalid"}, {Tool: string(make([]byte, 257))}} {
		if _, err = s.QueryReports(ctx, "ws", q); !errors.Is(err, ErrInvalid) {
			t.Fatal(q, err)
		}
	}
	if _, err = s.ReportTools(ctx, "ws", "", -1); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestReportFilenameSearchCombinesFiltersAndCounts(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for i, entry := range []struct {
		workspace, tool, name string
		archived              bool
	}{
		{"ws", "A", "web-PROD-2026-11.sarif", false},
		{"ws", "A", "WEB-prod-2026-10.SARIF", true},
		{"ws", "B", "web-prod-other.sarif", false},
		{"ws", "A", "100%_O'Reilly.sarif", false},
		{"private", "A", "web-prod-private.sarif", false},
	} {
		r, _ := retentionFixture(t, s, entry.workspace, []string{entry.tool}, i)
		if _, err := s.db.Exec("UPDATE reports SET filename=? WHERE id=?", entry.name, r.ID); err != nil {
			t.Fatal(err)
		}
		if entry.archived {
			if _, err := s.SetReportArchived(ctx, entry.workspace, "owner", r.ID, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, status := range []string{"all", "active", "archived"} {
		p, err := s.QueryReports(ctx, "ws", ReportQuery{Tool: "A", Search: "WEB-PrOd", Status: status})
		want := 1
		if status == "all" {
			want = 2
		}
		if err != nil || p.Total != want || len(p.Items) != want || p.StatusCounts["all"] != 2 || p.StatusCounts["active"] != 1 || p.StatusCounts["archived"] != 1 {
			t.Fatal(status, p, err)
		}
	}
	for _, search := range []string{"%_", "O'Reilly"} {
		p, err := s.QueryReports(ctx, "ws", ReportQuery{Search: search})
		if err != nil || p.Total != 1 || p.Items[0].Filename != "100%_O'Reilly.sarif" {
			t.Fatal(search, p, err)
		}
	}
	// Scanner names and imported finding messages do not contribute to filename search.
	for _, search := range []string{"Sensitive evidence", "' OR 1=1 --", "private"} {
		p, err := s.QueryReports(ctx, "ws", ReportQuery{Search: search, Status: "all"})
		if err != nil || p.Total != 0 || p.StatusCounts["all"] != 0 {
			t.Fatal(search, p, err)
		}
	}
	if _, err := s.QueryReports(ctx, "ws", ReportQuery{Search: string(make([]byte, 257))}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}
