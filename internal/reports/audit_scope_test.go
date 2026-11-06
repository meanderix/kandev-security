package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestAuditDefaultScopeAndExplicitArchiveSelection(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a := importFixture(t, s, "ws", "Active", "ACTIVE", "error", "src/a.go", "", 9.5)
	archived := importFixture(t, s, "ws", "Archived", "ARCHIVED", "warning", "src/b.py", "", nil)
	importFixture(t, s, "other", "Private", "PRIVATE", "error", "secret.go", "", 10)
	if _, err := s.SetReportArchived(ctx, "ws", "actor", archived.ID, true); err != nil {
		t.Fatal(err)
	}
	empty, _, err := s.Import(ctx, "ws", "actor", "empty.sarif", []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Zero findings","version":"1"}},"results":[]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	summary, err := s.AuditSummary(ctx, "ws", nil)
	if err != nil || summary.ReportScope != "active_workspace" || summary.ReportCount != 2 || summary.FindingCount != 1 || summary.SeverityCounts["critical"] != 1 || summary.LatestImportAt != empty.UpdatedAt || !reflect.DeepEqual(summary.Scanners, []string{"Active", "Zero findings"}) {
		t.Fatalf("workspace summary: %+v %v", summary, err)
	}
	page, err := s.AuditFindings(ctx, "ws", AuditQuery{})
	if err != nil || page.ReportScope != "active_workspace" || page.ReportCount != 2 || page.Total != 1 || page.LatestImportAt != empty.UpdatedAt || len(page.Reports) != 1 || page.Reports[0].SHA256 != a.Digest || !page.ReportsTruncated {
		t.Fatalf("workspace findings: %+v %v", page, err)
	}
	if len(page.Items) != 1 || page.Items[0].ReportID != a.ID {
		t.Fatal("inactive or foreign source included", page)
	}
	for facet, want := range map[string][]string{"tool": {"Active"}, "rule": {"ACTIVE"}, "language": {"Go"}} {
		values, err := s.AuditFilterValues(ctx, "ws", nil, facet, "", 0)
		if err != nil || values.ReportScope != "active_workspace" || values.ReportCount != 2 || values.ReportsTruncated || !reflect.DeepEqual(values.Items, want) {
			t.Fatalf("workspace %s: %+v %v", facet, values, err)
		}
	}
	ids := []string{a.ID, archived.ID}
	explicit, err := s.AuditSummary(ctx, "ws", ids)
	if err != nil || explicit.ReportScope != "explicit" || explicit.ReportCount != 2 || explicit.FindingCount != 2 || explicit.ReportsTruncated {
		t.Fatalf("explicit summary: %+v %v", explicit, err)
	}
	page, err = s.AuditFindings(ctx, "ws", AuditQuery{ReportIDs: []string{archived.ID}})
	if err != nil || page.Total != 1 || len(page.Reports) != 1 || page.Reports[0].ArchivedAt == "" || page.ReportScope != "explicit" || page.ReportsTruncated {
		t.Fatalf("explicit archived findings: %+v %v", page, err)
	}
	values, err := s.AuditFilterValues(ctx, "ws", []string{archived.ID}, "tool", "", 0)
	if err != nil || !reflect.DeepEqual(values.Items, []string{"Archived"}) || values.ReportScope != "explicit" || values.Reports[0].ArchivedAt == "" {
		t.Fatalf("explicit archived filters: %+v %v", values, err)
	}
	if _, err = s.SetReportArchived(ctx, "ws", "actor", a.ID, true); err != nil {
		t.Fatal(err)
	}
	page, err = s.AuditFindings(ctx, "ws", AuditQuery{})
	if err != nil || page.Total != 0 || page.ReportCount != 1 {
		t.Fatal("default scope did not follow current archive state", page, err)
	}
}

func TestAuditDefaultScopeBeyondSelectionLimit(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	count := MaxAuditReports + 7
	digests := map[string]string{}
	for i := 0; i < count; i++ {
		r := importFixture(t, s, "ws", "Scanner", fmt.Sprintf("R%03d", i), "warning", "a.go", "", nil)
		digests[r.ID] = r.Digest
	}
	summary, err := s.AuditSummary(ctx, "ws", nil)
	if err != nil || summary.ReportCount != count || summary.FindingCount != count || summary.ProvenanceIncompleteReportCount != count || len(summary.Reports) != MaxAuditReports || len(summary.ProvenanceIncompleteReportIDs) != MaxAuditReports || !summary.ReportsTruncated || !summary.ProvenanceIncompleteReportIDsTruncated {
		t.Fatalf("complete summary with bounded metadata: %+v %v", summary, err)
	}
	seen := map[string]bool{}
	offset := 0
	for {
		page, err := s.AuditFindings(ctx, "ws", AuditQuery{AggregateQuery: AggregateQuery{Offset: offset}})
		if err != nil || page.Total != count || page.ReportCount != count || page.SeverityCounts["medium"] != count || !page.ReportsTruncated || len(page.Reports) > PageSize {
			t.Fatalf("complete findings scope: %+v %v", page, err)
		}
		refs := map[string]string{}
		for _, ref := range page.Reports {
			refs[ref.ReportID] = ref.SHA256
		}
		for _, item := range page.Items {
			if seen[item.ReportID] || refs[item.ReportID] == "" || refs[item.ReportID] != digests[item.ReportID] {
				t.Fatal("duplicate finding or missing source hash", item)
			}
			seen[item.ReportID] = true
		}
		if !page.HasMore {
			break
		}
		if page.NextOffset <= offset {
			t.Fatal("pagination did not advance")
		}
		offset = page.NextOffset
	}
	if len(seen) != count {
		t.Fatalf("lost reports beyond selection limit: %d", len(seen))
	}
	filters := []string{}
	offset = 0
	for {
		page, err := s.AuditFilterValues(ctx, "ws", nil, "rule", "", offset)
		if err != nil || page.ReportCount != count || len(page.Reports) != MaxAuditReports || !page.ReportsTruncated {
			t.Fatalf("complete filter scope: %+v %v", page, err)
		}
		filters = append(filters, page.Items...)
		if !page.HasMore {
			break
		}
		offset = page.NextOffset
	}
	if len(filters) != count || filters[0] != "R000" || filters[count-1] != fmt.Sprintf("R%03d", count-1) {
		t.Fatal("filter scope truncated", filters)
	}
	filtered, err := s.AuditFindings(ctx, "ws", AuditQuery{AggregateQuery: AggregateQuery{Language: "Go", Tool: "Scanner", Severity: "medium", Rule: "R056", Search: "Finding R056"}})
	if err != nil || filtered.Total != 1 || filtered.SeverityCounts["medium"] != 1 || filtered.ReportCount != count {
		t.Fatal("workspace filters changed semantics", filtered, err)
	}
}

func TestAuditDefaultScopeEmptyValidationAndCancellation(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	summary, err := s.AuditSummary(ctx, "empty", nil)
	if err != nil || summary.ReportCount != 0 || summary.FindingCount != 0 || summary.LatestImportAt != "" || summary.ReportsTruncated || summary.Reports == nil || summary.Scanners == nil || summary.ProvenanceIncompleteReportIDs == nil {
		t.Fatal("empty summary", summary, err)
	}
	page, err := s.AuditFindings(ctx, "empty", AuditQuery{})
	if err != nil || page.Total != 0 || page.Items == nil || page.Reports == nil || page.HasMore || page.ReportsTruncated {
		t.Fatal("empty findings", page, err)
	}
	values, err := s.AuditFilterValues(ctx, "empty", nil, "rule", "", 0)
	if err != nil || values.Items == nil || values.Reports == nil || values.HasMore || values.ReportsTruncated {
		t.Fatal("empty filter values", values, err)
	}
	for _, tc := range []struct {
		workspace string
		ids       []string
	}{{"", nil}, {"ws", []string{}}} {
		if _, err = s.AuditSummary(ctx, tc.workspace, tc.ids); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid scope accepted: %+v %v", tc, err)
		}
		if _, err = s.AuditFindings(ctx, tc.workspace, AuditQuery{ReportIDs: tc.ids}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid finding scope accepted: %+v %v", tc, err)
		}
		if _, err = s.AuditFilterValues(ctx, tc.workspace, tc.ids, "rule", "", 0); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid filter scope accepted: %+v %v", tc, err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = s.AuditSummary(cancelled, "ws", nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
}

func TestAuditWorkspaceScannerMetadataBounded(t *testing.T) {
	s := openTestStore(t)
	runs := []map[string]any{}
	for i := 110; i >= 0; i-- {
		runs = append(runs, map[string]any{"tool": map[string]any{"driver": map[string]any{"name": fmt.Sprintf("Scanner%03d", i)}}, "results": []any{}})
	}
	raw, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": runs})
	if _, _, err := s.Import(context.Background(), "ws", "actor", "many-scanners.sarif", raw); err != nil {
		t.Fatal(err)
	}
	summary, err := s.AuditSummary(context.Background(), "ws", nil)
	if err != nil || summary.FindingCount != 0 || summary.ReportCount != 1 || len(summary.Scanners) != 100 || !summary.ScannersTruncated || summary.Scanners[0] != "Scanner000" || summary.Scanners[99] != "Scanner099" {
		t.Fatal("bounded scanner names lost coverage or ordering", summary, err)
	}
}

func TestAuditDefaultScopeFreshnessMatchesExplicitSelection(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	ids := []string{}
	latest := "2026-01-01T00:00:00.11Z"
	for i, timestamp := range []string{"2026-01-01T00:00:00Z", "2026-01-01T00:00:00.1Z", latest} {
		r := importFixture(t, s, "ws", "Scanner", fmt.Sprint(i), "warning", "a.go", "", nil)
		if _, err := s.db.Exec("UPDATE reports SET updated_at=? WHERE id=?", timestamp, r.ID); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.ID)
	}
	for _, selection := range [][]string{nil, ids} {
		page, err := s.AuditFindings(ctx, "ws", AuditQuery{ReportIDs: selection})
		if err != nil || page.LatestImportAt != latest {
			t.Fatalf("finding freshness differs between scopes: %+v %v", page, err)
		}
		summary, err := s.AuditSummary(ctx, "ws", selection)
		if err != nil || summary.LatestImportAt != latest {
			t.Fatalf("summary freshness differs between scopes: %+v %v", summary, err)
		}
	}
}
