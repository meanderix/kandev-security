package reports

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestAuditSelectionsFiltersAndProvenance(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a := importFixture(t, s, "ws", "CodeQL", "R1", "error", "src/a.go", "", 9.5)
	b := importFixture(t, s, "ws", "Semgrep", "R2", "warning", "src/b.py", "", nil)
	private := importFixture(t, s, "private", "Secret", "PRIVATE", "error", "secret.go", "", 10)
	summary, err := s.AuditSummary(ctx, "ws", []string{a.ID, b.ID})
	if err != nil || summary.FindingCount != 2 || summary.SeverityCounts["critical"] != 1 || summary.SeverityCounts["medium"] != 1 || len(summary.Scanners) != 2 || len(summary.ProvenanceIncompleteReportIDs) != 2 {
		t.Fatalf("summary: %+v %v", summary, err)
	}
	report, err := s.AuditReport(ctx, "ws", a.ID)
	if err != nil || report.Report.SHA256 != a.Digest || len(report.ProvenanceGaps) != 1 || len(report.Runs) != 1 {
		t.Fatalf("provenance: %+v %v", report, err)
	}
	for _, ids := range [][]string{nil, {}, []string{a.ID, a.ID}, []string{""}, []string{strings.Repeat("x", 129)}} {
		if _, err = s.AuditSummary(ctx, "ws", ids); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted invalid selection: %v %v", ids, err)
		}
	}
	for _, ids := range [][]string{{a.ID, private.ID}, {a.ID, "unknown"}, {private.ID}} {
		if _, err = s.AuditSummary(ctx, "ws", ids); !errors.Is(err, ErrNotFound) {
			t.Fatalf("partial selection: %v", err)
		}
		if _, err = s.AuditFindings(ctx, "ws", AuditQuery{ReportIDs: ids}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("findings leaked: %v", err)
		}
		if _, err = s.AuditFilterValues(ctx, "ws", ids, "tool", "", 0); !errors.Is(err, ErrNotFound) {
			t.Fatalf("facets leaked: %v", err)
		}
	}
	for _, q := range []AggregateQuery{{Language: "Go"}, {Tool: "CodeQL"}, {Rule: "R1"}, {Severity: "critical"}, {Search: "Finding R1"}, {Language: "Go", Tool: "CodeQL", Rule: "R1", Severity: "critical"}} {
		page, err := s.AuditFindings(ctx, "ws", AuditQuery{ReportIDs: []string{a.ID, b.ID}, AggregateQuery: q})
		if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].ReportID != a.ID {
			t.Fatalf("filter %+v: %+v %v", q, page, err)
		}
	}
	facets, err := s.AuditFilterValues(ctx, "ws", []string{a.ID}, "tool", "", 0)
	if err != nil || len(facets.Items) != 1 || facets.Items[0] != "CodeQL" {
		t.Fatalf("facets: %+v %v", facets, err)
	}
	page, err := s.AuditFindings(ctx, "ws", AuditQuery{ReportIDs: []string{b.ID}, AggregateQuery: AggregateQuery{Severity: "critical"}})
	if err != nil || page.Total != 0 || page.SeverityCounts["critical"] != 0 || page.SeverityCounts["medium"] != 0 {
		t.Fatalf("counts must honor severity: %+v %v", page, err)
	}
	if err = s.Delete(ctx, "ws", a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AuditSummary(ctx, "ws", []string{a.ID, b.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted selected report silently dropped: %v", err)
	}
}
func TestAuditPaginationAndZeroFindingReports(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for i := 0; i < 31; i++ {
		importFixture(t, s, "ws", "Scanner", fmt.Sprintf("R%02d", i), "warning", "a.go", "", nil)
	}
	page, err := s.AuditReports(ctx, "ws", 0)
	if err != nil || page.Total != 31 || len(page.Items) != 25 || !page.HasMore || page.NextOffset != 25 {
		t.Fatalf("first reports: %+v %v", page, err)
	}
	next, err := s.AuditReports(ctx, "ws", page.NextOffset)
	if err != nil || len(next.Items) != 6 || next.HasMore || next.NextOffset != 0 {
		t.Fatalf("next reports: %+v %v", next, err)
	}
	ids := []string{}
	for _, item := range append(page.Items, next.Items...) {
		ids = append(ids, item.ReportID)
	}
	findings, err := s.AuditFindings(ctx, "ws", AuditQuery{ReportIDs: ids})
	if err != nil || len(findings.Items) != 25 || findings.Total != 31 || findings.NextOffset != 25 {
		t.Fatalf("first findings: %+v %v", findings, err)
	}
	findings, err = s.AuditFindings(ctx, "ws", AuditQuery{ReportIDs: ids, AggregateQuery: AggregateQuery{Offset: 25}})
	if err != nil || len(findings.Items) != 6 || findings.HasMore {
		t.Fatalf("last findings: %+v %v", findings, err)
	}
	facets, err := s.AuditFilterValues(ctx, "ws", ids, "rule", "", 0)
	if err != nil || len(facets.Items) != 25 || facets.NextOffset != 25 {
		t.Fatalf("first facets: %+v %v", facets, err)
	}
	facets, err = s.AuditFilterValues(ctx, "ws", ids, "rule", "", 25)
	if err != nil || len(facets.Items) != 6 || facets.HasMore {
		t.Fatalf("last facets: %+v %v", facets, err)
	}
	empty, _, err := s.Import(ctx, "ws", "actor", "empty.sarif", []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Empty scanner","version":"1"}},"results":[]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	summary, err := s.AuditSummary(ctx, "ws", []string{empty.ID})
	if err != nil || summary.FindingCount != 0 || summary.LatestImportAt != empty.UpdatedAt || len(summary.Scanners) != 1 || summary.Scanners[0] != "Empty scanner" {
		t.Fatalf("zero findings: %+v %v", summary, err)
	}
	other, _, err := s.Import(ctx, "ws", "actor", "other.sarif", []byte(`{"version":"2.1.0","runs":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	summary, err = s.AuditSummary(ctx, "ws", []string{empty.ID})
	if err != nil || summary.LatestImportAt == other.UpdatedAt {
		t.Fatal("unselected report changed freshness")
	}
}
func TestAuditReadValidationAndCancellation(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	r := importSample(t, s, "ws")
	for _, q := range []AggregateQuery{{Offset: -1}, {Sort: "invalid"}, {Severity: "invalid"}, {Search: strings.Repeat("x", 257)}} {
		if _, err := s.AuditFindings(ctx, "ws", AuditQuery{ReportIDs: []string{r.ID}, AggregateQuery: q}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted query: %+v %v", q, err)
		}
	}
	ids := make([]string, MaxAuditReports+1)
	for i := range ids {
		ids[i] = fmt.Sprint(i)
	}
	if _, err := s.AuditSummary(ctx, "ws", ids); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := s.AuditFilterValues(ctx, "ws", []string{r.ID}, "bogus", "", 0); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.AuditSummary(cancelled, "ws", []string{r.ID}); !errors.Is(err, context.Canceled) {
		t.Fatalf("ignored cancellation: %v", err)
	}
}
