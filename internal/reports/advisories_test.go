package reports

import (
	"context"

	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func advisoryFixture(t *testing.T, s *Store, workspace, tool, id, level, pkg string, tagged bool) Report {
	t.Helper()
	properties := map[string]any{}
	if tagged {
		properties["tags"] = []string{"vulnerability"}
	}
	doc := map[string]any{"version": "2.1.0", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": tool, "rules": []any{map[string]any{"id": id, "shortDescription": map[string]any{"text": "Advisory title"}, "properties": properties}}}}, "results": []any{map[string]any{"ruleId": id, "level": level, "message": map[string]any{"text": "Package: " + pkg}, "locations": []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": "image/path"}}}}}}}}}
	raw, _ := json.Marshal(doc)
	r, _, err := s.Import(context.Background(), workspace, "actor", pkg+".sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestAdvisoryGroupsKeepOccurrencesAndWorkspaceIsolation(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a := advisoryFixture(t, s, "ws", "Trivy", "CVE-2026-12345", "error", "apt", true)
	b := advisoryFixture(t, s, "ws", "osv-scanner", "cve-2026-12345", "note", "libapt", false)
	advisoryFixture(t, s, "ws", "ZAP", "10027", "none", "page", false)
	advisoryFixture(t, s, "private", "Private", "CVE-2026-12345", "error", "secret", true)
	p, err := s.Advisories(ctx, "ws", AggregateQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Total != 1 || p.FindingCount != 2 || p.Items[0].ID != "CVE-2026-12345" || p.Items[0].OccurrenceCount != 2 || p.Items[0].IssueCount != 2 || p.Items[0].ScannerCount != 2 || p.Items[0].ReportCount != 2 || p.Items[0].Severity != "high" {
		t.Fatal(p)
	}
	key := p.Items[0].Key
	members, err := s.AdvisoryFindings(ctx, "ws", key, AggregateQuery{})
	if err != nil || members.Total != 2 {
		t.Fatal(members, err)
	}
	if members.Items[0].ReportID != a.ID || members.Items[1].ReportID != b.ID || members.Items[0].IssueID == members.Items[1].IssueID {
		t.Fatal(members)
	}
	for _, q := range []AggregateQuery{{Tool: "osv-scanner"}, {Search: "libapt"}} {
		filtered, err := s.Advisories(ctx, "ws", q)
		if err != nil || filtered.Items[0].OccurrenceCount != 1 || filtered.Items[0].Severity != "low" {
			t.Fatal(filtered, err)
		}
	}
	filtered, err := s.Advisories(ctx, "ws", AggregateQuery{Severity: "low"})
	if err != nil || filtered.Total != 0 || filtered.SeverityCounts["high"] != 1 {
		t.Fatal(filtered, err)
	}
	if _, err = s.AdvisoryFindings(ctx, "other", key, AggregateQuery{}); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign advisory", err)
	}
	if err = s.Delete(ctx, "ws", a.ID); err != nil {
		t.Fatal(err)
	}
	p, err = s.Advisories(ctx, "ws", AggregateQuery{})
	if err != nil || p.Total != 1 || p.Items[0].OccurrenceCount != 1 || p.Items[0].Severity != "low" {
		t.Fatal(p, err)
	}
	if err = s.Delete(ctx, "ws", b.ID); err != nil {
		t.Fatal(err)
	}
	p, err = s.Advisories(ctx, "ws", AggregateQuery{})
	if err != nil || p.Total != 0 {
		t.Fatal(p, err)
	}
}
func TestPrivateAdvisoriesAndAliasBoundaries(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for _, tool := range []string{"Scanner A", "Scanner B"} {
		advisoryFixture(t, s, "ws", tool, "TEMP-123", "note", tool, true)
	}
	advisoryFixture(t, s, "ws", "Scanner", "GHSA-ABCD-1234-EFGH", "warning", "one", false)
	advisoryFixture(t, s, "ws", "Other", "ghsa-abcd-1234-efgh", "error", "two", false)
	advisoryFixture(t, s, "ws", "Scanner", "CVE-2026-11111", "warning", "three", false)
	advisoryFixture(t, s, "ws", "Scanner", "CWE-79", "warning", "four", false)
	p, err := s.Advisories(ctx, "ws", AggregateQuery{})
	if err != nil || p.Total != 4 || p.FindingCount != 5 {
		t.Fatal(p, err)
	}
	for _, a := range p.Items {
		if a.Namespace == "GHSA" && (a.ID != "GHSA-abcd-1234-efgh" || a.OccurrenceCount != 2) {
			t.Fatal(a)
		}
	}
	for _, q := range []AggregateQuery{{Offset: -1}, {Sort: "SQL"}, {Severity: "wrong"}} {
		if _, err = s.Advisories(ctx, "ws", q); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	if _, err = s.AdvisoryFindings(ctx, "ws", "invalid", AggregateQuery{}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err = s.AdvisoryFindings(ctx, "ws", p.Items[0].Key, AggregateQuery{Severity: "high"}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}
func TestAdvisoryPaginationAndImportSorts(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for i := 0; i < 31; i++ {
		advisoryFixture(t, s, "ws", "Scanner", fmt.Sprintf("CVE-2026-%05d", i), "warning", fmt.Sprint(i), false)
	}
	p, err := s.Advisories(ctx, "ws", AggregateQuery{})
	if err != nil || len(p.Items) != 25 || p.Total != 31 || p.NextOffset != 25 {
		t.Fatal(p, err)
	}
	next, err := s.Advisories(ctx, "ws", AggregateQuery{Offset: 25})
	if err != nil || len(next.Items) != 6 || next.NextOffset != 0 {
		t.Fatal(next, err)
	}
	seen := map[string]bool{}
	for _, a := range append(p.Items, next.Items...) {
		if seen[a.Key] {
			t.Fatal("duplicate page row")
		}
		seen[a.Key] = true
	}
	for _, sort := range []string{"newest", "oldest", "recently_updated", "least_recently_updated", "severity"} {
		if _, err = s.Advisories(ctx, "ws", AggregateQuery{Sort: sort}); err != nil {
			t.Fatal(sort, err)
		}
	}
}

func TestAdvisoryMembersPaginateWithoutDroppingPackages(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for i := 0; i < 31; i++ {
		advisoryFixture(t, s, "ws", "Scanner", "CVE-2026-12345", "warning", fmt.Sprintf("package-%02d", i), false)
	}
	p, err := s.Advisories(ctx, "ws", AggregateQuery{})
	if err != nil || p.Total != 1 || p.Items[0].OccurrenceCount != 31 {
		t.Fatal(p, err)
	}
	first, err := s.AdvisoryFindings(ctx, "ws", p.Items[0].Key, AggregateQuery{})
	if err != nil || len(first.Items) != 25 || first.NextOffset != 25 {
		t.Fatal(first, err)
	}
	next, err := s.AdvisoryFindings(ctx, "ws", p.Items[0].Key, AggregateQuery{Offset: first.NextOffset})
	if err != nil || len(next.Items) != 6 || next.NextOffset != 0 || next.Total != 31 {
		t.Fatal(next, err)
	}
	seen := map[string]bool{}
	for _, f := range append(first.Items, next.Items...) {
		if seen[f.ReportID] {
			t.Fatal("repeated member")
		}
		seen[f.ReportID] = true
	}
}

func TestRealAdvisoryCorpus(t *testing.T) {
	dir := os.Getenv("KANDEV_SECURITY_ADVISORY_CORPUS")
	if dir == "" {
		t.Skip("set KANDEV_SECURITY_ADVISORY_CORPUS for a private corpus")
	}
	s := openTestStore(t)
	ctx := context.Background()
	for _, tool := range []string{"Trivy", "osv-scanner", "ZAP"} {
		raw, err := os.ReadFile(filepath.Join(dir, tool+".sarif"))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = s.Import(ctx, "ws", "actor", tool+".sarif", raw); err != nil {
			t.Fatal(err)
		}
	}
	p, err := s.Advisories(ctx, "ws", AggregateQuery{Tool: "Trivy"})
	if err != nil || p.Total != 1379 || p.FindingCount != 2419 {
		t.Fatal(p.Total, p.FindingCount, err)
	}
	zap, err := s.Advisories(ctx, "ws", AggregateQuery{Tool: "ZAP"})
	if err != nil || zap.Total != 0 {
		t.Fatal(zap, err)
	}
	for _, a := range p.Items {
		members, err := s.AdvisoryFindings(ctx, "ws", a.Key, AggregateQuery{Tool: "Trivy"})
		if err != nil || members.Total != a.OccurrenceCount {
			t.Fatal(a, err)
		}
	}
	t.Logf("Trivy: %d advisories covering %d findings", p.Total, p.FindingCount)
}
