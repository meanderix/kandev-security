package reports

import (
	"context"

	"encoding/json"
	"errors"
	"fmt"

	"strings"
	"testing"
)

func scanFixture(tool, rule, level, path, language string, score any) []byte {
	artifact := map[string]any{"location": map[string]any{"uri": path}}
	if language != "" {
		artifact["sourceLanguage"] = language
	}
	properties := map[string]any{}
	if score != nil {
		properties["security-severity"] = score
	}
	doc := map[string]any{"version": "2.1.0", "runs": []any{map[string]any{
		"tool":      map[string]any{"driver": map[string]any{"name": tool, "rules": []any{map[string]any{"id": rule, "properties": properties}}}},
		"artifacts": []any{artifact}, "results": []any{map[string]any{"ruleId": rule, "level": level, "message": map[string]any{"text": "Finding " + rule}, "locations": []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"index": 0}, "region": map[string]any{"startLine": 1}}}}}},
	}}}
	raw, _ := json.Marshal(doc)
	return raw
}
func importFixture(t *testing.T, s *Store, workspace, tool, rule, level, path, lang string, score any) Report {
	t.Helper()
	r, _, err := s.Import(context.Background(), workspace, "actor", tool+".sarif", scanFixture(tool, rule, level, path, lang, score))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestAggregateFiltersWorkspaceAndSource(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a := importFixture(t, s, "ws", "CodeQL", "R1", "warning", "src/main.go", "", 9.2)
	b := importFixture(t, s, "ws", "Semgrep", "R2", "error", "src/app.py", "python/3", nil)
	importFixture(t, s, "other", "PrivateScanner", "SECRET", "error", "secret.rs", "", nil)
	p, err := s.Aggregate(ctx, "ws", AggregateQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Total != 2 || len(p.Items) != 2 || p.Items[0].ReportID != a.ID || p.Items[0].Language != "Go" || p.Items[0].Severity != "critical" || p.Items[0].Tool != "CodeQL" {
		t.Fatalf("aggregate: %+v", p)
	}
	for _, q := range []AggregateQuery{{Language: "Python"}, {Tool: "Semgrep"}, {Rule: "R2"}, {Severity: "high"}, {Language: "Python", Tool: "Semgrep", Rule: "R2", Severity: "high"}, {Search: "Finding R2"}} {
		p, err = s.Aggregate(ctx, "ws", q)
		if err != nil || p.Total != 1 || p.Items[0].ReportID != b.ID {
			t.Fatalf("filter %+v: %+v %v", q, p, err)
		}
	}
	p, err = s.Aggregate(ctx, "ws", AggregateQuery{Language: "Go", Tool: "Semgrep"})
	if err != nil || p.Total != 0 {
		t.Fatalf("AND filters: %+v %v", p, err)
	}
	facets, err := s.Facets(ctx, "ws", "tool", "", 0)
	if err != nil || len(facets.Items) != 2 {
		t.Fatalf("facets: %+v %v", facets, err)
	}
	for _, v := range facets.Items {
		if v == "PrivateScanner" {
			t.Fatal("workspace leak")
		}
	}
	if err = s.Delete(ctx, "ws", a.ID); err != nil {
		t.Fatal(err)
	}
	p, err = s.Aggregate(ctx, "ws", AggregateQuery{})
	if err != nil || p.Total != 1 {
		t.Fatal("deleted findings still aggregated")
	}
}
func TestAggregateAllSortModesAndReimport(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a := importFixture(t, s, "ws", "ScannerA", "old", "error", "old.go", "", 7.1)
	b := importFixture(t, s, "ws", "ScannerB", "new", "warning", "new.py", "", 9.1)
	for _, entry := range []struct{ id, created, updated string }{{a.ID, "2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z"}, {b.ID, "2026-02-01T00:00:00Z", "2026-02-01T00:00:00Z"}} {
		if _, err := s.db.Exec("UPDATE reports SET created_at=?,updated_at=? WHERE id=?", entry.created, entry.updated, entry.id); err != nil {
			t.Fatal(err)
		}
	}
	for sort, want := range map[string]string{"severity": b.ID, "newest": b.ID, "oldest": a.ID, "recently_updated": a.ID, "least_recently_updated": b.ID} {
		p, err := s.Aggregate(ctx, "ws", AggregateQuery{Sort: sort})
		if err != nil || p.Items[0].ReportID != want {
			t.Fatalf("sort %s: %+v %v", sort, p, err)
		}
	}
	updated, duplicate, err := s.Import(ctx, "ws", "other", "renamed.sarif", scanFixture("ScannerB", "new", "warning", "new.py", "", 9.1))
	if err != nil || !duplicate || updated.ID != b.ID || updated.CreatedAt != "2026-02-01T00:00:00Z" || updated.UpdatedAt <= b.CreatedAt {
		t.Fatalf("reimport: %+v %v", updated, err)
	}
	p, err := s.Aggregate(ctx, "ws", AggregateQuery{Sort: "recently_updated"})
	if err != nil || p.Items[0].ReportID != b.ID || p.Total != 2 {
		t.Fatal("reimport should update ordering without adding findings")
	}
}
func TestAggregatePaginationFacetsAndValidation(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for i := 0; i < PageSize+3; i++ {
		importFixture(t, s, "ws", "Scanner", fmt.Sprintf("RULE%03d", i), "note", "file.unknown", "", nil)
	}
	p, err := s.Aggregate(ctx, "ws", AggregateQuery{Sort: "oldest"})
	if err != nil || len(p.Items) != PageSize || p.NextOffset != PageSize {
		t.Fatalf("first page: %+v %v", p, err)
	}
	last, err := s.Aggregate(ctx, "ws", AggregateQuery{Sort: "oldest", Offset: p.NextOffset})
	if err != nil || len(last.Items) != 3 || last.NextOffset != 0 {
		t.Fatalf("last page: %+v %v", last, err)
	}
	seen := map[string]bool{}
	for _, f := range append(p.Items, last.Items...) {
		key := f.ReportID + fmt.Sprint(f.Ordinal)
		if seen[key] {
			t.Fatal("unstable paging")
		}
		seen[key] = true
	}
	facets, err := s.Facets(ctx, "ws", "rule", "", 0)
	if err != nil || len(facets.Items) != PageSize || facets.NextOffset != PageSize {
		t.Fatalf("facet paging: %+v %v", facets, err)
	}
	facets, err = s.Facets(ctx, "ws", "rule", "RULE027", 0)
	if err != nil || len(facets.Items) != 1 || facets.Items[0] != "RULE027" {
		t.Fatalf("facet search: %+v %v", facets, err)
	}
	for _, q := range []AggregateQuery{{Sort: "id; DROP TABLE reports"}, {Offset: -1}, {Severity: "bad"}, {Language: strings.Repeat("x", 257)}} {
		if _, err := s.Aggregate(ctx, "ws", q); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid query: %+v %v", q, err)
		}
	}
	if _, err := s.Facets(ctx, "ws", "value_json", "", 0); !errors.Is(err, ErrInvalid) {
		t.Fatal("untrusted facet column")
	}
	if _, err := s.Aggregate(ctx, "", AggregateQuery{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing workspace")
	}
}

func TestLanguageAndSeverityNormalization(t *testing.T) {
	cases := []struct{ path, lang, want string }{{"a.go", "", "Go"}, {"a.tsx", "", "TypeScript"}, {"file:///src/app.py?x=1", "", "Python"}, {`C:\src\app.cs`, "", "C#"}, {"a.go", "javascript/2024", "JavaScript"}, {"unknown", "", "Unknown"}}
	for _, c := range cases {
		runs, findings, err := parseSARIF(scanFixture("Tool", "R", "warning", c.path, c.lang, nil))
		if err != nil || len(runs) != 1 || findings[0].Language != c.want {
			t.Fatalf("%+v: %+v %v", c, findings, err)
		}
	}
	for _, c := range []struct {
		score       any
		level, want string
	}{{9.0, "note", "critical"}, {7.0, "note", "high"}, {4.0, "error", "medium"}, {0.1, "error", "low"}, {0.0, "error", "informational"}, {nil, "error", "high"}, {nil, "warning", "medium"}, {nil, "note", "low"}, {nil, "none", "informational"}, {"NaN", "error", "high"}} {
		_, f, err := parseSARIF(scanFixture("Tool", "R", c.level, "file.go", "", c.score))
		if err != nil || f[0].Severity != c.want {
			t.Fatalf("%+v: %+v %v", c, f, err)
		}
	}
}
