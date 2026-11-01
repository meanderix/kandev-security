package reports

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestFindingDetailsExistingImportsAndRunOrdinals(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	raw := []byte(`{"version":"2.1.0","runs":[
 {"tool":{"driver":{"name":"First"}},"results":[{"message":{"text":"First result"}}]},
 {"tool":{"driver":{"name":"Second","version":"2","rules":[{"id":"R","shortDescription":{"text":"Rule title"},"fullDescription":{"markdown":"Full <script>description</script>"},"help":{"text":"Upgrade safely. See https://example.com/advisory"},"helpUri":"https://example.com/rule","properties":{"security-severity":"9.5"}}]}},"results":[{"ruleId":"R","ruleIndex":-1,"message":{"text":"Selected result"},"fixes":[{"description":{"markdown":"Upgrade to the patched version"}}]}]}
 ]}`)
	report, _, err := s.Import(ctx, "ws", "actor", "old.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.Finding(ctx, "ws", report.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if d.Finding.Ordinal != 1 || d.Finding.RunIndex != 1 || d.Finding.Message != "Selected result" || d.Run.Tool != "Second" || d.Run.Version != "2" || d.Title != "Rule title" || d.Description != "Full <script>description</script>" || !strings.Contains(d.Guidance, "Upgrade safely") || len(d.Fixes) != 1 || d.Fixes[0] != "Upgrade to the patched version" || d.Finding.SecuritySeverity != 9.5 {
		t.Fatalf("detail: %+v", d)
	}
	if _, err = s.Finding(ctx, "other", report.ID, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross workspace: %v", err)
	}
	if _, err = s.Finding(ctx, "ws", report.ID, 2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing ordinal: %v", err)
	}
	if _, err = s.Finding(ctx, "ws", report.ID, -1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative ordinal: %v", err)
	}
	first, err := s.Finding(ctx, "ws", report.ID, 0)
	if err != nil || first.Finding.Message != "First result" || first.Guidance != "" || len(first.Fixes) != 0 {
		t.Fatalf("no rule: %+v %v", first, err)
	}
	if err = s.Delete(ctx, "ws", report.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Finding(ctx, "ws", report.ID, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
}
func TestFindingDetailBoundsAndUTF8(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	doc := map[string]any{"version": "2.1.0", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "Scanner", "rules": []any{map[string]any{"id": "R", "help": map[string]any{"text": strings.Repeat("😀<", 100000)}, "fullDescription": map[string]any{"text": strings.Repeat("é", 20000)}}}}}, "results": []any{map[string]any{"ruleIndex": 0, "message": map[string]any{"text": "Finding"}}}}}}
	raw, _ := json.Marshal(doc)
	r, _, err := s.Import(ctx, "ws", "actor", "large.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.Finding(ctx, "ws", r.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(d)
	if !d.Truncated || !utf8.ValidString(d.Guidance) || len(d.Guidance) > 32<<10 || len(d.Description) > 16<<10 || len(encoded) > 1<<20 {
		t.Fatalf("unbounded detail: %d bytes", len(encoded))
	}
}
func TestSeveritySummaryAcrossPagesAndFilters(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	var r Report
	for i := 0; i < 30; i++ {
		r = importFixture(t, s, "ws", "CodeQL", strings.Repeat("R", i+1), "error", "src/a.go", "", 9.5)
	}
	importFixture(t, s, "ws", "Semgrep", "OTHER", "warning", "src/b.py", "", nil)
	importFixture(t, s, "private", "Private", "SECRET", "error", "src/x.go", "", 10)
	p, err := s.Aggregate(ctx, "ws", AggregateQuery{Severity: "medium", Offset: 0})
	if err != nil || p.Total != 1 || p.SeverityCounts["critical"] != 30 || p.SeverityCounts["medium"] != 1 || p.LatestImportAt == "" {
		t.Fatalf("summary: %+v %v", p, err)
	}
	p, err = s.Aggregate(ctx, "ws", AggregateQuery{Tool: "CodeQL", Severity: "medium"})
	if err != nil || p.Total != 0 || p.SeverityCounts["critical"] != 30 || p.SeverityCounts["medium"] != 0 {
		t.Fatalf("tool filter: %+v %v", p, err)
	}
	p, err = s.Aggregate(ctx, "ws", AggregateQuery{Tool: "CodeQL", Search: "Finding R", Offset: 25})
	if err != nil || len(p.Items) != 5 || p.Total != 30 || p.SeverityCounts["critical"] != 30 {
		t.Fatalf("page: %+v %v", p, err)
	}
	if err = s.Delete(ctx, "ws", r.ID); err != nil {
		t.Fatal(err)
	}
	p, err = s.Aggregate(ctx, "ws", AggregateQuery{Language: "Go"})
	if err != nil || p.SeverityCounts["critical"] != 29 || p.Total != 29 {
		t.Fatalf("deleted: %+v %v", p, err)
	}
	p, err = s.Aggregate(ctx, "empty", AggregateQuery{})
	if err != nil || p.Total != 0 || len(p.SeverityCounts) != 5 || p.LatestImportAt != "" {
		t.Fatalf("empty: %+v %v", p, err)
	}
}
