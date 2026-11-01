package reports

import (
	"context"

	"encoding/json"
	"errors"
	"fmt"

	"strings"
	"testing"
)

func identityFixture(t *testing.T, change func(map[string]any, map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(sample), &doc); err != nil {
		t.Fatal(err)
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	result := run["results"].([]any)[0].(map[string]any)
	run["results"] = []any{result}
	result["partialFingerprints"] = map[string]any{"primaryLocationLineHash": "stable:1"}
	if change != nil {
		change(run, result)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func parsedIdentity(t *testing.T, raw []byte) findingIdentity {
	t.Helper()
	_, f, err := parseSARIF(raw)
	if err != nil {
		t.Fatal(err)
	}
	return f[0].identity
}
func TestIssueIdentityMatchingBoundaries(t *testing.T) {
	base := parsedIdentity(t, identityFixture(t, nil))
	// Freeze the version-1 canonical format so refactors cannot silently change IDs.
	if got := base.id("ws"); got != "ce23746845a0bd90e3193ce0cb17b5bb3b0637507ac679e2b9b32659add8a3fc" {
		t.Fatalf("identity v1 changed: %s", got)
	}
	if base.Method != "scanner-fingerprint" {
		t.Fatal(base)
	}
	moved := parsedIdentity(t, identityFixture(t, func(run, r map[string]any) {
		r["message"] = map[string]any{"text": "Changed explanation"}
		r["level"] = "note"
		r["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["region"].(map[string]any)["startLine"] = 99
		run["versionControlProvenance"].([]any)[0].(map[string]any)["revisionId"] = "new commit"
	}))
	if base.id("ws") != moved.id("ws") || base.id("other") == base.id("ws") {
		t.Fatal("unstable or unscoped identity")
	}
	for name, change := range map[string]func(map[string]any, map[string]any){
		"repository": func(run, r map[string]any) {
			run["versionControlProvenance"].([]any)[0].(map[string]any)["repositoryUri"] = "https://example.com/other"
		},
		"branch": func(run, r map[string]any) {
			run["versionControlProvenance"].([]any)[0].(map[string]any)["branch"] = "release"
		},
		"category": func(run, r map[string]any) { run["automationDetails"] = map[string]any{"id": "other-analysis/"} },
		"scanner":  func(run, r map[string]any) { run["tool"].(map[string]any)["driver"].(map[string]any)["name"] = "Other" },
		"rule":     func(run, r map[string]any) { delete(r, "ruleIndex"); r["ruleId"] = "OtherRule" },
		"path": func(run, r map[string]any) {
			r["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"] = map[string]any{"uri": "other.go"}
		},
		"fingerprint": func(run, r map[string]any) {
			r["partialFingerprints"] = map[string]any{"primaryLocationLineHash": "other"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if parsedIdentity(t, identityFixture(t, change)).id("ws") == base.id("ws") {
				t.Fatal("merged different scope")
			}
		})
	}
	unknown := func(run, r map[string]any) { delete(run, "versionControlProvenance") }
	a := parsedIdentity(t, identityFixture(t, unknown))
	b := parsedIdentity(t, identityFixture(t, func(run, r map[string]any) { unknown(run, r); r["level"] = "note" }))
	if a.Method != "occurrence-only" || a.id("ws") == b.id("ws") {
		t.Fatal("ambiguous relative paths merged")
	}
	absolute := parsedIdentity(t, identityFixture(t, func(run, r map[string]any) {
		unknown(run, r)
		r["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"] = map[string]any{"uri": "file:///project/src/db.go"}
	}))
	if absolute.Scope != "absolute-path" || absolute.Method != "scanner-fingerprint" {
		t.Fatal(absolute)
	}
}
func TestIssueContextFingerprintAndDependencyFallbacks(t *testing.T) {
	snippet := func(run, r map[string]any) {
		delete(r, "partialFingerprints")
		r["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["region"].(map[string]any)["snippet"] = map[string]any{"text": "execute(query)"}
	}
	if i := parsedIdentity(t, identityFixture(t, snippet)); i.Method != "code-context" {
		t.Fatal(i)
	}
	if i := parsedIdentity(t, identityFixture(t, func(run, r map[string]any) { delete(r, "partialFingerprints") })); i.Method != "occurrence-only" {
		t.Fatal(i)
	}
	raw := identityFixture(t, func(run, r map[string]any) {
		r["fingerprints"] = map[string]any{"z": "2", "a": "1"}
		r["partialFingerprints"] = map[string]any{"fallback": "ignored"}
	})
	identity := parsedIdentity(t, raw)
	if identity.FingerprintType != "fingerprints" || identity.Fingerprints[0].Name != "a" {
		t.Fatal(identity)
	}
	_, findings, err := parseSARIF(identityFixture(t, func(run, r map[string]any) { run["results"] = []any{r, r} }))
	if err != nil || len(findings) != 2 || findings[0].identity.Method != "occurrence-only" || findings[0].identity.id("ws") == findings[1].identity.id("ws") {
		t.Fatalf("ambiguous identity: %+v %v", findings, err)
	}
	osv := func(pkg, version, manifest string) []byte {
		return identityFixture(t, func(run, r map[string]any) {
			run["tool"].(map[string]any)["driver"].(map[string]any)["name"] = "osv-scanner"
			delete(r, "ruleIndex")
			r["ruleId"] = "CVE-2026-1"
			r["message"] = map[string]any{"text": fmt.Sprintf("Package '%s@%s' is vulnerable to 'CVE-2026-1'", pkg, version)}
			r["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"] = map[string]any{"uri": manifest}
		})
	}
	dep := parsedIdentity(t, osv("@scope/pkg", "1.0", "package-lock.json"))
	newer := parsedIdentity(t, osv("@scope/pkg", "2.0", "package-lock.json"))
	if dep.Method != "dependency" || dep.Package != "@scope/pkg" || dep.id("ws") != newer.id("ws") {
		t.Fatal("package versions should share issue", dep, newer)
	}
	for _, raw := range [][]byte{osv("@other/pkg", "1.0", "package-lock.json"), osv("@scope/pkg", "1.0", "nested/package-lock.json")} {
		if parsedIdentity(t, raw).id("ws") == dep.id("ws") {
			t.Fatal("different package or manifest merged")
		}
	}
	if identityPath(`C:\repo\src\..\app.go`) != "C:/repo/app.go" || identityPath("file:///repo/my%20file.go") != "/repo/my file.go" {
		t.Fatal("path normalization")
	}
}
func TestPersistentIssuesOccurrencesStatusAndIsolation(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	raw := identityFixture(t, nil)
	a, _, err := s.Import(ctx, "ws", "actor", "first.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	changed := identityFixture(t, func(run, r map[string]any) { r["level"] = "note"; r["message"] = map[string]any{"text": "Second scan"} })
	b, _, err := s.Import(ctx, "ws", "actor", "second.sarif", changed)
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.Issues(ctx, "ws", IssueQuery{})
	if err != nil || page.Total != 1 || page.Items[0].OccurrenceCount != 2 {
		t.Fatalf("groups: %+v %v", page, err)
	}
	id := page.Items[0].IssueID
	rawPage, err := s.Aggregate(ctx, "ws", AggregateQuery{})
	if err != nil || rawPage.Total != 2 || rawPage.Items[0].IssueID != id {
		t.Fatal("occurrences changed", rawPage, err)
	}
	detail, err := s.Issue(ctx, "ws", id, 0, 0)
	if err != nil || detail.Total != 2 || detail.Occurrences[0].SHA256 == "" {
		t.Fatal(detail, err)
	}
	if _, err = s.Issue(ctx, "other", id, 0, 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign issue exposed", err)
	}
	if err = s.SetIssueStatus(ctx, "other", "actor", id, "closed", "fix"); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign issue modified", err)
	}
	for _, args := range [][3]string{{"", "closed", "reason"}, {"actor", "bad", "reason"}, {"actor", "closed", " "}} {
		if err = s.SetIssueStatus(ctx, "ws", args[0], id, args[1], args[2]); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	if err = s.SetIssueStatus(ctx, "ws", "reviewer", id, "closed", "Reviewed patch"); err != nil {
		t.Fatal(err)
	}
	if _, duplicate, err := s.Import(ctx, "ws", "actor", "again.sarif", raw); err != nil || !duplicate {
		t.Fatal(err)
	}
	detail, err = s.Issue(ctx, "ws", id, 0, 0)
	if err != nil || detail.Issue.Status != "closed" || len(detail.History) != 1 || detail.History[0].Actor != "reviewer" {
		t.Fatal(detail, err)
	}
	if err = s.SetIssueStatus(ctx, "ws", "reviewer", id, "open", "Needs investigation"); err != nil {
		t.Fatal(err)
	}
	if err = s.Delete(ctx, "ws", a.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.Delete(ctx, "ws", b.ID); err != nil {
		t.Fatal(err)
	}
	page, err = s.Issues(ctx, "ws", IssueQuery{})
	if err != nil || page.Total != 0 {
		t.Fatal("orphan visible", page, err)
	}
	detail, err = s.Issue(ctx, "ws", id, 0, 0)
	if err != nil || detail.Total != 0 || len(detail.History) != 2 {
		t.Fatal("audit history lost", detail, err)
	}
	_, _, err = s.Import(ctx, "ws", "actor", "return.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	page, err = s.Issues(ctx, "ws", IssueQuery{})
	if err != nil || page.Items[0].IssueID != id || page.Items[0].Issue.Status != "open" {
		t.Fatal("identity lost", page, err)
	}
}
func TestIssueAggregationFiltersSortsAndPagination(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for n := 0; n < 28; n++ {
		raw := identityFixture(t, func(run, r map[string]any) {
			delete(r, "ruleIndex")
			r["ruleId"] = fmt.Sprint("RULE", n)
			r["message"] = map[string]any{"text": fmt.Sprint("Finding ", n)}
		})
		if _, _, err := s.Import(ctx, "ws", "actor", "scan", raw); err != nil {
			t.Fatal(err)
		}
	}
	for _, sort := range []string{"severity", "newest", "oldest", "recently_updated", "least_recently_updated"} {
		p, err := s.Issues(ctx, "ws", IssueQuery{AggregateQuery: AggregateQuery{Sort: sort}})
		if err != nil || p.Total != 28 || len(p.Items) != 25 || p.NextOffset != 25 {
			t.Fatal(sort, p, err)
		}
		last, err := s.Issues(ctx, "ws", IssueQuery{AggregateQuery: AggregateQuery{Sort: sort, Offset: p.NextOffset}})
		if err != nil || len(last.Items) != 3 {
			t.Fatal(last, err)
		}
		seen := map[string]bool{}
		for _, f := range append(p.Items, last.Items...) {
			if seen[f.IssueID] {
				t.Fatal("unstable paging")
			}
			seen[f.IssueID] = true
		}
	}
	for _, q := range []IssueQuery{{AggregateQuery: AggregateQuery{Language: "Go", Tool: "Scanner", Rule: "RULE1", Search: "Finding 1", Severity: "medium"}}, {Status: "open", AggregateQuery: AggregateQuery{Rule: "RULE1"}}} {
		p, err := s.Issues(ctx, "ws", q)
		if err != nil || p.Total != 1 {
			t.Fatal(p, err)
		}
	}
	for _, q := range []IssueQuery{{Status: "bad"}, {AggregateQuery: AggregateQuery{Offset: -1}}, {AggregateQuery: AggregateQuery{Sort: "bad"}}, {AggregateQuery: AggregateQuery{Search: strings.Repeat("x", 257)}}} {
		if _, err := s.Issues(ctx, "ws", q); !errors.Is(err, ErrInvalid) {
			t.Fatal(q, err)
		}
	}
}

func TestIssueRepresentativeSeverityAndHistoricalSortDates(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a, _, err := s.Import(ctx, "ws", "actor", "high", identityFixture(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := s.Import(ctx, "ws", "actor", "critical", identityFixture(t, func(run, r map[string]any) {
		run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)[0].(map[string]any)["properties"] = map[string]any{"security-severity": "9.7"}
		r["message"] = map[string]any{"text": "Escalated severity"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.Issues(ctx, "ws", IssueQuery{})
	if err != nil || page.Total != 1 || page.Items[0].ReportID != b.ID || page.SeverityCounts["critical"] != 1 || page.SeverityCounts["high"] != 0 {
		t.Fatal("representative/counts", page, err)
	}
	issueID := page.Items[0].IssueID
	high, err := s.Issues(ctx, "ws", IssueQuery{AggregateQuery: AggregateQuery{Severity: "high"}})
	if err != nil || high.Total != 0 || high.SeverityCounts["critical"] != 1 {
		t.Fatal(high, err)
	}
	search, err := s.Issues(ctx, "ws", IssueQuery{AggregateQuery: AggregateQuery{Search: "SQL injection"}})
	if err != nil || search.Total != 1 || search.Items[0].ReportID != a.ID || search.Items[0].Severity != "high" || search.Items[0].OccurrenceCount != 2 {
		t.Fatal(search, err)
	}
	other := importFixture(t, s, "ws", "Other", "other", "error", "other.go", "", nil)
	raw, err := s.Detail(ctx, "ws", other.ID, FindingQuery{})
	if err != nil {
		t.Fatal(err)
	}
	otherID := raw.Findings[0].IssueID
	if _, err = s.db.Exec("UPDATE issues SET first_seen_at='2026-01-01T00:00:00.000000000Z',last_seen_at='2026-03-01T00:00:00.000000000Z' WHERE id=?", issueID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE issues SET first_seen_at='2026-02-01T00:00:00.000000000Z',last_seen_at='2026-02-01T00:00:00.000000000Z' WHERE id=?", otherID); err != nil {
		t.Fatal(err)
	}
	for sort, want := range map[string]string{"newest": otherID, "oldest": issueID, "recently_updated": issueID, "least_recently_updated": otherID} {
		p, err := s.Issues(ctx, "ws", IssueQuery{AggregateQuery: AggregateQuery{Sort: sort}})
		if err != nil || p.Items[0].IssueID != want {
			t.Fatal(sort, p, err)
		}
	}
}
func TestIssueOccurrenceAndStatusHistoryPagination(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for n := 0; n < 28; n++ {
		if _, _, err := s.Import(ctx, "ws", "actor", "scan", identityFixture(t, func(run, r map[string]any) { r["message"] = map[string]any{"text": fmt.Sprint("Occurrence ", n)} })); err != nil {
			t.Fatal(err)
		}
	}
	p, err := s.Issues(ctx, "ws", IssueQuery{})
	if err != nil || p.Total != 1 {
		t.Fatal(p, err)
	}
	id := p.Items[0].IssueID
	for n := 0; n < 28; n++ {
		status := "closed"
		if n%2 == 1 {
			status = "open"
		}
		if err := s.SetIssueStatus(ctx, "ws", "reviewer", id, status, fmt.Sprint("Reason ", n)); err != nil {
			t.Fatal(err)
		}
	}
	d, err := s.Issue(ctx, "ws", id, 0, 0)
	if err != nil || d.Total != 28 || len(d.Occurrences) != 25 || len(d.History) != 25 || d.NextOffset != 25 || d.HistoryNextOffset != 25 {
		t.Fatal(d, err)
	}
	last, err := s.Issue(ctx, "ws", id, d.NextOffset, d.HistoryNextOffset)
	if err != nil || len(last.Occurrences) != 3 || len(last.History) != 3 || last.NextOffset != 0 || last.HistoryNextOffset != 0 {
		t.Fatal(last, err)
	}
	if last.History[0].ID == d.History[0].ID {
		t.Fatal("history offset ignored")
	}
}
