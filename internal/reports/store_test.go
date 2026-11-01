package reports

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const sample = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Scanner","version":"1.0","rules":[{"id":"SQL001","helpUri":"https://example.com/rules/SQL001","defaultConfiguration":{"level":"error"},"properties":{"security-severity":"8.1"}}]}},"versionControlProvenance":[{"repositoryUri":"https://example.com/repo","revisionId":"abc123","branch":"main"}],"results":[{"ruleIndex":0,"message":{"text":"SQL injection"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/db.go"},"region":{"startLine":12,"startColumn":3}}}]},{"ruleId":"NOTE","level":"note","message":{"markdown":"Review this"}}]}]}`

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "security.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func importSample(t *testing.T, s *Store, workspace string) Report {
	t.Helper()
	r, _, err := s.Import(context.Background(), workspace, "actor", "scan.sarif", []byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestImportPersistenceIsolationAndOriginal(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "security.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r := importSample(t, s, "ws-a")
	if r.FindingCount != 2 || r.ActorID != "actor" || r.WorkspaceID != "ws-a" {
		t.Fatalf("report: %+v", r)
	}
	duplicate, existing, err := s.Import(ctx, "ws-a", "other", "renamed.sarif", []byte(sample))
	if err != nil || !existing || duplicate.ID != r.ID {
		t.Fatalf("duplicate: %+v %v %v", duplicate, existing, err)
	}
	other := importSample(t, s, "ws-b")
	if other.ID == r.ID {
		t.Fatal("cross-workspace dedup")
	}
	if _, err := s.Detail(ctx, "ws-b", r.ID, FindingQuery{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross workspace detail: %v", err)
	}
	if _, err := s.Source(ctx, "ws-b", r.ID, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross workspace export: %v", err)
	}
	if err := s.Delete(ctx, "ws-b", r.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross workspace delete: %v", err)
	}
	src, err := s.Source(ctx, "ws-a", r.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(src.Data)
	if string(raw) != sample {
		t.Fatal("original changed")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	page, err := s.List(ctx, "ws-a", 0)
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("restart: %+v %v", page, err)
	}
	d, err := s.Detail(ctx, "ws-a", r.ID, FindingQuery{Level: "error", Search: "injection"})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Findings) != 1 || d.Total != 1 || d.Findings[0].RuleID != "SQL001" || d.Findings[0].Line != 12 || d.Findings[0].SecuritySeverity != 8.1 {
		t.Fatalf("findings: %+v", d)
	}
	if len(d.Runs) != 1 || d.Runs[0].Revision != "abc123" {
		t.Fatalf("runs: %+v", d.Runs)
	}
	if err := s.Delete(ctx, "ws-a", r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Detail(ctx, "ws-a", r.ID, FindingQuery{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
}
func TestInvalidImportDoesNotPublish(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for _, raw := range []string{`{`, `null`, `{}`, `{"version":"1.0","runs":[]}`, `{"version":"2.1.0"}`, `{"version":"2.1.0","runs":[{}]}`, `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{}]}]}`, `{"version":"2.1.0","runs":[]} {}`} {
		if _, _, err := s.Import(ctx, "ws", "actor", "bad.sarif", []byte(raw)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %s: %v", raw, err)
		}
	}
	if _, _, err := s.Import(ctx, "", "actor", "x", []byte(sample)); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing workspace")
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := s.Import(ctx, "ws", "actor", "x", []byte(sample)); err == nil {
		t.Fatal("cancelled import succeeded")
	}
	p, err := s.List(context.Background(), "ws", 0)
	if err != nil || len(p.Items) != 0 {
		t.Fatal("invalid import published")
	}
}
func TestUploadChunksRetryAndWorkspace(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, err := s.StartUpload(ctx, "ws-a", "actor", "scan.sarif", len(sample))
	if err != nil {
		t.Fatal(err)
	}
	chunk := []byte(sample[:100])
	if _, err := s.AppendUpload(ctx, "ws-b", u.ID, 0, chunk); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-workspace upload")
	}
	if _, err := s.CompleteUpload(ctx, "ws-a", u.ID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("incomplete upload: %v", err)
	}
	if _, err := s.AppendUpload(ctx, "ws-a", u.ID, 1, chunk); !errors.Is(err, ErrConflict) {
		t.Fatalf("out-of-order: %v", err)
	}
	if _, err := s.AppendUpload(ctx, "ws-a", u.ID, 0, chunk); err != nil {
		t.Fatal(err)
	}
	if next, err := s.AppendUpload(ctx, "ws-a", u.ID, 0, chunk); err != nil || next != 100 {
		t.Fatalf("retry: %d %v", next, err)
	}
	if _, err := s.AppendUpload(ctx, "ws-a", u.ID, 0, []byte(strings.Repeat("z", 100))); !errors.Is(err, ErrConflict) {
		t.Fatal("conflicting retry")
	}
	if _, err := s.AppendUpload(ctx, "ws-a", u.ID, 100, []byte(sample[100:])); err != nil {
		t.Fatal(err)
	}
	result, err := s.CompleteUpload(ctx, "ws-a", u.ID)
	if err != nil || result.Report.FindingCount != 2 {
		t.Fatalf("complete: %+v %v", result, err)
	}
	// Retrying completion after an uncertain response returns the same report.
	again, err := s.CompleteUpload(ctx, "ws-a", u.ID)
	if err != nil || again.Report.ID != result.Report.ID {
		t.Fatalf("complete retry: %+v %v", again, err)
	}
}
func TestUploadLimitsAndExpiry(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if _, err := s.StartUpload(ctx, "ws", "a", "x", MaxReportBytes+1); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized upload")
	}
	u, err := s.StartUpload(ctx, "ws", "a", "x", 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendUpload(ctx, "ws", u.ID, 0, []byte("abc")); !errors.Is(err, ErrInvalid) {
		t.Fatal("overrun upload")
	}
	if err := s.CancelUpload(ctx, "other", u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("cancel cross workspace")
	}
	if _, err := s.db.Exec("UPDATE uploads SET created_at='2000-01-01T00:00:00Z'"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendUpload(ctx, "ws", u.ID, 0, []byte("{}")); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired upload")
	}
}
func TestConcurrentDuplicateAndRollback(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := s.Import(ctx, "ws", "a", "x", []byte(sample)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	p, err := s.List(ctx, "ws", 0)
	if err != nil || len(p.Items) != 1 {
		t.Fatalf("duplicate concurrent: %+v %v", p, err)
	}
	if _, err := s.db.Exec("CREATE TRIGGER reject_findings BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT, 'test failure'); END;"); err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(sample, "SQL injection", "Other finding", 1)
	if _, _, err := s.Import(ctx, "ws", "a", "x", []byte(changed)); err == nil {
		t.Fatal("expected transaction failure")
	}
	p, err = s.List(ctx, "ws", 0)
	if err != nil || len(p.Items) != 1 {
		t.Fatalf("partial import: %+v %v", p, err)
	}
}
func TestMultipleRunsPaginationAndLiteralSearch(t *testing.T) {
	s := openTestStore(t)
	var doc map[string]any
	json.Unmarshal([]byte(sample), &doc)
	run := doc["runs"].([]any)[0]
	doc["runs"] = []any{run, run}
	raw, _ := json.Marshal(doc)
	r, _, err := s.Import(context.Background(), "ws", "a", "x", raw)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.Detail(context.Background(), "ws", r.ID, FindingQuery{Limit: 1, Offset: 1})
	if err != nil || d.Total != 4 || len(d.Findings) != 1 || d.NextOffset != 2 || len(d.Runs) != 2 {
		t.Fatalf("page: %+v %v", d, err)
	}
	d, err = s.Detail(context.Background(), "ws", r.ID, FindingQuery{Search: "%"})
	if err != nil || d.Total != 0 {
		t.Fatal("search interpreted wildcard")
	}
}

func TestLargeUnicodeUploadAndChunkedExport(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	raw := []byte(strings.Replace(sample, `"version":"2.1.0"`, `"extra":"`+strings.Repeat("é😀", 200000)+`","version":"2.1.0"`, 1))
	u, err := s.StartUpload(ctx, "ws", "actor", "large.sarif", len(raw))
	if err != nil {
		t.Fatal(err)
	}
	for offset := 0; offset < len(raw); {
		end := offset + ChunkBytes
		if end > len(raw) {
			end = len(raw)
		}
		next, err := s.AppendUpload(ctx, "ws", u.ID, offset, raw[offset:end])
		if err != nil {
			t.Fatal(err)
		}
		offset = next
	}
	result, err := s.CompleteUpload(ctx, "ws", u.ID)
	if err != nil {
		t.Fatal(err)
	}
	restored := []byte{}
	for offset := 0; ; {
		part, err := s.Source(ctx, "ws", result.Report.ID, offset)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := base64.StdEncoding.DecodeString(part.Data)
		if err != nil {
			t.Fatal(err)
		}
		restored = append(restored, decoded...)
		if part.NextOffset == 0 {
			break
		}
		offset = part.NextOffset
	}
	if string(restored) != string(raw) {
		t.Fatal("chunked original export changed the file")
	}
}
func TestUploadQuota(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := s.StartUpload(ctx, "ws", "a", "x", 1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.StartUpload(ctx, "ws", "a", "x", 1); !errors.Is(err, ErrConflict) {
		t.Fatal("workspace quota not enforced")
	}
	if _, err := s.StartUpload(ctx, "other", "a", "x", 1); err != nil {
		t.Fatal(err)
	}

}

func TestRejectsLargeStructuredArraysBeforeDecoding(t *testing.T) {
	raw := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Scanner"}},"results":[` + strings.Repeat(`{},`, MaxFindings) + `{}]}]}`
	if _, _, err := parseSARIF([]byte(raw)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "50000") {
		t.Fatalf("unbounded results: %v", err)
	}
	raw = `{"version":"2.1.0","runs":[],"extra":` + strings.Repeat(`[`, 130) + `0` + strings.Repeat(`]`, 130) + `}`
	if _, _, err := parseSARIF([]byte(raw)); !errors.Is(err, ErrInvalid) {
		t.Fatal("unbounded nesting")
	}
}
