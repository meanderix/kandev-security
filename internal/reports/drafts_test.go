package reports

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func draftAuthority() DraftAuthority { return DraftAuthority{"ws", "task", "session", "invocation"} }
func draftSpec() AgentReportSpec {
	return AgentReportSpec{ClientReportID: "audit-1", Title: "Application audit", Instructions: "Inspect request handlers for injection.", Scope: []string{"src/handlers"}, Repository: "https://example.com/repo", Revision: "abc123", Branch: "main"}
}
func draftFinding(id string) AgentFinding {
	return AgentFinding{FindingID: id, Title: "Unparameterized query", Description: "**Untrusted input** reaches SQL execution.", Severity: "critical", Confidence: "medium", Evidence: "The request parameter is concatenated into the query before db.Query.", Remediation: "Use parameterized queries.", RuleID: "CWE-89", CWEs: []string{"CWE-89"}, URI: "src/handlers/db.go", Line: 12, Snippet: "db.Query(query + input)", Language: "Go"}
}
func draftCompletion() AgentCompletion {
	return AgentCompletion{Summary: "Found a query construction risk.", Coverage: "Inspected request handlers and database call sites.", Limitations: []string{"No runtime exploit validation."}}
}
func startDraft(t *testing.T, s *Store, a DraftAuthority) ReportDraft {
	t.Helper()
	d, err := s.StartReport(context.Background(), a, draftSpec())
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func TestDraftLifecyclePersistencePublicationAndReceipts(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	a := draftAuthority()
	d := startDraft(t, s, a)
	retry, err := s.StartReport(ctx, a, draftSpec())
	if err != nil || retry.ID != d.ID || retry.Revision != 0 {
		t.Fatal(retry, err)
	}
	changed := draftSpec()
	changed.Instructions = "Different audit"
	if _, err = s.StartReport(ctx, a, changed); !errors.Is(err, ErrConflict) {
		t.Fatal("changed retry metadata accepted", err)
	}
	f := draftFinding("query-1")
	d, err = s.SubmitFinding(ctx, a, d.ID, 0, f)
	if err != nil || d.Revision != 1 || d.FindingCount != 1 {
		t.Fatal(d, err)
	}
	noOp, err := s.SubmitFinding(ctx, a, d.ID, 0, f)
	if err != nil || noOp.Revision != 1 || noOp.UpdatedAt != d.UpdatedAt {
		t.Fatal("retry mutated draft", noOp, err)
	}
	other := f
	other.Evidence = "New evidence"
	if _, err = s.SubmitFinding(ctx, a, d.ID, 0, other); !errors.Is(err, ErrConflict) {
		t.Fatal("stale overwrite accepted", err)
	}
	invisible, err := s.Aggregate(ctx, "ws", AggregateQuery{})
	if err != nil || invisible.Total != 0 {
		t.Fatal("draft leaked into published findings", invisible, err)
	}
	s.Close()
	s, err = Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a.SessionID = "resumed-session"
	a.InvocationID = "update-invocation"
	saved, err := s.Draft(ctx, a, d.ID, 0)
	if err != nil || len(saved.Items) != 1 || saved.Items[0].Submission.SessionID != "session" {
		t.Fatal("draft not recoverable", saved, err)
	}
	d, err = s.SubmitFinding(ctx, a, d.ID, 1, other)
	if err != nil || d.Revision != 2 || d.FindingCount != 1 {
		t.Fatal(d, err)
	}
	if _, err = s.CompleteReport(ctx, a, d.ID, 1, draftCompletion()); !errors.Is(err, ErrConflict) {
		t.Fatal("stale completion accepted", err)
	}
	published, err := s.CompleteReport(ctx, a, d.ID, 2, draftCompletion())
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := s.CompleteReport(ctx, a, d.ID, 2, draftCompletion())
	if err != nil || repeated.Report.ID != published.Report.ID || repeated.Report.UpdatedAt != published.Report.UpdatedAt {
		t.Fatal("completion retry changed source", repeated, err)
	}
	detail, err := s.Finding(ctx, "ws", published.Report.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Finding.Severity != "critical" || detail.Finding.SecuritySeverity != 0 || detail.Finding.Confidence != "medium" || detail.Finding.Origin != "llm" || detail.Description != f.Description || detail.Guidance != f.Remediation || detail.AgentFinding == nil || detail.AgentFinding.Finding.Evidence != other.Evidence || detail.AgentFinding.Submission.SessionID != a.SessionID || detail.Run.AgentAudit == nil || detail.Run.AgentAudit.Spec.Instructions != draftSpec().Instructions || detail.Report.ActorID != "task:task" {
		t.Fatalf("published data lost: %+v", detail)
	}
	chunk, err := s.Source(ctx, "ws", published.Report.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(chunk.Data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "kandevSecurity") || strings.Contains(string(raw), "security-severity") {
		t.Fatal("missing evidence or invented CVSS")
	}
	completed, err := s.Draft(ctx, a, d.ID, 0)
	if err != nil || completed.Draft.Status != "completed" || !completed.Draft.ReportAvailable || len(completed.Items) != 0 || completed.NextOffset != 0 {
		t.Fatal(completed, err)
	}
	if _, err = s.SubmitFinding(ctx, a, d.ID, 3, f); !errors.Is(err, ErrConflict) {
		t.Fatal("modified frozen report", err)
	}
	if _, err = s.CancelReport(ctx, a, d.ID, 3); !errors.Is(err, ErrConflict) {
		t.Fatal("cancelled published report", err)
	}
	differentCompletion := draftCompletion()
	differentCompletion.Summary = "Changed"
	if _, err = s.CompleteReport(ctx, a, d.ID, 2, differentCompletion); !errors.Is(err, ErrConflict) {
		t.Fatal("changed published receipt", err)
	}
	if err = s.Delete(ctx, "ws", published.Report.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CompleteReport(ctx, a, d.ID, 2, draftCompletion()); !errors.Is(err, ErrConflict) {
		t.Fatal("deleted report resurrected", err)
	}
	completed, err = s.Draft(ctx, a, d.ID, 0)
	if err != nil || completed.Draft.ReportAvailable || len(completed.Items) != 0 {
		t.Fatal("deleted evidence retained as draft", completed, err)
	}
}
func TestDraftTaskIsolationAndCancellation(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a := draftAuthority()
	d := startDraft(t, s, a)
	if _, err := s.SubmitFinding(ctx, a, d.ID, 0, draftFinding("a")); err != nil {
		t.Fatal(err)
	}
	for _, foreign := range []DraftAuthority{{"other", "task", "session", "invocation"}, {"ws", "other", "session", "invocation"}} {
		if _, err := s.Draft(ctx, foreign, d.ID, 0); !errors.Is(err, ErrNotFound) {
			t.Fatal("draft leaked", err)
		}
		if _, err := s.SubmitFinding(ctx, foreign, d.ID, 1, draftFinding("b")); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign write", err)
		}
		if _, err := s.CompleteReport(ctx, foreign, d.ID, 1, draftCompletion()); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign completion", err)
		}
		if _, err := s.CancelReport(ctx, foreign, d.ID, 1); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign cancellation", err)
		}
		list, err := s.Drafts(ctx, foreign, "", 0)
		if err != nil || list.Total != 0 {
			t.Fatal("list leaked", list, err)
		}
	}
	if _, err := s.CancelReport(ctx, a, d.ID, 0); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	cancelled, err := s.CancelReport(ctx, a, d.ID, 1)
	if err != nil || cancelled.Status != "cancelled" || cancelled.FindingCount != 0 {
		t.Fatal(cancelled, err)
	}
	if _, err = s.CancelReport(ctx, a, d.ID, 1); err != nil {
		t.Fatal("cancel retry failed", err)
	}
	detail, err := s.Draft(ctx, a, d.ID, 0)
	if err != nil || len(detail.Items) != 0 {
		t.Fatal(detail, err)
	}
	if _, err = s.CompleteReport(ctx, a, d.ID, 2, draftCompletion()); !errors.Is(err, ErrConflict) {
		t.Fatal("published cancelled draft", err)
	}
}
func TestDraftPaginationValidationAndZeroFindingPublication(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a := draftAuthority()
	d := startDraft(t, s, a)
	for n := 0; n < 28; n++ {
		var err error
		d, err = s.SubmitFinding(ctx, a, d.ID, d.Revision, draftFinding(fmt.Sprintf("f%03d", n)))
		if err != nil {
			t.Fatal(err)
		}
	}
	first, err := s.Draft(ctx, a, d.ID, 0)
	if err != nil || len(first.Items) != 25 || first.NextOffset != 25 {
		t.Fatal(first, err)
	}
	last, err := s.Draft(ctx, a, d.ID, 25)
	if err != nil || len(last.Items) != 3 || last.NextOffset != 0 {
		t.Fatal(last, err)
	}
	for _, change := range []func(*AgentFinding){func(f *AgentFinding) { f.Confidence = "certain" }, func(f *AgentFinding) { f.Evidence = "" }, func(f *AgentFinding) { f.Severity = "extreme" }, func(f *AgentFinding) { f.Column = 1; f.Line = 0 }, func(f *AgentFinding) { f.URI = "" }, func(f *AgentFinding) { f.CWEs = []string{"CWE-bad"} }, func(f *AgentFinding) { f.Description = strings.Repeat("x", 4097) }} {
		f := draftFinding("invalid")
		change(&f)
		if _, err = s.SubmitFinding(ctx, a, d.ID, d.Revision, f); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid finding accepted", f, err)
		}
	}
	if _, err = s.Draft(ctx, a, d.ID, -1); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err = s.StartReport(ctx, DraftAuthority{}, draftSpec()); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing context", err)
	}
	fresh := draftSpec()
	fresh.ClientReportID = "empty"
	zero, err := s.StartReport(ctx, a, fresh)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := s.CompleteReport(ctx, a, zero.ID, 0, AgentCompletion{Summary: "No supported findings.", Coverage: "Inspected listed handlers.", Limitations: []string{"Did not inspect dependencies."}})
	if err != nil || pub.Report.FindingCount != 0 {
		t.Fatal(pub, err)
	}
	read, err := s.AuditReport(ctx, "ws", pub.Report.ID)
	if err != nil || read.Runs[0].AgentAudit == nil || read.Runs[0].AgentAudit.Completion.Limitations[0] != "Did not inspect dependencies." {
		t.Fatal(read, err)
	}
}
func TestDraftPublishRollbackAndConcurrentRevision(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a := draftAuthority()
	d := startDraft(t, s, a)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, id := range []string{"a", "b"} {
		wg.Go(func() { _, err := s.SubmitFinding(ctx, a, d.ID, 0, draftFinding(id)); errs <- err })
	}
	wg.Wait()
	close(errs)
	success, conflicts := 0, 0
	for err := range errs {
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatal("lost update", success, conflicts)
	}
	// Force a failure after the report is written but before the receipt is saved.
	if _, err := s.db.Exec(`CREATE TRIGGER reject_completion BEFORE UPDATE OF status ON report_drafts WHEN NEW.status='completed' BEGIN SELECT RAISE(ABORT,'forced completion failure'); END;`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteReport(ctx, a, d.ID, 1, draftCompletion()); err == nil {
		t.Fatal("forced failure ignored")
	}
	reports, err := s.List(ctx, "ws", 0)
	if err != nil || len(reports.Items) != 0 {
		t.Fatal("partially published report", reports, err)
	}
	current, err := s.Draft(ctx, a, d.ID, 0)
	if err != nil || current.Draft.Status != "draft" || len(current.Items) != 1 || current.Draft.Revision != 1 {
		t.Fatal("draft lost on failed publication", current, err)
	}
	if _, err = s.db.Exec("DROP TRIGGER reject_completion"); err != nil {
		t.Fatal(err)
	}
	pub, err := s.CompleteReport(ctx, a, d.ID, 1, draftCompletion())
	if err != nil {
		t.Fatal(err)
	}
	_, findings, err := parseSARIF(mustSource(t, s, pub.Report.ID))
	if err != nil || len(findings) != 1 {
		t.Fatal(err)
	}
}
func mustSource(t *testing.T, s *Store, id string) []byte {
	t.Helper()
	var raw []byte
	if err := s.db.QueryRow("SELECT original FROM reports WHERE id=?", id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestDraftQuotaAndByteAccounting(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a := draftAuthority()
	d := startDraft(t, s, a)
	f := draftFinding("a")
	d, err := s.SubmitFinding(ctx, a, d.ID, 0, f)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(f)
	if d.ByteCount != len(raw) {
		t.Fatal(d.ByteCount, len(raw))
	}
	f.Description = "Short"
	d, err = s.SubmitFinding(ctx, a, d.ID, 1, f)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(f)
	if d.ByteCount != len(raw) || d.FindingCount != 1 {
		t.Fatal(d)
	}
	if _, err = s.db.Exec("UPDATE report_drafts SET byte_count=? WHERE id=?", MaxDraftBytes, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SubmitFinding(ctx, a, d.ID, d.Revision, draftFinding("b")); !errors.Is(err, ErrConflict) {
		t.Fatal("byte quota ignored", err)
	}
	if _, err = s.db.Exec("UPDATE report_drafts SET byte_count=0,finding_count=? WHERE id=?", MaxDraftFindings, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SubmitFinding(ctx, a, d.ID, d.Revision, draftFinding("b")); !errors.Is(err, ErrConflict) {
		t.Fatal("finding quota ignored", err)
	}
	for i := 1; i < MaxWorkspaceDrafts; i++ {
		spec := draftSpec()
		spec.ClientReportID = fmt.Sprint(i)
		if _, err = s.StartReport(ctx, a, spec); err != nil {
			t.Fatal(err)
		}
	}
	spec := draftSpec()
	spec.ClientReportID = "over-quota"
	if _, err = s.StartReport(ctx, a, spec); !errors.Is(err, ErrConflict) {
		t.Fatal("active quota ignored", err)
	}
	page, err := s.Drafts(ctx, a, "draft", 0)
	if err != nil || page.Total != MaxWorkspaceDrafts {
		t.Fatal(page, err)
	}
}
