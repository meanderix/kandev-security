package reports

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func reviewAuthority(inv string) ReviewAuthority {
	return ReviewAuthority{WorkspaceID: "ws", TaskID: "task", SessionID: "session", InvocationID: inv}
}
func reviewIssue(t *testing.T, s *Store) (Report, string) {
	t.Helper()
	r := importSample(t, s, "ws")
	d, err := s.Detail(context.Background(), "ws", r.ID, FindingQuery{})
	if err != nil {
		t.Fatal(err)
	}
	return r, d.Findings[0].IssueID
}
func TestAgentReviewChangesReasonAndStatusWithAttribution(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	r, id := reviewIssue(t, s)
	if err := s.LinkIssueTask(ctx, "ws", "owner", id, "linked", "fix"); err != nil {
		t.Fatal(err)
	}
	for i, entry := range []struct{ status, reason, kind string }{
		{"open", "Needs runtime verification", "reason_updated"}, {"closed", "False positive after checking the call path", "status_changed"}, {"closed", "Expanded assessment with supporting evidence", "reason_updated"}, {"open", "New evidence warrants another review", "status_changed"},
	} {
		a := reviewAuthority(string(rune('a' + i)))
		result, err := s.UpdateIssueReview(ctx, a, id, entry.status, entry.reason)
		if err != nil || !result.Changed || result.Replayed || result.Issue.Status != entry.status || result.Issue.StatusReason != entry.reason || result.Issue.StatusActor != "agent:task:task" {
			t.Fatal(result, err)
		}
		d, err := s.Issue(ctx, "ws", id, 0, 0)
		if err != nil || len(d.History) != i+1 {
			t.Fatal(d, err)
		}
		h := d.History[0]
		if h.Kind != entry.kind || h.TaskID != "task" || h.SessionID != "session" || h.InvocationID != a.InvocationID {
			t.Fatal(h)
		}
	}
	detail, err := s.Detail(ctx, "ws", r.ID, FindingQuery{})
	if err != nil || detail.Report.CreatedAt != r.CreatedAt || detail.Report.UpdatedAt != r.UpdatedAt {
		t.Fatal(detail, err)
	}
	src, err := s.Source(ctx, "ws", r.ID, 0)
	decoded, _ := base64.StdEncoding.DecodeString(src.Data)
	if err != nil || string(decoded) != sample {
		t.Fatal("review modified source", err)
	}
	links, err := s.IssueTasks(ctx, "ws", id, 0)
	if err != nil || links.Total != 1 {
		t.Fatal(links, err)
	}
	// Existing UI/HTTP semantics still require a transition to change the reason.
	if err = s.SetIssueStatus(ctx, "ws", "human", id, "open", "Ignored same-state UI reason"); err != nil {
		t.Fatal(err)
	}
	d, err := s.Issue(ctx, "ws", id, 0, 0)
	if err != nil || len(d.History) != 4 || d.Issue.StatusReason != "New evidence warrants another review" {
		t.Fatal(d, err)
	}
}
func TestAgentReviewRetriesDoNotOverwriteLaterDecisions(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, id := reviewIssue(t, s)
	a := reviewAuthority("first")
	if _, err := s.UpdateIssueReview(ctx, a, id, "open", "Initial assessment"); err != nil {
		t.Fatal(err)
	}
	noop := reviewAuthority("noop")
	result, err := s.UpdateIssueReview(ctx, noop, id, "open", "Initial assessment")
	if err != nil || result.Changed || result.Replayed {
		t.Fatal(result, err)
	}
	if err = s.SetIssueStatus(ctx, "ws", "human", id, "closed", "Human review"); err != nil {
		t.Fatal(err)
	}
	for _, authority := range []ReviewAuthority{a, noop} {
		result, err = s.UpdateIssueReview(ctx, authority, id, "open", "Initial assessment")
		if err != nil || result.Changed || !result.Replayed || result.Issue.Status != "closed" || result.Issue.StatusReason != "Human review" {
			t.Fatal(result, err)
		}
	}
	if _, err = s.UpdateIssueReview(ctx, a, id, "closed", "Changed arguments"); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	d, err := s.Issue(ctx, "ws", id, 0, 0)
	if err != nil || len(d.History) != 2 || d.History[0].TaskID != "" || d.History[0].Kind != "status_changed" {
		t.Fatal(d, err)
	}
}
func TestAgentReviewValidationIsolationAndAtomicRollback(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, id := reviewIssue(t, s)
	a := reviewAuthority("one")
	foreign := a
	foreign.WorkspaceID = "private"
	if _, err := s.UpdateIssueReview(ctx, foreign, id, "closed", "Review"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	for _, entry := range []struct{ status, reason string }{{"bad", "Review"}, {"open", "  "}, {"open", strings.Repeat("é", 1001)}, {"open", "invalid\x00reason"}} {
		if _, err := s.UpdateIssueReview(ctx, a, id, entry.status, entry.reason); !errors.Is(err, ErrInvalid) {
			t.Fatal(entry.status, err)
		}
	}
	for _, field := range []string{"workspace", "task", "session", "invocation"} {
		bad := a
		switch field {
		case "workspace":
			bad.WorkspaceID = ""
		case "task":
			bad.TaskID = ""
		case "session":
			bad.SessionID = ""
		case "invocation":
			bad.InvocationID = ""
		}
		if _, err := s.UpdateIssueReview(ctx, bad, id, "closed", "Review"); !errors.Is(err, ErrInvalid) {
			t.Fatal(field, err)
		}
	}
	if _, err := s.db.Exec(`CREATE TRIGGER reject_review BEFORE INSERT ON issue_agent_reviews BEGIN SELECT RAISE(ABORT,'simulated receipt failure'); END;`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateIssueReview(ctx, a, id, "closed", "Must roll back"); err == nil {
		t.Fatal("expected failure")
	}
	d, err := s.Issue(ctx, "ws", id, 0, 0)
	if err != nil || d.Issue.Status != "open" || d.Issue.StatusReason != "" || len(d.History) != 0 {
		t.Fatal(d, err)
	}
}
func TestAgentReviewPersistenceAndHistoryPaging(t *testing.T) {
	path := filepath.Join(t.TempDir(), "review.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, id := reviewIssue(t, s)
	if err = s.SetIssueStatus(ctx, "ws", "human", id, "closed", "Existing human decision"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	old, err := s.Issue(ctx, "ws", id, 0, 0)
	if err != nil || len(old.History) != 1 || old.History[0].Actor != "human" || old.History[0].TaskID != "" {
		t.Fatal(old, err)
	}
	for i := 0; i < 27; i++ {
		if _, err = s.UpdateIssueReview(ctx, reviewAuthority(string(rune('a'+i))), id, "closed", "Assessment "+string(rune('a'+i))); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	d, err := s.Issue(ctx, "ws", id, 0, 0)
	if err != nil || len(d.History) != 25 || d.HistoryNextOffset != 25 || d.History[0].TaskID != "task" {
		t.Fatal(d, err)
	}
	last, err := s.Issue(ctx, "ws", id, 0, 25)
	if err != nil || len(last.History) != 3 || last.HistoryNextOffset != 0 || last.History[2].Actor != "human" {
		t.Fatal(last, err)
	}
	result, err := s.UpdateIssueReview(ctx, reviewAuthority("a"), id, "closed", "Assessment a")
	if err != nil || !result.Replayed || result.Issue.StatusReason != "Assessment "+string(rune('a'+26)) {
		t.Fatal(result, err)
	}
}

func TestConcurrentAgentReviewDeliveryHasOneHistoryEntry(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_, id := reviewIssue(t, s)
	type outcome struct {
		result IssueReviewResult
		err    error
	}
	results := make(chan outcome, 6)
	for i := 0; i < 6; i++ {
		go func() {
			r, err := s.UpdateIssueReview(ctx, reviewAuthority("delivery"), id, "closed", "Verified the call path")
			results <- outcome{r, err}
		}()
	}
	changed, replayed := 0, 0
	for i := 0; i < 6; i++ {
		entry := <-results
		if entry.err != nil {
			t.Fatal(entry.err)
		}
		if entry.result.Changed {
			changed++
		}
		if entry.result.Replayed {
			replayed++
		}
	}
	if changed != 1 || replayed != 5 {
		t.Fatal(changed, replayed)
	}
	d, err := s.Issue(ctx, "ws", id, 0, 0)
	if err != nil || len(d.History) != 1 {
		t.Fatal(d, err)
	}
}
