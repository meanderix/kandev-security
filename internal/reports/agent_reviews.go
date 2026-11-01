package reports

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// ReviewAuthority is supplied by the verified MCP context, never tool arguments.
// MCP provides task/session identity, not a human actor identity.
type ReviewAuthority struct{ WorkspaceID, TaskID, SessionID, InvocationID string }
type IssueReviewResult struct {
	Issue    Issue `json:"issue"`
	Changed  bool  `json:"changed"`
	Replayed bool  `json:"replayed"`
}

// UpdateIssueReview records both status changes and reason-only changes. A
// receipt also covers no-ops, so replaying an old invocation cannot undo a
// subsequent agent or human decision. The current issue is returned on replay.
func (s *Store) UpdateIssueReview(ctx context.Context, a ReviewAuthority, id, status, reason string) (IssueReviewResult, error) {
	result := IssueReviewResult{}
	for _, v := range []string{a.WorkspaceID, a.TaskID, a.SessionID, a.InvocationID} {
		if !validText(v, 1, 512) || !utf8.ValidString(v) {
			return result, ErrInvalid
		}
	}
	reason = strings.TrimSpace(reason)
	if !validText(id, 1, 128) || (status != "open" && status != "closed") || !validText(reason, 1, 2000) || !utf8.ValidString(reason) {
		return result, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	result.Issue, err = scanIssue(tx.QueryRowContext(ctx, "SELECT "+issueColumns+" FROM issues WHERE workspace_id=? AND id=?", a.WorkspaceID, id))
	if err != nil {
		return result, err
	}
	var previousID, previousStatus, previousReason string
	err = tx.QueryRowContext(ctx, `SELECT issue_id,requested_status,requested_reason FROM issue_agent_reviews WHERE workspace_id=? AND task_id=? AND session_id=? AND invocation_id=?`, a.WorkspaceID, a.TaskID, a.SessionID, a.InvocationID).Scan(&previousID, &previousStatus, &previousReason)
	if err == nil {
		if previousID != id || previousStatus != status || previousReason != reason {
			return result, fmt.Errorf("%w: invocation was already used for a different review", ErrConflict)
		}
		result.Replayed = true
		return result, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	current := &result.Issue
	result.Changed = current.Status != status || current.StatusReason != reason
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var historyID any
	if result.Changed {
		actor := "agent:task:" + a.TaskID
		if _, err = tx.ExecContext(ctx, "UPDATE issues SET status=?,status_reason=?,status_actor=?,status_updated_at=? WHERE workspace_id=? AND id=?", status, reason, actor, now, a.WorkspaceID, id); err != nil {
			return result, err
		}
		res, err := tx.ExecContext(ctx, "INSERT INTO issue_status_history(issue_id,old_status,new_status,reason,actor,created_at) VALUES(?,?,?,?,?,?)", id, current.Status, status, reason, actor, now)
		if err != nil {
			return result, err
		}
		historyID, err = res.LastInsertId()
		if err != nil {
			return result, err
		}
		current.Status, current.StatusReason, current.StatusActor, current.StatusUpdatedAt = status, reason, actor, now
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO issue_agent_reviews(workspace_id,task_id,session_id,invocation_id,issue_id,requested_status,requested_reason,history_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, a.WorkspaceID, a.TaskID, a.SessionID, a.InvocationID, id, status, reason, historyID, now); err != nil {
		return result, err
	}
	return result, tx.Commit()
}
