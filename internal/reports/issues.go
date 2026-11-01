package reports

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Issue struct {
	ID              string `json:"id"`
	IdentityVersion int    `json:"identity_version"`
	Method          string `json:"identity_method"`
	Scope           string `json:"identity_scope"`
	Reason          string `json:"identity_reason"`
	Status          string `json:"status"`
	StatusReason    string `json:"status_reason"`
	StatusActor     string `json:"status_actor"`
	StatusUpdatedAt string `json:"status_updated_at"`
	FirstSeenAt     string `json:"first_seen_at"`
	LastSeenAt      string `json:"last_seen_at"`
}
type IssueStatusChange struct {
	Kind         string `json:"kind"`
	TaskID       string `json:"task_id,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	InvocationID string `json:"invocation_id,omitempty"`
	ID           int64  `json:"id"`
	OldStatus    string `json:"old_status"`
	NewStatus    string `json:"new_status"`
	Reason       string `json:"reason"`
	Actor        string `json:"actor"`
	CreatedAt    string `json:"created_at"`
}
type IssueOccurrence struct {
	ArchivedAt  string `json:"archived_at,omitempty"`
	ArchivedBy  string `json:"archived_by,omitempty"`
	PurgedAt    string `json:"purged_at,omitempty"`
	PurgeReason string `json:"purge_reason,omitempty"`
	AggregateFinding
	SHA256 string `json:"sha256"`
}
type IssueDetail struct {
	PurgedCount       int                 `json:"purged_count,omitempty"`
	Issue             Issue               `json:"issue"`
	Occurrences       []IssueOccurrence   `json:"occurrences"`
	Total             int                 `json:"total"`
	NextOffset        int                 `json:"next_offset"`
	History           []IssueStatusChange `json:"history"`
	HistoryNextOffset int                 `json:"history_next_offset"`
}

const issueColumns = "id,identity_version,identity_method,identity_scope,identity_reason,status,status_reason,status_actor,status_updated_at,first_seen_at,last_seen_at"

func scanIssue(row interface{ Scan(...any) error }) (Issue, error) {
	var i Issue
	err := row.Scan(&i.ID, &i.IdentityVersion, &i.Method, &i.Scope, &i.Reason, &i.Status, &i.StatusReason, &i.StatusActor, &i.StatusUpdatedAt, &i.FirstSeenAt, &i.LastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return i, err
}
func issueTimestamp(value string) (string, error) {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return "", err
	}
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z"), nil
}
func linkIssuesTx(ctx context.Context, tx *sql.Tx, r Report, findings []Finding) error {
	first, err := issueTimestamp(r.CreatedAt)
	if err != nil {
		return err
	}
	last, err := issueTimestamp(r.UpdatedAt)
	if err != nil {
		return err
	}
	insert, err := tx.PrepareContext(ctx, `INSERT INTO issues(id,workspace_id,identity_version,identity_key,identity_method,identity_scope,identity_reason,first_seen_at,last_seen_at)
 VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET first_seen_at=min(issues.first_seen_at,excluded.first_seen_at),last_seen_at=max(issues.last_seen_at,excluded.last_seen_at)
 WHERE issues.workspace_id=excluded.workspace_id AND issues.identity_key=excluded.identity_key`)
	if err != nil {
		return err
	}
	defer insert.Close()
	link, err := tx.PrepareContext(ctx, "UPDATE findings SET issue_id=? WHERE report_id=? AND ordinal=?")
	if err != nil {
		return err
	}
	defer link.Close()
	for _, f := range findings {
		identity := f.identity
		id := identity.id(r.WorkspaceID)
		res, err := insert.ExecContext(ctx, id, r.WorkspaceID, identity.Version, identity.key(), identity.Method, identity.Scope, identity.Reason, first, last)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("issue identity hash collision")
		}
		res, err = link.ExecContext(ctx, id, r.ID, f.Ordinal)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("stored finding ordinal does not match original SARIF")
		}
	}
	return nil
}

func (s *Store) Issue(ctx context.Context, workspace, id string, offset, historyOffset int) (IssueDetail, error) {
	d := IssueDetail{Occurrences: []IssueOccurrence{}, History: []IssueStatusChange{}}
	if err := validScope(workspace); err != nil {
		return d, err
	}
	if id == "" || offset < 0 || historyOffset < 0 {
		return d, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return d, err
	}
	defer tx.Rollback()
	d.Issue, err = scanIssue(tx.QueryRowContext(ctx, "SELECT "+issueColumns+" FROM issues WHERE workspace_id=? AND id=?", workspace, id))
	if err != nil {
		return d, err
	}
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM findings f JOIN reports r ON r.id=f.report_id WHERE r.workspace_id=? AND f.issue_id=?", workspace, id).Scan(&d.Total); err != nil {
		return d, err
	}
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM issue_purged_occurrences f JOIN purged_reports r ON r.id=f.report_id WHERE r.workspace_id=? AND f.issue_id=?", workspace, id).Scan(&d.PurgedCount); err != nil {
		return d, err
	}
	d.Total += d.PurgedCount
	rows, err := tx.QueryContext(ctx, `SELECT * FROM (
 SELECT f.value_json,r.id,r.filename,r.created_at,r.updated_at,r.digest,'' purged_at,'' reason,f.ordinal,coalesce(a.archived_at,'') archived_at,coalesce(a.archived_by,'') archived_by FROM findings f JOIN reports r ON r.id=f.report_id LEFT JOIN report_archives a ON a.report_id=r.id WHERE r.workspace_id=? AND f.issue_id=?
 UNION ALL
 SELECT f.value_json,r.id,json_extract(r.metadata_json,'$.filename'),json_extract(r.metadata_json,'$.created_at'),json_extract(r.metadata_json,'$.updated_at'),r.digest,r.purged_at,r.reason,f.ordinal,coalesce(json_extract(r.metadata_json,'$.archived_at'),''),coalesce(json_extract(r.metadata_json,'$.archived_by'),'') FROM issue_purged_occurrences f JOIN purged_reports r ON r.id=f.report_id WHERE r.workspace_id=? AND f.issue_id=?
 ) ORDER BY updated_at DESC,id,ordinal LIMIT ? OFFSET ?`, workspace, id, workspace, id, PageSize, offset)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var o IssueOccurrence
		var raw string
		var ordinal int
		if err = rows.Scan(&raw, &o.ReportID, &o.ReportName, &o.CreatedAt, &o.UpdatedAt, &o.SHA256, &o.PurgedAt, &o.PurgeReason, &ordinal, &o.ArchivedAt, &o.ArchivedBy); err != nil {
			rows.Close()
			return d, err
		}
		if err = json.Unmarshal([]byte(raw), &o.Finding); err != nil {
			rows.Close()
			return d, err
		}
		o.IssueID = id
		d.Occurrences = append(d.Occurrences, o)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return d, err
	}
	if offset+len(d.Occurrences) < d.Total {
		d.NextOffset = offset + len(d.Occurrences)
	}
	history, err := tx.QueryContext(ctx, "SELECT h.id,h.old_status,h.new_status,h.reason,h.actor,h.created_at,coalesce(a.task_id,''),coalesce(a.session_id,''),coalesce(a.invocation_id,'') FROM issue_status_history h LEFT JOIN issue_agent_reviews a ON a.history_id=h.id WHERE h.issue_id=? ORDER BY h.id DESC LIMIT ? OFFSET ?", id, PageSize+1, historyOffset)
	if err != nil {
		return d, err
	}
	defer history.Close()
	for history.Next() {
		var change IssueStatusChange
		if err = history.Scan(&change.ID, &change.OldStatus, &change.NewStatus, &change.Reason, &change.Actor, &change.CreatedAt, &change.TaskID, &change.SessionID, &change.InvocationID); err != nil {
			return d, err
		}
		change.Kind = "status_changed"
		if change.OldStatus == change.NewStatus {
			change.Kind = "reason_updated"
		}
		d.History = append(d.History, change)
	}
	if len(d.History) > PageSize {
		d.History = d.History[:PageSize]
		d.HistoryNextOffset = historyOffset + PageSize
	}
	// Source history and decision history share the Host response budget.
	for {
		encoded, _ := json.Marshal(d)
		if len(encoded) <= 850<<10 {
			break
		}
		if len(d.Occurrences) > 1 {
			d.Occurrences = d.Occurrences[:len(d.Occurrences)/2]
			d.NextOffset = offset + len(d.Occurrences)
		}
		if len(d.History) > 1 {
			d.History = d.History[:len(d.History)/2]
			d.HistoryNextOffset = historyOffset + len(d.History)
		}
		if len(d.Occurrences) <= 1 && len(d.History) <= 1 {
			break
		}
	}
	return d, history.Err()
}
func (s *Store) SetIssueStatus(ctx context.Context, workspace, actor, id, status, reason string) error {
	if err := validScope(workspace); err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	if strings.TrimSpace(actor) == "" || id == "" || (status != "open" && status != "closed") || len(reason) == 0 || len(reason) > 2000 {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := scanIssue(tx.QueryRowContext(ctx, "SELECT "+issueColumns+" FROM issues WHERE workspace_id=? AND id=?", workspace, id))
	if err != nil {
		return err
	}
	if current.Status == status {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, "UPDATE issues SET status=?,status_reason=?,status_actor=?,status_updated_at=? WHERE workspace_id=? AND id=?", status, reason, actor, now, workspace, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO issue_status_history(issue_id,old_status,new_status,reason,actor,created_at) VALUES(?,?,?,?,?,?)", id, current.Status, status, reason, actor, now); err != nil {
		return err
	}
	return tx.Commit()
}
