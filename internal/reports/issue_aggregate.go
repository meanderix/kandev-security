package reports

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

type IssueQuery struct {
	AggregateQuery
	Status string `json:"status"`
}
type IssueFinding struct {
	AggregateFinding
	Issue           Issue `json:"issue"`
	OccurrenceCount int   `json:"occurrence_count"`
}
type IssuePage struct {
	Items          []IssueFinding `json:"items"`
	Total          int            `json:"total"`
	NextOffset     int            `json:"next_offset"`
	SeverityCounts map[string]int `json:"severity_counts"`
	LatestImportAt string         `json:"latest_import_at"`
}

// Select one representative per issue from occurrences matching the non-severity
// filters. Highest severity wins; score, import date and exact reference break ties.
// Apply severity afterwards so each issue belongs to exactly one severity bucket.
func (s *Store) Issues(ctx context.Context, workspace string, q IssueQuery) (IssuePage, error) {
	p := IssuePage{Items: []IssueFinding{}, SeverityCounts: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}}
	if err := validScope(workspace); err != nil {
		return p, err
	}
	if q.Offset < 0 || len(q.Search) > 256 || len(q.Language) > 128 || len(q.Tool) > 256 || len(q.Rule) > 1024 || (q.Severity != "" && severityRank(q.Severity) == 0) || (q.Status != "" && q.Status != "open" && q.Status != "closed") {
		return p, ErrInvalid
	}
	order, ok := map[string]string{"": "severity_rank DESC,security_score DESC,first_seen_at DESC", "severity": "severity_rank DESC,security_score DESC,first_seen_at DESC", "newest": "first_seen_at DESC", "oldest": "first_seen_at ASC", "recently_updated": "last_seen_at DESC", "least_recently_updated": "last_seen_at ASC"}[q.Sort]
	if !ok {
		return p, ErrInvalid
	}
	where := " WHERE r.workspace_id=?" + activeReports("r")
	args := []any{workspace}
	for _, f := range []struct{ column, value string }{{"f.language", q.Language}, {"f.tool", q.Tool}, {"f.rule_id", q.Rule}, {"i.status", q.Status}} {
		if f.value != "" {
			where += " AND " + f.column + "=?"
			args = append(args, f.value)
		}
	}
	if q.Search != "" {
		where += " AND instr(f.search_text,?)>0"
		args = append(args, strings.ToLower(q.Search))
	}
	cte := `WITH ranked AS (SELECT f.value_json,f.issue_id,f.severity,f.severity_rank,f.security_score,r.id report_id,r.filename,r.created_at,r.updated_at,i.identity_version,i.identity_method,i.identity_scope,i.identity_reason,i.status,i.status_reason,i.status_actor,i.status_updated_at,i.first_seen_at,i.last_seen_at,
 row_number() OVER (PARTITION BY f.issue_id ORDER BY f.severity_rank DESC,f.security_score DESC,r.updated_at DESC,r.id,f.ordinal) position
 FROM findings f JOIN reports r ON r.id=f.report_id JOIN issues i ON i.id=f.issue_id AND i.workspace_id=r.workspace_id` + where + `) `
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, cte+"SELECT severity,count(*) FROM ranked WHERE position=1 GROUP BY severity", args...)
	if err != nil {
		return p, err
	}
	for rows.Next() {
		var severity string
		var n int
		if err = rows.Scan(&severity, &n); err != nil {
			rows.Close()
			return p, err
		}
		p.SeverityCounts[severity] = n
		if q.Severity == "" || q.Severity == severity {
			p.Total += n
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return p, err
	}
	var latest sql.NullString
	if err = tx.QueryRowContext(ctx, "SELECT max(updated_at) FROM reports WHERE workspace_id=?"+activeReports("reports"), workspace).Scan(&latest); err != nil {
		return p, err
	}
	p.LatestImportAt = latest.String
	selection := " WHERE position=1"
	if q.Severity != "" {
		selection += " AND severity=?"
		args = append(args, q.Severity)
	}
	args = append(args, PageSize, q.Offset)
	rows, err = tx.QueryContext(ctx, cte+`SELECT value_json,report_id,filename,created_at,updated_at,issue_id,identity_version,identity_method,identity_scope,identity_reason,status,status_reason,status_actor,status_updated_at,first_seen_at,last_seen_at,(SELECT count(*) FROM findings all_f JOIN reports active_r ON active_r.id=all_f.report_id WHERE all_f.issue_id=ranked.issue_id`+activeReports("active_r")+`),(SELECT count(*) FROM issue_task_links l WHERE l.issue_id=ranked.issue_id) FROM ranked`+selection+" ORDER BY "+order+",issue_id LIMIT ? OFFSET ?", args...)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var f IssueFinding
		var raw string
		i := &f.Issue
		if err = rows.Scan(&raw, &f.ReportID, &f.ReportName, &f.CreatedAt, &f.UpdatedAt, &i.ID, &i.IdentityVersion, &i.Method, &i.Scope, &i.Reason, &i.Status, &i.StatusReason, &i.StatusActor, &i.StatusUpdatedAt, &i.FirstSeenAt, &i.LastSeenAt, &f.OccurrenceCount, &f.TaskCount); err != nil {
			return p, err
		}
		if err = json.Unmarshal([]byte(raw), &f.Finding); err != nil {
			return p, err
		}
		f.IssueID = i.ID
		p.Items = append(p.Items, f)
	}
	if q.Offset+len(p.Items) < p.Total {
		p.NextOffset = q.Offset + len(p.Items)
	}
	return p, rows.Err()
}
