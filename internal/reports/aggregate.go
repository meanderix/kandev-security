package reports

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

type AggregateQuery struct {
	advisoryKey string
	Language    string `json:"language"`
	Tool        string `json:"tool"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Search      string `json:"search"`
	Sort        string `json:"sort"`
	Offset      int    `json:"offset"`
}
type AggregateFinding struct {
	TaskCount int `json:"task_count,omitempty"`
	Finding
	ReportID   string `json:"report_id"`
	ReportName string `json:"report_name"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}
type AggregatePage struct {
	Items          []AggregateFinding `json:"items"`
	Total          int                `json:"total"`
	NextOffset     int                `json:"next_offset"`
	SeverityCounts map[string]int     `json:"severity_counts"`
	LatestImportAt string             `json:"latest_import_at"`
}
type FacetPage struct {
	Items      []string `json:"items"`
	NextOffset int      `json:"next_offset"`
}

func (s *Store) Aggregate(ctx context.Context, workspace string, q AggregateQuery) (AggregatePage, error) {
	return s.AggregateWithStatus(ctx, workspace, q, "")
}

// AggregateWithStatus filters occurrences by their persistent issue's manual
// review status. It does not interpret scanner baseline/evaluation state.
func (s *Store) AggregateWithStatus(ctx context.Context, workspace string, q AggregateQuery, status string) (AggregatePage, error) {
	p := AggregatePage{Items: []AggregateFinding{}, SeverityCounts: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}}
	if err := validScope(workspace); err != nil {
		return p, err
	}
	if q.Offset < 0 || len(q.Search) > 256 || len(q.Language) > 128 || len(q.Tool) > 256 || len(q.Rule) > 1024 || (q.Severity != "" && severityRank(q.Severity) == 0) || (status != "" && status != "open" && status != "closed") {
		return p, ErrInvalid
	}
	orders := map[string]string{"": "f.severity_rank DESC,f.security_score DESC,r.created_at DESC", "severity": "f.severity_rank DESC,f.security_score DESC,r.created_at DESC", "newest": "r.created_at DESC", "oldest": "r.created_at ASC", "recently_updated": "r.updated_at DESC", "least_recently_updated": "r.updated_at ASC"}
	order, ok := orders[q.Sort]
	if !ok {
		return p, fmt.Errorf("%w: unsupported sort order", ErrInvalid)
	}
	where := " FROM findings f JOIN reports r ON r.id=f.report_id WHERE r.workspace_id=?" + activeReports("r")
	args := []any{workspace}
	if status != "" {
		where += " AND EXISTS(SELECT 1 FROM issues i WHERE i.id=f.issue_id AND i.workspace_id=r.workspace_id AND i.status=?)"
		args = append(args, status)
	}
	if q.advisoryKey != "" {
		where += " AND EXISTS(SELECT 1 FROM finding_advisories a WHERE a.report_id=f.report_id AND a.ordinal=f.ordinal AND a.advisory_key=?)"
		args = append(args, q.advisoryKey)
	}
	for _, filter := range []struct{ column, value string }{{"f.language", q.Language}, {"f.tool", q.Tool}, {"f.rule_id", q.Rule}} {
		if filter.value != "" {
			where += " AND " + filter.column + "=?"
			args = append(args, filter.value)
		}
	}
	if q.Search != "" {
		where += " AND instr(f.search_text,?)>0"
		args = append(args, strings.ToLower(q.Search))
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	// Counts honor all filters except severity so every severity remains selectable.
	counts, err := tx.QueryContext(ctx, "SELECT f.severity,count(*)"+where+" GROUP BY f.severity", args...)
	if err != nil {
		return p, err
	}
	for counts.Next() {
		var severity string
		var count int
		if err = counts.Scan(&severity, &count); err != nil {
			counts.Close()
			return p, err
		}
		p.SeverityCounts[severity] = count
		if q.Severity == "" || q.Severity == severity {
			p.Total += count
		}
	}
	err = counts.Err()
	counts.Close()
	if err != nil {
		return p, err
	}
	var latest sql.NullString
	if err = tx.QueryRowContext(ctx, "SELECT max(updated_at) FROM reports WHERE workspace_id=?"+activeReports("reports"), workspace).Scan(&latest); err != nil {
		return p, err
	}
	p.LatestImportAt = latest.String
	if q.Severity != "" {
		where += " AND f.severity=?"
		args = append(args, q.Severity)
	}
	args = append(args, PageSize, q.Offset)
	rows, err := tx.QueryContext(ctx, "SELECT f.value_json,r.id,r.filename,r.created_at,r.updated_at,coalesce(f.issue_id,''),(SELECT count(*) FROM issue_task_links l WHERE l.issue_id=f.issue_id)"+where+" ORDER BY "+order+",r.id ASC,f.ordinal ASC LIMIT ? OFFSET ?", args...)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var f AggregateFinding
		var raw string
		if err = rows.Scan(&raw, &f.ReportID, &f.ReportName, &f.CreatedAt, &f.UpdatedAt, &f.IssueID, &f.TaskCount); err != nil {
			return p, err
		}
		if err = json.Unmarshal([]byte(raw), &f.Finding); err != nil {
			return p, err
		}
		p.Items = append(p.Items, f)
	}
	if q.Offset+len(p.Items) < p.Total {
		p.NextOffset = q.Offset + len(p.Items)
	}
	return p, rows.Err()
}

// Facets are independently paged and searchable, so workspaces with thousands
// of distinct scanner rules do not overflow the host's bounded action response.
func (s *Store) Facets(ctx context.Context, workspace, facet, search string, offset int) (FacetPage, error) {
	p := FacetPage{Items: []string{}}
	if err := validScope(workspace); err != nil {
		return p, err
	}
	column, ok := map[string]string{"language": "f.language", "tool": "f.tool", "rule": "f.rule_id"}[facet]
	if !ok || offset < 0 || len(search) > 256 {
		return p, ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, "SELECT DISTINCT "+column+" FROM findings f JOIN reports r ON r.id=f.report_id WHERE r.workspace_id=?"+activeReports("r")+" AND "+column+"<>'' AND instr(lower("+column+"),?)>0 ORDER BY "+column+" COLLATE NOCASE,"+column+" LIMIT ? OFFSET ?", workspace, strings.ToLower(search), PageSize+1, offset)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var value string
		if err = rows.Scan(&value); err != nil {
			return p, err
		}
		p.Items = append(p.Items, value)
	}
	if len(p.Items) > PageSize {
		p.Items = p.Items[:PageSize]
		p.NextOffset = offset + PageSize
	}
	return p, rows.Err()
}
