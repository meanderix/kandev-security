package reports

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"strings"
)

// Advisory groups are a browsing index, never an alternative issue identity.
type advisoryIdentity struct{ Key, ID, Namespace string }

var cveID = regexp.MustCompile(`(?i)^CVE-[0-9]{4}-[0-9]{4,}$`)
var ghsaID = regexp.MustCompile(`(?i)^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$`)
var advisoryKey = regexp.MustCompile(`^[a-f0-9]{64}$`)

func identifyAdvisory(scanner, id string, rule sarifRule) advisoryIdentity {
	a := advisoryIdentity{ID: id}
	switch {
	case cveID.MatchString(id):
		a.ID = strings.ToUpper(id)
		a.Namespace = "CVE"
	case ghsaID.MatchString(id):
		a.ID = "GHSA-" + strings.ToLower(id[5:])
		a.Namespace = "GHSA"
	default:
		// SARIF's conventional vulnerability tag permits private/vendor advisory
		// IDs without treating ordinary scanner rules as public advisories.
		var tags []string
		if json.Unmarshal(rule.Properties["tags"], &tags) != nil || id == "" {
			return advisoryIdentity{}
		}
		found := false
		for _, tag := range tags {
			if strings.EqualFold(tag, "vulnerability") {
				found = true
				break
			}
		}
		if !found {
			return advisoryIdentity{}
		}
		a.Namespace = "scanner:" + scanner
	}
	key, _ := json.Marshal([]string{a.Namespace, a.ID})
	a.Key = digestBytes(key)
	return a
}

func writeAdvisories(ctx context.Context, tx *sql.Tx, reportID string, findings []Finding) error {
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO finding_advisories(report_id,ordinal,advisory_key,advisory_id,namespace) VALUES(?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, f := range findings {
		if a := f.advisory; a.Key != "" {
			if _, err = stmt.ExecContext(ctx, reportID, f.Ordinal, a.Key, a.ID, a.Namespace); err != nil {
				return err
			}
		}
	}
	return nil
}

type Advisory struct {
	Key             string `json:"key"`
	ID              string `json:"id"`
	Namespace       string `json:"namespace"`
	Severity        string `json:"severity"`
	Title           string `json:"title"`
	OccurrenceCount int    `json:"occurrence_count"`
	IssueCount      int    `json:"issue_count"`
	ReportCount     int    `json:"report_count"`
	ScannerCount    int    `json:"scanner_count"`
	FirstImportedAt string `json:"first_imported_at"`
	LastImportedAt  string `json:"last_imported_at"`
}
type AdvisoryPage struct {
	Items          []Advisory     `json:"items"`
	Total          int            `json:"total"`
	FindingCount   int            `json:"finding_count"`
	NextOffset     int            `json:"next_offset"`
	SeverityCounts map[string]int `json:"severity_counts"`
}

func (s *Store) Advisories(ctx context.Context, workspace string, q AggregateQuery) (AdvisoryPage, error) {
	p := AdvisoryPage{Items: []Advisory{}, SeverityCounts: map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}}
	if err := validScope(workspace); err != nil {
		return p, err
	}
	orders := map[string]string{"": "severity_rank DESC,security_score DESC,last_imported_at DESC", "severity": "severity_rank DESC,security_score DESC,last_imported_at DESC", "newest": "first_imported_at DESC", "oldest": "first_imported_at ASC", "recently_updated": "last_imported_at DESC", "least_recently_updated": "last_imported_at ASC"}
	order, ok := orders[q.Sort]
	if !ok || q.Offset < 0 || len(q.Search) > 256 || len(q.Tool) > 256 || len(q.Language) > 128 || len(q.Rule) > 1024 || (q.Severity != "" && severityRank(q.Severity) == 0) {
		return p, ErrInvalid
	}
	where := " WHERE r.workspace_id=?" + activeReports("r")
	args := []any{workspace}
	for _, filter := range []struct{ column, value string }{{"f.tool", q.Tool}, {"f.language", q.Language}, {"f.rule_id", q.Rule}} {
		if filter.value != "" {
			where += " AND " + filter.column + "=?"
			args = append(args, filter.value)
		}
	}
	if q.Search != "" {
		where += " AND (instr(f.search_text,?)>0 OR instr(lower(a.advisory_id),?)>0)"
		args = append(args, strings.ToLower(q.Search), strings.ToLower(q.Search))
	}
	cte := `WITH matching AS (SELECT a.advisory_key,a.advisory_id,a.namespace,f.value_json,f.issue_id,f.severity,f.severity_rank,f.security_score,f.tool,r.id report_id,r.created_at,r.updated_at,f.ordinal
 FROM finding_advisories a JOIN findings f ON f.report_id=a.report_id AND f.ordinal=a.ordinal JOIN reports r ON r.id=f.report_id` + where + `),
 ranked AS (SELECT *,row_number() OVER(PARTITION BY advisory_key ORDER BY severity_rank DESC,security_score DESC,updated_at DESC,report_id,ordinal) position FROM matching),
 groups AS (SELECT advisory_key,count(*) occurrence_count,count(DISTINCT issue_id) issue_count,count(DISTINCT report_id) report_count,count(DISTINCT tool) scanner_count,min(created_at) first_imported_at,max(updated_at) last_imported_at FROM matching GROUP BY advisory_key),
 summaries AS (SELECT r.*,g.occurrence_count,g.issue_count,g.report_count,g.scanner_count,g.first_imported_at,g.last_imported_at FROM ranked r JOIN groups g USING(advisory_key) WHERE position=1) `
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, cte+"SELECT severity,count(*),sum(occurrence_count) FROM summaries GROUP BY severity", args...)
	if err != nil {
		return p, err
	}
	for rows.Next() {
		var severity string
		var count, findings int
		if err = rows.Scan(&severity, &count, &findings); err != nil {
			rows.Close()
			return p, err
		}
		p.SeverityCounts[severity] = count
		if q.Severity == "" || q.Severity == severity {
			p.Total += count
			p.FindingCount += findings
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return p, err
	}
	filter := ""
	if q.Severity != "" {
		filter = " WHERE severity=?"
		args = append(args, q.Severity)
	}
	args = append(args, PageSize, q.Offset)
	rows, err = tx.QueryContext(ctx, cte+"SELECT advisory_key,advisory_id,namespace,severity,value_json,occurrence_count,issue_count,report_count,scanner_count,first_imported_at,last_imported_at FROM summaries"+filter+" ORDER BY "+order+",advisory_key LIMIT ? OFFSET ?", args...)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var a Advisory
		var raw string
		if err = rows.Scan(&a.Key, &a.ID, &a.Namespace, &a.Severity, &raw, &a.OccurrenceCount, &a.IssueCount, &a.ReportCount, &a.ScannerCount, &a.FirstImportedAt, &a.LastImportedAt); err != nil {
			return p, err
		}
		var f Finding
		if err = json.Unmarshal([]byte(raw), &f); err != nil {
			return p, err
		}
		a.Title = f.Title
		if a.Title == "" {
			a.Title = summaryTitle(f.Message)
		}
		p.Items = append(p.Items, a)
	}
	if q.Offset+len(p.Items) < p.Total {
		p.NextOffset = q.Offset + len(p.Items)
	}
	return p, rows.Err()
}

func (s *Store) AdvisoryFindings(ctx context.Context, workspace, key string, q AggregateQuery) (AggregatePage, error) {
	if !advisoryKey.MatchString(key) || q.Severity != "" {
		return AggregatePage{}, ErrInvalid
	}
	q.advisoryKey = key
	p, err := s.Aggregate(ctx, workspace, q)
	if err == nil && p.Total == 0 {
		return p, ErrNotFound
	}
	return p, err
}
