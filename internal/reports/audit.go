package reports

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const MaxAuditReports = 50

type ReportReference struct {
	ArchivedAt   string `json:"archived_at,omitempty"`
	ArchivedBy   string `json:"archived_by,omitempty"`
	ReportID     string `json:"report_id"`
	Filename     string `json:"filename"`
	SHA256       string `json:"sha256"`
	FindingCount int    `json:"finding_count"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}
type RunProvenanceGap struct {
	RunIndex      int      `json:"run_index"`
	MissingFields []string `json:"missing_fields"`
}
type AuditReport struct {
	ProvenanceIncomplete bool               `json:"provenance_incomplete"`
	Report               ReportReference    `json:"report"`
	Runs                 []Run              `json:"runs"`
	ProvenanceGaps       []RunProvenanceGap `json:"provenance_gaps"`
}
type AuditReportListItem struct {
	ReportReference
	Tools     string `json:"tools"`
	Truncated bool   `json:"truncated"`
}
type AuditReportPage struct {
	Items      []AuditReportListItem `json:"items"`
	Total      int                   `json:"total"`
	NextOffset int                   `json:"next_offset"`
	HasMore    bool                  `json:"has_more"`
}
type AuditQuery struct {
	AggregateQuery
	ReportIDs []string `json:"report_ids"`
}
type AuditSelection struct {
	ReportScope      string `json:"report_scope"`
	ReportCount      int    `json:"report_count"`
	ReportsTruncated bool   `json:"reports_truncated"`
}
type AuditFindingPage struct {
	AuditSelection
	Reports []ReportReference `json:"reports"`
	AggregatePage
	HasMore bool `json:"has_more"`
}
type AuditFacetPage struct {
	AuditSelection
	Reports []ReportReference `json:"reports"`
	FacetPage
	HasMore bool `json:"has_more"`
}
type AuditSummary struct {
	AuditSelection
	Reports                                []ReportReference `json:"reports"`
	FindingCount                           int               `json:"finding_count"`
	SeverityCounts                         map[string]int    `json:"severity_counts"`
	Scanners                               []string          `json:"scanners"`
	ScannersTruncated                      bool              `json:"scanners_truncated"`
	LatestImportAt                         string            `json:"latest_import_at"`
	ProvenanceIncompleteReportIDs          []string          `json:"provenance_incomplete_report_ids"`
	ProvenanceIncompleteReportCount        int               `json:"provenance_incomplete_report_count"`
	ProvenanceIncompleteReportIDsTruncated bool              `json:"provenance_incomplete_report_ids_truncated"`
}

func reference(r Report) ReportReference {
	return ReportReference{ReportID: r.ID, Filename: r.Filename, SHA256: r.Digest, FindingCount: r.FindingCount, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, ArchivedAt: r.ArchivedAt, ArchivedBy: r.ArchivedBy}
}
func provenanceGaps(runs []Run) []RunProvenanceGap {
	gaps := []RunProvenanceGap{}
	for _, r := range runs {
		fields := []string{}
		for _, field := range []struct{ name, value string }{{"repository", r.Repository}, {"branch", r.Branch}, {"revision", r.Revision}, {"scanner_version", r.Version}} {
			if strings.TrimSpace(field.value) == "" {
				fields = append(fields, field.name)
			}
		}
		if len(fields) > 0 {
			gaps = append(gaps, RunProvenanceGap{r.Index, fields})
		}
	}
	return gaps
}
func scanAuditReport(row interface{ Scan(...any) error }) (AuditReport, string, error) {
	var r Report
	var raw string
	err := row.Scan(append(reportDestinations(&r), &raw, &r.ArchivedAt, &r.ArchivedBy)...)
	d := AuditReport{Report: reference(r), Runs: []Run{}, ProvenanceGaps: []RunProvenanceGap{}}
	if err == sql.ErrNoRows {
		return d, "", ErrNotFound
	}
	if err != nil {
		return d, "", err
	}
	if err = json.Unmarshal([]byte(raw), &d.Runs); err != nil {
		return d, "", err
	}
	d.ProvenanceGaps = provenanceGaps(d.Runs)
	d.ProvenanceIncomplete = len(d.Runs) == 0 || len(d.ProvenanceGaps) > 0
	return d, r.Tools, nil
}
func (s *Store) AuditReports(ctx context.Context, workspace string, offset int) (AuditReportPage, error) {
	return s.AuditReportsByStatus(ctx, workspace, offset, "active")
}
func (s *Store) AuditReportsByStatus(ctx context.Context, workspace string, offset int, status string) (AuditReportPage, error) {
	p := AuditReportPage{Items: []AuditReportListItem{}}
	if err := validScope(workspace); err != nil {
		return p, err
	}
	if offset < 0 {
		return p, ErrInvalid
	}
	filter, err := reportVisibility("reports", status)
	if err != nil {
		return p, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM reports WHERE workspace_id=?"+filter, workspace).Scan(&p.Total); err != nil {
		return p, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+reportColumns+",runs_json"+archiveColumns+" FROM reports WHERE workspace_id=?"+filter+" ORDER BY created_at DESC,id LIMIT ? OFFSET ?", workspace, PageSize, offset)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		d, tools, err := scanAuditReport(rows)
		if err != nil {
			return p, err
		}
		item := AuditReportListItem{ReportReference: d.Report}
		item.Tools = boundedDetail(tools, 1024, &item.Truncated)
		p.Items = append(p.Items, item)
	}
	if offset+len(p.Items) < p.Total {
		p.NextOffset = offset + len(p.Items)
		p.HasMore = true
	}
	return p, rows.Err()
}
func selectedReports(ctx context.Context, tx *sql.Tx, workspace string, ids []string) ([]AuditReport, error) {
	if err := validScope(workspace); err != nil {
		return nil, err
	}
	if len(ids) < 1 || len(ids) > MaxAuditReports {
		return nil, fmt.Errorf("%w: select between 1 and %d report IDs", ErrInvalid, MaxAuditReports)
	}
	seen := map[string]bool{}
	args := []any{workspace}
	for _, id := range ids {
		if id == "" || len(id) > 128 || strings.TrimSpace(id) != id || seen[id] {
			return nil, fmt.Errorf("%w: report IDs must be unique nonempty strings of at most 128 bytes", ErrInvalid)
		}
		seen[id] = true
		args = append(args, id)
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+reportColumns+",runs_json"+archiveColumns+" FROM reports WHERE workspace_id=? AND id IN ("+placeholders(len(ids))+") ORDER BY id", args...)
	if err != nil {
		return nil, err
	}
	result := []AuditReport{}
	for rows.Next() {
		d, _, err := scanAuditReport(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		result = append(result, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	// Fail the whole selection; never silently drop foreign, deleted, or unknown IDs.
	if len(result) != len(ids) {
		return nil, ErrNotFound
	}
	return result, nil
}
func placeholders(n int) string { return strings.TrimSuffix(strings.Repeat("?,", n), ",") }
func reportReferences(selected []AuditReport) []ReportReference {
	refs := make([]ReportReference, 0, len(selected))
	for _, r := range selected {
		refs = append(refs, r.Report)
	}
	return refs
}
func selectedLatest(refs []ReportReference) string {
	var latest time.Time
	var value string
	for _, r := range refs {
		if t, err := time.Parse(time.RFC3339Nano, r.UpdatedAt); err == nil && t.After(latest) {
			latest = t
			value = r.UpdatedAt
		}
	}
	return value
}
func (s *Store) AuditReport(ctx context.Context, workspace, id string) (AuditReport, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AuditReport{}, err
	}
	defer tx.Rollback()
	selected, err := selectedReports(ctx, tx, workspace, []string{id})
	if err != nil {
		return AuditReport{}, err
	}
	return selected[0], nil
}
func auditWhere(workspace string, q AuditQuery) (string, []any, error) {
	if q.Offset < 0 || len(q.Language) > 128 || len(q.Tool) > 256 || len(q.Rule) > 1024 || len(q.Search) > 256 || (q.Severity != "" && severityRank(q.Severity) == 0) {
		return "", nil, ErrInvalid
	}
	condition, args := auditReportCondition(workspace, q.ReportIDs, "r")
	where := " FROM findings f JOIN reports r ON r.id=f.report_id WHERE " + condition
	for _, f := range []struct{ column, value string }{{"f.language", q.Language}, {"f.tool", q.Tool}, {"f.rule_id", q.Rule}, {"f.severity", q.Severity}} {
		if f.value != "" {
			where += " AND " + f.column + "=?"
			args = append(args, f.value)
		}
	}
	if q.Search != "" {
		where += " AND instr(f.search_text,?)>0"
		args = append(args, strings.ToLower(q.Search))
	}
	return where, args, nil
}
func severityTotals(ctx context.Context, tx *sql.Tx, where string, args []any) (map[string]int, int, error) {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
	total := 0
	rows, err := tx.QueryContext(ctx, "SELECT f.severity,count(*)"+where+" GROUP BY f.severity", args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var severity string
		var n int
		if err = rows.Scan(&severity, &n); err != nil {
			return nil, 0, err
		}
		counts[severity] = n
		total += n
	}
	return counts, total, rows.Err()
}
func (s *Store) AuditFindings(ctx context.Context, workspace string, q AuditQuery) (AuditFindingPage, error) {
	p := AuditFindingPage{AggregatePage: AggregatePage{Items: []AggregateFinding{}}}
	orders := map[string]string{"": "f.severity_rank DESC,f.security_score DESC,r.created_at DESC", "severity": "f.severity_rank DESC,f.security_score DESC,r.created_at DESC", "newest": "r.created_at DESC", "oldest": "r.created_at ASC", "recently_updated": "r.updated_at DESC", "least_recently_updated": "r.updated_at ASC"}
	order, ok := orders[q.Sort]
	if !ok {
		return p, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	scope, err := resolveAuditScope(ctx, tx, workspace, q.ReportIDs)
	if err != nil {
		return p, err
	}
	p.AuditSelection = scope.AuditSelection
	p.LatestImportAt = scope.latest
	where, args, err := auditWhere(workspace, q)
	if err != nil {
		return p, err
	}
	// MCP counts honor every supplied filter, including severity.
	p.SeverityCounts, p.Total, err = severityTotals(ctx, tx, where, args)
	if err != nil {
		return p, err
	}
	args = append(args, PageSize, q.Offset)
	rows, err := tx.QueryContext(ctx, "SELECT f.value_json,r.id,r.filename,r.created_at,r.updated_at,coalesce(f.issue_id,'')"+where+" ORDER BY "+order+",r.id,f.ordinal LIMIT ? OFFSET ?", args...)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var f AggregateFinding
		var value string
		if err = rows.Scan(&value, &f.ReportID, &f.ReportName, &f.CreatedAt, &f.UpdatedAt, &f.IssueID); err != nil {
			return p, err
		}
		if err = json.Unmarshal([]byte(value), &f.Finding); err != nil {
			return p, err
		}
		p.Items = append(p.Items, f)
	}
	if err = rows.Err(); err != nil {
		return p, err
	}
	if err = rows.Close(); err != nil {
		return p, err
	}
	p.Reports = reportReferences(scope.reports)
	if q.ReportIDs == nil {
		p.Reports, err = auditFindingReferences(ctx, tx, workspace, p.Items)
		if err != nil {
			return p, err
		}
		p.ReportsTruncated = p.ReportCount > len(p.Reports)
	}
	if q.Offset+len(p.Items) < p.Total {
		p.NextOffset = q.Offset + len(p.Items)
		p.HasMore = true
	}
	return p, nil
}
func (s *Store) AuditSummary(ctx context.Context, workspace string, ids []string) (AuditSummary, error) {
	p := AuditSummary{Reports: []ReportReference{}, Scanners: []string{}, ProvenanceIncompleteReportIDs: []string{}}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	scope, err := resolveAuditScope(ctx, tx, workspace, ids)
	if err != nil {
		return p, err
	}
	p.AuditSelection = scope.AuditSelection
	scanners := map[string]bool{}
	var latest time.Time
	err = scope.eachReport(ctx, tx, workspace, func(r AuditReport) {
		if len(p.Reports) < MaxAuditReports {
			p.Reports = append(p.Reports, r.Report)
		}
		if imported, parseErr := time.Parse(time.RFC3339Nano, r.Report.UpdatedAt); parseErr == nil && imported.After(latest) {
			latest = imported
			p.LatestImportAt = r.Report.UpdatedAt
		}
		if r.ProvenanceIncomplete {
			p.ProvenanceIncompleteReportCount++
			if len(p.ProvenanceIncompleteReportIDs) < MaxAuditReports {
				p.ProvenanceIncompleteReportIDs = append(p.ProvenanceIncompleteReportIDs, r.Report.ReportID)
			}
		}
		for _, run := range r.Runs {
			if includeAuditScanner(scanners, run.Tool) {
				p.ScannersTruncated = true
			}
		}
	})
	if err != nil {
		return p, err
	}
	p.ReportsTruncated = p.ReportCount > len(p.Reports)
	p.ProvenanceIncompleteReportIDsTruncated = p.ProvenanceIncompleteReportCount > len(p.ProvenanceIncompleteReportIDs)
	for scanner := range scanners {
		p.Scanners = append(p.Scanners, scanner)
	}
	sort.Strings(p.Scanners)
	where, args, err := auditWhere(workspace, AuditQuery{ReportIDs: ids})
	if err != nil {
		return p, err
	}
	p.SeverityCounts, p.FindingCount, err = severityTotals(ctx, tx, where, args)
	return p, err
}
func (s *Store) AuditFilterValues(ctx context.Context, workspace string, ids []string, facet, search string, offset int) (AuditFacetPage, error) {
	p := AuditFacetPage{FacetPage: FacetPage{Items: []string{}}}
	column, ok := map[string]string{"language": "f.language", "tool": "f.tool", "rule": "f.rule_id"}[facet]
	if !ok || len(search) > 256 || offset < 0 {
		return p, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	scope, err := resolveAuditScope(ctx, tx, workspace, ids)
	if err != nil {
		return p, err
	}
	p.AuditSelection = scope.AuditSelection
	p.Reports = reportReferences(scope.reports)
	if ids == nil {
		p.Reports, err = auditScopeReferences(ctx, tx, workspace)
		if err != nil {
			return p, err
		}
		p.ReportsTruncated = p.ReportCount > len(p.Reports)
	}
	where, args, err := auditWhere(workspace, AuditQuery{ReportIDs: ids})
	if err != nil {
		return p, err
	}
	args = append(args, strings.ToLower(search), PageSize+1, offset)
	rows, err := tx.QueryContext(ctx, "SELECT DISTINCT "+column+where+" AND "+column+"<>'' AND instr(lower("+column+"),?)>0 ORDER BY "+column+" COLLATE NOCASE,"+column+" LIMIT ? OFFSET ?", args...)
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
		p.HasMore = true
	}
	return p, rows.Err()
}
