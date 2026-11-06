package reports

import (
	"context"
	"database/sql"
)

// A nil selection means the live active workspace. A non-nil empty selection
// stays invalid so an explicit selection can never silently widen its scope.
type auditScope struct {
	AuditSelection
	reports []AuditReport
	latest  string
}

func auditReportCondition(workspace string, ids []string, alias string) (string, []any) {
	condition := alias + ".workspace_id=?"
	args := []any{workspace}
	if ids == nil {
		return condition + activeReports(alias), args
	}
	condition += " AND " + alias + ".id IN (" + placeholders(len(ids)) + ")"
	for _, id := range ids {
		args = append(args, id)
	}
	return condition, args
}

func resolveAuditScope(ctx context.Context, tx *sql.Tx, workspace string, ids []string) (auditScope, error) {
	scope := auditScope{}
	if err := validScope(workspace); err != nil {
		return scope, err
	}
	if ids != nil {
		selected, err := selectedReports(ctx, tx, workspace, ids)
		if err != nil {
			return scope, err
		}
		scope.ReportScope = "explicit"
		scope.ReportCount = len(selected)
		scope.reports = selected
		scope.latest = selectedLatest(reportReferences(selected))
		return scope, nil
	}
	scope.ReportScope = "active_workspace"
	condition, args := auditReportCondition(workspace, nil, "reports")
	err := tx.QueryRowContext(ctx, "SELECT count(*) FROM reports WHERE "+condition, args...).Scan(&scope.ReportCount)
	if err != nil || scope.ReportCount == 0 {
		return scope, err
	}
	// Imports use UTC RFC3339Nano. Compare seconds and fractional seconds
	// separately: lexical ordering would put .1Z after the newer .11Z.
	err = tx.QueryRowContext(ctx, "SELECT updated_at FROM reports WHERE "+condition+" ORDER BY substr(updated_at,1,19) DESC,CAST('0.'||substr(updated_at,21) AS REAL) DESC,id DESC LIMIT 1", args...).Scan(&scope.latest)
	return scope, err
}

func (scope auditScope) eachReport(ctx context.Context, tx *sql.Tx, workspace string, visit func(AuditReport)) error {
	if scope.ReportScope == "explicit" {
		for _, report := range scope.reports {
			visit(report)
		}
		return ctx.Err()
	}
	condition, args := auditReportCondition(workspace, nil, "reports")
	rows, err := tx.QueryContext(ctx, "SELECT "+reportColumns+",runs_json"+archiveColumns+" FROM reports WHERE "+condition+" ORDER BY id", args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		report, _, err := scanAuditReport(rows)
		if err != nil {
			return err
		}
		visit(report)
	}
	return rows.Err()
}

// Finding pages retain a hash-bearing source reference for every returned
// report, even when the workspace has more than 50 active reports.
func auditFindingReferences(ctx context.Context, tx *sql.Tx, workspace string, items []AggregateFinding) ([]ReportReference, error) {
	ids := []string{}
	seen := map[string]bool{}
	for _, item := range items {
		if !seen[item.ReportID] {
			seen[item.ReportID] = true
			ids = append(ids, item.ReportID)
		}
	}
	if len(ids) == 0 {
		return []ReportReference{}, nil
	}
	selected, err := selectedReports(ctx, tx, workspace, ids)
	return reportReferences(selected), err
}

func auditScopeReferences(ctx context.Context, tx *sql.Tx, workspace string) ([]ReportReference, error) {
	refs := []ReportReference{}
	condition, args := auditReportCondition(workspace, nil, "reports")
	args = append(args, MaxAuditReports)
	rows, err := tx.QueryContext(ctx, "SELECT "+reportColumns+archiveColumns+" FROM reports WHERE "+condition+" ORDER BY id LIMIT ?", args...)
	if err != nil {
		return refs, err
	}
	defer rows.Close()
	for rows.Next() {
		var report Report
		if err = rows.Scan(append(reportDestinations(&report), &report.ArchivedAt, &report.ArchivedBy)...); err != nil {
			return refs, err
		}
		refs = append(refs, reference(report))
	}
	return refs, rows.Err()
}

// Keep the first 100 scanner names in lexical order without building an
// unbounded set while streaming the workspace's report metadata.
func includeAuditScanner(scanners map[string]bool, scanner string) bool {
	if scanners[scanner] {
		return false
	}
	if len(scanners) < 100 {
		scanners[scanner] = true
		return false
	}
	largest := ""
	for value := range scanners {
		if value > largest {
			largest = value
		}
	}
	if scanner < largest {
		delete(scanners, largest)
		scanners[scanner] = true
	}
	return true
}
