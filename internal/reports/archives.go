package reports

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Archiving controls visibility; the report remains in retention accounting.
const archiveColumns = ",coalesce((SELECT archived_at FROM report_archives WHERE report_id=reports.id),''),coalesce((SELECT archived_by FROM report_archives WHERE report_id=reports.id),'')"
const reportStateColumns = ",EXISTS(SELECT 1 FROM report_pins p WHERE p.report_id=reports.id)" + archiveColumns

func reportVisibility(alias, status string) (string, error) {
	switch status {
	case "", "active":
		return " AND NOT EXISTS(SELECT 1 FROM report_archives ar WHERE ar.report_id=" + alias + ".id)", nil
	case "archived":
		return " AND EXISTS(SELECT 1 FROM report_archives ar WHERE ar.report_id=" + alias + ".id)", nil
	case "all":
		return "", nil
	default:
		return "", ErrInvalid
	}
}
func activeReports(alias string) string {
	filter, _ := reportVisibility(alias, "active")
	return filter
}

func readReportStateTx(ctx context.Context, tx *sql.Tx, r *Report) error {
	return tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM report_pins WHERE report_id=?)"+archiveColumns+" FROM reports WHERE workspace_id=? AND id=?", r.ID, r.WorkspaceID, r.ID).Scan(&r.Pinned, &r.ArchivedAt, &r.ArchivedBy)
}
func (s *Store) SetReportArchived(ctx context.Context, workspace, actor, id string, archived bool) (Report, error) {
	if err := validScope(workspace); err != nil {
		return Report{}, err
	}
	if !validText(actor, 1, 512) || id == "" {
		return Report{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Report{}, err
	}
	defer tx.Rollback()
	r, err := scanReport(tx.QueryRowContext(ctx, "SELECT "+reportColumns+" FROM reports WHERE workspace_id=? AND id=?", workspace, id))
	if err != nil {
		return r, err
	}
	if archived {
		_, err = tx.ExecContext(ctx, "INSERT INTO report_archives(report_id,archived_at,archived_by) VALUES(?,?,?) ON CONFLICT(report_id) DO NOTHING", id, time.Now().UTC().Format(time.RFC3339Nano), actor)
	} else {
		_, err = tx.ExecContext(ctx, "DELETE FROM report_archives WHERE report_id=?", id)
	}
	if err != nil {
		return r, err
	}
	if err = readReportStateTx(ctx, tx, &r); err != nil {
		return r, err
	}
	return r, tx.Commit()
}

func (s *Store) ListReports(ctx context.Context, workspace string, offset int, status string) (ReportPage, error) {
	return s.QueryReports(ctx, workspace, ReportQuery{Offset: offset, Status: status})
}

type ReportQuery struct {
	Offset int
	Status string
	Tool   string
	Search string
}

func (s *Store) QueryReports(ctx context.Context, workspace string, q ReportQuery) (ReportPage, error) {
	p := ReportPage{Items: []Report{}, StatusCounts: map[string]int{"active": 0, "archived": 0, "all": 0}}
	if err := validScope(workspace); err != nil {
		return p, err
	}
	if q.Offset < 0 || len(q.Tool) > 256 || len(q.Search) > 256 {
		return p, ErrInvalid
	}
	filter, err := reportVisibility("reports", q.Status)
	if err != nil {
		return p, err
	}
	where := " WHERE workspace_id=?"
	args := []any{workspace}
	if q.Tool != "" {
		where += " AND EXISTS(SELECT 1 FROM report_scanners s WHERE s.report_id=reports.id AND s.tool=?)"
		args = append(args, q.Tool)
	}
	if q.Search != "" {
		where += " AND instr(lower(filename),?)>0"
		args = append(args, strings.ToLower(q.Search))
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	var total, archived int
	if err = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(EXISTS(SELECT 1 FROM report_archives a WHERE a.report_id=reports.id)),0) FROM reports"+where, args...).Scan(&total, &archived); err != nil {
		return p, err
	}
	p.StatusCounts["all"], p.StatusCounts["archived"], p.StatusCounts["active"] = total, archived, total-archived
	status := q.Status
	if status == "" {
		status = "active"
	}
	p.Total = p.StatusCounts[status]
	rows, err := tx.QueryContext(ctx, "SELECT "+reportColumns+reportStateColumns+" FROM reports"+where+filter+" ORDER BY created_at DESC,id LIMIT ? OFFSET ?", append(args, PageSize+1, q.Offset)...)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		r, err := scanPinnedReport(rows)
		if err != nil {
			return p, err
		}
		p.Items = append(p.Items, r)
	}
	if len(p.Items) > PageSize {
		p.Items = p.Items[:PageSize]
		p.NextOffset = q.Offset + PageSize
	}
	return p, rows.Err()
}

// Report scanner choices include archived and zero-finding reports. Filtering
// uses the indexed scanner membership, never the comma-joined display label.
func (s *Store) ReportTools(ctx context.Context, workspace, search string, offset int) (FacetPage, error) {
	p := FacetPage{Items: []string{}}
	if err := validScope(workspace); err != nil {
		return p, err
	}
	if offset < 0 || len(search) > 256 {
		return p, ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT s.tool FROM report_scanners s JOIN reports r ON r.id=s.report_id WHERE r.workspace_id=? AND s.tool<>'' AND instr(lower(s.tool),?)>0 ORDER BY s.tool COLLATE NOCASE,s.tool LIMIT ? OFFSET ?`, workspace, strings.ToLower(search), PageSize+1, offset)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var tool string
		if err = rows.Scan(&tool); err != nil {
			return p, err
		}
		p.Items = append(p.Items, tool)
	}
	if len(p.Items) > PageSize {
		p.Items = p.Items[:PageSize]
		p.NextOffset = offset + PageSize
	}
	return p, rows.Err()
}

func reportStateAfterImport(ctx context.Context, tx *sql.Tx, r Report) (Report, error) {
	err := readReportStateTx(ctx, tx, &r)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return r, err
}
