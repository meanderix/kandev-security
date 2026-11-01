package reports

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrTooLarge     = errors.New("report too large")
	ErrInvalid      = errors.New("invalid request")
	ErrNotFound     = errors.New("not found")
	ErrConflict     = errors.New("conflict")
)

const PageSize = 25

type Store struct{ db *sql.DB }
type Report struct {
	ArchivedAt   string   `json:"archived_at,omitempty"`
	ArchivedBy   string   `json:"archived_by,omitempty"`
	Pinned       bool     `json:"pinned,omitempty"`
	PurgedAt     string   `json:"purged_at,omitempty"`
	PurgeReason  string   `json:"purge_reason,omitempty"`
	PurgedBy     string   `json:"purged_by,omitempty"`
	Scanners     []string `json:"scanners,omitempty"`
	ID           string   `json:"id"`
	WorkspaceID  string   `json:"workspace_id"`
	Filename     string   `json:"filename"`
	Digest       string   `json:"sha256"`
	ActorID      string   `json:"actor_id"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
	FindingCount int      `json:"finding_count"`
	Size         int      `json:"size"`
	Tools        string   `json:"tools"`
}
type ReportPage struct {
	Items        []Report       `json:"items"`
	NextOffset   int            `json:"next_offset"`
	Total        int            `json:"total"`
	StatusCounts map[string]int `json:"status_counts"`
}
type FindingQuery struct {
	Level  string `json:"level"`
	Search string `json:"search"`
	Offset int    `json:"offset"`
	Limit  int    `json:"limit"`
}
type Detail struct {
	Report     Report    `json:"report"`
	Runs       []Run     `json:"runs"`
	Findings   []Finding `json:"findings"`
	Total      int       `json:"total"`
	NextOffset int       `json:"next_offset"`
}
type SourceChunk struct {
	Data       string `json:"data"`
	NextOffset int    `json:"next_offset"`
	Size       int    `json:"size"`
	Filename   string `json:"filename"`
}

// Open owns its schema and connection. One connection serializes writers and
// keeps per-connection SQLite settings effective across every operation.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	// Pre-create with private permissions; SQLite's WAL inherits database access.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err = s.initialize(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }

func expiry() string { return time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339Nano) }
func validScope(workspace string) error {
	if strings.TrimSpace(workspace) == "" {
		return fmt.Errorf("%w: workspace is required", ErrInvalid)
	}
	return nil
}

const reportColumns = "id,workspace_id,filename,digest,actor_id,created_at,finding_count,size,tools,updated_at"

func scanReport(row interface{ Scan(...any) error }) (Report, error) {
	var r Report
	err := row.Scan(reportDestinations(&r)...)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return r, err
}
func (s *Store) Import(ctx context.Context, workspace, actor, filename string, raw []byte) (Report, bool, error) {
	if err := validScope(workspace); err != nil {
		return Report{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return Report{}, false, err
	}
	if filename == "" || len(filename) > 255 {
		return Report{}, false, fmt.Errorf("%w: filename must be 1 to 255 bytes", ErrInvalid)
	}
	runs, findings, err := parseSARIF(raw)
	if err != nil {
		return Report{}, false, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Report{}, false, err
	}
	defer tx.Rollback()
	report, duplicate, err := importReportTx(ctx, tx, workspace, actor, filename, raw, runs, findings)
	if err != nil {
		return Report{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return Report{}, false, err
	}
	return report, duplicate, nil
}
func importReportTx(ctx context.Context, tx *sql.Tx, workspace, actor, filename string, raw []byte, runs []Run, findings []Finding) (Report, bool, error) {
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	existing, err := scanReport(tx.QueryRowContext(ctx, "SELECT "+reportColumns+" FROM reports WHERE workspace_id=? AND digest=?", workspace, digest))
	if err == nil {
		existing.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if _, err = tx.ExecContext(ctx, "UPDATE reports SET updated_at=? WHERE workspace_id=? AND id=?", existing.UpdatedAt, workspace, existing.ID); err != nil {
			return Report{}, false, err
		}

		last, err := issueTimestamp(existing.UpdatedAt)
		if err != nil {
			return Report{}, false, err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE issues SET last_seen_at=max(last_seen_at,?) WHERE workspace_id=? AND id IN (SELECT issue_id FROM findings WHERE report_id=?)", last, workspace, existing.ID); err != nil {
			return Report{}, false, err
		}
		existing, err = finishRetentionImport(ctx, tx, existing)
		return existing, true, err
	}
	if !errors.Is(err, ErrNotFound) {
		return Report{}, false, err
	}
	r := Report{ID: rand.Text(), WorkspaceID: workspace, Filename: filename, Digest: digest, ActorID: actor, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), FindingCount: len(findings), Size: len(raw)}
	var archived string
	archiveErr := tx.QueryRowContext(ctx, "SELECT metadata_json FROM purged_reports WHERE workspace_id=? AND digest=?", workspace, digest).Scan(&archived)
	restored := archiveErr == nil
	if restored {
		if err = json.Unmarshal([]byte(archived), &r); err != nil {
			return Report{}, false, err
		}
		r.PurgedAt = ""
		r.PurgeReason = ""
		r.PurgedBy = ""
		r.Scanners = nil
		if _, err = tx.ExecContext(ctx, "DELETE FROM purged_reports WHERE workspace_id=? AND id=?", workspace, r.ID); err != nil {
			return Report{}, false, err
		}
	} else if !errors.Is(archiveErr, sql.ErrNoRows) {
		return Report{}, false, archiveErr
	}
	r.UpdatedAt = r.CreatedAt
	if restored {
		r.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	tools := []string{}
	seen := map[string]bool{}
	for _, run := range runs {
		if !seen[run.Tool] {
			tools = append(tools, run.Tool)
			seen[run.Tool] = true
		}
	}
	r.Tools = strings.Join(tools, ", ")
	metadata, _ := json.Marshal(runs)
	_, err = tx.ExecContext(ctx, "INSERT INTO reports("+reportColumns+",runs_json,original) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", r.ID, workspace, r.Filename, digest, r.ActorID, r.CreatedAt, r.FindingCount, len(raw), r.Tools, r.UpdatedAt, string(metadata), raw)
	if err != nil {
		return Report{}, false, err
	}
	if err = writeFindings(ctx, tx, r.ID, findings); err != nil {
		return Report{}, false, err
	}
	if err = writeReportScanners(ctx, tx, r.ID, runs); err != nil {
		return Report{}, false, err
	}
	if r.ArchivedAt != "" {
		if _, err = tx.ExecContext(ctx, "INSERT INTO report_archives(report_id,archived_at,archived_by) VALUES(?,?,?)", r.ID, r.ArchivedAt, r.ArchivedBy); err != nil {
			return Report{}, false, err
		}
	}
	if err = writeAdvisories(ctx, tx, r.ID, findings); err != nil {
		return Report{}, false, err
	}
	if err = linkIssuesTx(ctx, tx, r, findings); err != nil {
		return Report{}, false, err
	}
	r, err = finishRetentionImport(ctx, tx, r)
	return r, restored, err
}
func (s *Store) List(ctx context.Context, workspace string, offset int) (ReportPage, error) {
	return s.ListReports(ctx, workspace, offset, "active")
}

func (s *Store) Detail(ctx context.Context, workspace, id string, q FindingQuery) (Detail, error) {
	var d Detail
	d.Findings = []Finding{}
	if err := validScope(workspace); err != nil {
		return d, err
	}
	if q.Offset < 0 || q.Limit < 0 || len(q.Search) > 256 {
		return d, ErrInvalid
	}
	if q.Limit == 0 || q.Limit > PageSize {
		q.Limit = PageSize
	}
	if q.Level != "" && q.Level != "error" && q.Level != "warning" && q.Level != "note" && q.Level != "none" {
		return d, ErrInvalid
	}
	// A read transaction keeps report, count and page consistent during deletion.
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return d, err
	}
	defer tx.Rollback()
	d.Report, err = scanReport(tx.QueryRowContext(ctx, "SELECT "+reportColumns+" FROM reports WHERE workspace_id=? AND id=?", workspace, id))
	if err != nil {
		return d, err
	}
	err = readReportStateTx(ctx, tx, &d.Report)
	if err != nil {
		return d, err
	}
	var metadata string
	if err = tx.QueryRowContext(ctx, "SELECT runs_json FROM reports WHERE workspace_id=? AND id=?", workspace, id).Scan(&metadata); err != nil {
		return d, err
	}
	if err = json.Unmarshal([]byte(metadata), &d.Runs); err != nil {
		return d, err
	}
	where := " FROM findings f JOIN reports r ON r.id=f.report_id WHERE r.workspace_id=? AND r.id=?"
	args := []any{workspace, id}
	if q.Level != "" {
		where += " AND f.level=?"
		args = append(args, q.Level)
	}
	if q.Search != "" {
		where += " AND instr(f.search_text,?)>0"
		args = append(args, strings.ToLower(q.Search))
	}
	if err = tx.QueryRowContext(ctx, "SELECT count(*)"+where, args...).Scan(&d.Total); err != nil {
		return d, err
	}
	args = append(args, q.Limit, q.Offset)
	rows, err := tx.QueryContext(ctx, "SELECT f.value_json,coalesce(f.issue_id,'')"+where+" ORDER BY f.ordinal LIMIT ? OFFSET ?", args...)
	if err != nil {
		return d, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		var f Finding
		if err = rows.Scan(&raw, &f.IssueID); err != nil {
			return d, err
		}
		if err = json.Unmarshal([]byte(raw), &f); err != nil {
			return d, err
		}
		d.Findings = append(d.Findings, f)
	}
	if err = rows.Err(); err != nil {
		return d, err
	}
	if q.Offset+len(d.Findings) < d.Total {
		d.NextOffset = q.Offset + len(d.Findings)
	}
	return d, nil
}
func (s *Store) Source(ctx context.Context, workspace, id string, offset int) (SourceChunk, error) {
	var chunk SourceChunk
	if err := validScope(workspace); err != nil {
		return chunk, err
	}
	if offset < 0 {
		return chunk, ErrInvalid
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT substr(original,?,?),size,filename FROM reports WHERE workspace_id=? AND id=?", offset+1, ChunkBytes, workspace, id).Scan(&raw, &chunk.Size, &chunk.Filename)
	if errors.Is(err, sql.ErrNoRows) {
		return chunk, ErrNotFound
	}
	if err != nil {
		return chunk, err
	}
	if offset >= chunk.Size {
		return chunk, ErrInvalid
	}
	chunk.Data = base64.StdEncoding.EncodeToString(raw)
	if offset+len(raw) < chunk.Size {
		chunk.NextOffset = offset + len(raw)
	}
	return chunk, nil
}
func (s *Store) Delete(ctx context.Context, workspace, id string) error {
	if err := validScope(workspace); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "DELETE FROM reports WHERE workspace_id=? AND id=?", workspace, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM uploads WHERE workspace_id=? AND report_id=?", workspace, id); err != nil {
		return err
	}
	return tx.Commit()
}
