package reports

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type Upload struct {
	ID         string `json:"id"`
	ChunkBytes int    `json:"chunk_bytes"`
}
type ImportResult struct {
	Report    Report `json:"report"`
	Duplicate bool   `json:"duplicate"`
}

func (s *Store) StartUpload(ctx context.Context, workspace, actor, filename string, size int) (Upload, error) {
	var u Upload
	if err := validScope(workspace); err != nil {
		return u, err
	}
	if size < 1 || size > MaxReportBytes || filename == "" || len(filename) > 255 {
		return u, fmt.Errorf("%w: choose a SARIF file between 1 byte and 20 MiB with a filename up to 255 bytes", ErrInvalid)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return u, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM uploads WHERE created_at < ?", expiry()); err != nil {
		return u, err
	}
	var total, owned int
	if err = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(CASE WHEN workspace_id=? THEN 1 ELSE 0 END),0) FROM uploads WHERE report_id IS NULL", workspace).Scan(&total, &owned); err != nil {
		return u, err
	}
	if total >= 16 || owned >= 3 {
		return u, fmt.Errorf("%w: too many active imports; cancel an import or wait for expiry", ErrConflict)
	}
	u = Upload{ID: rand.Text(), ChunkBytes: ChunkBytes}
	if _, err = tx.ExecContext(ctx, "INSERT INTO uploads(id,workspace_id,actor_id,filename,expected_size,created_at) VALUES(?,?,?,?,?,?)", u.ID, workspace, actor, filename, size, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return u, err
	}
	return u, tx.Commit()
}
func (s *Store) AppendUpload(ctx context.Context, workspace, id string, offset int, chunk []byte) (int, error) {
	if err := validScope(workspace); err != nil {
		return 0, err
	}
	if offset < 0 || len(chunk) == 0 || len(chunk) > ChunkBytes {
		return 0, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var size, received int
	var reportID sql.NullString
	err = tx.QueryRowContext(ctx, "SELECT expected_size,length(content),report_id FROM uploads WHERE workspace_id=? AND id=? AND created_at>=?", workspace, id, expiry()).Scan(&size, &received, &reportID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if reportID.Valid {
		return 0, ErrConflict
	}
	if len(chunk) > size || offset > size-len(chunk) {
		return 0, fmt.Errorf("%w: chunk exceeds declared size", ErrInvalid)
	}
	if offset < received && offset+len(chunk) <= received {
		var previous []byte
		if err = tx.QueryRowContext(ctx, "SELECT substr(content,?,?) FROM uploads WHERE workspace_id=? AND id=?", offset+1, len(chunk), workspace, id).Scan(&previous); err != nil {
			return 0, err
		}
		if bytes.Equal(previous, chunk) {
			return received, nil
		}
	}
	if offset != received {
		return 0, fmt.Errorf("%w: upload offset mismatch", ErrConflict)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE uploads SET content=CAST(content || ? AS BLOB) WHERE workspace_id=? AND id=?", chunk, workspace, id); err != nil {
		return 0, err
	}
	return received + len(chunk), tx.Commit()
}
func (s *Store) CompleteUpload(ctx context.Context, workspace, id string) (ImportResult, error) {
	var result ImportResult
	if err := validScope(workspace); err != nil {
		return result, err
	}
	var actor, filename string
	var size int
	var raw []byte
	var reportID sql.NullString
	err := s.db.QueryRowContext(ctx, "SELECT actor_id,filename,expected_size,content,report_id FROM uploads WHERE workspace_id=? AND id=? AND created_at>=?", workspace, id, expiry()).Scan(&actor, &filename, &size, &raw, &reportID)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	if reportID.Valid {
		result.Report, err = scanPinnedReport(s.db.QueryRowContext(ctx, "SELECT "+reportColumns+reportStateColumns+" FROM reports WHERE workspace_id=? AND id=?", workspace, reportID.String))
		if errors.Is(err, ErrNotFound) {
			var tx *sql.Tx
			tx, err = s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
			if err != nil {
				return result, err
			}
			defer tx.Rollback()
			result.Report, err = purgedReportTx(ctx, tx, workspace, reportID.String)
		}
		result.Duplicate = true
		return result, err
	}
	if len(raw) != size {
		return result, fmt.Errorf("%w: upload is incomplete", ErrInvalid)
	}
	result.Report, result.Duplicate, err = s.Import(ctx, workspace, actor, filename, raw)
	if err != nil {
		return result, err
	}
	// Keep a bounded-lived receipt so a lost completion response is safe to retry.
	_, err = s.db.ExecContext(ctx, "UPDATE uploads SET report_id=?,content=X'' WHERE workspace_id=? AND id=?", result.Report.ID, workspace, id)
	return result, err
}
func (s *Store) CancelUpload(ctx context.Context, workspace, id string) error {
	if err := validScope(workspace); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, "DELETE FROM uploads WHERE workspace_id=? AND id=?", workspace, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
