package reports

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const MaxWebhookBytes = 16 << 20
const tokenColumns = "id,workspace_id,actor_id,name,created_at,last_used_at,revoked_at,revoked_by"

type UploadToken struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	ActorID     string `json:"actor_id"`
	Name        string `json:"name"`
	CreatedAt   string `json:"created_at"`
	LastUsedAt  string `json:"last_used_at"`
	RevokedAt   string `json:"revoked_at"`
	RevokedBy   string `json:"revoked_by"`
}
type CreatedUploadToken struct {
	Token  UploadToken `json:"token"`
	Secret string      `json:"secret"`
}
type UploadTokenPage struct {
	Items      []UploadToken `json:"items"`
	NextOffset int           `json:"next_offset"`
}

func (s *Store) CreateUploadToken(ctx context.Context, workspace, actor, name string) (CreatedUploadToken, error) {
	var result CreatedUploadToken
	if err := validScope(workspace); err != nil {
		return result, err
	}
	name = strings.TrimSpace(name)
	if strings.TrimSpace(actor) == "" || name == "" || len(name) > 80 {
		return result, fmt.Errorf("%w: issuer and a token name of 1 to 80 bytes are required", ErrInvalid)
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return result, err
	}
	result.Secret = "ksr_" + base64.RawURLEncoding.EncodeToString(secretBytes)
	digest, err := uploadTokenDigest(result.Secret)
	if err != nil {
		return CreatedUploadToken{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CreatedUploadToken{}, err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM upload_tokens WHERE workspace_id=? AND revoked_at=''", workspace).Scan(&count); err != nil {
		return CreatedUploadToken{}, err
	}
	if count >= 100 {
		return CreatedUploadToken{}, fmt.Errorf("%w: at most 100 active upload tokens are allowed per workspace", ErrConflict)
	}
	result.Token = UploadToken{ID: rand.Text(), WorkspaceID: workspace, ActorID: actor, Name: name, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	t := result.Token
	if _, err = tx.ExecContext(ctx, "INSERT INTO upload_tokens(id,workspace_id,actor_id,name,token_hash,created_at) VALUES(?,?,?,?,?,?)", t.ID, workspace, actor, name, digest, t.CreatedAt); err != nil {
		return CreatedUploadToken{}, err
	}
	if err = tx.Commit(); err != nil {
		return CreatedUploadToken{}, err
	}
	return result, nil
}
func scanUploadToken(row interface{ Scan(...any) error }) (UploadToken, error) {
	var token UploadToken
	err := row.Scan(&token.ID, &token.WorkspaceID, &token.ActorID, &token.Name, &token.CreatedAt, &token.LastUsedAt, &token.RevokedAt, &token.RevokedBy)
	return token, err
}
func (s *Store) ListUploadTokens(ctx context.Context, workspace string, offset int) (UploadTokenPage, error) {
	p := UploadTokenPage{Items: []UploadToken{}}
	if err := validScope(workspace); err != nil {
		return p, err
	}
	if offset < 0 {
		return p, ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+tokenColumns+" FROM upload_tokens WHERE workspace_id=? ORDER BY created_at DESC,id LIMIT ? OFFSET ?", workspace, PageSize+1, offset)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		token, err := scanUploadToken(rows)
		if err != nil {
			return p, err
		}
		p.Items = append(p.Items, token)
	}
	if len(p.Items) > PageSize {
		p.Items = p.Items[:PageSize]
		p.NextOffset = offset + PageSize
	}
	return p, rows.Err()
}
func (s *Store) RevokeUploadToken(ctx context.Context, workspace, actor, id string) error {
	if err := validScope(workspace); err != nil {
		return err
	}
	if strings.TrimSpace(actor) == "" {
		return ErrInvalid
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, "UPDATE upload_tokens SET revoked_by=CASE WHEN revoked_at='' THEN ? ELSE revoked_by END,revoked_at=CASE WHEN revoked_at='' THEN ? ELSE revoked_at END WHERE workspace_id=? AND id=?", actor, now, workspace, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
func uploadTokenDigest(secret string) (string, error) {
	if !strings.HasPrefix(secret, "ksr_") || len(secret) != 47 {
		return "", ErrUnauthorized
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(secret, "ksr_"))
	if err != nil || len(raw) != 32 {
		return "", ErrUnauthorized
	}
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:]), nil
}

type tokenQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func authenticateUploadToken(ctx context.Context, db tokenQuerier, digest string) (UploadToken, error) {
	token, err := scanUploadToken(db.QueryRowContext(ctx, "SELECT "+tokenColumns+" FROM upload_tokens WHERE token_hash=? AND revoked_at=''", digest))
	if errors.Is(err, sql.ErrNoRows) {
		return UploadToken{}, ErrUnauthorized
	}
	return token, err
}
func (s *Store) AuthenticateUploadToken(ctx context.Context, secret string) (UploadToken, error) {
	digest, err := uploadTokenDigest(secret)
	if err != nil {
		return UploadToken{}, err
	}
	return authenticateUploadToken(ctx, s.db, digest)
}

// Recheck the token inside the report transaction. A revocation that commits
// before this transaction begins cannot authorize a later import.
func (s *Store) ImportWithToken(ctx context.Context, secret, filename string, raw []byte) (ImportResult, error) {
	var result ImportResult
	if _, err := s.AuthenticateUploadToken(ctx, secret); err != nil {
		return result, err
	}
	if len(raw) > MaxWebhookBytes {
		return result, ErrTooLarge
	}
	if filename == "" || len(filename) > 255 {
		return result, fmt.Errorf("%w: filename must be 1 to 255 bytes", ErrInvalid)
	}
	runs, findings, err := parseSARIF(raw)
	if err != nil {
		return result, err
	}
	digest, err := uploadTokenDigest(secret)
	if err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	token, err := authenticateUploadToken(ctx, tx, digest)
	if err != nil {
		return result, err
	}
	result.Report, result.Duplicate, err = importReportTx(ctx, tx, token.WorkspaceID, token.ActorID, filename, raw, runs, findings)
	if err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE upload_tokens SET last_used_at=? WHERE id=?", time.Now().UTC().Format(time.RFC3339Nano), token.ID); err != nil {
		return ImportResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return ImportResult{}, err
	}
	return result, nil
}
