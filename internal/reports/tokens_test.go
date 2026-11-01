package reports

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestUploadTokenLifecycleAndHashStorage(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	created, err := s.CreateUploadToken(ctx, "ws-a", "issuer", "CI upload")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Secret, "ksr_") || created.Token.WorkspaceID != "ws-a" || created.Token.ActorID != "issuer" {
		t.Fatalf("created: %+v", created.Token)
	}
	var hash string
	if err = s.db.QueryRow("SELECT token_hash FROM upload_tokens WHERE id=?", created.Token.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == created.Secret || strings.Contains(hash, "ksr_") || len(hash) != 64 {
		t.Fatal("secret was not hashed")
	}
	page, err := s.ListUploadTokens(ctx, "ws-a", 0)
	if err != nil || len(page.Items) != 1 || page.Items[0].Name != "CI upload" {
		t.Fatalf("list: %+v %v", page, err)
	}
	page, err = s.ListUploadTokens(ctx, "ws-b", 0)
	if err != nil || len(page.Items) != 0 {
		t.Fatal("tokens leaked across workspaces")
	}
	if err = s.RevokeUploadToken(ctx, "ws-b", "other", created.Token.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross workspace revoke: %v", err)
	}
	token, err := s.AuthenticateUploadToken(ctx, created.Secret)
	if err != nil || token.ID != created.Token.ID {
		t.Fatal("token rejected")
	}
	if err = s.RevokeUploadToken(ctx, "ws-a", "manager", created.Token.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AuthenticateUploadToken(ctx, created.Secret); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revoked token accepted")
	}
	if err = s.RevokeUploadToken(ctx, "ws-a", "other", created.Token.ID); err != nil {
		t.Fatal(err)
	}
	page, err = s.ListUploadTokens(ctx, "ws-a", 0)
	if err != nil || page.Items[0].RevokedBy != "manager" || page.Items[0].RevokedAt == "" {
		t.Fatalf("revocation audit: %+v %v", page, err)
	}
}
func TestTokenImportWorkspaceAttributionAndDuplicates(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	token, err := s.CreateUploadToken(ctx, "ws-a", "issuer", "Scanner")
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.ImportWithToken(ctx, token.Secret, "scan.sarif", []byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if result.Report.WorkspaceID != "ws-a" || result.Report.ActorID != "issuer" || result.Duplicate {
		t.Fatalf("import: %+v", result)
	}
	again, err := s.ImportWithToken(ctx, token.Secret, "renamed.sarif", []byte(sample))
	if err != nil || !again.Duplicate || again.Report.ID != result.Report.ID {
		t.Fatalf("duplicate: %+v %v", again, err)
	}
	page, err := s.ListUploadTokens(ctx, "ws-a", 0)
	if err != nil || page.Items[0].LastUsedAt == "" {
		t.Fatal("successful use was not recorded")
	}
	if _, err = s.ImportWithToken(ctx, "invalid", "x", []byte(sample)); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("invalid token accepted")
	}
	if err = s.RevokeUploadToken(ctx, "ws-a", "issuer", token.Token.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ImportWithToken(ctx, token.Secret, "x", []byte(sample)); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revoked token imported report")
	}
}
func TestUploadTokenPersistenceAndLimits(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "tokens.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.CreateUploadToken(ctx, "ws", "actor", "Persistent")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.AuthenticateUploadToken(ctx, token.Secret); err != nil {
		t.Fatal("token did not survive restart")
	}
	for _, secret := range []string{"", token.Secret + "x", strings.Replace(token.Secret, "ksr_", "kandev_pat_", 1), "ksr_" + strings.Repeat("a", 43)} {
		if _, err = s.AuthenticateUploadToken(ctx, secret); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("malformed token accepted")
		}
	}
	if _, err = s.CreateUploadToken(ctx, "", "actor", "x"); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing workspace")
	}
	if _, err = s.CreateUploadToken(ctx, "ws", "", "x"); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing issuer")
	}
	if _, err = s.CreateUploadToken(ctx, "ws", "actor", "  "); !errors.Is(err, ErrInvalid) {
		t.Fatal("blank name")
	}
	if _, err = s.ImportWithToken(ctx, token.Secret, "x", make([]byte, MaxWebhookBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatal("oversized webhook accepted")
	}
	if _, err = s.ImportWithToken(ctx, token.Secret, "x", []byte("bad")); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid SARIF accepted")
	}
	p, err := s.ListUploadTokens(ctx, "ws", 0)
	if err != nil || p.Items[0].LastUsedAt != "" {
		t.Fatal("failed upload marked used")
	}
}
func TestTokenRevocationRecheckedAtCommitBoundary(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	token, err := s.CreateUploadToken(ctx, "ws", "actor", "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AuthenticateUploadToken(ctx, token.Secret); err != nil {
		t.Fatal(err)
	}
	if err = s.RevokeUploadToken(ctx, "ws", "actor", token.Token.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ImportWithToken(ctx, token.Secret, "x", []byte(sample)); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("stale authorization accepted")
	}
	p, err := s.List(ctx, "ws", 0)
	if err != nil || len(p.Items) != 0 {
		t.Fatal("revoked upload created a report")
	}
}

func TestUploadTokenPaginationAndActiveQuota(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	var first CreatedUploadToken
	for i := 0; i < 100; i++ {
		created, err := s.CreateUploadToken(ctx, "ws", "actor", "CI")
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = created
		}
	}
	if _, err := s.CreateUploadToken(ctx, "ws", "actor", "extra"); !errors.Is(err, ErrConflict) {
		t.Fatal("active token quota missing")
	}
	p, err := s.ListUploadTokens(ctx, "ws", 0)
	if err != nil || len(p.Items) != PageSize || p.NextOffset != PageSize {
		t.Fatalf("token pagination: %+v %v", p, err)
	}
	if err = s.RevokeUploadToken(ctx, "ws", "actor", first.Token.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateUploadToken(ctx, "ws", "actor", "replacement"); err != nil {
		t.Fatal(err)
	}
}
