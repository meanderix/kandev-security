package reports

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func storageSnapshot(t *testing.T, s *Store) []byte {
	t.Helper()
	rows, err := s.db.Query("SELECT name,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' AND type='table' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	type table struct{ name, ddl string }
	var tables []table
	for rows.Next() {
		var tbl table
		if err = rows.Scan(&tbl.name, &tbl.ddl); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, tbl)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	snapshot := map[string]any{}
	for _, tbl := range tables {
		// Table names come from our schema; quoting preserves exact names.
		rows, err = s.db.Query(`SELECT * FROM "` + strings.ReplaceAll(tbl.name, `"`, `""`) + `" ORDER BY rowid`)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		var data [][]any
		for rows.Next() {
			values := make([]any, len(columns))
			dest := make([]any, len(columns))
			for i := range values {
				dest[i] = &values[i]
			}
			if err = rows.Scan(dest...); err != nil {
				t.Fatal(err)
			}
			data = append(data, values)
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		rows.Close()
		snapshot[tbl.name] = map[string]any{"ddl": tbl.ddl, "columns": columns, "data": data}
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBaselineReopenPreservesWorkspaceDataWithoutReparsing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r, id := reviewIssue(t, s)
	if _, err = s.SetReportPinned(ctx, "ws", "owner", r.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetReportArchived(ctx, "ws", "owner", r.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpdateIssueReview(ctx, reviewAuthority("baseline"), id, "closed", "Recorded review"); err != nil {
		t.Fatal(err)
	}
	if err = s.LinkIssueTask(ctx, "ws", "owner", id, "remediation-task", "fix"); err != nil {
		t.Fatal(err)
	}
	presets := DefaultTaskPresets()
	presets[0].Label = "Custom investigation"
	if _, err = s.SaveTaskPresets(ctx, "ws", "owner", 0, presets, false); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateUploadToken(ctx, "ws", "owner", "CI"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.StartReport(ctx, draftAuthority(), draftSpec()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.StartUpload(ctx, "ws", "owner", "pending.sarif", len(sample)); err != nil {
		t.Fatal(err)
	}
	retentionFixture(t, s, "ws", []string{"Scanner"}, 1)
	saveRetention(t, s, "ws", RetentionConfig{Default: RetentionPolicy{MaxReports: 2}})
	// No startup backfill should read or rewrite an existing original, even if
	// external corruption has made it unparsable. Explicit evidence reads may fail.
	if _, err = s.db.Exec("UPDATE reports SET original=? WHERE id=?", []byte("unparsable retained source"), r.ID); err != nil {
		t.Fatal(err)
	}
	before := storageSnapshot(t, s)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if after := storageSnapshot(t, s); !bytes.Equal(before, after) {
		t.Fatal("opening the current baseline rewrote stored data")
	}
	if err = s.initialize(); err != nil {
		t.Fatal(err)
	}
	if after := storageSnapshot(t, s); !bytes.Equal(before, after) {
		t.Fatal("repeated initialization rewrote stored data")
	}
}

func TestBaselineInitializationRollsBackAndCanRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "atomic.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err = s.initializeSchema(schemaSQL + "\nCREATE TABLE reports(duplicate TEXT);"); err == nil {
		t.Fatal("expected initialization failure")
	}
	var version, objects int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'").Scan(&objects); err != nil {
		t.Fatal(err)
	}
	if version != 0 || objects != 0 {
		t.Fatal("failed initialization left a partial schema", version, objects)
	}
	if err = s.initializeSchema(schemaSQL); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != schemaVersion {
		t.Fatal(version, err)
	}
	if err = s.initializeSchema(schemaSQL); err != nil {
		t.Fatal("baseline initialization was not repeatable", err)
	}
}

func TestUnsupportedSchemasAreRejectedWithoutChangingData(t *testing.T) {
	for _, version := range []int{0, 1, 3, 6, 10, schemaVersion + 1} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "unsupported.db")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec("CREATE TABLE sentinel(value TEXT NOT NULL); INSERT INTO sentinel(value) VALUES('keep me');"); err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(fmt.Sprintf("PRAGMA user_version=%d", version)); err != nil {
				t.Fatal(err)
			}
			db.Close()
			reopened, err := Open(path)
			if err == nil {
				reopened.Close()
				t.Fatal("unsupported schema opened")
			}
			want := "unsupported development"
			if version == 0 {
				want = "nonempty unversioned"
			}
			if version > schemaVersion {
				want = "newer than supported"
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatal(err)
			}
			db, err = sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var storedVersion, objects int
			var value string
			if err = db.QueryRow("PRAGMA user_version").Scan(&storedVersion); err != nil {
				t.Fatal(err)
			}
			if err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'").Scan(&objects); err != nil {
				t.Fatal(err)
			}
			if err = db.QueryRow("SELECT value FROM sentinel").Scan(&value); err != nil {
				t.Fatal(err)
			}
			if storedVersion != version || objects != 1 || value != "keep me" {
				t.Fatal("unsupported database changed", storedVersion, objects, value)
			}
		})
	}
}
