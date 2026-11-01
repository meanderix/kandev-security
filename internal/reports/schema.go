package reports

import (
	_ "embed"
	"fmt"
)

// Keep the current storage identifier so existing baseline databases remain
// readable. Historical unpublished formats have no upgrade path.
const schemaVersion = 11

//go:embed schema.sql
var schemaSQL string

func (s *Store) initialize() error {
	if _, err := s.db.Exec("PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;"); err != nil {
		return err
	}
	if err := s.initializeSchema(schemaSQL); err != nil {
		return err
	}
	_, err := s.db.Exec("DELETE FROM uploads WHERE created_at < ?", expiry())
	return err
}

func (s *Store) initializeSchema(ddl string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err = tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version == schemaVersion {
		return tx.Commit()
	}
	if version > schemaVersion {
		return fmt.Errorf("database schema %d is newer than supported schema %d", version, schemaVersion)
	}
	if version != 0 {
		return fmt.Errorf("unsupported development database schema %d; expected %d; historical upgrade routines are not available", version, schemaVersion)
	}
	var objects int
	if err = tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' AND type IN ('table','view')").Scan(&objects); err != nil {
		return err
	}
	if objects != 0 {
		return fmt.Errorf("refusing to initialize a nonempty unversioned database")
	}
	if _, err = tx.Exec(ddl); err != nil {
		return err
	}
	if _, err = tx.Exec(fmt.Sprintf("PRAGMA user_version=%d", schemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
}
