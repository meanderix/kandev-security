package reports

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

func writeFindings(ctx context.Context, tx *sql.Tx, id string, findings []Finding) error {
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO findings(report_id,ordinal,level,search_text,value_json,language,tool,rule_id,severity,severity_rank,security_score) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, f := range findings {
		value, err := json.Marshal(f)
		if err != nil {
			return err
		}
		search := findingSearchText(f)
		if _, err = stmt.ExecContext(ctx, id, f.Ordinal, f.Level, search, string(value), f.Language, f.Tool, f.RuleID, f.Severity, severityRank(f.Severity), f.SecuritySeverity); err != nil {
			return err
		}
	}
	return nil
}

func findingSearchText(f Finding) string {
	return strings.ToLower(f.Title + " " + f.Message + " " + f.RuleID + " " + f.URI)
}
