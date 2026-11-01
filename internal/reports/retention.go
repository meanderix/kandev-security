package reports

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type RetentionPolicy struct {
	MaxReports int `json:"max_reports"`
	MaxAgeDays int `json:"max_age_days"`
}
type ScannerRetention struct {
	Tool string `json:"tool"`
	RetentionPolicy
}
type RetentionConfig struct {
	Enabled   bool               `json:"enabled"`
	Default   RetentionPolicy    `json:"default"`
	Overrides []ScannerRetention `json:"overrides"`
}
type RetentionSettings struct {
	Config          RetentionConfig `json:"config"`
	Revision        int             `json:"revision"`
	UpdatedAt       string          `json:"updated_at"`
	UpdatedBy       string          `json:"updated_by"`
	LastRunAt       string          `json:"last_run_at"`
	LastPurgedCount int             `json:"last_purged_count"`
	Scanners        []string        `json:"scanners"`
}
type RetentionCandidate struct {
	Report Report `json:"report"`
	Reason string `json:"reason"`
}
type RetentionPlan struct {
	EligibleReports int                  `json:"eligible_reports"`
	EligibleBytes   int64                `json:"eligible_bytes"`
	PinnedReports   int                  `json:"pinned_reports"`
	Candidates      []RetentionCandidate `json:"candidates"`
	HasMore         bool                 `json:"has_more"`
}
type RetentionResult struct {
	PurgedCount int   `json:"purged_count"`
	PurgedBytes int64 `json:"purged_bytes"`
}
type RetentionSaveResult struct {
	Settings RetentionSettings `json:"settings"`
	RetentionResult
}
type ReportPinResult struct {
	RetentionResult
	Pinned   bool `json:"pinned"`
	Retained bool `json:"retained"`
}
type PurgedReportPage struct {
	Items      []Report `json:"items"`
	NextOffset int      `json:"next_offset"`
}

func validateRetention(c RetentionConfig) error {
	if raw, _ := json.Marshal(c); len(raw) > 60<<10 {
		return fmt.Errorf("%w: retention configuration exceeds 60 KiB", ErrInvalid)
	}
	valid := func(p RetentionPolicy) bool {
		return p.MaxReports >= 0 && p.MaxReports <= 100000 && p.MaxAgeDays >= 0 && p.MaxAgeDays <= 36500
	}
	if !valid(c.Default) || len(c.Overrides) > 100 {
		return fmt.Errorf("%w: retention allows 0–100000 reports, 0–36500 days, and up to 100 scanner overrides", ErrInvalid)
	}
	seen := map[string]bool{}
	for _, o := range c.Overrides {
		if !validText(o.Tool, 1, 256) || strings.TrimSpace(o.Tool) != o.Tool || seen[o.Tool] || !valid(o.RetentionPolicy) {
			return fmt.Errorf("%w: scanner overrides must have unique exact scanner names and valid limits", ErrInvalid)
		}
		seen[o.Tool] = true
	}
	return nil
}

func writeReportScanners(ctx context.Context, tx *sql.Tx, id string, runs []Run) error {
	tools := map[string]bool{}
	for _, r := range runs {
		tools[r.Tool] = true
	}
	if len(tools) == 0 {
		tools[""] = true
	}
	for tool := range tools {
		if _, err := tx.ExecContext(ctx, "INSERT INTO report_scanners(report_id,tool) VALUES(?,?)", id, tool); err != nil {
			return err
		}
	}
	return nil
}
func retentionSettingsTx(ctx context.Context, tx *sql.Tx, workspace string) (RetentionSettings, error) {
	d := RetentionSettings{Config: RetentionConfig{Overrides: []ScannerRetention{}}, Scanners: []string{}}
	var raw string
	err := tx.QueryRowContext(ctx, "SELECT revision,config_json,updated_at,updated_by,last_run_at,last_purged_count FROM retention_settings WHERE workspace_id=?", workspace).Scan(&d.Revision, &raw, &d.UpdatedAt, &d.UpdatedBy, &d.LastRunAt, &d.LastPurgedCount)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	} else if err == nil {
		err = json.Unmarshal([]byte(raw), &d.Config)
	}
	return d, err
}
func (s *Store) RetentionSettings(ctx context.Context, workspace string) (RetentionSettings, error) {
	if err := validScope(workspace); err != nil {
		return RetentionSettings{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return RetentionSettings{}, err
	}
	defer tx.Rollback()
	d, err := retentionSettingsTx(ctx, tx, workspace)
	if err != nil {
		return d, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT DISTINCT s.tool FROM report_scanners s JOIN reports r ON r.id=s.report_id WHERE r.workspace_id=? AND s.tool<>'' ORDER BY s.tool LIMIT 101", workspace)
	if err != nil {
		return d, err
	}
	defer rows.Close()
	for rows.Next() {
		var tool string
		if err = rows.Scan(&tool); err != nil {
			return d, err
		}
		d.Scanners = append(d.Scanners, tool)
	}
	return d, rows.Err()
}

type retentionReport struct {
	report  Report
	created time.Time
	tools   []string
}

func retentionCandidatesTx(ctx context.Context, tx *sql.Tx, workspace string, c RetentionConfig, now time.Time) ([]RetentionCandidate, int, error) {
	if !c.Enabled {
		var pinned int
		err := tx.QueryRowContext(ctx, "SELECT count(*) FROM report_pins p JOIN reports r ON r.id=p.report_id WHERE r.workspace_id=?", workspace).Scan(&pinned)
		return nil, pinned, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+reportColumns+reportStateColumns+" FROM reports WHERE workspace_id=?", workspace)
	if err != nil {
		return nil, 0, err
	}
	var all []*retentionReport
	byID := map[string]*retentionReport{}
	pinned := 0
	for rows.Next() {
		r, err := scanPinnedReport(rows)
		if err != nil {
			rows.Close()
			return nil, 0, err
		}
		if r.Pinned {
			pinned++
			continue
		}
		created, err := time.Parse(time.RFC3339Nano, r.CreatedAt)
		if err != nil {
			rows.Close()
			return nil, 0, err
		}
		item := &retentionReport{report: r, created: created}
		all = append(all, item)
		byID[r.ID] = item
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, 0, err
	}
	rows, err = tx.QueryContext(ctx, "SELECT s.report_id,s.tool FROM report_scanners s JOIN reports r ON r.id=s.report_id WHERE r.workspace_id=? ORDER BY s.tool", workspace)
	if err != nil {
		return nil, 0, err
	}
	for rows.Next() {
		var id, tool string
		if err = rows.Scan(&id, &tool); err != nil {
			rows.Close()
			return nil, 0, err
		}
		if r := byID[id]; r != nil {
			r.tools = append(r.tools, tool)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, 0, err
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].created.Equal(all[j].created) {
			return all[i].report.ID < all[j].report.ID
		}
		return all[i].created.After(all[j].created)
	})
	policies := map[string]RetentionPolicy{}
	for _, o := range c.Overrides {
		policies[o.Tool] = o.RetentionPolicy
	}
	ranks := map[string]int{}
	var out []RetentionCandidate
	for _, r := range all {
		if len(r.tools) == 0 {
			return nil, 0, fmt.Errorf("report %s has no scanner retention index", r.report.ID)
		}
		eligible := true
		var reasons []string
		for _, tool := range r.tools {
			ranks[tool]++
			p, ok := policies[tool]
			if !ok {
				p = c.Default
			}
			age := p.MaxAgeDays > 0 && r.created.Before(now.AddDate(0, 0, -p.MaxAgeDays))
			count := p.MaxReports > 0 && ranks[tool] > p.MaxReports
			if !age && !count {
				eligible = false
			}
			if age {
				reasons = append(reasons, tool+": max age")
			}
			if count {
				reasons = append(reasons, tool+": max reports")
			}
		}
		if eligible {
			r.report.Scanners = r.tools
			out = append(out, RetentionCandidate{r.report, clipTaskText(strings.Join(reasons, "; "), 2048)})
		}
	}
	return out, pinned, nil
}
func summarizeRetention(items []RetentionCandidate, pinned int) RetentionPlan {
	p := RetentionPlan{EligibleReports: len(items), PinnedReports: pinned, Candidates: []RetentionCandidate{}}
	for _, item := range items {
		p.EligibleBytes += int64(item.Report.Size)
	}
	p.Candidates = items
	if len(items) > PageSize {
		p.Candidates = items[:PageSize]
		p.HasMore = true
	}
	if p.Candidates == nil {
		p.Candidates = []RetentionCandidate{}
	}
	for len(p.Candidates) > 1 {
		raw, _ := json.Marshal(p)
		if len(raw) <= 700<<10 {
			break
		}
		p.Candidates = p.Candidates[:len(p.Candidates)/2]
		p.HasMore = true
	}
	return p
}
func (s *Store) PreviewRetention(ctx context.Context, workspace string, c RetentionConfig) (RetentionPlan, error) {
	if err := validScope(workspace); err != nil {
		return RetentionPlan{}, err
	}
	if err := validateRetention(c); err != nil {
		return RetentionPlan{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return RetentionPlan{}, err
	}
	defer tx.Rollback()
	items, pinned, err := retentionCandidatesTx(ctx, tx, workspace, c, time.Now().UTC())
	return summarizeRetention(items, pinned), err
}
func purgeReportTx(ctx context.Context, tx *sql.Tx, r Report, reason, actor string, now time.Time) error {
	r.PurgedAt = now.UTC().Format(time.RFC3339Nano)
	r.PurgeReason = reason
	r.PurgedBy = actor
	r.Pinned = false
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO purged_reports(id,workspace_id,digest,metadata_json,purged_at,reason,actor_id) VALUES(?,?,?,?,?,?,?)", r.ID, r.WorkspaceID, r.Digest, string(raw), r.PurgedAt, reason, actor); err != nil {
		return err
	}
	// Deliberately exclude result messages, snippets, HTTP bodies and secret values.
	if _, err = tx.ExecContext(ctx, `INSERT INTO issue_purged_occurrences(issue_id,report_id,ordinal,value_json)
 SELECT issue_id,report_id,ordinal,json_object('ordinal',ordinal,'run_index',json_extract(value_json,'$.run_index'),'tool',tool,'rule_id',rule_id,'severity',severity,'uri',json_extract(value_json,'$.uri'),'line',json_extract(value_json,'$.line'),'column',json_extract(value_json,'$.column')) FROM findings WHERE report_id=? AND issue_id IS NOT NULL`, r.ID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM reports WHERE workspace_id=? AND id=?", r.WorkspaceID, r.ID)
	return err
}
func enforceRetentionTx(ctx context.Context, tx *sql.Tx, workspace, actor string) (RetentionResult, error) {
	var result RetentionResult
	d, err := retentionSettingsTx(ctx, tx, workspace)
	if err != nil || !d.Config.Enabled {
		return result, err
	}
	now := time.Now().UTC()
	items, _, err := retentionCandidatesTx(ctx, tx, workspace, d.Config, now)
	if err != nil {
		return result, err
	}
	for _, item := range items {
		if err = purgeReportTx(ctx, tx, item.Report, item.Reason, actor, now); err != nil {
			return result, err
		}
		result.PurgedCount++
		result.PurgedBytes += int64(item.Report.Size)
	}
	_, err = tx.ExecContext(ctx, "UPDATE retention_settings SET last_run_at=?,last_purged_count=? WHERE workspace_id=?", now.Format(time.RFC3339Nano), result.PurgedCount, workspace)
	return result, err
}
func (s *Store) SaveRetention(ctx context.Context, workspace, actor string, expected int, c RetentionConfig) (RetentionSaveResult, error) {
	var result RetentionSaveResult
	if err := validScope(workspace); err != nil {
		return result, err
	}
	if err := validateRetention(c); err != nil {
		return result, err
	}
	if !validText(actor, 1, 512) || expected < 0 {
		return result, ErrInvalid
	}
	if c.Overrides == nil {
		c.Overrides = []ScannerRetention{}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	previous, err := retentionSettingsTx(ctx, tx, workspace)
	if err != nil {
		return result, err
	}
	if previous.Revision != expected {
		return result, fmt.Errorf("%w: retention settings changed; reload before saving", ErrConflict)
	}
	raw, _ := json.Marshal(c)
	_, err = tx.ExecContext(ctx, "INSERT INTO retention_settings(workspace_id,revision,config_json,updated_at,updated_by) VALUES(?,?,?,?,?) ON CONFLICT(workspace_id) DO UPDATE SET revision=excluded.revision,config_json=excluded.config_json,updated_at=excluded.updated_at,updated_by=excluded.updated_by", workspace, expected+1, string(raw), time.Now().UTC().Format(time.RFC3339Nano), actor)
	if err != nil {
		return result, err
	}
	result.RetentionResult, err = enforceRetentionTx(ctx, tx, workspace, actor)
	if err != nil {
		return result, err
	}
	result.Settings, err = retentionSettingsTx(ctx, tx, workspace)
	if err != nil {
		return result, err
	}
	return result, tx.Commit()
}
func (s *Store) RunRetention(ctx context.Context, workspace, actor string) (RetentionResult, error) {
	if err := validScope(workspace); err != nil {
		return RetentionResult{}, err
	}
	if !validText(actor, 1, 512) {
		return RetentionResult{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RetentionResult{}, err
	}
	defer tx.Rollback()
	r, err := enforceRetentionTx(ctx, tx, workspace, actor)
	if err != nil {
		return r, err
	}
	return r, tx.Commit()
}
func (s *Store) RunAllRetention(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT workspace_id FROM retention_settings WHERE json_extract(config_json,'$.enabled')=1")
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var failures []error
	for _, id := range ids {
		if _, err := s.RunRetention(ctx, id, "system:retention"); err != nil {
			failures = append(failures, fmt.Errorf("workspace %s: %w", id, err))
		}
	}
	return errors.Join(failures...)
}
func purgedReportTx(ctx context.Context, tx *sql.Tx, workspace, id string) (Report, error) {
	var r Report
	var raw string
	err := tx.QueryRowContext(ctx, "SELECT metadata_json FROM purged_reports WHERE workspace_id=? AND id=?", workspace, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err == nil {
		err = json.Unmarshal([]byte(raw), &r)
	}
	return r, err
}
func (s *Store) PurgedReports(ctx context.Context, workspace string, offset int) (PurgedReportPage, error) {
	p := PurgedReportPage{Items: []Report{}}
	if err := validScope(workspace); err != nil {
		return p, err
	}
	if offset < 0 {
		return p, ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, "SELECT metadata_json FROM purged_reports WHERE workspace_id=? ORDER BY purged_at DESC,id LIMIT ? OFFSET ?", workspace, PageSize+1, offset)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		var r Report
		if err = rows.Scan(&raw); err != nil {
			return p, err
		}
		if err = json.Unmarshal([]byte(raw), &r); err != nil {
			return p, err
		}
		p.Items = append(p.Items, r)
	}
	if len(p.Items) > PageSize {
		p.Items = p.Items[:PageSize]
		p.NextOffset = offset + PageSize
	}
	for len(p.Items) > 1 {
		raw, _ := json.Marshal(p)
		if len(raw) <= 800<<10 {
			break
		}
		p.Items = p.Items[:len(p.Items)/2]
		p.NextOffset = offset + len(p.Items)
	}
	return p, rows.Err()
}
func (s *Store) SetReportPinned(ctx context.Context, workspace, actor, id string, pinned bool) (ReportPinResult, error) {
	if err := validScope(workspace); err != nil {
		return ReportPinResult{}, err
	}
	if id == "" || !validText(actor, 1, 512) {
		return ReportPinResult{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ReportPinResult{}, err
	}
	defer tx.Rollback()
	var found string
	if err = tx.QueryRowContext(ctx, "SELECT id FROM reports WHERE workspace_id=? AND id=?", workspace, id).Scan(&found); errors.Is(err, sql.ErrNoRows) {
		return ReportPinResult{}, ErrNotFound
	} else if err != nil {
		return ReportPinResult{}, err
	}
	if pinned {
		_, err = tx.ExecContext(ctx, "INSERT INTO report_pins(report_id,created_at,created_by) VALUES(?,?,?) ON CONFLICT(report_id) DO NOTHING", id, time.Now().UTC().Format(time.RFC3339Nano), actor)
	} else {
		_, err = tx.ExecContext(ctx, "DELETE FROM report_pins WHERE report_id=?", id)
	}
	if err != nil {
		return ReportPinResult{}, err
	}
	r, err := enforceRetentionTx(ctx, tx, workspace, actor)
	if err != nil {
		return ReportPinResult{}, err
	}
	result := ReportPinResult{RetentionResult: r, Pinned: pinned}
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM reports WHERE workspace_id=? AND id=?)", workspace, id).Scan(&result.Retained); err != nil {
		return result, err
	}
	return result, tx.Commit()
}

func reportDestinations(r *Report) []any {
	return []any{&r.ID, &r.WorkspaceID, &r.Filename, &r.Digest, &r.ActorID, &r.CreatedAt, &r.FindingCount, &r.Size, &r.Tools, &r.UpdatedAt}
}
func scanPinnedReport(row interface{ Scan(...any) error }) (Report, error) {
	var r Report
	err := row.Scan(append(reportDestinations(&r), &r.Pinned, &r.ArchivedAt, &r.ArchivedBy)...)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return r, err
}
func reportPinnedTx(ctx context.Context, tx *sql.Tx, id string) (bool, error) {
	var pinned bool
	err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM report_pins WHERE report_id=?)", id).Scan(&pinned)
	return pinned, err
}
func finishRetentionImport(ctx context.Context, tx *sql.Tx, r Report) (Report, error) {
	if _, err := enforceRetentionTx(ctx, tx, r.WorkspaceID, "system:retention"); err != nil {
		return r, err
	}
	purged, err := purgedReportTx(ctx, tx, r.WorkspaceID, r.ID)
	if err == nil {
		return purged, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return r, err
	}
	return reportStateAfterImport(ctx, tx, r)
}
