package reports

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	MaxDraftFindings     = 1000
	MaxDraftBytes        = 8 << 20
	MaxDraftFindingBytes = 12 << 10
	MaxWorkspaceDrafts   = 25
)

// These identities come from the verified MCP task context, never tool arguments.
// The SDK supplies task/session identity, but does not supply a human actor ID.
type DraftAuthority struct{ WorkspaceID, TaskID, SessionID, InvocationID string }
type AgentReportSpec struct {
	ClientReportID   string   `json:"client_report_id"`
	Title            string   `json:"title"`
	Instructions     string   `json:"instructions"`
	Scope            []string `json:"scope"`
	Repository       string   `json:"repository,omitempty"`
	Revision         string   `json:"revision,omitempty"`
	Branch           string   `json:"branch,omitempty"`
	AnalysisCategory string   `json:"analysis_category,omitempty"`
	AgentLabel       string   `json:"agent_label,omitempty"`
}
type AgentCompletion struct {
	Summary     string   `json:"summary"`
	Coverage    string   `json:"coverage"`
	Limitations []string `json:"limitations"`
}
type AgentFinding struct {
	FindingID   string   `json:"finding_id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation,omitempty"`
	RuleID      string   `json:"rule_id,omitempty"`
	CWEs        []string `json:"cwes,omitempty"`
	URI         string   `json:"uri,omitempty"`
	Line        int      `json:"line,omitempty"`
	Column      int      `json:"column,omitempty"`
	Snippet     string   `json:"snippet,omitempty"`
	Language    string   `json:"language,omitempty"`
}
type AgentSubmission struct {
	TaskID       string `json:"task_id"`
	SessionID    string `json:"session_id"`
	InvocationID string `json:"invocation_id"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}
type DraftFinding struct {
	Finding    AgentFinding    `json:"finding"`
	Submission AgentSubmission `json:"submission"`
}
type ReportDraft struct {
	ID              string           `json:"id"`
	Spec            AgentReportSpec  `json:"spec"`
	TaskID          string           `json:"task_id"`
	SessionID       string           `json:"session_id"`
	Status          string           `json:"status"`
	Revision        int              `json:"revision"`
	FindingCount    int              `json:"finding_count"`
	ByteCount       int              `json:"byte_count"`
	CreatedAt       string           `json:"created_at"`
	UpdatedAt       string           `json:"updated_at"`
	ReportID        string           `json:"report_id,omitempty"`
	ReportAvailable bool             `json:"report_available"`
	Completion      *AgentCompletion `json:"completion,omitempty"`
}
type DraftPage struct {
	Items      []ReportDraft `json:"items"`
	Total      int           `json:"total"`
	NextOffset int           `json:"next_offset"`
}
type DraftDetail struct {
	Draft      ReportDraft    `json:"draft"`
	Items      []DraftFinding `json:"items"`
	NextOffset int            `json:"next_offset"`
}
type PublishedDraft struct {
	DraftID string `json:"draft_id"`
	Report  Report `json:"report"`
}

func (a DraftAuthority) validate() error {
	for _, v := range []string{a.WorkspaceID, a.TaskID, a.SessionID, a.InvocationID} {
		if strings.TrimSpace(v) == "" || len(v) > 512 {
			return fmt.Errorf("%w: verified task identity is required", ErrInvalid)
		}
	}
	return nil
}
func validText(v string, min, max int) bool {
	return len(v) <= max && len(strings.TrimSpace(v)) >= min && !strings.ContainsRune(v, 0)
}
func validStrings(v []string, min, max, size int) bool {
	if len(v) < min || len(v) > max {
		return false
	}
	for _, s := range v {
		if !validText(s, 1, size) {
			return false
		}
	}
	return true
}
func validateSpec(spec *AgentReportSpec) error {
	if spec.AnalysisCategory == "" {
		spec.AnalysisCategory = "llm-security-audit"
	}
	if !validText(spec.ClientReportID, 1, 128) || !validText(spec.Title, 1, 200) || !validText(spec.Instructions, 1, 4096) || !validStrings(spec.Scope, 1, 32, 256) || !validText(spec.Repository, 0, 2048) || !validText(spec.Revision, 0, 256) || !validText(spec.Branch, 0, 256) || !validText(spec.AnalysisCategory, 1, 128) || !validText(spec.AgentLabel, 0, 128) {
		return fmt.Errorf("%w: invalid draft metadata or scope", ErrInvalid)
	}
	if spec.Repository != "" {
		u, err := url.Parse(spec.Repository)
		if err != nil || !u.IsAbs() {
			return fmt.Errorf("%w: repository must be an absolute URI, such as https:// or ssh://", ErrInvalid)
		}
		if u.User != nil {
			if _, hasPassword := u.User.Password(); hasPassword {
				return fmt.Errorf("%w: repository must not contain credentials", ErrInvalid)
			}
		}
	}
	if raw, _ := json.Marshal(spec); len(raw) > 12<<10 {
		return fmt.Errorf("%w: draft metadata exceeds 12 KiB", ErrInvalid)
	}
	return nil
}

var cwePattern = regexp.MustCompile(`^CWE-[1-9][0-9]{0,5}$`)

func validateAgentFinding(f AgentFinding) error {
	if !validText(f.FindingID, 1, 128) || !validText(f.Title, 1, 256) || !validText(f.Description, 1, 4096) || !validText(f.Evidence, 1, 4096) || !validText(f.Remediation, 0, 2048) || !validText(f.RuleID, 0, 128) || !validText(f.URI, 0, 2048) || !validText(f.Snippet, 0, 2048) || !validText(f.Language, 0, 128) || severityRank(f.Severity) == 0 || (f.Confidence != "low" && f.Confidence != "medium" && f.Confidence != "high") || len(f.CWEs) > 8 {
		return fmt.Errorf("%w: finding requires bounded title, description, evidence, severity and confidence", ErrInvalid)
	}
	for _, c := range f.CWEs {
		if !cwePattern.MatchString(c) {
			return fmt.Errorf("%w: invalid CWE identifier", ErrInvalid)
		}
	}
	if f.Line < 0 || f.Line > 10000000 || f.Column < 0 || f.Column > 1000000 || (f.Column > 0 && f.Line == 0) || (f.URI == "" && (f.Line > 0 || f.Column > 0 || f.Snippet != "")) {
		return fmt.Errorf("%w: invalid source location", ErrInvalid)
	}
	if f.URI != "" {
		u, err := url.Parse(strings.ReplaceAll(f.URI, `\`, "/"))
		if err != nil || u.User != nil {
			return fmt.Errorf("%w: invalid source URI", ErrInvalid)
		}
	}
	if raw, _ := json.Marshal(f); len(raw) > MaxDraftFindingBytes {
		return fmt.Errorf("%w: finding exceeds 12 KiB encoded", ErrInvalid)
	}
	return nil
}
func validateCompletion(c *AgentCompletion) error {
	if c.Limitations == nil {
		c.Limitations = []string{}
	}
	if !validText(c.Summary, 1, 2048) || !validText(c.Coverage, 1, 4096) || !validStrings(c.Limitations, 0, 16, 256) {
		return fmt.Errorf("%w: completion requires summary and actual coverage, with bounded limitations", ErrInvalid)
	}
	if raw, _ := json.Marshal(c); len(raw) > 8<<10 {
		return fmt.Errorf("%w: completion exceeds 8 KiB", ErrInvalid)
	}
	return nil
}

const draftColumns = "d.id,d.spec_json,d.task_id,d.session_id,d.status,d.revision,d.finding_count,d.byte_count,d.created_at,d.updated_at,d.report_id,d.completion_json,EXISTS(SELECT 1 FROM reports r WHERE r.id=d.report_id AND r.workspace_id=d.workspace_id)"

func scanDraft(row interface{ Scan(...any) error }) (ReportDraft, error) {
	var d ReportDraft
	var spec, completion string
	err := row.Scan(&d.ID, &spec, &d.TaskID, &d.SessionID, &d.Status, &d.Revision, &d.FindingCount, &d.ByteCount, &d.CreatedAt, &d.UpdatedAt, &d.ReportID, &completion, &d.ReportAvailable)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	if err = json.Unmarshal([]byte(spec), &d.Spec); err != nil {
		return d, err
	}
	if completion != "" {
		err = json.Unmarshal([]byte(completion), &d.Completion)
	}
	return d, err
}
func draftTx(ctx context.Context, tx *sql.Tx, a DraftAuthority, id string) (ReportDraft, error) {
	return scanDraft(tx.QueryRowContext(ctx, "SELECT "+draftColumns+" FROM report_drafts d WHERE d.workspace_id=? AND d.task_id=? AND d.id=?", a.WorkspaceID, a.TaskID, id))
}
func (s *Store) StartReport(ctx context.Context, a DraftAuthority, spec AgentReportSpec) (ReportDraft, error) {
	if err := a.validate(); err != nil {
		return ReportDraft{}, err
	}
	if err := validateSpec(&spec); err != nil {
		return ReportDraft{}, err
	}
	raw, _ := json.Marshal(spec)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ReportDraft{}, err
	}
	defer tx.Rollback()
	existing, err := scanDraft(tx.QueryRowContext(ctx, "SELECT "+draftColumns+" FROM report_drafts d WHERE d.workspace_id=? AND d.task_id=? AND d.client_id=?", a.WorkspaceID, a.TaskID, spec.ClientReportID))
	if err == nil {
		previous, _ := json.Marshal(existing.Spec)
		if string(previous) != string(raw) {
			return ReportDraft{}, fmt.Errorf("%w: client_report_id already identifies different metadata; choose a new ID", ErrConflict)
		}
		return existing, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return ReportDraft{}, err
	}
	var workspaceCount, total int
	if err = tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(CASE WHEN workspace_id=? THEN 1 ELSE 0 END),0) FROM report_drafts WHERE status='draft'", a.WorkspaceID).Scan(&total, &workspaceCount); err != nil {
		return ReportDraft{}, err
	}
	if workspaceCount >= MaxWorkspaceDrafts || total >= 100 {
		return ReportDraft{}, fmt.Errorf("%w: active report draft quota reached", ErrConflict)
	}
	id, now := rand.Text(), time.Now().UTC().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, "INSERT INTO report_drafts(id,workspace_id,task_id,client_id,session_id,spec_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", id, a.WorkspaceID, a.TaskID, spec.ClientReportID, a.SessionID, string(raw), now, now); err != nil {
		return ReportDraft{}, err
	}
	d, err := draftTx(ctx, tx, a, id)
	if err != nil {
		return d, err
	}
	return d, tx.Commit()
}
func (s *Store) Drafts(ctx context.Context, a DraftAuthority, status string, offset int) (DraftPage, error) {
	p := DraftPage{Items: []ReportDraft{}}
	if err := a.validate(); err != nil {
		return p, err
	}
	if offset < 0 || (status != "" && status != "draft" && status != "completed" && status != "cancelled") {
		return p, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	where := " FROM report_drafts d WHERE d.workspace_id=? AND d.task_id=?"
	args := []any{a.WorkspaceID, a.TaskID}
	if status != "" {
		where += " AND d.status=?"
		args = append(args, status)
	}
	if err = tx.QueryRowContext(ctx, "SELECT count(*)"+where, args...).Scan(&p.Total); err != nil {
		return p, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+draftColumns+where+" ORDER BY d.created_at DESC,d.id LIMIT ? OFFSET ?", append(args, PageSize, offset)...)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		d, err := scanDraft(rows)
		if err != nil {
			return p, err
		}
		p.Items = append(p.Items, d)
	}
	if offset+len(p.Items) < p.Total {
		p.NextOffset = offset + len(p.Items)
	}
	return p, rows.Err()
}
func (s *Store) Draft(ctx context.Context, a DraftAuthority, id string, offset int) (DraftDetail, error) {
	p := DraftDetail{Items: []DraftFinding{}}
	if err := a.validate(); err != nil {
		return p, err
	}
	if id == "" || offset < 0 {
		return p, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	p.Draft, err = draftTx(ctx, tx, a, id)
	if err != nil {
		return p, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT value_json,submission_json FROM draft_findings WHERE draft_id=? ORDER BY finding_id LIMIT ? OFFSET ?", id, PageSize, offset)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var f DraftFinding
		var v, submission string
		if err = rows.Scan(&v, &submission); err != nil {
			return p, err
		}
		if err = json.Unmarshal([]byte(v), &f.Finding); err != nil {
			return p, err
		}
		if err = json.Unmarshal([]byte(submission), &f.Submission); err != nil {
			return p, err
		}
		p.Items = append(p.Items, f)
	}
	if p.Draft.Status == "draft" && offset+len(p.Items) < p.Draft.FindingCount {
		p.NextOffset = offset + len(p.Items)
	}
	return p, rows.Err()
}
func (s *Store) SubmitFinding(ctx context.Context, a DraftAuthority, id string, expected int, f AgentFinding) (ReportDraft, error) {
	if err := a.validate(); err != nil {
		return ReportDraft{}, err
	}
	if id == "" || expected < 0 {
		return ReportDraft{}, ErrInvalid
	}
	if err := validateAgentFinding(f); err != nil {
		return ReportDraft{}, err
	}
	raw, _ := json.Marshal(f)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ReportDraft{}, err
	}
	defer tx.Rollback()
	d, err := draftTx(ctx, tx, a, id)
	if err != nil {
		return d, err
	}
	if d.Status != "draft" {
		return d, fmt.Errorf("%w: only drafts accept findings", ErrConflict)
	}
	var old, previousSubmission string
	err = tx.QueryRowContext(ctx, "SELECT value_json,submission_json FROM draft_findings WHERE draft_id=? AND finding_id=?", id, f.FindingID).Scan(&old, &previousSubmission)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return d, err
	}
	if old == string(raw) {
		return d, nil
	} // Uncertain-response retries never change dates or attribution.
	if d.Revision != expected {
		return d, fmt.Errorf("%w: draft revision changed; read the draft before retrying", ErrConflict)
	}
	count := d.FindingCount
	if old == "" {
		count++
	}
	size := d.ByteCount - len(old) + len(raw)
	if count > MaxDraftFindings || size > MaxDraftBytes {
		return d, fmt.Errorf("%w: report draft finding or byte limit reached", ErrConflict)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	submission := AgentSubmission{a.TaskID, a.SessionID, a.InvocationID, now, now}
	if previousSubmission != "" {
		var oldSubmission AgentSubmission
		if err = json.Unmarshal([]byte(previousSubmission), &oldSubmission); err != nil {
			return d, err
		}
		submission.CreatedAt = oldSubmission.CreatedAt
	}
	sr, _ := json.Marshal(submission)
	if _, err = tx.ExecContext(ctx, "INSERT INTO draft_findings(draft_id,finding_id,value_json,submission_json) VALUES(?,?,?,?) ON CONFLICT(draft_id,finding_id) DO UPDATE SET value_json=excluded.value_json,submission_json=excluded.submission_json", id, f.FindingID, string(raw), string(sr)); err != nil {
		return d, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE report_drafts SET revision=revision+1,finding_count=?,byte_count=?,updated_at=? WHERE id=?", count, size, now, id); err != nil {
		return d, err
	}
	d, err = draftTx(ctx, tx, a, id)
	if err != nil {
		return d, err
	}
	return d, tx.Commit()
}
func (s *Store) CancelReport(ctx context.Context, a DraftAuthority, id string, expected int) (ReportDraft, error) {
	if err := a.validate(); err != nil {
		return ReportDraft{}, err
	}
	if id == "" || expected < 0 {
		return ReportDraft{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ReportDraft{}, err
	}
	defer tx.Rollback()
	d, err := draftTx(ctx, tx, a, id)
	if err != nil {
		return d, err
	}
	if d.Status == "cancelled" {
		return d, nil
	}
	if d.Status != "draft" || d.Revision != expected {
		return d, fmt.Errorf("%w: draft state or revision changed", ErrConflict)
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM draft_findings WHERE draft_id=?", id); err != nil {
		return d, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE report_drafts SET status='cancelled',revision=revision+1,finding_count=0,byte_count=0,updated_at=? WHERE id=?", time.Now().UTC().Format(time.RFC3339Nano), id); err != nil {
		return d, err
	}
	d, err = draftTx(ctx, tx, a, id)
	if err != nil {
		return d, err
	}
	return d, tx.Commit()
}
