package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// AgentAudit records authenticated task/session identities. Repository, model
// labels, audit conclusions and evidence are agent claims, never verified fixes.
type AgentAudit struct {
	Origin                 string          `json:"origin"`
	DraftID                string          `json:"draft_id"`
	TaskID                 string          `json:"task_id"`
	StartedSessionID       string          `json:"started_session_id"`
	CompletedSessionID     string          `json:"completed_session_id"`
	CompletionInvocationID string          `json:"completion_invocation_id"`
	StartedAt              string          `json:"started_at"`
	CompletedAt            string          `json:"completed_at"`
	Spec                   AgentReportSpec `json:"spec"`
	Completion             AgentCompletion `json:"completion"`
}

func (s *Store) CompleteReport(ctx context.Context, a DraftAuthority, id string, expected int, completion AgentCompletion) (PublishedDraft, error) {
	result := PublishedDraft{DraftID: id}
	if err := a.validate(); err != nil {
		return result, err
	}
	if id == "" || expected < 0 {
		return result, ErrInvalid
	}
	if err := validateCompletion(&completion); err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	d, err := draftTx(ctx, tx, a, id)
	if err != nil {
		return result, err
	}
	encodedCompletion, _ := json.Marshal(completion)
	if d.Status == "completed" {
		previous, _ := json.Marshal(d.Completion)
		if expected != d.Revision-1 || string(previous) != string(encodedCompletion) {
			return result, fmt.Errorf("%w: published report is immutable; use its original completion receipt or start another report", ErrConflict)
		}
		if !d.ReportAvailable {
			archived, archiveErr := purgedReportTx(ctx, tx, a.WorkspaceID, d.ReportID)
			if archiveErr == nil {
				result.Report = archived
				return result, nil
			}
			if !errors.Is(archiveErr, ErrNotFound) {
				return result, archiveErr
			}
			return result, fmt.Errorf("%w: the published report was deleted; start a new draft", ErrConflict)
		}
		result.Report, err = scanPinnedReport(tx.QueryRowContext(ctx, "SELECT "+reportColumns+reportStateColumns+" FROM reports WHERE workspace_id=? AND id=?", a.WorkspaceID, d.ReportID))
		return result, err
	}
	if d.Status != "draft" || d.Revision != expected {
		return result, fmt.Errorf("%w: draft state or revision changed; review before completing", ErrConflict)
	}
	rows, err := tx.QueryContext(ctx, "SELECT value_json,submission_json FROM draft_findings WHERE draft_id=? ORDER BY finding_id", id)
	if err != nil {
		return result, err
	}
	entries := []DraftFinding{}
	for rows.Next() {
		var e DraftFinding
		var finding, submission string
		if err = rows.Scan(&finding, &submission); err != nil {
			rows.Close()
			return result, err
		}
		if err = json.Unmarshal([]byte(finding), &e.Finding); err != nil {
			rows.Close()
			return result, err
		}
		if err = json.Unmarshal([]byte(submission), &e.Submission); err != nil {
			rows.Close()
			return result, err
		}
		entries = append(entries, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	if len(entries) != d.FindingCount {
		return result, fmt.Errorf("stored draft finding count mismatch")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	audit := AgentAudit{Origin: "llm", DraftID: d.ID, TaskID: a.TaskID, StartedSessionID: d.SessionID, CompletedSessionID: a.SessionID, CompletionInvocationID: a.InvocationID, StartedAt: d.CreatedAt, CompletedAt: now, Spec: d.Spec, Completion: completion}
	raw, err := generateAgentSARIF(audit, entries)
	if err != nil {
		return result, err
	}
	runs, findings, err := parseSARIF(raw)
	if err != nil {
		return result, err
	}
	result.Report, _, err = importReportTx(ctx, tx, a.WorkspaceID, "task:"+a.TaskID, "llm-audit-"+d.ID+".sarif", raw, runs, findings)
	if err != nil {
		return result, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE report_drafts SET status='completed',revision=revision+1,report_id=?,completion_json=?,updated_at=? WHERE id=?", result.Report.ID, string(encodedCompletion), now, id); err != nil {
		return result, err
	}
	// Preserve submitted evidence in the immutable generated SARIF, without a
	// second draft copy surviving deletion of the published report.
	if _, err = tx.ExecContext(ctx, "DELETE FROM draft_findings WHERE draft_id=?", id); err != nil {
		return result, err
	}
	return result, tx.Commit()
}

func generateAgentSARIF(audit AgentAudit, entries []DraftFinding) ([]byte, error) {
	rules := []any{}
	results := []any{}
	seen := map[string]bool{}
	for _, entry := range entries {
		f := entry.Finding
		if err := validateAgentFinding(f); err != nil {
			return nil, err
		}
		if f.RuleID != "" && !seen[f.RuleID] {
			rules = append(rules, map[string]any{"id": f.RuleID})
			seen[f.RuleID] = true
		}
		level := map[string]string{"critical": "error", "high": "error", "medium": "warning", "low": "note", "informational": "none"}[f.Severity]
		r := map[string]any{"level": level, "message": map[string]any{"text": f.Title + "\n\n" + f.Description}, "properties": map[string]any{"kandevSecurity": entry}}
		if f.RuleID != "" {
			r["ruleId"] = f.RuleID
		}
		if f.URI != "" {
			physical := map[string]any{"artifactLocation": map[string]any{"uri": agentSourceURI(f.URI)}}
			region := map[string]any{}
			if f.Line > 0 {
				region["startLine"] = f.Line
			}
			if f.Column > 0 {
				region["startColumn"] = f.Column
			}
			if f.Snippet != "" {
				region["snippet"] = map[string]any{"text": f.Snippet}
			}
			if len(region) > 0 {
				physical["region"] = region
			}
			r["locations"] = []any{map[string]any{"physicalLocation": physical}}
		}
		results = append(results, r)
	}
	run := map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "Kandev LLM audit", "version": "1", "rules": rules}}, "automationDetails": map[string]any{"id": audit.Spec.AnalysisCategory}, "properties": map[string]any{"kandevSecurity": audit}, "results": results}
	if audit.Spec.Repository != "" {
		run["versionControlProvenance"] = []any{map[string]any{"repositoryUri": audit.Spec.Repository, "revisionId": audit.Spec.Revision, "branch": audit.Spec.Branch}}
	}
	raw, err := json.Marshal(map[string]any{"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json", "version": "2.1.0", "runs": []any{run}})
	if err == nil && len(raw) > MaxReportBytes {
		return nil, fmt.Errorf("%w: generated SARIF exceeds 20 MiB", ErrInvalid)
	}
	return raw, err
}

func readAgentAudit(raw json.RawMessage) *AgentAudit {
	if len(raw) == 0 || len(raw) > 28<<10 {
		return nil
	}
	var a AgentAudit
	if json.Unmarshal(raw, &a) != nil || a.Origin != "llm" || validateSpec(&a.Spec) != nil || validateCompletion(&a.Completion) != nil {
		return nil
	}
	return &a
}
func readAgentFinding(raw json.RawMessage) *DraftFinding {
	if len(raw) == 0 || len(raw) > 16<<10 {
		return nil
	}
	var e DraftFinding
	if json.Unmarshal(raw, &e) != nil || validateAgentFinding(e.Finding) != nil {
		return nil
	}
	return &e
}

func agentSourceURI(value string) string {
	value = strings.ReplaceAll(value, `\`, "/")
	if len(value) > 2 && value[1] == ':' && value[2] == '/' {
		return (&url.URL{Scheme: "file", Path: "/" + value}).String()
	}
	if u, err := url.Parse(value); err == nil {
		return u.String()
	}
	return value
}
