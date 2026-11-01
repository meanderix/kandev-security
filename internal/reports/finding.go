package reports

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

// FindingDetail is fetched separately so rule guidance never enlarges list pages.
// It reads the retained SARIF, including for reports imported before this feature.
type FindingDetail struct {
	Context             FindingContext          `json:"context"`
	Locations           []FindingLocation       `json:"locations,omitempty"`
	RelatedLocations    []FindingLocation       `json:"related_locations,omitempty"`
	Evidence            []FindingEvidence       `json:"evidence,omitempty"`
	HTTP                *HTTPExchange           `json:"http,omitempty"`
	Classifications     []FindingClassification `json:"classifications,omitempty"`
	References          []FindingReference      `json:"references,omitempty"`
	Fingerprints        map[string]string       `json:"fingerprints,omitempty"`
	PartialFingerprints map[string]string       `json:"partial_fingerprints,omitempty"`
	NormalizationNotes  []string                `json:"normalization_notes,omitempty"`
	AgentFinding        *DraftFinding           `json:"agent_finding,omitempty"`
	Markup              *FindingMarkup          `json:"markup,omitempty"`
	Finding             Finding                 `json:"finding"`
	Report              Report                  `json:"report"`
	Run                 Run                     `json:"run"`
	Title               string                  `json:"title"`
	Description         string                  `json:"description"`
	Guidance            string                  `json:"guidance"`
	Fixes               []string                `json:"fixes"`
	Truncated           bool                    `json:"truncated"`
}

func (s *Store) Finding(ctx context.Context, workspace, id string, ordinal int) (FindingDetail, error) {
	d := FindingDetail{Fixes: []string{}}
	if err := validScope(workspace); err != nil {
		return d, err
	}
	if ordinal < 0 || id == "" {
		return d, ErrInvalid
	}
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
	var value, metadata string
	var original []byte
	err = tx.QueryRowContext(ctx, "SELECT value_json,coalesce(issue_id,'') FROM findings WHERE report_id=? AND ordinal=?", id, ordinal).Scan(&value, &d.Finding.IssueID)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	if err = json.Unmarshal([]byte(value), &d.Finding); err != nil {
		return d, err
	}
	if err = tx.QueryRowContext(ctx, "SELECT original,runs_json FROM reports WHERE workspace_id=? AND id=?", workspace, id).Scan(&original, &metadata); err != nil {
		return d, err
	}
	if err = tx.Commit(); err != nil {
		return d, err
	}
	var runs []Run
	if err = json.Unmarshal([]byte(metadata), &runs); err != nil {
		return d, err
	}
	if d.Finding.RunIndex < 0 || d.Finding.RunIndex >= len(runs) {
		return d, fmt.Errorf("stored finding has invalid run index")
	}
	d.Run = runs[d.Finding.RunIndex]
	if err = enrichFinding(&d, original); err != nil {
		return d, err
	}
	return d, ctx.Err()
}

func enrichFinding(d *FindingDetail, original []byte) error {
	var doc struct {
		Runs []json.RawMessage `json:"runs"`
	}
	if err := json.Unmarshal(original, &doc); err != nil {
		return err
	}
	var run struct {
		Tool struct {
			Driver struct {
				Rules []json.RawMessage `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []json.RawMessage `json:"results"`
	}
	budget := &markdownBudget{remaining: 2048}
	markup := &FindingMarkup{}
	ordinal := d.Finding.Ordinal
	for i := 0; i <= d.Finding.RunIndex && i < len(doc.Runs); i++ {
		if err := json.Unmarshal(doc.Runs[i], &run); err != nil {
			return err
		}
		if i < d.Finding.RunIndex {
			ordinal -= len(run.Results)
			run.Results = nil
			run.Tool.Driver.Rules = nil
		}
	}
	if ordinal < 0 || ordinal >= len(run.Results) {
		return fmt.Errorf("stored finding has invalid result ordinal")
	}
	var result struct {
		Properties map[string]json.RawMessage `json:"properties"`
		RuleIndex  *int                       `json:"ruleIndex"`
		Fixes      []json.RawMessage          `json:"fixes"`
	}
	if err := json.Unmarshal(run.Results[ordinal], &result); err != nil {
		return err
	}
	var selected json.RawMessage
	if result.RuleIndex != nil && *result.RuleIndex >= 0 {
		if *result.RuleIndex >= len(run.Tool.Driver.Rules) {
			return fmt.Errorf("stored finding has invalid rule index")
		}
		selected = run.Tool.Driver.Rules[*result.RuleIndex]
	} else {
		for _, raw := range run.Tool.Driver.Rules {
			var rule struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(raw, &rule); err != nil {
				return err
			}
			if rule.ID == d.Finding.RuleID {
				selected = raw
			}
		}
	}
	if selected != nil {
		var rule struct {
			Name  string       `json:"name"`
			Short sarifMessage `json:"shortDescription"`
			Full  sarifMessage `json:"fullDescription"`
			Help  sarifMessage `json:"help"`
		}
		if err := json.Unmarshal(selected, &rule); err != nil {
			return err
		}
		d.Title = messageText(rule.Short)
		if d.Title == "" {
			d.Title = rule.Name
		}
		d.Title = boundedDetail(d.Title, 1024, &d.Truncated)
		d.Description = boundedDetail(messageText(rule.Full), 16<<10, &d.Truncated)
		markup.Description = markdownDocument(boundedDetail(rule.Full.Markdown, 16<<10, &d.Truncated), budget)
		d.Guidance = boundedDetail(messageText(rule.Help), 32<<10, &d.Truncated)
		markup.Guidance = markdownDocument(boundedDetail(rule.Help.Markdown, 32<<10, &d.Truncated), budget)
	}
	if d.Title == "" {
		d.Title = d.Finding.Title
	}
	if d.Run.AgentAudit != nil {
		if entry := readAgentFinding(result.Properties["kandevSecurity"]); entry != nil {
			d.AgentFinding = entry
			d.Title = entry.Finding.Title
			d.Description = entry.Finding.Description
			d.Guidance = entry.Finding.Remediation
			markup.Description = markdownDocument(d.Description, budget)
			markup.Guidance = markdownDocument(d.Guidance, budget)
		}
	}
	for i, raw := range result.Fixes {
		if i >= 8 {
			d.Truncated = true
			break
		}
		var fix struct {
			Description sarifMessage `json:"description"`
		}
		if err := json.Unmarshal(raw, &fix); err != nil {
			return err
		}
		if text := messageText(fix.Description); text != "" {
			d.Fixes = append(d.Fixes, boundedDetail(text, 2048, &d.Truncated))
			markup.Fixes = append(markup.Fixes, markdownDocument(boundedDetail(fix.Description.Markdown, 2048, &d.Truncated), budget))
		}
	}
	if err := enrichCommonFinding(d, doc.Runs[d.Finding.RunIndex], run.Results[ordinal], selected); err != nil {
		d.note("Additional SARIF evidence could not be normalized; inspect the original report for the supplied fields.")
		d.Truncated = true
	}
	if budget.exceeded {
		d.Truncated = true
	} else if len(markup.Description) > 0 || len(markup.Guidance) > 0 || len(markup.Fixes) > 0 {
		d.Markup = markup
	}
	// Preserve the host response cap even for unusually verbose Markdown trees.
	if encoded, _ := json.Marshal(d); len(encoded) > 900<<10 {
		d.Markup = nil
		d.Truncated = true
	}
	return nil
}
func messageText(message sarifMessage) string {
	if message.Text != "" {
		return message.Text
	}
	return message.Markdown
}
func boundedDetail(text string, limit int, truncated *bool) string {
	if len(text) <= limit {
		return text
	}
	*truncated = true
	text = text[:limit]
	for !utf8.ValidString(text) {
		text = text[:len(text)-1]
	}
	return text
}
