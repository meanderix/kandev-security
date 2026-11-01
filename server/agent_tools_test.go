package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/kandev/kandev/pkg/pluginsdk"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
	"kandev-security/internal/reports"
)

func auditRequest(name string, args map[string]any) *pluginsdk.AgentToolRequest {
	return &pluginsdk.AgentToolRequest{InvocationID: "invocation", Name: name, Arguments: args, Context: pluginsdk.AgentToolContext{WorkspaceID: "ws", TaskID: "task", SessionID: "session", Surface: "kanban-task"}}
}
func auditFixture(t *testing.T, p *securityPlugin, workspace string) (string, string) {
	t.Helper()
	raw := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Scanner","version":"1","rules":[{"id":"R","properties":{"security-severity":"9.5"},"help":{"text":"Scanner suggestion, not a verified fix"}}]}},"results":[{"ruleId":"R","message":{"text":"Critical finding"}},{"ruleId":"OTHER","level":"note","message":{"text":"Low finding"}}]}]}`)
	r, _, err := p.store.Import(context.Background(), workspace, "actor", "scan.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	return r.ID, r.Digest
}
func toolData(t *testing.T, p *securityPlugin, name string, args map[string]any) map[string]any {
	t.Helper()
	r, err := p.InvokeAgentTool(context.Background(), auditRequest(name, args))
	if err != nil || r.IsError {
		t.Fatalf("%s: %+v %v", name, r, err)
	}
	source := "imported_sarif"
	switch name {
	case "start_report", "list_report_drafts", "get_report_draft", "submit_finding", "cancel_report":
		source = "llm_report_draft"
	case "complete_report":
		source = "generated_sarif"
	case "set_issue_status":
		source = "issue_review"
	}
	if r.StructuredContent["workspace_id"] != "ws" || r.StructuredContent["source"] != source {
		t.Fatal("missing authority/provenance")
	}
	return r.StructuredContent["data"].(map[string]any)
}
func TestAuditToolsReadOnlyWorkflow(t *testing.T) {
	p := testPlugin(t)
	id, digest := auditFixture(t, p, "ws")
	foreign, _ := auditFixture(t, p, "private")
	listed := toolData(t, p, "list_reports", nil)
	if listed["total"] != float64(1) {
		t.Fatal(listed)
	}
	report := toolData(t, p, "get_report", map[string]any{"report_id": id})
	if report["report"].(map[string]any)["sha256"] != digest || len(report["provenance_gaps"].([]any)) == 0 {
		t.Fatal(report)
	}
	summary := toolData(t, p, "get_audit_summary", map[string]any{"report_ids": []string{id}})
	if summary["finding_count"] != float64(2) || summary["severity_counts"].(map[string]any)["critical"] != float64(1) {
		t.Fatal(summary)
	}
	page := toolData(t, p, "list_findings", map[string]any{"report_ids": []string{id}, "severity": "critical"})
	if page["total"] != float64(1) {
		t.Fatal(page)
	}
	item := page["items"].([]any)[0].(map[string]any)
	detail := toolData(t, p, "get_finding", map[string]any{"report_id": item["report_id"], "ordinal": item["ordinal"]})
	toolData(t, p, "get_issue", map[string]any{"issue_id": item["issue_id"]})
	if detail["guidance"] != "Scanner suggestion, not a verified fix" || detail["markup"] != nil {
		t.Fatal(detail)
	}
	facet := toolData(t, p, "list_filter_values", map[string]any{"report_ids": []string{id}, "facet": "rule"})
	if len(facet["items"].([]any)) != 2 {
		t.Fatal(facet)
	}
	for _, tc := range []struct {
		name string
		args map[string]any
	}{{"get_report", map[string]any{"report_id": foreign}}, {"get_finding", map[string]any{"report_id": foreign, "ordinal": 0}}, {"get_audit_summary", map[string]any{"report_ids": []string{id, foreign}}}, {"list_findings", map[string]any{"report_ids": []string{id, foreign}}}, {"list_filter_values", map[string]any{"report_ids": []string{foreign}, "facet": "rule"}}} {
		r, err := p.InvokeAgentTool(context.Background(), auditRequest(tc.name, tc.args))
		if err != nil || !r.IsError || r.StructuredContent["error"].(map[string]any)["code"] != "not_found" {
			t.Fatalf("foreign report leaked: %+v %v", r, err)
		}
	}
	after := toolData(t, p, "get_report", map[string]any{"report_id": id})
	if after["report"].(map[string]any)["updated_at"] != report["report"].(map[string]any)["updated_at"] {
		t.Fatal("read mutated report")
	}
}
func TestAuditToolsRejectAuthoritySpoofingAndWrites(t *testing.T) {
	p := testPlugin(t)
	id, _ := auditFixture(t, p, "ws")
	for _, tc := range []struct {
		name string
		args map[string]any
	}{{"reports.delete", map[string]any{"id": id}}, {"tokens.create", map[string]any{"name": "secret"}}, {"list_reports", map[string]any{"workspace_id": "private"}}, {"get_report", map[string]any{"report_id": id, "task_id": "other"}}, {"get_finding", map[string]any{"report_id": id}}, {"get_finding", map[string]any{"report_id": id, "ordinal": 0.5}}, {"list_findings", map[string]any{}}, {"list_reports", map[string]any{"offset": -1}}} {
		result, err := p.InvokeAgentTool(context.Background(), auditRequest(tc.name, tc.args))
		if err != nil || !result.IsError {
			t.Fatalf("accepted %s: %+v %v", tc.name, result, err)
		}
	}
	for _, field := range []string{"workspace", "task", "session", "surface", "invocation"} {
		r := auditRequest("list_reports", nil)
		switch field {
		case "workspace":
			r.Context.WorkspaceID = ""
		case "task":
			r.Context.TaskID = ""
		case "session":
			r.Context.SessionID = ""
		case "surface":
			r.Context.Surface = "external"
		case "invocation":
			r.InvocationID = ""
		}
		result, err := p.InvokeAgentTool(context.Background(), r)
		if err != nil || !result.IsError {
			t.Fatalf("missing %s accepted", field)
		}
	}
	req := auditRequest("get_report", map[string]any{"report_id": id})
	req.Context.Surface = "office-task"
	if r, err := p.InvokeAgentTool(context.Background(), req); err != nil || r.IsError {
		t.Fatal("office surface rejected")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.InvokeAgentTool(cancelled, auditRequest("list_reports", nil)); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation")
	}
}
func TestAuditToolResultBudgetAndTextFallback(t *testing.T) {
	p := testPlugin(t)
	results := []map[string]any{}
	for i := 0; i < 40; i++ {
		results = append(results, map[string]any{"ruleId": strings.Repeat("<", 900) + fmt.Sprint(i), "message": map[string]any{"text": strings.Repeat("é", 3000)}, "locations": []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": strings.Repeat("<", 1900)}}}}})
	}
	raw, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "Scanner"}}, "results": results}}})
	report, _, err := p.store.Import(context.Background(), "ws", "actor", "large.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[float64]bool{}
	offset := 0
	for {
		req := auditRequest("list_findings", map[string]any{"report_ids": []string{report.ID}, "offset": offset})
		r, err := p.InvokeAgentTool(context.Background(), req)
		if err != nil || r.IsError {
			t.Fatalf("page: %+v %v", r, err)
		}
		encoded, _ := json.Marshal(r.StructuredContent)
		if len(encoded)+len(r.Text) > 1<<20 {
			t.Fatal("exceeded host limit")
		}
		var fallback map[string]any
		if err = json.Unmarshal([]byte(r.Text), &fallback); err != nil || fallback["source"] != "imported_sarif" {
			t.Fatal("unusable text fallback")
		}
		if r.StructuredContent["truncated"] != true {
			t.Fatal("shortened messages not marked")
		}
		data := r.StructuredContent["data"].(map[string]any)
		for _, item := range data["items"].([]any) {
			ordinal := item.(map[string]any)["ordinal"].(float64)
			if seen[ordinal] {
				t.Fatal("duplicate page item")
			}
			seen[ordinal] = true
		}
		next := int(data["next_offset"].(float64))
		if next == 0 {
			break
		}
		if next <= offset {
			t.Fatal("pagination stuck")
		}
		offset = next
	}
	if len(seen) != 40 {
		t.Fatalf("lost findings: %d", len(seen))
	}
}

type declaredAuditTool struct {
	Name        string          `yaml:"name"`
	Surfaces    []string        `yaml:"surfaces"`
	Input       map[string]any  `yaml:"input_schema"`
	Output      map[string]any  `yaml:"output_schema"`
	Annotations map[string]bool `yaml:"annotations"`
}

func compileAuditSchema(t *testing.T, value map[string]any) *jsonschema.Schema {
	t.Helper()
	raw, _ := json.Marshal(value)
	normalized, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err = c.AddResource("https://security.test/schema.json", normalized); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile("https://security.test/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return schema
}
func TestDeclaredAuditSchemasMatchHandlers(t *testing.T) {
	raw, err := os.ReadFile("../manifest.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		AgentTools []declaredAuditTool `yaml:"agent_tools"`
	}
	if err = yaml.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	p := testPlugin(t)
	id, _ := auditFixture(t, p, "ws")
	issuePage, err := p.store.Issues(context.Background(), "ws", reports.IssueQuery{})
	if err != nil || len(issuePage.Items) == 0 {
		t.Fatal(err)
	}
	args := map[string]map[string]any{"get_issue": {"issue_id": issuePage.Items[0].IssueID}, "list_reports": {}, "get_report": {"report_id": id}, "get_audit_summary": {"report_ids": []string{id}}, "list_findings": {"report_ids": []string{id}}, "get_finding": {"report_id": id, "ordinal": 0}, "list_filter_values": {"report_ids": []string{id}, "facet": "rule"}}
	args["set_issue_status"] = map[string]any{"issue_id": issuePage.Items[0].IssueID, "status": "open", "reason": "Reviewed evidence; needs verification"}
	args["start_report"] = map[string]any{"client_report_id": "schema-start", "title": "Review handlers", "instructions": "Inspect SQL queries.", "scope": []string{"handlers"}}
	args["list_report_drafts"] = map[string]any{}
	for _, name := range []string{"get_report_draft", "submit_finding", "complete_report", "cancel_report"} {
		spec := reports.AgentReportSpec{ClientReportID: "schema-" + name, Title: "Review", Instructions: "Inspect", Scope: []string{"handlers"}}
		d, err := p.store.StartReport(context.Background(), reports.DraftAuthority{WorkspaceID: "ws", TaskID: "task", SessionID: "session", InvocationID: "schema"}, spec)
		if err != nil {
			t.Fatal(err)
		}
		args[name] = map[string]any{"draft_id": d.ID}
		if name != "get_report_draft" {
			args[name]["expected_revision"] = 0
		}
		if name == "submit_finding" {
			args[name]["finding"] = map[string]any{"finding_id": "one", "title": "Risk", "description": "Untrusted query", "severity": "high", "confidence": "medium", "evidence": "db.Query concatenates input"}
		}
		if name == "complete_report" {
			args[name]["completion"] = map[string]any{"summary": "No findings", "coverage": "Inspected handlers"}
		}
	}
	if len(manifest.AgentTools) != len(args) {
		t.Fatal("unexpected tool catalog")
	}
	for _, tool := range manifest.AgentTools {
		t.Run(tool.Name, func(t *testing.T) {
			body, ok := args[tool.Name]
			if !ok {
				t.Fatal("undeclared handler")
			}
			writes := map[string]bool{"set_issue_status": true, "start_report": true, "submit_finding": true, "complete_report": true, "cancel_report": true}
			if tool.Annotations["read_only_hint"] == writes[tool.Name] || tool.Annotations["destructive_hint"] != (tool.Name == "cancel_report") || !tool.Annotations["idempotent_hint"] || tool.Annotations["open_world_hint"] || len(tool.Surfaces) != 2 {
				t.Fatal("incorrect tool annotations/surfaces")
			}
			input, output := compileAuditSchema(t, tool.Input), compileAuditSchema(t, tool.Output)
			normalized, _ := json.Marshal(body)
			var value any
			json.Unmarshal(normalized, &value)
			if err = input.Validate(value); err != nil {
				t.Fatal(err)
			}
			spoof := map[string]any{"workspace_id": "foreign"}
			if err = input.Validate(spoof); err == nil {
				t.Fatal("schema permits authority override")
			}
			result, err := p.InvokeAgentTool(context.Background(), auditRequest(tool.Name, body))
			if err != nil || result.IsError {
				t.Fatalf("dispatch: %+v %v", result, err)
			}
			if err = output.Validate(result.StructuredContent); err != nil {
				t.Fatal(err)
			}
			failure, _ := agentFailure("not_found", "Missing report")
			if err = output.Validate(failure.StructuredContent); err != nil {
				t.Fatal("error violates output schema", err)
			}
		})
	}
}

func TestActualSARIFAuditTools(t *testing.T) {
	path := os.Getenv("KANDEV_SECURITY_SARIF_SMOKE")
	if path == "" {
		t.Skip("set KANDEV_SECURITY_SARIF_SMOKE to verify a local SARIF file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p := testPlugin(t)
	report, _, err := p.store.Import(context.Background(), "ws", "actor", "actual.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	toolData(t, p, "list_reports", nil)
	toolData(t, p, "get_report", map[string]any{"report_id": report.ID})
	summary := toolData(t, p, "get_audit_summary", map[string]any{"report_ids": []string{report.ID}})
	if summary["finding_count"] != float64(report.FindingCount) {
		t.Fatal("summary count mismatch")
	}
	toolData(t, p, "list_filter_values", map[string]any{"report_ids": []string{report.ID}, "facet": "tool"})
	read := 0
	offset := 0
	for {
		page := toolData(t, p, "list_findings", map[string]any{"report_ids": []string{report.ID}, "offset": offset})
		items := page["items"].([]any)
		read += len(items)
		if len(items) > 0 {
			item := items[0].(map[string]any)
			toolData(t, p, "get_finding", map[string]any{"report_id": item["report_id"], "ordinal": item["ordinal"]})
			toolData(t, p, "get_issue", map[string]any{"issue_id": item["issue_id"]})
		}
		next := int(page["next_offset"].(float64))
		if next == 0 {
			break
		}
		if next <= offset {
			t.Fatal("pagination did not advance")
		}
		offset = next
	}
	if read != report.FindingCount {
		t.Fatalf("expected %d findings, read %d", report.FindingCount, read)
	}
	// A formatting-only new report retains every original occurrence and reuses
	// established issue IDs rather than duplicating the grouped rows.
	before, err := p.store.Issues(context.Background(), "ws", reports.IssueQuery{})
	if err != nil {
		t.Fatal(err)
	}
	_, duplicate, err := p.store.Import(context.Background(), "ws", "actor", "second.sarif", append(append([]byte{}, raw...), '\n'))
	if err != nil || duplicate {
		t.Fatal("distinct source not retained", err)
	}
	after, err := p.store.Issues(context.Background(), "ws", reports.IssueQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if before.Total != after.Total {
		t.Fatalf("group count changed: %d -> %d", before.Total, after.Total)
	}
	occurrences, err := p.store.Aggregate(context.Background(), "ws", reports.AggregateQuery{})
	if err != nil || occurrences.Total != 2*report.FindingCount {
		t.Fatal("source occurrences lost", occurrences.Total, err)
	}
	t.Logf("Grouped %d original occurrences into %d issues; second distinct report preserves %d occurrences and the same issue count.", report.FindingCount, before.Total, occurrences.Total)
	t.Logf("All seven audit tools verified against %d findings, with complete pagination and detail reads.", read)
}
