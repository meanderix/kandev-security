package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAuditToolsDefaultScopeAndInvalidExplicitSelection(t *testing.T) {
	p := testPlugin(t)
	id, digest := auditFixture(t, p, "ws")
	foreign, _ := auditFixture(t, p, "private")
	archived, _, err := p.store.Import(context.Background(), "ws", "actor", "archived.sarif", []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Archived scanner"}},"results":[{"ruleId":"OLD","message":{"text":"Archived finding"}}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.store.SetReportArchived(context.Background(), "ws", "actor", archived.ID, true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args map[string]any
	}{{"get_audit_summary", nil}, {"list_findings", map[string]any{"severity": "critical"}}, {"list_filter_values", map[string]any{"facet": "rule"}}} {
		t.Run(tc.name, func(t *testing.T) {
			data := toolData(t, p, tc.name, tc.args)
			if data["report_scope"] != "active_workspace" || data["report_count"] != float64(1) || data["reports_truncated"] != false {
				t.Fatal("wrong default scope", data)
			}
			refs := data["reports"].([]any)
			if len(refs) != 1 || refs[0].(map[string]any)["report_id"] != id || refs[0].(map[string]any)["sha256"] != digest {
				t.Fatal("default scope lost source evidence", data)
			}
			args := map[string]any{}
			for key, value := range tc.args {
				args[key] = value
			}
			delete(args, "severity")
			args["report_ids"] = []string{archived.ID}
			data = toolData(t, p, tc.name, args)
			if data["report_scope"] != "explicit" || data["report_count"] != float64(1) || data["reports"].([]any)[0].(map[string]any)["archived_at"] == nil {
				t.Fatal("explicit archive scope lost", data)
			}
			for _, selection := range []any{nil, []string{}, []string{id, id}, []string{id, foreign}, []string{id, "missing"}} {
				args["report_ids"] = selection
				result, err := p.InvokeAgentTool(context.Background(), auditRequest(tc.name, args))
				if err != nil || !result.IsError {
					t.Fatalf("invalid explicit selection widened the query: %v %+v %v", selection, result, err)
				}
			}
		})
	}
}

func TestAuditOptionalReportSelectionSchemas(t *testing.T) {
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
	for _, tool := range manifest.AgentTools {
		if tool.Name != "get_audit_summary" && tool.Name != "list_findings" && tool.Name != "list_filter_values" {
			continue
		}
		t.Run(tool.Name, func(t *testing.T) {
			schema := compileAuditSchema(t, tool.Input)
			args := map[string]any{}
			if tool.Name == "list_filter_values" {
				args["facet"] = "rule"
			}
			if err := schema.Validate(args); err != nil {
				t.Fatal("omitted report selection rejected", err)
			}
			args["report_ids"] = []any{"report"}
			if err := schema.Validate(args); err != nil {
				t.Fatal("explicit report selection rejected", err)
			}
			oversize := []any{}
			for i := 0; i < 51; i++ {
				oversize = append(oversize, fmt.Sprint(i))
			}
			for _, invalid := range []any{nil, []any{}, []any{"report", "report"}, []any{1}, oversize} {
				args["report_ids"] = invalid
				if err := schema.Validate(args); err == nil {
					t.Fatalf("invalid selection allowed by schema: %v", invalid)
				}
			}
		})
	}
}

func TestAuditWorkspaceMetadataBudgetAndNotices(t *testing.T) {
	p := testPlugin(t)
	for i := 0; i < 57; i++ {
		raw := fmt.Sprintf(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Scanner"}},"results":[{"ruleId":"R%03d","message":{"text":"Finding"}}]}]}`, i)
		if _, _, err := p.store.Import(context.Background(), "ws", "actor", "source.sarif", []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name string
		args map[string]any
	}{{"get_audit_summary", nil}, {"list_findings", nil}, {"list_filter_values", map[string]any{"facet": "rule"}}} {
		result, err := p.InvokeAgentTool(context.Background(), auditRequest(tc.name, tc.args))
		if err != nil || result.IsError {
			t.Fatal(tc.name, result, err)
		}
		data := result.StructuredContent["data"].(map[string]any)
		if data["report_count"] != float64(57) || data["reports_truncated"] != true || result.StructuredContent["truncated"] != true {
			t.Fatal("bounded metadata lost complete scope", result)
		}
		if tc.name == "get_audit_summary" && (data["finding_count"] != float64(57) || data["provenance_incomplete_report_count"] != float64(57) || data["provenance_incomplete_report_ids_truncated"] != true) {
			t.Fatal("summary counts truncated with metadata", data)
		}
		encoded, _ := json.Marshal(result.StructuredContent)
		if len(encoded) > maxAgentJSONBytes || len(encoded)+len(result.Text) > 1<<20 {
			t.Fatal("workspace-wide result exceeded host budget")
		}
	}
}
