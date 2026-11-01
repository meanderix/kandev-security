package reports

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestGeneratedAgentSARIFConformsToOfficialSchema(t *testing.T) {
	raw, err := os.ReadFile("testdata/sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	const schemaURI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	if err = compiler.AddResource(schemaURI, document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(schemaURI)
	if err != nil {
		t.Fatal(err)
	}
	spec := draftSpec()
	if err = validateSpec(&spec); err != nil {
		t.Fatal(err)
	}
	audit := AgentAudit{Origin: "llm", DraftID: "draft", TaskID: "task", Spec: spec, Completion: draftCompletion()}
	cases := [][]DraftFinding{{}}
	entries := []DraftFinding{}
	for _, severity := range []string{"critical", "high", "medium", "low", "informational"} {
		f := draftFinding(severity)
		f.Severity = severity
		entries = append(entries, DraftFinding{Finding: f})
	}
	cases = append(cases, entries)
	noLocation := draftFinding("architectural")
	noLocation.URI = ""
	noLocation.Line = 0
	noLocation.Snippet = ""
	noLocation.RuleID = ""
	cases = append(cases, []DraftFinding{{Finding: noLocation}})
	for _, uri := range []string{"src/my file.go", `C:\src\my file.go`, "file:///tmp/a.go"} {
		f := draftFinding(uri)
		f.URI = uri
		cases = append(cases, []DraftFinding{{Finding: f}})
	}
	for i, entries := range cases {
		generated, err := generateAgentSARIF(audit, entries)
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err = json.Unmarshal(generated, &value); err != nil {
			t.Fatal(err)
		}
		if err = schema.Validate(value); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if _, _, err = parseSARIF(generated); err != nil {
			t.Fatal("our own importer rejected generated SARIF", err)
		}
	}
}
