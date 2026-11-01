package reports

import (
	"context"

	"encoding/json"
	"os"
	"path/filepath"

	"strings"
	"testing"
)

// All projected fields here are standard SARIF, with no scanner property bags.
const commonFixture = `{"version":"2.1.0","runs":[{
 "automationDetails":{"id":"web-audit/staging/"},
 "originalUriBaseIds":{"ROOT":{"uri":"file:///checkout/"},"SRC":{"uri":"src/","uriBaseId":"ROOT"}},
 "artifacts":[{"location":{"uri":"handler.php","uriBaseId":"SRC"}}],
 "logicalLocations":[{"fullyQualifiedName":"App.Handler.handle"}],
 "versionControlProvenance":[{"repositoryUri":"https://example.com/app.git","revisionId":"abc","branch":"main"},{"repositoryUri":"https://example.com/lib.git","revisionId":"def"}],
 "invocations":[{"startTimeUtc":"2026-01-01T12:00:00Z","endTimeUtc":"2026-01-01T12:01:00Z","executionSuccessful":false}],
 "webRequests":[{"method":"GET","target":"https://stage.example.com/login","headers":{"Authorization":"Bearer private","Cookie":"secret","Accept":"text/html"},"body":{"text":"request evidence"}}],
 "webResponses":[{"statusCode":403,"reasonPhrase":"Forbidden","headers":{"Set-Cookie":"secret","Content-Type":"text/html"},"body":{"text":"<script>window.executed=true</script>response evidence"}}],
 "taxonomies":[{"name":"CWE","taxa":[{"id":"79","name":"Cross-site scripting","shortDescription":{"text":"Untrusted output"},"helpUri":"https://example.com/cwe/79"}]}],
 "tool":{"driver":{"name":"Generic scanner","version":"1","rules":[{"id":"R1","shortDescription":{"text":"Unsafe output"},"help":{"text":"Encode the value before output."}}]}},
 "results":[{"ruleId":"R1","level":"warning","kind":"review","rank":0,"message":{"text":"Specific result with input details"},
 "analysisTarget":{"uri":"https://stage.example.com/"},"baselineState":"unchanged","provenance":{"firstDetectionTimeUtc":"2025-12-01T12:00:00Z","lastDetectionTimeUtc":"2026-01-01T12:00:00Z"},
 "locations":[{"physicalLocation":{"artifactLocation":{"index":0},"region":{"startLine":12,"startColumn":2,"endLine":14,"endColumn":9,"snippet":{"text":"echo $value;"}}},"logicalLocations":[{"index":0}]},{"message":{"text":"Second affected location"},"physicalLocation":{"artifactLocation":{"uri":"https://stage.example.com/login"}}}],
 "relatedLocations":[{"id":3,"message":{"text":"Input source"},"physicalLocation":{"artifactLocation":{"uri":"input.php","uriBaseId":"SRC"},"region":{"startLine":3,"snippet":{"text":"$value = input();"}}}}],
 "webRequest":{"index":0},"webResponse":{"index":0},"taxa":[{"index":0,"toolComponent":{"index":0}}],
 "attachments":[{"artifactLocation":{"uri":"evidence.txt","uriBaseId":"ROOT"},"description":{"text":"Supporting trace"}}],
 "hostedViewerUri":"javascript:alert(1)","workItemUris":["https://example.com/ticket/1"],"fingerprints":{"stable":"abc"},"partialFingerprints":{"line":"def"}}]}]}`

func TestCommonFindingStandardSARIF(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	r, _, err := s.Import(ctx, "ws", "actor", "scan.sarif", []byte(commonFixture))
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.Finding(ctx, "ws", r.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if d.Finding.Title != "Unsafe output" || d.Title != "Unsafe output" || d.Finding.Kind != "review" || d.Finding.Rank == nil || *d.Finding.Rank != 0 || d.Finding.SeveritySource != "result.level" || d.Finding.Confidence != "" {
		t.Fatalf("summary %+v", d.Finding)
	}
	if d.Context.AutomationID != "web-audit/staging/" || len(d.Context.Repositories) != 2 || d.Context.Repositories[1].Revision != "def" || d.Context.AnalysisTarget.URI != "https://stage.example.com/" || d.Context.FirstDetectedAt != "2025-12-01T12:00:00Z" || d.Context.BaselineState != "unchanged" || len(d.Context.Invocations) != 1 || d.Context.Invocations[0].ExecutionSuccessful == nil || *d.Context.Invocations[0].ExecutionSuccessful {
		t.Fatalf("context %+v", d.Context)
	}
	if len(d.Locations) != 2 || d.Locations[0].ResolvedURI != "file:///checkout/src/handler.php" || d.Locations[0].URI != "handler.php" || d.Locations[0].Snippet != "echo $value;" || d.Locations[0].EndLine != 14 || d.Locations[0].LogicalNames[0] != "App.Handler.handle" || len(d.RelatedLocations) != 1 || *d.RelatedLocations[0].ID != 3 {
		t.Fatalf("locations %+v / %+v", d.Locations, d.RelatedLocations)
	}
	if d.HTTP == nil || d.HTTP.Request.Method != "GET" || d.HTTP.Response.StatusCode != 403 || d.HTTP.Request.Headers["Authorization"] != "[redacted]" || d.HTTP.Request.Headers["Cookie"] != "[redacted]" || d.HTTP.Response.Headers["Set-Cookie"] != "[redacted]" || !strings.Contains(d.HTTP.Response.Body, "<script>") {
		t.Fatalf("http %+v", d.HTTP)
	}
	if len(d.Classifications) != 1 || d.Classifications[0].Taxonomy != "CWE" || d.Classifications[0].ID != "79" || len(d.Evidence) != 1 || d.Evidence[0].Artifact.ResolvedURI != "file:///checkout/evidence.txt" || len(d.References) != 2 || d.Fingerprints["stable"] != "abc" || d.PartialFingerprints["line"] != "def" {
		t.Fatalf("evidence %+v", d)
	}
	// Neither read-side projection nor resolving URI bases changes identity input.
	if d.Finding.URI != "handler.php" {
		t.Fatal("changed primary URI", d.Finding.URI)
	}
	p, err := s.Aggregate(ctx, "ws", AggregateQuery{Search: "Unsafe output"})
	if err != nil || p.Total != 1 || p.Items[0].Title != "Unsafe output" {
		t.Fatal(p, err)
	}
	title, prompt, err := BuildFindingTask(DefaultTaskPresets()[0], d)
	if err != nil || !strings.Contains(title, "Unsafe output") || !strings.Contains(prompt, "response evidence") || !strings.Contains(prompt, "echo $value;") {
		t.Fatal(title, prompt, err)
	}
}

func TestCommonFindingSeverityProvenanceAndAbsentData(t *testing.T) {
	for _, tc := range []struct{ name, rule, result, source, kind string }{
		{"default", `{"id":"R"}`, ``, "sarif.default", "fail"},
		{"rule", `{"id":"R","defaultConfiguration":{"level":"note"}}`, ``, "rule.defaultConfiguration.level", "fail"},
		{"score", `{"id":"R","properties":{"security-severity":0}}`, `,"level":"error","rank":-1`, "rule.properties.security-severity", "fail"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Scanner","rules":[` + tc.rule + `]}},"results":[{"ruleId":"R","message":{"text":"Observation"}` + tc.result + `}]}]}`)
			_, fs, err := parseSARIF(raw)
			if err != nil {
				t.Fatal(err)
			}
			f := fs[0]
			if f.SeveritySource != tc.source || f.Kind != tc.kind || f.Rank != nil || f.Confidence != "" {
				t.Fatal(f)
			}
		})
	}
}

func TestCommonFindingBoundsAndUnresolvedReferences(t *testing.T) {
	var doc map[string]any
	json.Unmarshal([]byte(commonFixture), &doc)
	run := doc["runs"].([]any)[0].(map[string]any)
	result := run["results"].([]any)[0].(map[string]any)
	result["webRequest"] = map[string]any{"index": 999}
	result["analysisTarget"] = map[string]any{"uri": "a", "uriBaseId": "CYCLE"}
	run["originalUriBaseIds"].(map[string]any)["CYCLE"] = map[string]any{"uriBaseId": "CYCLE"}
	response := run["webResponses"].([]any)[0].(map[string]any)
	response["body"] = map[string]any{"text": strings.Repeat("😀<", 10000)}
	result["taxa"] = []any{map[string]any{"id": "unknown", "toolComponent": map[string]any{"index": 99}}}
	locations := result["locations"].([]any)
	for i := 0; i < 15; i++ {
		locations = append(locations, locations[0])
	}
	result["locations"] = locations
	raw, _ := json.Marshal(doc)
	s := openTestStore(t)
	r, _, err := s.Import(context.Background(), "ws", "actor", "large.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.Finding(context.Background(), "ws", r.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(d)
	if !d.Truncated || len(d.Locations) != 8 || d.HTTP.Request != nil || len(d.HTTP.Response.Body) > 8192 || len(encoded) > 200<<10 || len(d.NormalizationNotes) < 3 || d.Context.AnalysisTarget.ResolvedURI != "" || d.Classifications[0].ID != "unknown" {
		t.Fatalf("bounds %d %+v", len(encoded), d)
	}
}

func TestCommonTaxonomyRelationshipsAndMismatches(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(commonFixture), &doc); err != nil {
		t.Fatal(err)
	}
	run := doc["runs"].([]any)[0].(map[string]any)
	result := run["results"].([]any)[0].(map[string]any)
	delete(result, "taxa")
	rule := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	rule["relationships"] = []any{map[string]any{"target": map[string]any{"id": "79", "toolComponent": map[string]any{"name": "CWE"}}}}
	s := openTestStore(t)
	raw, _ := json.Marshal(doc)
	r, _, err := s.Import(context.Background(), "ws", "a", "relationship.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.Finding(context.Background(), "ws", r.ID, 0)
	if err != nil || len(d.Classifications) != 1 || d.Classifications[0].Name != "Cross-site scripting" {
		t.Fatal(d.Classifications, err)
	}
	// A contradictory reference must not silently acquire a different taxonomy ID.
	delete(rule, "relationships")
	result["taxa"] = []any{map[string]any{"id": "999", "index": 0, "toolComponent": map[string]any{"index": 0}}}
	raw, _ = json.Marshal(doc)
	r, _, err = s.Import(context.Background(), "ws", "a", "mismatch.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	d, err = s.Finding(context.Background(), "ws", r.ID, 0)
	if err != nil || d.Classifications[0].ID != "999" || d.Classifications[0].Name != "" || len(d.NormalizationNotes) == 0 {
		t.Fatal(d.Classifications, err)
	}
}

func TestCommonOptionalMalformedEvidenceDoesNotHideFinding(t *testing.T) {
	s := openTestStore(t)
	raw := []byte(strings.Replace(commonFixture, `"fingerprints":{"stable":"abc"}`, `"fingerprints":{"stable":42}`, 1))
	r, _, err := s.Import(context.Background(), "ws", "actor", "malformed-optional.sarif", raw)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.Finding(context.Background(), "ws", r.ID, 0)
	if err != nil || d.Finding.Title != "Unsafe output" || !d.Truncated || len(d.NormalizationNotes) == 0 {
		t.Fatal(d, err)
	}
}

// Optional local corpus check; report content is never added to the repository.
func TestCommonRealReportsSmoke(t *testing.T) {
	dir := os.Getenv("KANDEV_SECURITY_SARIF_DIR")
	if dir == "" {
		t.Skip("set KANDEV_SECURITY_SARIF_DIR to a private SARIF corpus")
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := openTestStore(t)
	ctx := context.Background()
	count := 0
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sarif") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		r, _, err := s.Import(ctx, "ws", "actor", file.Name(), raw)
		if err != nil {
			t.Fatalf("%s: %v", file.Name(), err)
		}
		if r.FindingCount > 0 {
			d, err := s.Finding(ctx, "ws", r.ID, 0)
			if err != nil {
				t.Fatal(err)
			}
			if d.Finding.Title == "" || d.Finding.SeveritySource == "" {
				t.Fatalf("missing common summary: %+v", d.Finding)
			}
			if d.Finding.Tool == "ZAP" && (d.HTTP == nil || d.HTTP.Request == nil || d.HTTP.Response == nil || len(d.Locations) == 0 || len(d.NormalizationNotes) == 0) {
				t.Fatalf("missing web evidence: %+v", d)
			}
			if d.Finding.Origin == "llm" && (len(d.Evidence) == 0 || len(d.Evidence[0].Text) == 0 || d.Finding.ConfidenceSource != "agent.confidence") {
				t.Fatal("missing agent evidence")
			}
		}
		count++
		t.Logf("%s: %d findings", r.Tools, r.FindingCount)
	}
	if count == 0 {
		t.Fatal("no SARIF files found")
	}
	p, err := s.Issues(ctx, "ws", IssueQuery{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d reports, %d issues", count, p.Total)
}
