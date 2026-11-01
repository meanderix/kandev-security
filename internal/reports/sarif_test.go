package reports

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// Synthetic OSV-style report: the URI identifies the second artifact while the
// explicit -1 means no array reference. Never dereference it or assume index 0.
const unknownArtifactIndexSARIF = `{"version":"2.1.0","runs":[{
  "tool":{"driver":{"name":"osv-scanner","rules":[{"id":"OSV-TEST","properties":{"security-severity":"7.5"}}]}},
  "artifacts":[
    {"location":{"uri":"src/main.go"},"sourceLanguage":"go"},
    {"location":{"uri":"file:///project/composer.lock"},"sourceLanguage":"php"}
  ],
  "results":[{"ruleId":"OSV-TEST","ruleIndex":0,"message":{"text":"Dependency vulnerability"},
    "locations":[{"physicalLocation":{"artifactLocation":{"index":-1,"uri":"file:///project/composer.lock"}}}]}]
}]}`

func TestSARIFArtifactIndex(t *testing.T) {
	for _, tc := range []struct {
		name, location, uri, language string
		invalid                       bool
	}{
		{"unknown", `"index":-1,"uri":"file:///project/composer.lock"`, "file:///project/composer.lock", "PHP", false},
		{"omitted", `"uri":"file:///project/composer.lock"`, "file:///project/composer.lock", "PHP", false},
		{"zero", `"index":0`, "src/main.go", "Go", false},
		{"last", `"index":1`, "file:///project/composer.lock", "PHP", false},
		{"below unknown", `"index":-2,"uri":"file:///project/composer.lock"`, "", "", true},
		{"out of bounds", `"index":2,"uri":"file:///project/composer.lock"`, "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(unknownArtifactIndexSARIF, `"index":-1,"uri":"file:///project/composer.lock"`, tc.location, 1)
			_, findings, err := parseSARIF([]byte(raw))
			if tc.invalid {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("expected invalid artifact index, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 || findings[0].URI != tc.uri || findings[0].Language != tc.language {
				t.Fatalf("artifact resolution: %+v", findings)
			}
		})
	}
}

func TestSARIFUnknownArtifactIndexWithoutArtifacts(t *testing.T) {
	raw := strings.Replace(unknownArtifactIndexSARIF, `"artifacts":[
    {"location":{"uri":"src/main.go"},"sourceLanguage":"go"},
    {"location":{"uri":"file:///project/composer.lock"},"sourceLanguage":"php"}
  ]`, `"artifacts":[]`, 1)
	raw = strings.ReplaceAll(raw, "file:///project/composer.lock", "src/app.py")
	_, findings, err := parseSARIF([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].URI != "src/app.py" || findings[0].Language != "Python" {
		t.Fatalf("URI fallback: %+v", findings)
	}
}

func TestSARIFRuleIndex(t *testing.T) {
	for _, tc := range []struct {
		name, rule string
		invalid    bool
	}{
		{"omitted", `"ruleId":"OSV-TEST"`, false},
		{"unknown", `"ruleId":"OSV-TEST","ruleIndex":-1`, false},
		{"zero", `"ruleId":"OSV-TEST","ruleIndex":0`, false},
		{"index only", `"ruleIndex":0`, false},
		{"below unknown", `"ruleId":"OSV-TEST","ruleIndex":-2`, true},
		{"out of bounds", `"ruleId":"OSV-TEST","ruleIndex":1`, true},
		{"disagreeing ID", `"ruleId":"OTHER","ruleIndex":0`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(unknownArtifactIndexSARIF, `"ruleId":"OSV-TEST","ruleIndex":0`, tc.rule, 1)
			_, findings, err := parseSARIF([]byte(raw))
			if tc.invalid {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("expected invalid rule reference, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 || findings[0].RuleID != "OSV-TEST" || findings[0].Severity != "high" || findings[0].SecuritySeverity != 7.5 {
				t.Fatalf("rule metadata: %+v", findings)
			}
		})
	}
}

func TestSARIFUnknownIndicesUploadRoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	raw := []byte(strings.Replace(unknownArtifactIndexSARIF, `"ruleIndex":0`, `"ruleIndex":-1`, 1))
	upload, err := s.StartUpload(ctx, "ws", "actor", "osv-scanner.sarif", len(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AppendUpload(ctx, "ws", upload.ID, 0, raw); err != nil {
		t.Fatal(err)
	}
	imported, err := s.CompleteUpload(ctx, "ws", upload.ID)
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.Aggregate(ctx, "ws", AggregateQuery{Tool: "osv-scanner", Severity: "high", Language: "PHP"})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].URI != "file:///project/composer.lock" {
		t.Fatalf("imported findings: %+v %v", page, err)
	}
	source, err := s.Source(ctx, "ws", imported.Report.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(source.Data)
	if err != nil || !bytes.Equal(raw, decoded) {
		t.Fatal("original SARIF changed")
	}
	token, err := s.CreateUploadToken(ctx, "ws", "issuer", "OSV")
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.ImportWithToken(ctx, token.Secret, "osv-scanner.sarif", raw)
	if err != nil || !again.Duplicate || again.Report.ID != imported.Report.ID {
		t.Fatalf("token reimport: %+v %v", again, err)
	}
}
