package reports

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

const MaxReportBytes = 20 << 20
const MaxFindings = 50000
const ChunkBytes = 192 << 10

type sarifDocument struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}
type sarifRule struct {
	ID                   string       `json:"id"`
	Name                 string       `json:"name"`
	Short                sarifMessage `json:"shortDescription"`
	HelpURI              string       `json:"helpUri"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties map[string]json.RawMessage `json:"properties"`
}
type sarifRun struct {
	Properties map[string]json.RawMessage `json:"properties"`
	Automation struct {
		ID string `json:"id"`
	} `json:"automationDetails"`
	Tool struct {
		Driver struct {
			Name    string      `json:"name"`
			Version string      `json:"version"`
			Rules   []sarifRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Artifacts []struct {
		SourceLanguage string `json:"sourceLanguage"`
		Location       struct {
			URI       string `json:"uri"`
			URIBaseID string `json:"uriBaseId"`
		} `json:"location"`
	} `json:"artifacts"`
	VersionControl []struct {
		RepositoryURI string `json:"repositoryUri"`
		Revision      string `json:"revisionId"`
		Branch        string `json:"branch"`
	} `json:"versionControlProvenance"`
	Results []struct {
		Properties          map[string]json.RawMessage `json:"properties"`
		RuleID              string                     `json:"ruleId"`
		RuleIndex           *int                       `json:"ruleIndex"`
		Kind                string                     `json:"kind"`
		Rank                *float64                   `json:"rank"`
		Level               string                     `json:"level"`
		Message             sarifMessage               `json:"message"`
		Fingerprints        json.RawMessage            `json:"fingerprints"`
		PartialFingerprints json.RawMessage            `json:"partialFingerprints"`
		Locations           []struct {
			Physical struct {
				Artifact struct {
					URI       string `json:"uri"`
					URIBaseID string `json:"uriBaseId"`
					Index     *int   `json:"index"`
				} `json:"artifactLocation"`
				Region struct {
					SourceLanguage string       `json:"sourceLanguage"`
					Snippet        sarifMessage `json:"snippet"`
					Line           int          `json:"startLine"`
					Column         int          `json:"startColumn"`
				} `json:"region"`
			} `json:"physicalLocation"`
			Logical []struct {
				FullyQualifiedName string `json:"fullyQualifiedName"`
			} `json:"logicalLocations"`
		} `json:"locations"`
	} `json:"results"`
}

type Run struct {
	AgentAudit *AgentAudit `json:"agent_audit,omitempty"`
	Index      int         `json:"index"`
	Tool       string      `json:"tool"`
	Version    string      `json:"version"`
	Repository string      `json:"repository"`
	Revision   string      `json:"revision"`
	Branch     string      `json:"branch"`
}
type Finding struct {
	Title            string   `json:"title,omitempty"`
	Kind             string   `json:"kind,omitempty"`
	SeveritySource   string   `json:"severity_source,omitempty"`
	ConfidenceSource string   `json:"confidence_source,omitempty"`
	Rank             *float64 `json:"rank,omitempty"`
	Origin           string   `json:"origin,omitempty"`
	Confidence       string   `json:"confidence,omitempty"`
	IssueID          string   `json:"issue_id,omitempty"`
	identity         findingIdentity
	advisory         advisoryIdentity
	Tool             string  `json:"tool"`
	Language         string  `json:"language"`
	Severity         string  `json:"severity"`
	Ordinal          int     `json:"ordinal"`
	RunIndex         int     `json:"run_index"`
	RuleID           string  `json:"rule_id"`
	Level            string  `json:"level"`
	Message          string  `json:"message"`
	URI              string  `json:"uri"`
	Line             int     `json:"line"`
	Column           int     `json:"column"`
	HelpURI          string  `json:"help_uri"`
	SecuritySeverity float64 `json:"security_severity"`
}

func parseSARIF(raw []byte) ([]Run, []Finding, error) {
	if len(raw) == 0 || len(raw) > MaxReportBytes {
		return nil, nil, fmt.Errorf("%w: report must be between 1 byte and 20 MiB", ErrInvalid)
	}
	if err := checkShapeLimits(raw); err != nil {
		return nil, nil, err
	}
	var doc sarifDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("%w: report must contain valid SARIF JSON", ErrInvalid)
	}
	if doc.Version != "2.1.0" || doc.Runs == nil {
		return nil, nil, fmt.Errorf("%w: SARIF version 2.1.0 and a runs array are required", ErrInvalid)
	}
	reportDigest := digestBytes(raw)
	runs := make([]Run, 0, len(doc.Runs))
	findings := make([]Finding, 0)
	for ri, run := range doc.Runs {
		if strings.TrimSpace(run.Tool.Driver.Name) == "" || len(run.Tool.Driver.Name) > 256 {
			return nil, nil, fmt.Errorf("%w: run %d has no scanner name", ErrInvalid, ri)
		}
		r := Run{AgentAudit: readAgentAudit(run.Properties["kandevSecurity"]), Index: ri, Tool: run.Tool.Driver.Name, Version: run.Tool.Driver.Version}
		if len(run.VersionControl) > 0 {
			p := run.VersionControl[0]
			r.Repository = p.RepositoryURI
			r.Revision = p.Revision
			r.Branch = p.Branch
		}
		runs = append(runs, r)
		rules := map[string]sarifRule{}
		for _, rule := range run.Tool.Driver.Rules {
			rules[rule.ID] = rule
		}
		artifactLanguages := map[string]string{}
		for _, artifact := range run.Artifacts {
			if artifact.SourceLanguage != "" {
				artifactLanguages[artifact.Location.URI] = artifact.SourceLanguage
			}
		}
		for _, result := range run.Results {
			if len(findings) >= MaxFindings {
				return nil, nil, fmt.Errorf("%w: report exceeds 50000 findings", ErrInvalid)
			}
			rule := rules[result.RuleID]
			// SARIF array indices use -1 for unknown, equivalent to omission.
			if result.RuleIndex != nil && *result.RuleIndex != -1 {
				if *result.RuleIndex < 0 || *result.RuleIndex >= len(run.Tool.Driver.Rules) {
					return nil, nil, fmt.Errorf("%w: invalid rule index", ErrInvalid)
				}
				indexed := run.Tool.Driver.Rules[*result.RuleIndex]
				if result.RuleID != "" && indexed.ID != result.RuleID {
					return nil, nil, fmt.Errorf("%w: rule id and index disagree", ErrInvalid)
				}
				rule = indexed
			}
			id := result.RuleID
			if id == "" {
				id = rule.ID
			}
			level := result.Level
			if level == "" {
				level = rule.DefaultConfiguration.Level
			}
			if level == "" {
				level = "warning"
			}
			if level != "error" && level != "warning" && level != "note" && level != "none" {
				return nil, nil, fmt.Errorf("%w: unsupported result level", ErrInvalid)
			}
			message := result.Message.Text
			if message == "" {
				message = result.Message.Markdown
			}
			if message == "" {
				return nil, nil, fmt.Errorf("%w: each result needs message text or markdown", ErrInvalid)
			}
			// Bound individual rows so a page always fits the Host's 1 MiB response cap.
			if len(message) > 8192 || len(id) > 1024 || len(rule.HelpURI) > 2048 {
				return nil, nil, fmt.Errorf("%w: finding text exceeds supported limits", ErrInvalid)
			}
			score, known := securityScore(rule)
			f := Finding{Tool: run.Tool.Driver.Name, Language: "Unknown", Severity: findingSeverity(level, score, known), Ordinal: len(findings), RunIndex: ri, RuleID: id, Level: level, Message: message, HelpURI: rule.HelpURI, SecuritySeverity: score}
			f.Title = summaryTitle(messageText(rule.Short), rule.Name, message)
			f.Kind = "fail" // SARIF's default result kind; it is not a security category.
			if map[string]bool{"notApplicable": true, "pass": true, "fail": true, "review": true, "open": true, "informational": true}[result.Kind] {
				f.Kind = result.Kind
			}
			if result.Rank != nil && *result.Rank >= 0 && *result.Rank <= 100 {
				f.Rank = result.Rank
			}
			f.SeveritySource = "sarif.default"
			if result.Level != "" {
				f.SeveritySource = "result.level"
			} else if rule.DefaultConfiguration.Level != "" {
				f.SeveritySource = "rule.defaultConfiguration.level"
			}
			if known {
				f.SeveritySource = "rule.properties.security-severity"
			}
			if r.AgentAudit != nil {
				f.Origin = "llm"
				if agent := readAgentFinding(result.Properties["kandevSecurity"]); agent != nil {
					f.Message = agent.Finding.Title
					f.Severity = agent.Finding.Severity
					f.Confidence = agent.Finding.Confidence
					f.Title = agent.Finding.Title
					f.SeveritySource = "agent.severity"
					f.ConfidenceSource = "agent.confidence"
					f.Language = sourceLanguage(agent.Finding.Language, agent.Finding.URI)
				}
			}
			if len(result.Locations) > 0 {
				p := result.Locations[0].Physical
				language := p.Region.SourceLanguage
				f.URI = p.Artifact.URI
				f.Line = p.Region.Line
				f.Column = p.Region.Column
				if p.Artifact.Index != nil && *p.Artifact.Index != -1 {
					idx := *p.Artifact.Index
					if idx < 0 || idx >= len(run.Artifacts) {
						return nil, nil, fmt.Errorf("%w: invalid artifact index", ErrInvalid)
					}
					if f.URI == "" {
						f.URI = run.Artifacts[idx].Location.URI
					}
					if language == "" {
						language = run.Artifacts[idx].SourceLanguage
					}
				}
				if language == "" {
					language = artifactLanguages[f.URI]
				}
				if language != "" || f.Language == "Unknown" {
					f.Language = sourceLanguage(language, f.URI)
				}
				if len(f.Language) > 128 {
					return nil, nil, fmt.Errorf("%w: language exceeds 128 bytes", ErrInvalid)
				}
				if len(f.URI) > 2048 || f.Line < 0 || f.Column < 0 {
					return nil, nil, fmt.Errorf("%w: invalid finding location", ErrInvalid)
				}
			}
			encoded, _ := json.Marshal(f)
			if len(encoded) > 32<<10 {
				return nil, nil, fmt.Errorf("%w: finding exceeds 32 KiB", ErrInvalid)
			}

			var snippet, logical, baseID string
			if len(result.Locations) > 0 {
				artifact := result.Locations[0].Physical.Artifact
				baseID = artifact.URIBaseID
				if baseID == "" && artifact.Index != nil && *artifact.Index >= 0 {
					baseID = run.Artifacts[*artifact.Index].Location.URIBaseID
				}
				snippet = messageText(result.Locations[0].Physical.Region.Snippet)
				if len(result.Locations[0].Logical) > 0 {
					logical = result.Locations[0].Logical[0].FullyQualifiedName
				}
			}
			f.identity = buildFindingIdentity(r, run.Automation.ID, f, result.Fingerprints, result.PartialFingerprints, snippet, logical, baseID, reportDigest)
			f.advisory = identifyAdvisory(f.Tool, f.RuleID, rule)
			findings = append(findings, f)
		}
	}
	separateAmbiguousIdentities(findings, reportDigest)
	// Run metadata is returned with each findings page; cap its encoded size too.
	metadata, _ := json.Marshal(runs)
	if len(metadata) > 32768 {
		return nil, nil, fmt.Errorf("%w: run metadata exceeds 32 KiB", ErrInvalid)
	}
	return runs, findings, nil
}

// Count potentially large schema arrays before decoding them into Go structs.
// This keeps compact malicious inputs from allocating millions of results.
func checkShapeLimits(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	findings := 0
	var walk func(string, int) error
	walk = func(path string, depth int) error {
		if depth > 128 {
			return fmt.Errorf("%w: JSON nesting exceeds 128 levels", ErrInvalid)
		}
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%w: invalid SARIF JSON", ErrInvalid)
		}
		switch token {
		case json.Delim('{'):
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return fmt.Errorf("%w: invalid SARIF object", ErrInvalid)
				}
				field, ok := key.(string)
				if !ok {
					return ErrInvalid
				}
				if path != "" {
					field = path + "." + field
				}
				if err := walk(field, depth+1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
		case json.Delim('['):
			count := 0
			for decoder.More() {
				count++
				if path == "runs[].results" {
					findings++
					if findings > MaxFindings {
						return fmt.Errorf("%w: report exceeds 50000 findings", ErrInvalid)
					}
				}
				if (path == "runs" && count > 1000) || ((path == "runs[].tool.driver.rules" || path == "runs[].artifacts") && count > 100000) {
					return fmt.Errorf("%w: SARIF run, rule, or artifact count exceeds supported limits", ErrInvalid)
				}
				if err := walk(path+"[]", depth+1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
		}
		if err != nil {
			return fmt.Errorf("%w: invalid SARIF JSON", ErrInvalid)
		}
		return nil
	}
	return walk("", 0)
}
