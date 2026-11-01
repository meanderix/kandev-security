package reports

// This file projects standard SARIF fields into the common finding model.
// Producer-specific property bags belong in optional adapters, not here.
import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

type FindingContext struct {
	AutomationID    string             `json:"automation_id,omitempty"`
	AnalysisTarget  *FindingArtifact   `json:"analysis_target,omitempty"`
	Repositories    []SourceRepository `json:"repositories,omitempty"`
	Invocations     []ScanInvocation   `json:"invocations,omitempty"`
	BaselineState   string             `json:"baseline_state,omitempty"`
	FirstDetectedAt string             `json:"first_detected_at,omitempty"`
	LastDetectedAt  string             `json:"last_detected_at,omitempty"`
}
type SourceRepository struct {
	URI      string `json:"uri"`
	Revision string `json:"revision,omitempty"`
	Branch   string `json:"branch,omitempty"`
}
type ScanInvocation struct {
	StartedAt           string `json:"started_at,omitempty"`
	EndedAt             string `json:"ended_at,omitempty"`
	ExecutionSuccessful *bool  `json:"execution_successful,omitempty"`
}
type FindingArtifact struct {
	URI         string `json:"uri,omitempty"`
	URIBaseID   string `json:"uri_base_id,omitempty"`
	ResolvedURI string `json:"resolved_uri,omitempty"`
}
type FindingLocation struct {
	FindingArtifact
	ID           *int     `json:"id,omitempty"`
	Line         int      `json:"line,omitempty"`
	Column       int      `json:"column,omitempty"`
	EndLine      int      `json:"end_line,omitempty"`
	EndColumn    int      `json:"end_column,omitempty"`
	Message      string   `json:"message,omitempty"`
	Snippet      string   `json:"snippet,omitempty"`
	LogicalNames []string `json:"logical_names,omitempty"`
}
type FindingEvidence struct {
	Kind     string           `json:"kind"`
	Text     string           `json:"text,omitempty"`
	Artifact *FindingArtifact `json:"artifact,omitempty"`
}
type FindingReference struct {
	Kind string `json:"kind"`
	URI  string `json:"uri"`
}
type FindingClassification struct {
	Taxonomy    string `json:"taxonomy,omitempty"`
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	HelpURI     string `json:"help_uri,omitempty"`
}
type HTTPExchange struct {
	Request  *HTTPRequest  `json:"request,omitempty"`
	Response *HTTPResponse `json:"response,omitempty"`
}
type HTTPRequest struct {
	Method   string            `json:"method,omitempty"`
	Target   string            `json:"target,omitempty"`
	Protocol string            `json:"protocol,omitempty"`
	Version  string            `json:"version,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     string            `json:"body,omitempty"`
}
type HTTPResponse struct {
	StatusCode         int               `json:"status_code,omitempty"`
	Reason             string            `json:"reason,omitempty"`
	Protocol           string            `json:"protocol,omitempty"`
	Version            string            `json:"version,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	Body               string            `json:"body,omitempty"`
	NoResponseReceived bool              `json:"no_response_received,omitempty"`
}

// Bounded detail-only projections leave the small persisted/list model intact.
// Charge escaped JSON bytes, not just source bytes (e.g. '<' costs six bytes).
type commonBudget struct {
	remaining int
	truncated *bool
}

func (b *commonBudget) text(value string, limit int) string {
	value = boundedDetail(value, limit, b.truncated)
	for {
		raw, _ := json.Marshal(value)
		if len(raw) <= b.remaining {
			b.remaining -= len(raw)
			return value
		}
		*b.truncated = true
		if value == "" {
			return ""
		}
		value = boundedDetail(value, len(value)/2, b.truncated)
	}
}
func summaryTitle(values ...string) string {
	for _, value := range values {
		if value != "" {
			truncated := false
			return boundedDetail(value, 512, &truncated)
		}
	}
	return ""
}

type sarifArtifact struct {
	URI   string `json:"uri"`
	Base  string `json:"uriBaseId"`
	Index *int   `json:"index"`
}
type commonSARIFLocation struct {
	ID       *int         `json:"id"`
	Message  sarifMessage `json:"message"`
	Physical struct {
		Artifact sarifArtifact `json:"artifactLocation"`
		Region   struct {
			Line      int          `json:"startLine"`
			Column    int          `json:"startColumn"`
			EndLine   int          `json:"endLine"`
			EndColumn int          `json:"endColumn"`
			Snippet   sarifMessage `json:"snippet"`
		} `json:"region"`
	} `json:"physicalLocation"`
	Logical []struct {
		Name               string `json:"name"`
		FullyQualifiedName string `json:"fullyQualifiedName"`
		Index              *int   `json:"index"`
	} `json:"logicalLocations"`
}
type commonSARIFWeb struct {
	Index      *int              `json:"index"`
	Target     string            `json:"target"`
	Method     string            `json:"method"`
	StatusCode int               `json:"statusCode"`
	Reason     string            `json:"reasonPhrase"`
	Protocol   string            `json:"protocol"`
	Version    string            `json:"version"`
	Headers    map[string]string `json:"headers"`
	Body       struct {
		Text   string `json:"text"`
		Binary string `json:"binary"`
	} `json:"body"`
	NoResponseReceived bool `json:"noResponseReceived"`
}
type commonSARIFDescriptor struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	GUID    string       `json:"guid"`
	Short   sarifMessage `json:"shortDescription"`
	Full    sarifMessage `json:"fullDescription"`
	HelpURI string       `json:"helpUri"`
}
type commonSARIFTaxonRef struct {
	ID        string `json:"id"`
	GUID      string `json:"guid"`
	Index     *int   `json:"index"`
	Component struct {
		Name  string `json:"name"`
		GUID  string `json:"guid"`
		Index *int   `json:"index"`
	} `json:"toolComponent"`
}
type commonSARIFRun struct {
	Automation struct {
		ID string `json:"id"`
	} `json:"automationDetails"`
	Bases     map[string]sarifArtifact `json:"originalUriBaseIds"`
	Artifacts []struct {
		Location sarifArtifact `json:"location"`
	} `json:"artifacts"`
	Repositories []struct {
		URI      string `json:"repositoryUri"`
		Revision string `json:"revisionId"`
		Branch   string `json:"branch"`
	} `json:"versionControlProvenance"`
	Invocations []struct {
		StartedAt string `json:"startTimeUtc"`
		EndedAt   string `json:"endTimeUtc"`
		Success   *bool  `json:"executionSuccessful"`
	} `json:"invocations"`
	Requests   []commonSARIFWeb `json:"webRequests"`
	Responses  []commonSARIFWeb `json:"webResponses"`
	Taxonomies []struct {
		Name string                  `json:"name"`
		GUID string                  `json:"guid"`
		Taxa []commonSARIFDescriptor `json:"taxa"`
	} `json:"taxonomies"`
	Logical []struct {
		Name               string `json:"name"`
		FullyQualifiedName string `json:"fullyQualifiedName"`
	} `json:"logicalLocations"`
}
type commonSARIFResult struct {
	AnalysisTarget *sarifArtifact `json:"analysisTarget"`
	BaselineState  string         `json:"baselineState"`
	Provenance     struct {
		First string `json:"firstDetectionTimeUtc"`
		Last  string `json:"lastDetectionTimeUtc"`
	} `json:"provenance"`
	Locations   []commonSARIFLocation `json:"locations"`
	Related     []commonSARIFLocation `json:"relatedLocations"`
	Request     *commonSARIFWeb       `json:"webRequest"`
	Response    *commonSARIFWeb       `json:"webResponse"`
	Taxa        []commonSARIFTaxonRef `json:"taxa"`
	Attachments []struct {
		Artifact    sarifArtifact `json:"artifactLocation"`
		Description sarifMessage  `json:"description"`
	} `json:"attachments"`
	Viewer              string            `json:"hostedViewerUri"`
	WorkItems           []string          `json:"workItemUris"`
	Fingerprints        map[string]string `json:"fingerprints"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

func (d *FindingDetail) note(message string) {
	for _, old := range d.NormalizationNotes {
		if old == message {
			return
		}
	}
	if len(d.NormalizationNotes) < 12 {
		d.NormalizationNotes = append(d.NormalizationNotes, message)
	}
}
func takeCommon[T any](items []T, count int, d *FindingDetail) []T {
	if len(items) > count {
		d.Truncated = true
		return items[:count]
	}
	return items
}
func (r *commonSARIFRun) resolve(a sarifArtifact, seen map[string]bool) (sarifArtifact, string, bool) {
	if a.Index != nil && *a.Index != -1 {
		if *a.Index < 0 || *a.Index >= len(r.Artifacts) {
			return a, "", false
		}
		indexed := r.Artifacts[*a.Index].Location
		if a.URI == "" {
			a.URI = indexed.URI
		}
		if a.Base == "" {
			a.Base = indexed.Base
		}
	}
	u, err := url.Parse(a.URI)
	if err != nil {
		return a, "", false
	}
	if u.IsAbs() || a.Base == "" {
		return a, a.URI, true
	}
	if len(seen) >= 8 || seen[a.Base] {
		return a, "", false
	}
	base, ok := r.Bases[a.Base]
	if !ok {
		return a, "", false
	}
	seen[a.Base] = true
	_, resolved, ok := r.resolve(base, seen)
	if !ok {
		return a, "", false
	}
	b, err := url.Parse(resolved)
	if err != nil {
		return a, "", false
	}
	return a, b.ResolveReference(u).String(), true
}
func (r *commonSARIFRun) artifact(a sarifArtifact, b *commonBudget, d *FindingDetail) FindingArtifact {
	a, resolved, ok := r.resolve(a, map[string]bool{})
	if !ok {
		d.note("An artifact reference or URI base could not be resolved; the supplied location is retained.")
	}
	return FindingArtifact{b.text(a.URI, 2048), b.text(a.Base, 128), b.text(resolved, 2048)}
}
func (r *commonSARIFRun) locations(items []commonSARIFLocation, b *commonBudget, d *FindingDetail) []FindingLocation {
	var out []FindingLocation
	for _, item := range takeCommon(items, 8, d) {
		p := item.Physical
		loc := FindingLocation{FindingArtifact: r.artifact(p.Artifact, b, d), Line: p.Region.Line, Column: p.Region.Column, EndLine: p.Region.EndLine, EndColumn: p.Region.EndColumn, Message: b.text(messageText(item.Message), 1024), Snippet: b.text(messageText(p.Region.Snippet), 2048)}
		if item.ID != nil && *item.ID >= 0 {
			loc.ID = item.ID
		}
		for _, logical := range takeCommon(item.Logical, 4, d) {
			name := logical.FullyQualifiedName
			if name == "" {
				name = logical.Name
			}
			if name == "" && logical.Index != nil && *logical.Index >= 0 && *logical.Index < len(r.Logical) {
				ref := r.Logical[*logical.Index]
				name = ref.FullyQualifiedName
				if name == "" {
					name = ref.Name
				}
			}
			if name != "" {
				loc.LogicalNames = append(loc.LogicalNames, b.text(name, 512))
			}
		}
		out = append(out, loc)
	}
	return out
}
func resolveWeb(w *commonSARIFWeb, cached []commonSARIFWeb, d *FindingDetail) *commonSARIFWeb {
	if w == nil || w.Index == nil || *w.Index == -1 {
		return w
	}
	if *w.Index < 0 || *w.Index >= len(cached) {
		d.note("An HTTP request or response index could not be resolved.")
		return nil
	}
	// Indexed entries supply cached fields; explicitly supplied fields take priority.
	ref := cached[*w.Index]
	if w.Target != "" {
		ref.Target = w.Target
	}
	if w.Method != "" {
		ref.Method = w.Method
	}
	if w.StatusCode != 0 {
		ref.StatusCode = w.StatusCode
	}
	if w.Reason != "" {
		ref.Reason = w.Reason
	}
	if w.Protocol != "" {
		ref.Protocol = w.Protocol
	}
	if w.Version != "" {
		ref.Version = w.Version
	}
	if w.Headers != nil {
		ref.Headers = w.Headers
	}
	if w.Body.Text != "" || w.Body.Binary != "" {
		ref.Body = w.Body
	}
	ref.NoResponseReceived = ref.NoResponseReceived || w.NoResponseReceived
	return &ref
}
func commonHeaders(headers map[string]string, b *commonBudget, d *FindingDetail) map[string]string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, key := range takeCommon(keys, 32, d) {
		value := headers[key]
		switch strings.ToLower(key) {
		case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key":
			value = "[redacted]"
			d.note("Credential and cookie headers are redacted in normalized HTTP evidence; the original SARIF is unchanged.")
		}
		name := b.text(key, 128)
		if name != "" {
			out[name] = b.text(value, 1024)
		}
	}
	return out
}
func (r *commonSARIFRun) classification(ref commonSARIFTaxonRef, b *commonBudget, d *FindingDetail) FindingClassification {
	c := FindingClassification{Taxonomy: b.text(ref.Component.Name, 128), ID: b.text(ref.ID, 256)}
	index := -1
	if ref.Component.Index != nil && *ref.Component.Index >= 0 {
		if *ref.Component.Index < len(r.Taxonomies) {
			index = *ref.Component.Index
		}
	} else {
		for i, t := range r.Taxonomies {
			if (ref.Component.Name != "" && ref.Component.Name == t.Name) || (ref.Component.GUID != "" && ref.Component.GUID == t.GUID) {
				index = i
				break
			}
		}
	}
	if index == -1 {
		d.note("A taxonomy reference could not be resolved; supplied identifiers are retained.")
		return c
	}
	taxonomy := r.Taxonomies[index]
	if (ref.Component.Name != "" && ref.Component.Name != taxonomy.Name) || (ref.Component.GUID != "" && ref.Component.GUID != taxonomy.GUID) {
		d.note("Taxonomy name or GUID disagrees with its index; supplied identifiers are retained.")
		return c
	}
	c.Taxonomy = b.text(taxonomy.Name, 128)
	var selected *commonSARIFDescriptor
	if ref.Index != nil && *ref.Index >= 0 && *ref.Index < len(taxonomy.Taxa) {
		selected = &taxonomy.Taxa[*ref.Index]
	} else {
		for i, t := range taxonomy.Taxa {
			if (ref.ID != "" && t.ID == ref.ID) || (ref.GUID != "" && t.GUID == ref.GUID) {
				selected = &taxonomy.Taxa[i]
				break
			}
		}
	}
	if selected == nil {
		d.note("A taxonomy descriptor could not be resolved; supplied identifiers are retained.")
		return c
	}
	if (ref.ID != "" && ref.ID != selected.ID) || (ref.GUID != "" && ref.GUID != selected.GUID) {
		d.note("Taxonomy descriptor identifiers disagree with its index; supplied identifiers are retained.")
		return c
	}
	c.ID = b.text(selected.ID, 256)
	c.Name = b.text(selected.Name, 512)
	c.Description = b.text(messageText(selected.Short), 1024)
	c.HelpURI = b.text(selected.HelpURI, 2048)
	return c
}

func enrichCommonFinding(d *FindingDetail, runRaw, resultRaw, ruleRaw json.RawMessage) error {
	var run commonSARIFRun
	var result commonSARIFResult
	if err := json.Unmarshal(runRaw, &run); err != nil {
		return err
	}
	if err := json.Unmarshal(resultRaw, &result); err != nil {
		return err
	}
	// Rule relationships may also associate results with run-level taxonomies.
	var rule struct {
		Relationships []struct {
			Target commonSARIFTaxonRef `json:"target"`
		} `json:"relationships"`
	}
	if len(ruleRaw) > 0 {
		if err := json.Unmarshal(ruleRaw, &rule); err != nil {
			return err
		}
	}
	for _, relationship := range takeCommon(rule.Relationships, 16, d) {
		ref := relationship.Target
		for i, taxonomy := range run.Taxonomies {
			if (ref.Component.Name != "" && ref.Component.Name == taxonomy.Name) || (ref.Component.GUID != "" && ref.Component.GUID == taxonomy.GUID) {
				index := i
				ref.Component.Index = &index
				result.Taxa = append(result.Taxa, ref)
				break
			}
		}
	}
	b := &commonBudget{remaining: 48 << 10, truncated: &d.Truncated}
	d.Context.AutomationID = b.text(run.Automation.ID, 2048)
	d.Context.BaselineState = b.text(result.BaselineState, 32)
	d.Context.FirstDetectedAt = b.text(result.Provenance.First, 64)
	d.Context.LastDetectedAt = b.text(result.Provenance.Last, 64)
	if result.AnalysisTarget != nil {
		a := run.artifact(*result.AnalysisTarget, b, d)
		d.Context.AnalysisTarget = &a
	}
	for _, r := range takeCommon(run.Repositories, 8, d) {
		d.Context.Repositories = append(d.Context.Repositories, SourceRepository{b.text(r.URI, 2048), b.text(r.Revision, 256), b.text(r.Branch, 256)})
	}
	for _, i := range takeCommon(run.Invocations, 8, d) {
		d.Context.Invocations = append(d.Context.Invocations, ScanInvocation{b.text(i.StartedAt, 64), b.text(i.EndedAt, 64), i.Success})
	}
	d.Locations = run.locations(result.Locations, b, d)
	d.RelatedLocations = run.locations(result.Related, b, d)
	if d.AgentFinding != nil {
		d.Evidence = append(d.Evidence, FindingEvidence{Kind: "agent", Text: b.text(d.AgentFinding.Finding.Evidence, 8192)})
	}
	for _, a := range takeCommon(result.Attachments, 8, d) {
		artifact := run.artifact(a.Artifact, b, d)
		d.Evidence = append(d.Evidence, FindingEvidence{Kind: "attachment", Text: b.text(messageText(a.Description), 2048), Artifact: &artifact})
	}
	w := resolveWeb(result.Request, run.Requests, d)
	response := resolveWeb(result.Response, run.Responses, d)
	if w != nil || response != nil {
		d.HTTP = &HTTPExchange{}
		if w != nil {
			d.HTTP.Request = &HTTPRequest{Method: b.text(w.Method, 32), Target: b.text(w.Target, 2048), Protocol: b.text(w.Protocol, 32), Version: b.text(w.Version, 32), Headers: commonHeaders(w.Headers, b, d), Body: b.text(w.Body.Text, 8192)}
			if w.Body.Binary != "" {
				d.note("Binary HTTP bodies are available only in the original SARIF.")
			}
		}
		if response != nil {
			d.HTTP.Response = &HTTPResponse{StatusCode: response.StatusCode, Reason: b.text(response.Reason, 128), Protocol: b.text(response.Protocol, 32), Version: b.text(response.Version, 32), Headers: commonHeaders(response.Headers, b, d), Body: b.text(response.Body.Text, 8192), NoResponseReceived: response.NoResponseReceived}
			if response.Body.Binary != "" {
				d.note("Binary HTTP bodies are available only in the original SARIF.")
			}
		}
	}
	for _, ref := range takeCommon(result.Taxa, 16, d) {
		d.Classifications = append(d.Classifications, run.classification(ref, b, d))
	}
	if d.AgentFinding != nil {
		for _, cwe := range d.AgentFinding.Finding.CWEs {
			d.Classifications = append(d.Classifications, FindingClassification{Taxonomy: "CWE", ID: b.text(cwe, 64)})
		}
	}
	if d.Finding.HelpURI != "" {
		d.References = append(d.References, FindingReference{"rule", b.text(d.Finding.HelpURI, 2048)})
	}
	if result.Viewer != "" {
		d.References = append(d.References, FindingReference{"viewer", b.text(result.Viewer, 2048)})
	}
	for _, u := range takeCommon(result.WorkItems, 8, d) {
		d.References = append(d.References, FindingReference{"work_item", b.text(u, 2048)})
	}
	projectFingerprints := func(values map[string]string) map[string]string {
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if len(keys) == 0 {
			return nil
		}
		out := map[string]string{}
		for _, key := range takeCommon(keys, 16, d) {
			name := b.text(key, 128)
			if name != "" {
				out[name] = b.text(values[key], 2048)
			}
		}
		return out
	}
	d.Fingerprints = projectFingerprints(result.Fingerprints)
	d.PartialFingerprints = projectFingerprints(result.PartialFingerprints)
	if d.Finding.SeveritySource != "rule.properties.security-severity" && d.Finding.SeveritySource != "agent.severity" {
		d.note("Severity is mapped from SARIF level; no numeric security score was supplied.")
	}
	return nil
}
