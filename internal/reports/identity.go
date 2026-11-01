package reports

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

const IdentityVersion = 1

type fingerprintPart struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type findingIdentity struct {
	Version         int               `json:"version"`
	Method          string            `json:"method"`
	Scope           string            `json:"scope"`
	Repository      string            `json:"repository,omitempty"`
	Branch          string            `json:"branch,omitempty"`
	Category        string            `json:"category,omitempty"`
	Scanner         string            `json:"scanner"`
	Rule            string            `json:"rule"`
	SourceBaseID    string            `json:"source_base_id,omitempty"`
	Path            string            `json:"path,omitempty"`
	Fingerprints    []fingerprintPart `json:"fingerprints,omitempty"`
	FingerprintType string            `json:"fingerprint_type,omitempty"`
	ContextHash     string            `json:"context_hash,omitempty"`
	LogicalLocation string            `json:"logical_location,omitempty"`
	Ecosystem       string            `json:"ecosystem,omitempty"`
	Package         string            `json:"package,omitempty"`
	ReportDigest    string            `json:"report_digest,omitempty"`
	Ordinal         *int              `json:"ordinal,omitempty"`
	Reason          string            `json:"-"`
}

func digestBytes(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func (i findingIdentity) key() string { raw, _ := json.Marshal(i); return string(raw) }
func (i findingIdentity) id(workspace string) string {
	raw, _ := json.Marshal(struct {
		Workspace string          `json:"workspace"`
		Identity  findingIdentity `json:"identity"`
	}{workspace, i})
	return digestBytes(raw)
}
func identityPath(uri string) string {
	value := strings.ReplaceAll(uri, `\`, "/")
	if u, err := url.Parse(value); err == nil && u.Scheme == "file" {
		if u.Host != "" && u.Host != "localhost" {
			return "file://" + u.Host + u.EscapedPath()
		}
		if decoded, err := url.PathUnescape(u.EscapedPath()); err == nil {
			value = decoded
		}
	}
	if u, err := url.Parse(value); err == nil && len(u.Scheme) > 1 && u.Scheme != "file" {
		return u.String()
	}
	if value == "" {
		return ""
	}
	return path.Clean(value)
}
func absoluteIdentityPath(value string) bool {
	return strings.HasPrefix(value, "/") || strings.HasPrefix(value, "file://") || (len(value) > 2 && value[1] == ':' && value[2] == '/')
}
func normalizeRepository(value string) string {
	value = strings.TrimSuffix(strings.TrimRight(strings.TrimSpace(value), "/"), ".git")
	if u, err := url.Parse(value); err == nil && u.Host != "" {
		u.Host = strings.ToLower(u.Host)
		if u.User != nil {
			u.User = url.User(u.User.Username())
		}
		return u.String()
	}
	return value
}
func occurrenceIdentity(base findingIdentity, reportDigest string, ordinal int, reason string) findingIdentity {
	base.Method = "occurrence-only"
	base.Scope = "report"
	base.ReportDigest = reportDigest
	base.Ordinal = &ordinal
	base.Fingerprints = nil
	base.FingerprintType = ""
	base.ContextHash = ""
	base.LogicalLocation = ""
	base.Reason = reason
	return base
}
func readFingerprints(raw json.RawMessage) []fingerprintPart {
	if len(raw) == 0 || len(raw) > 16<<10 {
		return nil
	}
	var values map[string]string
	if json.Unmarshal(raw, &values) != nil || len(values) > 16 {
		return nil
	}
	keys := []string{}
	for key, value := range values {
		if len(key) > 128 || len(value) > 2048 {
			return nil
		}
		if key != "" && strings.TrimSpace(value) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	result := []fingerprintPart{}
	for _, key := range keys {
		result = append(result, fingerprintPart{key, values[key]})
	}
	return result
}

var osvPackageMessage = regexp.MustCompile(`^Package '([^'\r\n]+)' is vulnerable to '([^'\r\n]+)'`)

func osvDependency(f Finding) (string, string, bool) {
	if f.Tool != "osv-scanner" {
		return "", "", false
	}
	match := osvPackageMessage.FindStringSubmatch(f.Message)
	if len(match) != 3 || match[2] != f.RuleID {
		return "", "", false
	}
	split := strings.LastIndex(match[1], "@")
	if split < 1 || split == len(match[1])-1 || split > 512 {
		return "", "", false
	}
	ecosystem := ""
	switch strings.ToLower(path.Base(identityPath(f.URI))) {
	case "composer.lock":
		ecosystem = "Composer"
	case "yarn.lock", "package-lock.json", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lock", "bun.lockb":
		ecosystem = "npm"
	case "poetry.lock", "uv.lock", "pipfile.lock", "requirements.txt":
		ecosystem = "PyPI"
	case "cargo.lock":
		ecosystem = "crates.io"
	case "go.sum", "go.mod":
		ecosystem = "Go"
	case "gemfile.lock":
		ecosystem = "RubyGems"
	default:
		return "", "", false
	}
	return ecosystem, match[1][:split], true
}
func buildFindingIdentity(run Run, category string, f Finding, full, partial json.RawMessage, snippet, logical, baseID, reportDigest string) findingIdentity {
	base := findingIdentity{Version: IdentityVersion, Scanner: f.Tool, Rule: f.RuleID, Repository: normalizeRepository(run.Repository), Branch: run.Branch, Category: category, Path: identityPath(f.URI), SourceBaseID: baseID}
	fallback := func(reason string) findingIdentity { return occurrenceIdentity(base, reportDigest, f.Ordinal, reason) }
	if f.RuleID == "" || len(category) > 2048 || len(baseID) > 2048 {
		return fallback("A stable rule and bounded analysis category are required for matching.")
	}
	switch {
	case base.Repository != "":
		base.Scope = "repository"
	case absoluteIdentityPath(base.Path):
		base.Scope = "absolute-path"
	default:
		return fallback("No repository identity or absolute source path was supplied; kept separate across reports.")
	}
	if base.Path == ".." || strings.HasPrefix(base.Path, "../") {
		return fallback("The source path escapes an unknown repository root; kept separate.")
	}
	if ecosystem, pkg, ok := osvDependency(f); ok {
		base.Method = "dependency"
		base.Ecosystem = ecosystem
		base.Package = pkg
		base.Reason = "OSV package, ecosystem, vulnerability and manifest identity; installed versions remain separate occurrences."
		return base
	}
	if len(readFingerprints(full)) > 0 {
		base.Fingerprints = readFingerprints(full)
		base.FingerprintType = "fingerprints"
	} else {
		base.Fingerprints = readFingerprints(partial)
		base.FingerprintType = "partialFingerprints"
	}
	if len(base.Fingerprints) > 0 {
		base.Method = "scanner-fingerprint"
		base.Reason = "Scanner fingerprints, rule, source scope, path and analysis context match."
		return base
	}
	if base.Path != "" && strings.TrimSpace(snippet) != "" && len(logical) <= 2048 {
		base.Method = "code-context"
		base.ContextHash = digestBytes([]byte(strings.TrimSpace(strings.ReplaceAll(snippet, "\r\n", "\n"))))
		base.LogicalLocation = logical
		base.Reason = "Rule, path and exact normalized code context match; line numbers are excluded."
		return base
	}
	return fallback("No reliable fingerprint, dependency identity or code context was supplied; kept separate.")
}
func separateAmbiguousIdentities(findings []Finding, reportDigest string) {
	counts := map[string]int{}
	for _, f := range findings {
		if f.identity.Method != "occurrence-only" && f.identity.Method != "dependency" {
			counts[f.identity.key()]++
		}
	}
	for index := range findings {
		f := &findings[index]
		if counts[f.identity.key()] > 1 {
			f.identity = occurrenceIdentity(f.identity, reportDigest, f.Ordinal, "This identity occurs more than once in the same report and is ambiguous; kept separate.")
		}
	}
}
