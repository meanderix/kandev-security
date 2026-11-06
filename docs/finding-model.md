# Common finding model

Requires Kandev **0.99.0** or later.

Finding normalization uses standard SARIF 2.1.0 fields across producers. The same
model is available through `findings.get`, the native `get_finding` MCP tool,
the finding drawer, and excerpts in finding task prompts. Source values are
scanner or agent claims; normalization does not verify them.

## Summary fields

Report, occurrence, issue, and MCP finding lists retain their existing fields and
add the following small fields:

| Field | Meaning |
| --- | --- |
| `title` | Rule short description, then rule name, then result message; native LLM findings use their title. Bounded to 512 UTF-8 bytes. |
| `kind` | SARIF evaluation state: `fail`, `review`, `pass`, `open`, `informational`, or `notApplicable`. Defaults to `fail`. This is not a security/operational category or the plugin's manual issue status. |
| `rank` | Optional scanner priority, 0–100. Missing or SARIF's unknown value `-1` is omitted. This is neither CVSS nor confidence. |
| `severity_source` | `rule.properties.security-severity`, `result.level`, `rule.defaultConfiguration.level`, `sarif.default`, or `agent.severity`. Existing severity precedence and sorting are unchanged. A supplied security score of zero remains distinguishable from an unknown score. |
| `confidence_source` | `agent.confidence` for native LLM findings. Other confidence values are not inferred from priority, severity, or arbitrary properties. |

Titles participate in existing free-text searches. The list uses the result
message when the title only repeats the rule ID, preserving package details in
dependency results. The original message remains available in all cases.

## Detail fields

`findings.get` and `get_finding` add these fields alongside the existing
`title`, `description`, `guidance`, `fixes`, `finding`, `report`, and `run`:

| Field | Standard source |
| --- | --- |
| `context.automation_id` | `run.automationDetails.id`; preserved without inferring its naming convention. |
| `context.analysis_target` | `result.analysisTarget`; the scanned artifact can differ from the finding location. |
| `context.repositories` | Multiple `run.versionControlProvenance` records, each with `uri`, optional `revision`, and `branch`. |
| `context.invocations` | Invocation `started_at`, `ended_at`, and optional `execution_successful`, including explicit `false`. |
| `context.first_detected_at`, `last_detected_at` | `result.provenance.firstDetectionTimeUtc` / `lastDetectionTimeUtc`. |
| `context.baseline_state` | Scanner-supplied `result.baselineState`, independent of manual issue status. |
| `locations`, `related_locations` | Physical/logical locations, region start/end coordinates, snippets, messages, and related location IDs. |
| `http.request`, `http.response` | Inline web evidence or references into `run.webRequests` / `run.webResponses`; method, target, status, protocol/version, headers, and textual bodies. |
| `classifications` | `result.taxa` resolved against `run.taxonomies`, plus named taxonomy references in rule relationships. Native LLM CWE claims use the same model. |
| `evidence` | Attachment descriptions and artifact references; native LLM supporting evidence. Location snippets remain in `locations`. |
| `references` | Rule help, hosted viewer, and work item URIs, each identified by `kind`. |
| `fingerprints`, `partial_fingerprints` | Supplied scanner identity evidence; bounded copies for inspection. |
| `normalization_notes` | Explanations of unresolved references, omitted binary HTTP bodies, credential header redaction, or severity inferred from SARIF level. |

Artifact references contain `uri`, optional `uri_base_id`, and `resolved_uri`.
The resolver follows artifact indices and chained `originalUriBaseIds` with
cycle protection. This only enriches detail evidence: stored primary URIs and
persistent issue identities do not change. It never fetches paths, URLs,
attachments, or external property files.

Detection and invocation timestamps are separate from report import/reimport
timestamps. Existing sorting continues to use import timestamps. An invocation
marked successful does not establish complete coverage or absence of findings.

## Limits and rendering

Large evidence stays out of list pages. Detail projections include up to eight
primary and eight related locations (2 KiB snippets), eight attachments, eight
repositories, eight invocations, sixteen classifications, sixteen entries per
fingerprint map, and eight work item references. Each HTTP body is limited to
8 KiB; each header set to 32 entries with values up to 1 KiB. Projected text has
an additional shared 48 KiB budget measured after JSON escaping. Existing
description/guidance limits and the host response cap still apply.

`truncated: true` indicates shortened content or omitted entries. Unresolved
optional references retain the supplied identifiers where possible and add a
note. Malformed optional evidence does not make the original finding unreadable.
The original SARIF remains the source for complete evidence.

The UI renders snippets, HTTP headers, and HTTP bodies as literal text, including
HTML bodies. Only HTTP(S) references become links. Credential/cookie headers
(`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`,
case insensitive) are redacted in normalized HTTP evidence. This is not a general
secret scrubber: bodies, URLs, and original SARIF can contain sensitive values.

## Evidence projection and boundaries

Summary fields and search values are populated on import. Details are projected
from retained SARIF on demand, preserving original source bytes and evidence.

This is a bounded subset of SARIF rather than a complete implementation. Message
ID expansion, external property files, extension rule tables, code/data-flow
graphs, and fix edit application are not resolved. Custom scanner property bags
remain in the source report. ZAP's custom `solution`/`confidence` properties,
OSV package enrichment, semantic environment/category inference, and new matching
or presentation grouping policies are separate work. Missing data is left
unknown rather than guessed from prose or lockfile extensions.
