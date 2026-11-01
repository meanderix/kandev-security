# Build security reports through MCP

Requires Kandev **0.97.0** or later. Task agents can
submit individual structured findings without assembling SARIF themselves. The
plugin persists a draft, then validates and generates an immutable SARIF 2.1.0
report when the agent explicitly completes it. Published results appear in the
existing report list, grouped issues, filters, finding drawers and SARIF export.

Tools are available on `kanban-task` and `office-task` surfaces, including workflow
step agents on those surfaces. Use discovered names; Kandev prefixes plugin-local
names with `kandev_kandev_security_`. No PAT or workspace upload token is needed.
The four authoring tools are declared as writes in the manifest; the original
seven audit tools remain read-only. `cancel_report` is marked destructive because
it discards unpublished findings. Normal Kandev tool availability/approval applies.

## Example workflow

The examples below show tool arguments, not an HTTP API or MCP transport envelope.

Call **`start_report`** once for each new audit:

```json
{
  "client_report_id": "sql-review-2026-10-30",
  "title": "SQL handler review",
  "instructions": "Inspect request handlers for SQL injection and report supported findings.",
  "scope": ["src/handlers", "src/database"],
  "repository": "https://example.com/team/app",
  "revision": "commit-sha-being-reviewed",
  "branch": "main",
  "analysis_category": "llm-sql-review",
  "agent_label": "Security audit agent"
}
```

Save the returned `id` and `revision` (initially zero). Repository, revision,
branch, analysis category and agent label are optional. Repository, when supplied,
must be an absolute URI such as HTTPS or SSH, without embedded passwords. Use a
stable analysis category across comparable scans; it defaults to
`llm-security-audit`. The model/agent label is self-reported, not verified.

Call **`submit_finding`** for each supported finding:

```json
{
  "draft_id": "returned-draft-id",
  "expected_revision": 0,
  "finding": {
    "finding_id": "handler-query-1",
    "title": "Request input reaches SQL construction",
    "description": "The request parameter is concatenated into a SQL statement.",
    "severity": "high",
    "confidence": "medium",
    "evidence": "src/handlers/search.go:42 passes a query containing request input to db.Query.",
    "remediation": "Use placeholders and pass the input as a query parameter.",
    "rule_id": "CWE-89",
    "cwes": ["CWE-89"],
    "uri": "src/handlers/search.go",
    "line": 42,
    "snippet": "db.Query(query + input)",
    "language": "Go"
  }
}
```

Use the returned revision for the next changed submission. Required finding fields
are `finding_id`, `title`, `description`, `severity`, `confidence`, and `evidence`.
Descriptions and remediation support safe Markdown; evidence is shown as text.
Severity is `critical`, `high`, `medium`, `low`, or `informational`. Confidence is
`low`, `medium`, or `high`; it is separate from impact. No CVSS score is fabricated.

`finding_id` is a stable retry/update key within this draft. Reusing it replaces
that draft entry. It is not an issue fingerprint. Supply a stable rule/classification
and source snippet when justified; the plugin computes conservative issue identities.
Without an explicit rule ID, findings remain separate across reports. The existing
[matching rules](issues.md) still apply; matching never changes manual review status.

Inspect **`get_report_draft`** before publication:

```json
{"draft_id":"returned-draft-id","offset":0}
```

It returns `draft` metadata and revision, paged `items` containing the submitted
finding and task/session/invocation attribution, and `next_offset`. Continue until
`next_offset` is zero. Draft findings are ordered by finding ID.

Call **`complete_report`** with the current draft revision:

```json
{
  "draft_id": "returned-draft-id",
  "expected_revision": 1,
  "completion": {
    "summary": "One supported SQL query construction risk.",
    "coverage": "Inspected search handlers and their database call sites at the declared revision.",
    "limitations": ["No runtime exploit verification.", "Dependencies were outside this review."]
  }
}
```

Summary and actual coverage are required; limitations default to an empty array.
Completion atomically generates SARIF, validates it with the plugin importer,
writes the report and issue occurrences, and records the publication receipt.
The result contains `draft_id` and the published `report`. Use its ID with the
existing [audit tools](agent-tools.md). Original structured submissions and their
attribution are retained in the generated SARIF under `properties.kandevSecurity`.

A zero-finding report can be completed, but still requires a summary and actual
coverage. Report completion means the agent finished its declared task. It does
not establish exhaustive coverage, repository security, or verified remediation.

## Recovery, ownership and retries

- Workspace, task, session and invocation come exclusively from Kandev's verified
  tool context; arguments cannot override them. Drafts are owned by **workspace +
  task**. Later sessions of the same task can resume them; another task cannot
  inspect, submit, complete or cancel them. Published reports use the existing
  workspace-wide read access.
- Use **`list_report_drafts`** with optional `status` (`draft`, `completed`,
  `cancelled`) and `offset` to recover draft IDs and receipts. Without status it
  includes all three states. Drafts survive plugin restarts and do not expire.
- Repeating `start_report` with the same task, client ID and normalized metadata
  returns the existing draft or receipt. Different metadata conflicts; use a new
  client ID for a new audit. This also applies to completed/cancelled IDs.
- An identical `submit_finding` retry is a no-op, preserving its revision,
  timestamps and original submission attribution. Changed entries require the
  latest `expected_revision`. On `conflict`, read the draft and reconcile before
  resubmitting; do not blindly retry a stale overwrite.
- Repeat a completion using the **original prepublication expected revision and
  identical completion arguments**. It returns the same report without changing
  import dates. If those arguments are lost, inspect the completed draft receipt
  for `report_id` and read that report instead.
- Published reports are immutable. Subsequent reviews create new drafts/reports.
  If a published report is deleted, retrying completion cannot recreate it; the
  receipt reports `report_available: false`.
  If [retention](retention.md) removed the source, an exact completion retry can
  return compact report metadata with `purged_at`; it never regenerates evidence.
- **`cancel_report`** takes `draft_id` and the current `expected_revision`. It
  discards unpublished findings and leaves a cancellation receipt. Repeating it
  is safe. It cannot cancel a completed report. To discard an individual finding
  without replacing it, cancel and rebuild the draft.

Draft changes are serialized with revision checks. Parallel agents sharing a task
must reconcile revisions, or use separate report drafts. Findings stay outside
the published report list and aggregate view until completion. There is no draft
editing page; recovery and cancellation use these MCP tools.

## Limits and retained data

All string limits below count UTF-8 bytes; the tool schemas also specify character
limits. Every tool argument object must fit within **16 KiB encoded**.

| Value | Limit |
| --- | --- |
| Active drafts | 25 per workspace, 100 across the installation |
| Findings per draft | 1,000 |
| Total encoded finding payloads per draft | 8 MiB |
| One encoded finding | 12 KiB |
| Finding ID / rule ID / language | 128 bytes each |
| Title / source URI / snippet | 256 / 2,048 / 2,048 bytes |
| Description / evidence / remediation | 4,096 / 4,096 / 2,048 bytes |
| CWE identifiers | Up to eight `CWE-<number>` values |
| Draft metadata / completion metadata | 12 KiB / 8 KiB encoded |
| Report title / instructions | 200 / 4,096 bytes |
| Declared scope | 1–32 entries, at most 256 bytes each |
| Completion summary / actual coverage | 2,048 / 4,096 bytes |
| Limitations | Up to 16 entries of 256 bytes each |
| Read pages | At most 25 items; follow `next_offset` |
| Generated SARIF | Existing 20 MiB importer and parser limits apply |

Completion failures roll back the report, issue links and receipt update while
preserving the draft for correction. List/detail responses use the existing
400 KiB JSON budget, shortening pages when necessary rather than losing entries.

Draft findings persist in SQLite until cancellation or successful publication.
Publication moves their evidence into the generated report and removes the draft
copies. Completed/cancelled receipts retain instructions, declared scope,
attribution, dates and completion metadata. Deleting a report removes its original
SARIF and finding occurrences; receipts cannot restore that evidence. There is no
automatic receipt purge.

Task/session identifiers recorded during native authoring come from Kandev. The
SDK does not provide a human actor ID for these tool calls: report attribution
uses `task:<task-id>`. Agent/model labels, repository/revision, evidence, severity,
confidence and coverage remain agent claims. Reimported SARIF metadata is source
content and is not independently authenticated as an original task invocation.

The generated file uses the [OASIS SARIF 2.1.0 schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json).
The test suite validates generated files against a local copy of that schema,
including URI formats. No schema download is needed at runtime.
