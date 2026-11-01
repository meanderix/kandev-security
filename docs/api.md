# Security reports API

Requires Kandev Security installed and enabled on Kandev 0.97.0 or later.
**Direct webhook uploads are the recommended approach for scripts and
CI.** They send the original SARIF file in one request, with no base64 or chunks.

## 1. Create a workspace upload token

In Kandev, select the workspace, open **Security > Upload tokens**, enter a name
such as `CI scanner`, and choose **Create upload token**. Save the `ksr_...`
secret in your CI secret store. It is shown once and cannot be retrieved later.

Each upload token grants **import-only access to one workspace**. It cannot read
reports, delete them, or manage tokens. The database stores its SHA-256 hash,
name, issuer, creation time, last successful use, and revocation metadata.
Revoke a token from the same view when it is no longer needed.

When Kandev authentication is enabled, also create a **Kandev personal access
token (PAT)** in **Settings > Account > API Tokens**. The two credentials have
separate roles: Kandev authenticates the caller using the PAT; the plugin uses
the upload token to determine the destination workspace. No per-upload ticket
request is needed.

## 2. Upload with curl

Set `KANDEV_URL` to your Kandev base URL, `KANDEV_TOKEN` to its PAT, and
`SECURITY_TOKEN` to the workspace upload token. Use HTTPS for remote uploads.

```bash
curl --fail-with-body \
  --request POST \
  "$KANDEV_URL/api/plugins/kandev-security/webhooks/upload" \
  -H "Authorization: Bearer $KANDEV_TOKEN" \
  -H "X-Security-Token: $SECURITY_TOKEN" \
  -H "Content-Type: application/sarif+json" \
  -H "X-Security-Filename: scan.sarif" \
  --data-binary @scan.sarif
```

If Kandev authentication is disabled, omit the `Authorization` header. The
`X-Security-Token` header is always required. A Kandev PAT alone cannot upload.

The endpoint accepts raw SARIF with `application/sarif+json` or `application/json`.
It does not accept multipart (`curl -F`), base64, or query parameters.
`X-Security-Filename` is optional and defaults to `report.sarif`; path components
are discarded. Workspace IDs are not accepted as upload selectors: ownership
comes exclusively from the plugin token, and the plugin verifies that the
workspace still exists before importing. An unavailable workspace check fails
closed with `503`.

**Limits:** SARIF 2.1.0, at most **16 MiB (16,777,216 bytes)** and **50,000
findings** per direct upload. Other parser limits are listed in the [README](../README.md).
Kandev requires authenticated webhook access for request limits above 4 MiB;
this is why the PAT is required when host authentication is enabled.

A successful upload returns `200` with this shape (report metadata abbreviated):

```json
{
  "report": {
    "id": "report-id",
    "workspace_id": "workspace-id",
    "filename": "scan.sarif",
    "actor_id": "token-issuer-id",
    "finding_count": 12
  },
  "duplicate": false
}
```

New reports are attributed to the upload token's issuer. Reuploading identical
bytes into the same workspace returns `duplicate: true`, updates its last-import
time, and preserves the original filename, importer, and findings. Retrying the
same file is safe after an uncertain response, though each successful reupload
updates the last-import time.

Upload tokens do not expire automatically. Revocation prevents later imports;
an import already committing may finish before revocation completes. Tokens
are independent of PATs and user membership: revoke the plugin token separately
when access should end. Uninstalling the plugin removes its token database.

## Token management through actions

The UI uses these workspace-scoped actions. They require normal Kandev
authentication (a PAT for scripts when enabled), not a plugin upload token:

```text
POST <kandev-url>/api/plugins/kandev-security/actions/<action>
Content-Type: application/json
Authorization: Bearer <kandev-personal-access-token>
```

Every request wraps its parameters in an authorized workspace envelope:

```json
{"workspaceId":"workspace-id","body":{"name":"CI scanner"}}
```

| Action | `body` | Response |
| --- | --- | --- |
| `tokens.create` | `name` (1 to 80 bytes) | `token` metadata and a one-time `secret` |
| `tokens.list` | Optional `offset` | Metadata `items`, `next_offset`; no secrets or hashes |
| `tokens.revoke` | Token `id` | `revoked: true` (safe to repeat) |

For example, create a token once through curl and extract its secret with `jq`:

```bash
token_response="$(curl --fail-with-body \
  "$KANDEV_URL/api/plugins/kandev-security/actions/tokens.create" \
  -H "Authorization: Bearer $KANDEV_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"workspaceId":"your-workspace-id","body":{"name":"CI scanner"}}')"
SECURITY_TOKEN="$(printf '%s' "$token_response" | jq -er '.secret')"
unset token_response
```

Save the returned `secret`; it is never returned by listing. If a creation
response is lost, list the tokens, revoke the unused entry, and create another.
Any caller authorized for the workspace can manage its upload tokens. There are
at most 100 active tokens per workspace; revoked entries remain in its history.

## Agent workflows

The task-scoped MCP `set_issue_status` tool supports explicit review status/reason
changes, including same-status reason updates. Workspace authority and task/session
attribution come from Kandev. `issues.get` history includes `kind` and optional
agent task/session/invocation IDs. The existing
`issues.set_status` HTTP action keeps its same-status no-op behavior; the UI
continues to use Close/Reopen. See [agent review updates](agent-tools.md#update-issue-review-status-and-reason).

Kandev task agents can use native MCP audit reads and structured report
authoring without an API token. See the [report authoring guide](agent-reporting.md)
for individual finding submission and atomic report publication. Draft authoring
is MCP-only; the webhook remains the recommended script/CI upload
path. See the [agent audit guide](agent-tools.md). The HTTP actions below remain
available to scripts and external clients using normal Kandev authentication.

## Task presets and linked tasks

Workspace-shared task preset settings and issue/task associations use normal
authenticated workspace actions, not upload tokens.
See the [task preset guide](task-presets.md) for action schemas, permissions,
revision checks, native dialog behavior and link recovery.

## Read and manage reports

Report scanner filters use exact scanner membership, including
multi-scanner and zero-finding reports. `reports.list.status_counts` honors the
scanner and filename filters across all statuses; `total` also honors status.
`reports.tools` lists names across all retained workspace reports, independently
of the current status. Its search matches substrings without case sensitivity.
Pages contain up to 25 entries. `reports.list.search` matches
partial filenames without case sensitivity (up to 256 UTF-8 bytes). Matching is
literal, including `%` and `_`; finding content is outside this search.

These actions use the same authenticated endpoint and workspace envelope.
Default report discovery, aggregate findings/issues, advisories and facets use
active retained reports. Explicit report/finding reads and exports also support
archived reports. Archiving preserves evidence; automatic retention can still
purge it unless pinned. See [archiving](archiving.md).

| Action | `body` parameters | Response |
| --- | --- | --- |
| `reports.list` | Optional `offset`, filename `search`, exact `tool`, `status`: `active` (default), `archived`, or `all` | `items`, `next_offset`, `total`, `status_counts` (`active`, `archived`, `all`) |
| `reports.tools` | Optional `search`, `offset` | Paginated scanner-name `items`, `next_offset`; includes archived and zero-finding reports |
| `retention.get` / `retention.preview` / `retention.save` / `retention.run` | See [retention API](retention.md#api) | Shared scanner policies, previews, revision-checked application, and cleanup summaries |
| `reports.archive` | `id`, required Boolean `archived` | Updated `report` with optional `archived_at`/`archived_by`; see [archiving](archiving.md) |
| `reports.pin` | `id`, required Boolean `pinned` | Pin status, whether the source remains retained, and cleanup summary |
| `reports.purged.list` | Optional `offset` | Compact source metadata `items`, `next_offset` |
| `advisories.list` | Optional existing aggregate filters/sorts | Advisory groups with finding/issue/report/scanner counts, `total`, `finding_count`, `severity_counts`, `next_offset` |
| `advisories.findings` | Advisory `key` as `id`; existing aggregate filters/sorts except `severity` | Paginated source findings for that group |
| `reports.get` | Report `id`; optional `level`, `search`, `offset` | `report`, `runs`, `findings`, `total`, `next_offset` |
| `reports.source` | Report `id`; optional byte `offset` | Base64 `data`, `filename`, total `size`, `next_offset` |
| `reports.delete` | Report `id` | `deleted: true` |
| `issues.list` | Same filters/sorts as `findings.list`; optional `status`: `open` or `closed` | One representative per issue, nested `issue` metadata, `occurrence_count`, `total`, `next_offset`, `severity_counts`, `latest_import_at` |
| `issues.get` | Issue `id`; optional `offset`, `history_offset` | `issue`, `occurrences` with report hashes, `total`, `next_offset`, `history`, `history_next_offset` |
| `issues.set_status` | Issue `id`, `status`: `open` or `closed`, required `reason` (1–2,000 UTF-8 bytes) | `updated: true`; attributed to Kandev’s verified actor |
| `findings.list` | Optional `language`, `tool`, `rule`, `severity`, `status` (`open` or `closed`), `search`, `sort`, `offset` | Aggregate `items`, `total`, `next_offset`, `severity_counts`, `latest_import_at` |
| `findings.get` | Report `id` and finding `ordinal` (required, zero-based across the report) | `finding`, `report`, `run`, `title`, `description`, `guidance`, `fixes`, optional `markup`, `truncated` |
| `findings.facets` | `facet`: `language`, `tool`, or `rule`; optional `search`, `offset` | Suggested `items`, `next_offset` |

The `issues.*` actions expose persistent issues, and findings include `issue_id`
fields. `issues.list` is the default UI data source. Existing `findings.list` and
MCP audit counts continue to count report occurrences. No source results are
removed by grouping. See [issue matching](issues.md) for identity and retention.

For example, list grouped issues using normal Kandev authentication:

```bash
curl --fail-with-body \
  "$KANDEV_URL/api/plugins/kandev-security/actions/issues.list" \
  -H "Authorization: Bearer $KANDEV_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"workspaceId":"your-workspace-id","body":{"sort":"severity"}}'
```

`issues.get` pages occurrences and status history independently. Pass returned
`next_offset` as `offset`, and `history_next_offset` as `history_offset`.
Both are zero at the end. Repeating a status already set is a no-op; a transition
requires a reason and records the verified actor and time. Upload-only tokens
cannot read issues or change status.

Retention-purged sources remain in `issues.get` history as compact references
with `purged_at` and `purge_reason`; `purged_count` reports how many occurrences
are unavailable. History `total` includes these references. Active aggregate
counts cover retained sources only. No source messages or full evidence are
retained in these references. See [retention](retention.md).

Filters combine with AND; empty filters include all values. Language, tool, and
rule filters match exact values discoverable through `findings.facets`. Severity
values are `critical`, `high`, `medium`, `low`, and `informational`. Sort values
are `severity` (default), `newest`, `oldest`, `recently_updated`, and
`least_recently_updated`. `reports.get` instead filters the original SARIF
`level`: `error`, `warning`, `note`, or `none`.

Grouped filters first select matching occurrences, then choose the highest
severity/score representative per issue (ties use latest import and exact source
reference). Severity filtering follows grouping; counts belong to that
representative. `occurrence_count` includes all active retained occurrences of that
issue, even outside the active filters. Grouped Newest/Oldest sorts use the
issue's first-import time; update sorts use its last-import time. These historical
dates survive deletion of individual reports. Status defaults to both states.
`findings.list` supports the same manual `status` filter as
`issues.list`; omit it or send an empty string for All. Both actions apply
status to totals, pagination and severity counts. This is separate from SARIF
baseline/evaluation state and report archive status.

`issues.list.severity_counts` and `findings.list.severity_counts` contain all five severity counts over all
matching pages. It honors every filter except `severity`. `total` and `items`
continue to honor the severity filter. `latest_import_at` is the most recent
import/reimport time for any active report in the workspace, or an empty string.

Use the `report_id` and `ordinal` from a list item to request `findings.get`.
The action reads the original SARIF for rule descriptions, help, and fix
descriptions, including for older imports. Existing string fields remain text.
When dedicated SARIF `markdown` fields are present, `markup.description`,
`markup.guidance`, and aligned `markup.fixes` entries contain optional document
trees for formatted display. Nodes have `kind`, optional `text` or `children`,
and allowlisted `url`, `start`, or `align` values. HTML is omitted, images retain
only their alt text, and links accept HTTP(S) only. The UI independently restricts
nodes to supported formatting elements; consumers should do the same.
Formatting is bounded to 2,048 parsed nodes and depth 32. If these limits or the
response budget are exceeded, strings remain available as the fallback and
`truncated` is set.
Details are bounded: title 1 KiB, description 16 KiB, guidance 32 KiB, and at most
eight fix descriptions of 2 KiB each. `truncated: true` indicates shortened
content; export the original SARIF to retrieve all content. The report's original
bytes are never changed.

The additive [common finding model](finding-model.md) also exposes `context`,
`locations`, `related_locations`, `evidence`, `http`, `classifications`,
`references`, scanner fingerprints, and `normalization_notes` in finding details.
Lists add `title`, `kind`, optional `rank`, and severity/confidence provenance.
Large evidence is bounded and loaded only for an individual finding. Summary
fields and search values are populated on import.

Pages contain at most 25 entries. Continue using the returned `next_offset`;
zero means the end. For `reports.source`, offsets count decoded bytes:
base64-decode each chunk and concatenate until `next_offset` is zero.

The [advisory view guide](advisories.md) describes identifier recognition,
cross-scanner grouping, severity filtering and drill-down semantics. Advisory
groups organize source findings without changing persistent issue identities.

## Alternative: chunked uploads

The browser UI and existing clients can still use workspace-scoped upload
actions, supporting reports up to 20 MiB. They require normal Kandev
authentication and do not use workspace upload tokens:

| Action | `body` parameters | Response |
| --- | --- | --- |
| `imports.start` | `filename`, `size` in raw bytes | Upload `id`, `chunk_bytes` (currently 196608) |
| `imports.append` | Upload `id`, raw byte `offset`, base64 `data` | Next accepted `offset` |
| `imports.complete` | Upload `id` | `report`, `duplicate` |
| `imports.cancel` | Upload `id` | `cancelled: true` |

Append chunks in order, then complete. Matching chunk retries and completion
retries are safe. Unfinished uploads expire after 24 hours.

## Errors

Non-2xx responses contain an `error` message. Common statuses: `400` invalid
input/SARIF, `401` missing or invalid credentials, `403` forbidden or deleted
workspace, `404` missing resource, `405` unsupported method, `409` quota or chunk
conflict, `413` request too large, and `415` unsupported content type. Storage or
host failures can return `500`, `503`, or `504`; retry transient failures with a
bounded backoff. Never log credential headers or enable verbose curl output or shell tracing in
shared CI logs.
