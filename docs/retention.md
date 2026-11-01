# Report retention

Requires Kandev **0.97.0** or later.

Open **Security → Report retention**, or **Settings → Workspaces → your
workspace → Integrations → Kandev Security**. Settings are shared by the
workspace. Automatic cleanup is **disabled by default**.

## Policies and pins

- **Maximum unpinned reports:** keep the newest N reports per exact scanner name,
  using first import time. Ties use report ID for deterministic ordering.
- **Maximum age in days:** remove reports older than this many days from their
  first import time, measured in UTC.
- **0 means unlimited** for either limit. Either enabled limit can remove a
  report; a policy with both limits at 0 keeps all reports.
- **Scanner overrides replace both defaults** for the named scanner. Names are
  exact, case sensitive `tool.driver.name` values, rather than filenames or
  scanner versions. Both limits at 0 exempt that scanner.

**Preview cleanup** shows candidate counts, source bytes, pinned count and a
bounded sample of filenames/reasons. It is read-only and uses the unsaved form.
**Save and apply retention** saves and immediately applies the policy atomically.
**Clean up now** uses the saved policy; save form changes first. Preview and
application can differ if reports or pins change in between.

Pin reports from **Reports** or an individual report page. Pinned reports are
exempt from both limits and do not consume the count budget: a limit of 20 can
keep 20 unpinned reports plus any pinned reports. Unpinning immediately applies
the saved policy and can remove that report. Pins protect against automatic
cleanup, not explicit manual deletion.

Every distinct scanner in a multi-run file counts that report once. A report
containing multiple scanners is removed only when **every** included scanner's
policy permits removal. Keeping it for one scanner can leave another scanner
above its count limit. The original file is never partially deleted. Zero-finding
reports count normally; files with no runs use a default unnamed-scanner bucket.

Cleanup runs after successful UI/webhook/MCP imports, at plugin startup, hourly
while the plugin runs, on policy saves, and on pin changes. Each workspace cleanup
is transactional. A cleanup failure rolls back a settings save or import rather
than publishing partial deletions. Failed scheduler sweeps are logged and retried
on later sweeps.

Archived reports remain subject to both limits and count normally unless pinned.
Archiving changes visibility while preserving full evidence; retention purging
removes that evidence. See [archive and restore](archiving.md).

## What remains

Cleanup removes original SARIF and full finding records from active storage.
These stop contributing to findings, advisories, facets, report lists and agent
audit summaries. Default views describe **active retained reports**, not a verified
current security state. Expiry never closes, reopens or resolves an issue.

**Purged report history** retains report IDs, workspace, filename, SHA-256,
original import/reimport dates, scanner names, original finding count/byte size,
archive time/actor when applicable, and cleanup time/actor/reason. Issues keep their identity, review decisions and
history, and task associations. Compact issue source references keep the
report/ordinal, scanner, rule, severity, location and hash. They exclude result
messages, snippets, HTTP evidence and other full finding content.

`issues.get` / MCP `get_issue` include retained and compact purged references
in their paginated occurrence history. Responses add `purged_count`; removed
sources have `purged_at` and `purge_reason`. The UI labels these as unavailable
instead of offering a finding link. Issues without retained occurrences disappear
from aggregates but remain readable by known issue ID. Export and `findings.get`
return `404` for purged sources.

Metadata history has no automatic expiry. Purging is not secure
erasure. SQLite makes deleted source pages reusable by later imports; the database
file does not necessarily shrink immediately.

## Reimports and retries

Identical bytes retain their first import time, including after purge. An explicit
reimport can restore the same report ID and source references, subject to the
current policy. A restored report still outside the policy is immediately purged
again; the import response has `report.purged_at`, `purge_reason` and `purged_by`.
The UI explains this outcome. Use a suitable policy or temporarily disable cleanup
before restoring evidence that you intend to pin.

Byte-identical reports submitted repeatedly over many days therefore eventually
expire under an age limit. Reupload timestamps do not prove a new scan. Use
count-only retention or pinning where first-import age is unsuitable.

Lost chunk-completion and exact LLM publication retries return compact report
receipts after retention removes their source; they do not regenerate the file.
Completed draft `report_available` is false. Manual report deletion keeps its
existing semantics and is distinct from retention history.

## API

Actions use normal authenticated workspace authorization through
`POST /api/plugins/kandev-security/actions/<action>`, with the existing
`{"workspaceId":"…","body":{…}}` envelope. Upload tokens cannot configure
retention, manage pins or read history.

| Action | Body | Result |
| --- | --- | --- |
| `retention.get` | `{}` | `config`, `revision`, editor/time, latest sweep time/count, scanner suggestions |
| `retention.preview` | `config` | `eligible_reports`, `eligible_bytes`, `pinned_reports`, bounded `candidates`, `has_more` |
| `retention.save` | `config`, required `expected_revision` | Updated `settings`, `purged_count`, `purged_bytes`; stale revisions return `409` |
| `retention.run` | `{}` | `purged_count`, `purged_bytes` under saved policy |
| `reports.pin` | `id`, required Boolean `pinned` | `pinned`, `retained`, `purged_count`, `purged_bytes` |
| `reports.purged.list` | Optional `offset` | Metadata `items`, `next_offset`; original content is unavailable |

Example configuration:

```json
{
  "enabled": true,
  "default": {"max_reports": 20, "max_age_days": 90},
  "overrides": [
    {"tool": "Trivy", "max_reports": 30, "max_age_days": 90},
    {"tool": "Kandev LLM audit", "max_reports": 0, "max_age_days": 0}
  ]
}
```

Limits are 100,000 reports, 36,500 days, 100 unique scanner overrides and 60 KiB
encoded configuration. History pages contain up to 25 rows and can be shortened
to respect response byte limits; always follow `next_offset`.

