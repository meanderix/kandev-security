# Archive and restore reports

Requires Kandev **0.99.0** or later.

Open **Security → Reports**. **Archive report** sits beside **Pin report** on
report rows and individual report pages. Use the **Archived** or
**All** status button to find archived reports, then **Restore report** to include them again.
Archive state is shared by the workspace.

The Reports toolbar uses status buttons with counts and a searchable
**Scanner tool** filter. A filename search box matches partial names
without case sensitivity, after a short typing delay or on Enter. Its clear
button clears the search while keeping scanner/status selections. Status counts
reflect the selected scanner and filename search. Pagination
shows a result range and page number beneath the scrollable list; filters reset
to page one. **Upload report** opens the existing import page.

Archiving hides a report from the default findings, grouped issues, advisories,
filter suggestions, severity counts and latest-import indicator. If an issue has
other active sources, those remain visible and determine its representative.
Issue history includes archived sources and labels them; original evidence,
report IDs, hashes and exact SARIF exports remain available.

Archiving and restoring preserve import/reimport dates, issue identity, manual
review status, decision history and linked tasks. They never resolve findings.
Reimporting an identical file updates its reimport timestamp but leaves it
archived. Restore explicitly to include those findings again.

## Pins and automatic cleanup

Archiving is a visibility setting. **Pinning protects a report from automatic
retention.** Either active or archived reports can be pinned.

Unpinned archived reports count toward per-scanner limits and can be removed by
count or age policies. Pin an archived report if its full evidence must remain
available. Unpinning immediately applies the saved policy and can remove it.
A retention-purged report has only compact source metadata; it cannot be restored
with the archive control. See [report retention](retention.md).

## API and agents

Use authenticated workspace actions through the [API envelope](api.md):

| Action | Body | Result |
| --- | --- | --- |
| `reports.archive` | `{"id":"REPORT_ID","archived":true}` | `{"report":{...}}`, including `archived_at` and `archived_by` |
| `reports.archive` | `{"id":"REPORT_ID","archived":false}` | Restored report; archive fields omitted |
| `reports.list` | `{"status":"archived","offset":0}` | Paginated report metadata |

`status` accepts `active` (default), `archived`, or `all`. Archive requests are
idempotent: repeating `true` preserves the initial archive time and verified
actor. The host supplies workspace and actor; request bodies cannot override
them. Workspace upload tokens grant import access only.

MCP `list_reports` accepts the same optional `status` filter and defaults to
active reports. Agents can deliberately discover archived reports with
`{"status":"archived"}` or `{"status":"all"}`. Explicit `get_report`,
`get_finding`, selected-report summaries, finding lists and filter queries still
read archived reports. Report references expose `archived_at` and `archived_by`
when applicable; `get_issue` includes archived occurrences in its full history.
No MCP tool changes archive status. See [agent tools](agent-tools.md).
