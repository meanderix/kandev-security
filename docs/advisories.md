# Advisory view

Requires Kandev **0.97.0** or later.

Open **Security → Advisories**, or visit `/security/advisories`. All findings
remains the default Security page. The advisory page collects retained findings
under an advisory identifier, across reports, scanners, packages, and targets in
the active workspace. It does not merge persistent issues or change review status.

Each row shows the highest severity among matching findings, a representative
title, and counts of findings, distinct issues, reports, and scanners. Open a row
to browse the affected source findings, including their package/version messages,
locations and source reports. Open any finding for full evidence, issue history,
and the existing **Start task** menu. Package details come from result messages;
the page does not infer package identities from shared rule descriptions.

## Grouping

- Exact **CVE** and **GHSA** identifiers group across scanners, with canonical
  casing. This is grouping by the claimed identifier, not advisory verification.
- Other nonempty rule IDs are included when the rule has the conventional SARIF
  `properties.tags` value `vulnerability`. These are scoped to the exact scanner
  name, so two producers' private IDs do not become the same advisory. This
  accommodates vendor/private vulnerability IDs such as Trivy's `TEMP-…` IDs.
- Other rules, including ZAP's ordinary numeric alert IDs and untagged CWE rule
  IDs, remain accessible through **All findings**.
- CVE/GHSA aliases are not inferred: different identifiers remain separate even
  if an external database might relate them. Advisory groups have no shared
  lifecycle, bulk close operation, or automatic task/remediation state.

Search matches advisory identifiers, finding titles, source messages (including
reported package names), rule IDs, and paths. Scanner filtering selects source
findings first. Severity filtering selects advisory groups by their highest
severity after the other filters. Drill-down includes all severities for that
advisory within the selected scanner/search filters, so affected lower-severity
findings are not hidden.

Sorting supports severity, newest, oldest, recently updated and least recently
updated. Dates use first/last report import times among currently matching,
retained occurrences. Deleting a report removes its contributions to counts,
severity and dates. List and drill-down pages contain at most 25 rows, with
deterministic tie breakers. List filters/page position are retained when returning
from the drill-down; workspace changes clear previous workspace results.

## API

These read-only actions use normal authenticated workspace authorization and the
existing `/api/plugins/kandev-security/actions/<action>` endpoint:

| Action | Body | Result |
| --- | --- | --- |
| `advisories.list` | Optional `search`, `tool`, `severity`, `sort`, `offset`; `language` and `rule` are also supported | `items`, `total`, `finding_count`, `severity_counts`, `next_offset` |
| `advisories.findings` | `id`: the opaque advisory `key`; optional `search`, `tool`, `language`, `rule`, `sort`, `offset` | Existing aggregate finding page with exact report IDs, ordinals, issue IDs, severity counts and source metadata |

Each list item has `key`, `id`, `namespace`, `title`, `severity`,
`occurrence_count`, `issue_count`, `report_count`, `scanner_count`,
`first_imported_at`, and `last_imported_at`. `finding_count` counts occurrences
across matching groups; `severity_counts` counts groups and ignores the selected
severity, matching the existing overview convention.

Do not send `severity` to `advisories.findings`: drill-down intentionally includes
all severities. Unknown or workspace-inaccessible groups return `404`. Reuse the
existing `findings.get` action or `get_finding` MCP tool for individual evidence.
Plugin upload tokens cannot read these actions.

The advisory index is populated when reports are imported. Deleting source
findings cascades to the index. Issue identities, review history and task links
remain independent of advisory grouping.
