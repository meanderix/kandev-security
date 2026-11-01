# Changelog

Kandev Security has not yet been published. This history groups development
changes by minor version, with patch changes included under their corresponding
minor version. It starts with the first packaged Security implementation, 0.2;
release history inherited from the plugin template is excluded.

## 0.14 — Agent review updates and database initialization

- Add the native MCP `set_issue_status` tool to set an issue's review status and
  reason. Supplying the current status allows agents to update the reason alone.
- Record verified task/session attribution and distinguish reason updates from
  status transitions in review history. Show the current review reason in the
  finding drawer while keeping the UI's Close/Reopen controls.
- Apply agent reviews atomically with invocation receipts. Retrying a completed
  invocation cannot overwrite a later review decision.
- Replace unpublished database migrations and source backfills with one atomic
  current-schema initializer. Existing current-format databases remain readable;
  incompatible development databases are rejected without being reset or deleted.
- Give all five severity levels distinct light/dark colours, with matching badge
  backgrounds and subdued counters with neutral counts. Reserve tinted counter
  backgrounds and coloured borders for the selected severity filter. Use neutral
  grays for Informational badges and counters in both themes.
- Reorganize the README, add an import-to-task sequence diagram, and remove
  unpublished plugin version requirements from the feature guides.
- Remove the unused source-control recipe, historical template baseline, and
  recipe-only tooling and dependencies.
- Simplify CI, release and package verification around the Security plugin, and
  use the local Playwright dependency for installed-host smoke tests.

## 0.13 — Report archiving and browsing filters

- Add reversible report archiving and Archive/Restore controls beside Pin report.
  Default discovery, aggregate findings and advisories use active reports;
  archived evidence remains available through explicit selection and export.
- Preserve archive state across identical reimports. Archiving remains independent
  of pinning and retention: archived reports can still expire unless pinned.
- Align Reports with the aggregated view using a full-width scrollable list,
  result ranges, page-number navigation, Active/All/Archived buttons with counts,
  and a compact Upload report shortcut.
- Add a searchable scanner filter and case-insensitive filename search, with
  combined filtering, matching counts, debounced search and pagination resets.
- Extend `reports.list` with archive status, exact scanner membership, filename
  search and consistent counts; add `reports.tools` scanner discovery, including
  scanners from zero-finding reports. Expose archive selection through MCP report
  discovery and the authenticated `reports.archive` action.
- Add an All/Open/Closed status dropdown to both grouped issues and report
  occurrences. Severity totals and pagination follow the selected review status;
  extend `findings.list` with the same filter.

## 0.12 — Workspace report retention

- Add disabled-by-default, workspace-shared retention settings with maximum
  report counts and ages per scanner, plus scanner-specific overrides.
- Provide a read-only cleanup preview, revision-checked settings saves, manual
  cleanup, and automatic cleanup after imports, at startup and hourly.
- Add report pins that exempt reports from cleanup and count limits. Preserve
  multi-scanner reports until every applicable scanner policy allows removal.
- Base age limits on first import, preserving that date across reimports. Keep
  compact purged-source metadata, issue decisions and task links after cleanup;
  retention never automatically closes issues.
- Keep upload and agent-publication retries safe after source purging.
- Improve integration settings typography, align Report retention with Task
  presets, and remove the redundant outer Task presets card while retaining
  the host's unsaved-change indicator.

## 0.11 — Cross-scanner advisory browsing

- Add a dedicated `/security/advisories` page grouping findings across reports
  and scanners by CVE, GHSA and producer-scoped vulnerability identifiers.
- Show matching finding, issue, report and scanner counts, with search,
  scanner/severity filters, severity and import-time sorting, and pagination.
- Provide source-finding drill-down and task creation from advisory results.
  Advisory grouping remains separate from persistent issue identity and review
  status.
- Add read-only `advisories.list` and `advisories.findings` actions.

## 0.10 — Common finding and evidence model

- Normalize standard SARIF fields into a shared model covering titles, severity
  provenance, evaluation state, priority, analysis context, repository revisions,
  invocation details and scanner detection timestamps.
- Include multiple physical, logical and related locations, snippets, HTTP
  requests/responses, evidence, taxonomy classifications, references and scanner
  fingerprints, with notes for missing or unresolved information.
- Expose the model through the finding drawer, existing API/MCP tools and task
  prompts while retaining original SARIF evidence and persistent issue identity.
- Bound detail projections and HTTP bodies, redact credential headers, and render
  HTTP evidence literally. Keep scanner timestamps separate from the import
  timestamps used for sorting.

## 0.9 — Workspace task presets and finding tasks

- Add Start task menus to aggregated findings and their detail drawers, opening
  Kandev's native task dialog with finding evidence and exact source references.
- Provide Investigate, Fix and Add regression coverage presets, plus editable
  workspace-shared templates, icons and ordering in native integration settings.
- Add revision-checked preset saves and reset controls; widen the task selector
  for more readable preset choices.
- Persist verified issue/task associations and show linked task states. Allow
  recovery when saving an association fails after task creation, without creating
  a duplicate task. Task completion leaves issue review status unchanged.

## 0.8 — Agent-authored security reports

- Let task agents build reports one finding at a time through six native MCP
  tools: `start_report`, `list_report_drafts`, `get_report_draft`,
  `submit_finding`, `complete_report` and `cancel_report`.
- Store task-owned drafts across sessions with revision checks, stable finding
  IDs and retry receipts. Draft findings enter workspace views only after
  explicit completion publishes the report atomically.
- Generate immutable SARIF 2.1.0 reports and validate them against the bundled
  OASIS schema without network access.
- Record LLM origin, confidence separately from severity, supporting evidence,
  task/session attribution, declared scope, actual coverage and limitations;
  display this context with published findings.

## 0.7 — Persistent issues and deduplication

- Introduce workspace-scoped issue identities using versioned SHA-256 hashes of
  normalized scanner, rule and source context, preferring scanner fingerprints
  and conservative dependency or code evidence.
- Match recognized OSV dependency findings by package, ecosystem, advisory and
  manifest rather than installed version. Keep ambiguous or insufficiently
  supported matches separate.
- Make Grouped issues the default, with a Report occurrences toggle preserving
  access to every original finding. Show occurrence history, matching method,
  and first/last import times.
- Add manual Close/Reopen decisions with required reasons and verified actor
  history. Imports preserve review status and source findings.
- Add `issues.list`, `issues.get`, `issues.set_status` and the read-only native
  `get_issue` MCP tool.

## 0.6 — Native MCP audit tools

- Expose six read-only tools through Kandev's native MCP connection:
  `list_reports`, `get_report`, `get_audit_summary`, `list_findings`,
  `get_finding` and `list_filter_values`.
- Support Kanban and Office task agents using the authenticated task workspace,
  without a separate MCP server or agent API token.
- Require explicit report selection for audit queries and return source hashes,
  exact finding references and provenance gaps alongside bounded, paginated data.
- Document evidence handling and audit workflows, distinguishing scanner claims
  from verified conclusions.

## 0.5 — Finding details and Markdown

- Add a finding detail drawer with descriptions, scanner guidance, suggested
  fixes, safe advisory links and source metadata, backed by `findings.get`.
- Render dedicated SARIF Markdown fields with headings, lists, code, tables and
  safe links. Preserve plain-text fields, ignore imported HTML and display image
  alt text without fetching resources.
- Add clickable severity totals across all matching pages and the latest
  workspace import time, including reimports and zero-finding reports.
- Compact finding rows, shorten displayed paths and move timestamps into the
  drawer while preserving browsing state when details close.
- Use a custom SVG shield for the Security navigation entry and page header.

## 0.4 — Webhook uploads and full-width navigation

- Add direct raw-file SARIF uploads through an authenticated webhook, supporting
  curl and CI clients up to 16 MiB per request.
- Add workspace-bound upload tokens with creation, one-time secret display,
  listing and revocation. Recommend webhook uploads in the API guide; Kandev
  authentication additionally requires a host PAT when enabled.
- Make aggregated findings the default full-width view with a Jira-style search
  toolbar, searchable filter pills, immediate filter application and debounced
  search. Move view navigation into the page header menu.
- Move manual imports to a dedicated Import SARIF view and align report browsing
  with the Jira integration. Add footer pagination with row ranges/page numbers
  and a sort menu showing the selected option.
- Accept SARIF artifact and rule indices of `-1` as unknown, fixing OSV-Scanner
  imports while preserving URI/rule metadata and rejecting invalid references.
- Fix SDK interpolation so report links display their filenames.

## 0.3 — Aggregated findings

- Combine findings from multiple workspace reports in one paginated view with
  source-report links and text search.
- Add language, scanner tool, rule and severity filters, including source-language
  normalization and severity derived from security scores or SARIF levels.
- Support Severity, Newest, Oldest, Recently updated and Least recently updated
  sorting. Use first-import and reimport timestamps rather than scanner detection
  timestamps.
- Add `findings.list` and `findings.facets` actions. Identical reimports update the
  last-import timestamp while preserving the original import and findings.

## 0.2 — Workspace-owned SARIF reports

- Establish Kandev Security as a native plugin with its own SQLite database and
  workspace ownership derived from Kandev's verified action context.
- Import SARIF 2.1.0 reports through bounded, retryable chunk uploads and publish
  reports, findings and original source bytes atomically.
- Browse reports and their findings, filter/search within reports, export the
  original SARIF and delete reports through the UI and workspace-scoped actions.
- Detect exact-byte duplicate reports within each workspace using SHA-256;
  support multiple runs and zero-finding reports.
- Package native backends for Linux, macOS and Windows with a bundled UI and
  require Kandev 0.97.0 or later.
