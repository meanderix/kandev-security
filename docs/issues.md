# Persistent issues and report occurrences

The default **All findings** view groups reliable matches
into persistent issues. Each original SARIF result remains an occurrence with
its report ID, content hash and zero-based ordinal. Toggle **Grouped issues** to
**Report occurrences** to see the individual results.

## Identity version 1

An issue ID is a SHA-256 hash of canonical JSON containing the workspace and the
normalized identity below. Object keys and fingerprint names have deterministic
ordering. The database also retains the canonical identity for collision checks.

Every cross-report key includes scanner name, rule ID, normalized source path,
repository identity when supplied, `uriBaseId`, branch and `automationDetails.id`. Scanner
version, revision, severity, message text, line numbers and import timestamps are
excluded. Different workspaces, repositories, branches, analysis categories,
scanners, rules or paths do not share an issue.

Matching uses these strategies in order:

1. **OSV dependency identity.** For scanner name `osv-scanner`, the recognized
   message `Package 'name@version' is vulnerable to 'rule-id'` and a recognized
   manifest/lockfile identify ecosystem + package + vulnerability + manifest.
   Versions are intentionally excluded: two affected installed versions remain
   separate source occurrences of one package vulnerability. This does not merge
   different packages sharing a CVE or infer CVE/GHSA alias equivalence. Supported
   manifests cover Composer, npm, PyPI, crates.io, Go and RubyGems.
2. **Scanner fingerprints.** Use nonempty bounded `fingerprints`, otherwise
   `partialFingerprints`. The entire sorted set of names and values participates
   in the identity. Changes to a scanner's fingerprint names or algorithm can
   leave separate issues; no speculative aliasing occurs.
3. **Code context.** Hash the exact primary-region snippet after normalizing
   CRLF to LF and trimming surrounding whitespace. Include the primary logical
   fully qualified name when present. A stable rule and source path are required.
4. **Occurrence only.** Use report SHA-256 + ordinal when the evidence above is
   insufficient. A repository URI or absolute source path is required for
   cross-report matching. Relative paths without repository provenance remain
   separate, even if a scanner supplies a fingerprint. Paths escaping an unknown
   root remain separate. Repeated nondependency identities within one report are
   ambiguous and all stay separate.

Path normalization resolves `.`/`..`, normalizes Windows separators and decodes
local `file:` paths. Repository normalization removes a trailing `/` or `.git`,
normalizes URL host case and strips URL passwords. It does not guess equivalence
between SSH and HTTPS repository names, different checkout roots, or renamed
files. Without repository provenance, absolute paths from different CI checkout
roots can produce different issues. Scanners without reliable identity evidence
can still produce duplicate-looking rows. Source SARIF bytes are never changed.

## View, dates and review status

The findings filter bar includes **Status → All / Open / Closed**.
All is the default. It filters manual issue review state in both Grouped issues
and Report occurrences, combines with the other filters, and resets pagination
to page one. Severity counts honor status while ignoring the selected severity.
The status pill's clear button restores All; **Clear filters** also clears status
while preserving the sort order. Workspace switches reset the selection.
Closing/reopening an issue refreshes the filtered results without closing its
evidence drawer.

Language, scanner, rule and search first select matching occurrences. One
representative per issue is chosen by highest severity, highest security score,
then latest report import and exact source reference. Severity filtering happens
after this choice, so an issue belongs to one severity bucket. Counts ignore the
selected severity, keeping other severity choices available. Occurrence counts
on a row include **all active retained occurrences** of that issue, outside active
filters as well.

Newest/Oldest use first import across the issue's history; update sorts use last
import/reimport. These are import times, not scanner detection times. The drawer
shows the exact representative occurrence and all retained occurrences with
source links, matching method/scope, first/last import times, and review history.

Issues start **open**. **Close issue** and **Reopen issue** require a reason and
record the verified Kandev actor and time. Setting the current status again is a
no-op. Imports never close or reopen an issue. An omitted result does not prove
that a vulnerability is fixed, and a closed issue does not establish verified
remediation. The audit MCP tools remain read-only; the separate `set_issue_status`
write tool accepts an issue ID, status and reason. Supplying the current status
updates the reason alone. Agent history entries include task/session/invocation
attribution and distinguish `reason_updated` from `status_changed`. See
[agent review updates](agent-tools.md#update-issue-review-status-and-reason).
Report-authoring tools publish new source reports without changing review status.

Deleting a report removes its source bytes and occurrences. Issues with no
remaining occurrences disappear from the aggregate view; their canonical identity,
import dates and manual status history remain in SQLite. They can be read by
known issue ID in the same workspace and reused if a matching finding returns.
There is no automatic issue purge, scan-based closure, fuzzy matching, manual
merge/split, cross-scanner matching or cross-workspace matching.

## API and agent access

[Report retention](retention.md) can remove old files without changing manual
issue state or task links. Compact removed-source references remain in issue
history, marked `purged_at`; these cannot be opened as full findings. Retained
aggregate counts exclude them. An issue can have history but no aggregate row.
Expiry does not establish a fix.

Use `issues.list`, `issues.get` and `issues.set_status` with normal Kandev workspace
authorization; upload tokens remain import-only. See the [API guide](api.md).
Existing `findings.list`, report details and MCP audit summaries continue to count
occurrences. Finding responses expose additive `issue_id` values. Agents can use
the read-only `get_issue` tool to inspect matching evidence and review history;
see the [agent guide](agent-tools.md). Its occurrence history can include reports
outside a selected audit set, but always within the authenticated workspace.
