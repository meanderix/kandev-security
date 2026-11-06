# Start tasks from security findings

Requires Kandev **0.99.0** or later.

Each row in the aggregated findings view and each finding drawer has a **Start
task** menu. Choose a preset to open Kandev's native task creation dialog with a
prepared title and description. Review the prompt and choose the workflow,
repository, agent and other native task options before creating or starting it.
Selecting a preset alone does not create a task or start an agent.

The `{{evidence}}` placeholder and default finding context include bounded
excerpts from the [common finding model](finding-model.md), including snippets
and HTTP evidence when supplied. Full details remain available through MCP.

The initial presets are **Investigate**, **Fix**, and **Add regression coverage**.
They ask the agent to verify the finding rather than assume scanner output is a
confirmed vulnerability. Further evidence can be read through the plugin's
existing [audit MCP tools](agent-tools.md), when Kandev MCP is enabled for the
chosen agent profile.

## Workspace-shared settings

Open **Settings > Workspaces > your workspace > Integrations > Kandev Security**
and edit **Task presets**. The Security page's header menu and each Start task
menu also contain a **Task presets** shortcut to that workspace's settings.

You can change names, descriptions, icons and prompt templates, add/remove
presets, and reorder them. Use the native settings save bar to save your edits.
A local Save button is provided when that host facility is unavailable.

Presets are stored in the plugin SQLite database by **workspace ID**, with no
user-specific override. All members reading the same workspace see the same
saved definitions. Another workspace has its own defaults/overrides. Callers
allowed to invoke the workspace preset-save action can edit these shared values;
the plugin does not add a separate role or administrator-only policy.

Saves use an expected revision. If another editor saved first, your save returns
a conflict and retains your local draft. Reload the workspace presets, review the
other editor's changes, and reapply your edits. **Reload presets** asks before
discarding unsaved changes. Open Start task menus refresh their preset list, and
task preparation resolves the selected preset from the current server settings.
There is no live push synchronization between open preset editors.

**Reset to defaults** asks for confirmation and immediately resets the shared
workspace configuration. It preserves the revision counter so older edits cannot
overwrite the reset. Saving an empty preset list intentionally disables preset
launches until presets are added or reset. Existing tasks and task links remain.

## Prompt context and placeholders

A prepared task includes the chosen finding's exact source report ID, SHA-256,
zero-based ordinal, persistent issue ID, scanner, severity, location, available
repository/revision, description, evidence and suggested remediation. For a
grouped row this is the representative occurrence shown in that row. The drawer
can select a different occurrence before starting a task from it.

The full evidence block is always included, even if a custom template omits it.
Imported content is explicitly marked as untrusted evidence. The task prompt
asks the agent to verify repository/revision and distinguish claims from verified
conclusions. Source descriptions and remediation are bounded in prepared prompts;
original SARIF remains available through the audit tools/export.

Supported placeholders:

| Placeholder | Value |
| --- | --- |
| `{{finding}}` | Complete source evidence and reference block |
| `{{title}}`, `{{rule}}`, `{{severity}}` | Finding message, rule ID, normalized severity |
| `{{scanner}}`, `{{language}}`, `{{location}}` | Scanner, language and primary location |
| `{{description}}`, `{{evidence}}`, `{{remediation}}` | Available finding context |
| `{{repository}}`, `{{revision}}` | Scanner-supplied repository provenance |
| `{{issue_id}}` | Persistent grouped issue ID |
| `{{report_id}}`, `{{sha256}}`, `{{ordinal}}` | Exact report evidence reference |

Substitution runs once; placeholder-looking text inside scanner evidence is not
interpreted as another template. Unknown placeholders are rejected on save.
Use a template such as:

```text
Investigate this finding using our team's review procedure.
Check applicability to the checked-out revision before proposing changes.

{{finding}}
```

## Linked tasks and recovery

After native task creation succeeds, the plugin verifies the task's actual
workspace and links it to the persistent issue. Rows show a linked-task count;
the Start task menu lists the linked tasks and their current states. Links work
across reports containing the same issue. They survive deletion of individual
report occurrences because the issue itself is retained.

A task whose details cannot be read is shown as unavailable; its previous title
or state is not presented as current. Link counts count stored associations,
including tasks whose current details are unavailable. The plugin does not
create another task automatically because a link already exists; the user can
choose whether another investigation or remediation task is appropriate.

If creation succeeds but saving its issue association fails, Security shows a
pending-link message with **Retry linking** and **Open task**. Retrying links the
already-created task; it does not submit another task creation. Keep the page
open until linking completes: pending recovery is held in the plugin UI session,
not persisted across a full browser reload. A workspace switch hides pending
entries for other workspaces; returning to the original workspace reveals them.

Task completion does not close or reopen the security issue. Review status
remains explicit and manual. The preset ID is retained on each association;
changing/deleting a preset does not alter tasks already created from it.

## Workspace actions

These use the normal authenticated Kandev plugin action endpoint and workspace
envelope documented in the [API guide](api.md). Upload-only tokens cannot manage
presets or read/link tasks.

| Action | Body | Result |
| --- | --- | --- |
| `task_presets.get` | `{}` | `presets`, `revision`, `customized`, `updated_at`, `updated_by` |
| `task_presets.save` | `expected_revision`, `presets` | Updated shared settings |
| `task_presets.reset` | `expected_revision` | Defaults with a new revision |
| `tasks.prepare` | Report `id`, required `ordinal`, `preset_id` | Prefilled native dialog data and workflow defaults; creates no task |
| `tasks.link` | `issue_id`, `task_id`, `preset_id` | `linked: true`, safe to repeat |
| `tasks.list` | `issue_id`, optional `offset` | Paged `items`, `total`, `next_offset`; current title/state or `unavailable` |

A preset has `id`, `label`, `hint`, `icon`, and `prompt_template`. Supported icons
are `search`, `tool`, `bug`, `check`, `code`, and `shield`. Limits are 20 presets,
128 bytes per unique ID, 80 per name, 160 per hint, 8 KiB per template, and 60 KiB
for the encoded preset list. Expanded descriptions are capped at 64 KiB. String
limits count UTF-8 bytes. Task link pages contain at most 25 entries.

Task preparation selects the first visible workspace workflow that has steps,
using the Host's public workflow projection and its start step when available.
The native dialog retains its normal workflow/last-used selection behavior.
Workspaces without a usable workflow receive an explanatory error.

The plugin requests Host **read** access to `workflows` and `tasks` in addition to
its existing `workspaces` access. Task creation itself uses Kandev's native dialog
and normal authenticated task flow; this feature adds no plugin Host task-write
capability and no task-creation MCP tool.

