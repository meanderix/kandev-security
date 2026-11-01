-- Current storage baseline. Created atomically for a new database.

CREATE TABLE draft_findings (
    draft_id TEXT NOT NULL REFERENCES report_drafts(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL,
    value_json TEXT NOT NULL,
    submission_json TEXT NOT NULL,
    PRIMARY KEY(draft_id,finding_id)
);

CREATE TABLE finding_advisories (
    report_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    advisory_key TEXT NOT NULL,
    advisory_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    PRIMARY KEY(report_id,ordinal),
    FOREIGN KEY(report_id,ordinal) REFERENCES findings(report_id,ordinal) ON DELETE CASCADE
);

CREATE TABLE findings (
    report_id TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    level TEXT NOT NULL,
    search_text TEXT NOT NULL,
    value_json TEXT NOT NULL,
    language TEXT NOT NULL DEFAULT 'Unknown',
    tool TEXT NOT NULL DEFAULT '',
    rule_id TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    severity_rank INTEGER NOT NULL DEFAULT 0,
    security_score REAL NOT NULL DEFAULT 0,
    issue_id TEXT REFERENCES issues(id),
    PRIMARY KEY(report_id,ordinal)
);

CREATE TABLE issue_agent_reviews (
    workspace_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    invocation_id TEXT NOT NULL,
    issue_id TEXT NOT NULL REFERENCES issues(id),
    requested_status TEXT NOT NULL,
    requested_reason TEXT NOT NULL,
    history_id INTEGER REFERENCES issue_status_history(id),
    created_at TEXT NOT NULL,
    PRIMARY KEY(workspace_id,task_id,session_id,invocation_id)
);

CREATE TABLE issue_purged_occurrences (
    issue_id TEXT NOT NULL REFERENCES issues(id),
    report_id TEXT NOT NULL REFERENCES purged_reports(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    value_json TEXT NOT NULL,
    PRIMARY KEY(report_id,ordinal)
);

CREATE TABLE issue_status_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    issue_id TEXT NOT NULL REFERENCES issues(id),
    old_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    reason TEXT NOT NULL,
    actor TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE issue_task_links (
    issue_id TEXT NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    task_id TEXT NOT NULL,
    preset_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    PRIMARY KEY(issue_id,task_id)
);

CREATE TABLE issues (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    identity_version INTEGER NOT NULL,
    identity_key TEXT NOT NULL,
    identity_method TEXT NOT NULL,
    identity_scope TEXT NOT NULL,
    identity_reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
    status_reason TEXT NOT NULL DEFAULT '',
    status_actor TEXT NOT NULL DEFAULT '',
    status_updated_at TEXT NOT NULL DEFAULT '',
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE TABLE purged_reports (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    digest TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    purged_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    UNIQUE(workspace_id,digest)
);

CREATE TABLE report_archives (
    report_id TEXT PRIMARY KEY REFERENCES reports(id) ON DELETE CASCADE,
    archived_at TEXT NOT NULL,
    archived_by TEXT NOT NULL
);

CREATE TABLE report_drafts (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    spec_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','completed','cancelled')),
    revision INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    byte_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    report_id TEXT NOT NULL DEFAULT '',
    completion_json TEXT NOT NULL DEFAULT '',
    UNIQUE(workspace_id,task_id,client_id)
);

CREATE TABLE report_pins (
    report_id TEXT PRIMARY KEY REFERENCES reports(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE report_scanners (
    report_id TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    PRIMARY KEY(report_id,tool)
);

CREATE TABLE reports (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    digest TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    finding_count INTEGER NOT NULL,
    size INTEGER NOT NULL,
    tools TEXT NOT NULL,
    runs_json TEXT NOT NULL,
    original BLOB NOT NULL,
    updated_at TEXT NOT NULL DEFAULT '',
    UNIQUE(workspace_id,digest)
);

CREATE TABLE retention_settings (
    workspace_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL,
    config_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    last_run_at TEXT NOT NULL DEFAULT '',
    last_purged_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE task_presets (
    workspace_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE TABLE upload_tokens (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL DEFAULT '',
    revoked_at TEXT NOT NULL DEFAULT '',
    revoked_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE uploads (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    expected_size INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    content BLOB NOT NULL DEFAULT X'',
    report_id TEXT
);

CREATE INDEX finding_advisories_key ON finding_advisories(advisory_key,report_id,ordinal);

CREATE INDEX findings_aggregate ON findings(language,tool,rule_id,severity,report_id);

CREATE INDEX findings_issue ON findings(issue_id,report_id,ordinal);

CREATE INDEX findings_level ON findings(report_id,level,ordinal);

CREATE UNIQUE INDEX issue_agent_review_history ON issue_agent_reviews(history_id) WHERE history_id IS NOT NULL;

CREATE INDEX issue_history_order ON issue_status_history(issue_id,id DESC);

CREATE INDEX issue_purged_sources ON issue_purged_occurrences(issue_id,report_id,ordinal);

CREATE INDEX issues_workspace ON issues(workspace_id,status,last_seen_at);

CREATE INDEX purged_reports_workspace ON purged_reports(workspace_id,purged_at DESC,id);

CREATE INDEX report_drafts_active ON report_drafts(status,workspace_id);

CREATE INDEX report_drafts_task ON report_drafts(workspace_id,task_id,status,created_at,id);

CREATE INDEX report_scanners_tool ON report_scanners(tool,report_id);

CREATE INDEX reports_workspace ON reports(workspace_id,created_at DESC,id);

CREATE INDEX upload_tokens_workspace ON upload_tokens(workspace_id,created_at DESC,id);

CREATE INDEX uploads_workspace ON uploads(workspace_id);
