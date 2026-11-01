import { test, expect } from "@playwright/test";

async function chooseView(page, name) {
  await page.getByRole("button", { name: "Security views", exact: true }).click();
  await page.getByRole("menuitem", { name, exact: true }).click();
}

async function chooseFilter(page, field, value, regionName = "Findings across reports") {
  const region = page.getByRole("region", { name: regionName });
  await region.getByRole("button", { name: new RegExp(`^${field}(:|$)`) }).click();
  const dialog = page.getByRole("dialog", { name: field, exact: true });
  if (!["Severity", "Status"].includes(field)) await dialog.getByRole("textbox", { name: `Search ${field}`, exact: true }).fill(value);
  await dialog.getByRole("button", { name: value, exact: true }).click();
  await expect(dialog).toHaveCount(0);
}

const raw = JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "Scanner" } }, results: [
  { ruleId: "SQL001", level: "error", message: { text: "SQL injection é😀 <script>alert(1)</script>" } },
  { ruleId: "NOTE", level: "note", message: { text: "Review configuration" } },
] }] });

function findingsOf(report) {
  return JSON.parse(report.original).runs.flatMap((run, run_index) => run.results.map((result, ordinal) => {
    const rule = run.tool.driver.rules?.find((entry) => entry.id === result.ruleId);
    const score = Number(rule?.properties?.["security-severity"]);
    const agent = run.properties?.kandevSecurity;
    const entry = result.properties?.kandevSecurity;
    const severity = agent && entry ? entry.finding.severity : Number.isFinite(score) ? score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : score > 0 ? "low" : "informational" : ({ error: "high", warning: "medium", note: "low", none: "informational" })[result.level];
    const artifact = run.artifacts?.[result.locations?.[0]?.physicalLocation?.artifactLocation?.index];
    const uri = result.locations?.[0]?.physicalLocation?.artifactLocation?.uri || artifact?.location.uri || "";
    const language = artifact?.sourceLanguage || (uri.endsWith(".py") ? "Python" : uri.endsWith(".go") ? "Go" : "Unknown");
    const fp = result.partialFingerprints || result.fingerprints;
    const issue_id = fp && run.versionControlProvenance?.[0]?.repositoryUri
      ? JSON.stringify([report.workspace_id, run.tool.driver.name, result.ruleId, uri, fp]) : `${report.id}:${ordinal}`;
    return { origin: agent ? "llm" : undefined, confidence: entry?.finding.confidence, issue_id, ordinal, run_index, rule_id: result.ruleId, level: result.level, message: result.message.text, tool: run.tool.driver.name,
      uri, line: 12, column: 3, language, severity, report_id: report.id, report_name: report.filename, created_at: report.created_at, updated_at: report.updated_at };
  }));
}
async function mockActions(page, { markup, failTaskLink = 0, commonDetail = {} } = {}) {
  const reports = new Map(); const uploads = new Map(); const tokens = new Map(); const issues = new Map(); let next = 0; let clock = 0;
  const presetSettings=new Map(), tasks=new Map(), taskLinks=new Map();
  const retentionSettings=new Map(), purgedReports=new Map();
  const defaults=()=>[
    {id:"investigate",label:"Investigate",hint:"Verify relevance and assess impact",icon:"search",prompt_template:"Investigate this finding.\n\n{{finding}}"},
    {id:"fix",label:"Fix",hint:"Verify, remediate and test",icon:"tool",prompt_template:"Verify and fix this finding.\n\n{{finding}}"},
    {id:"regression",label:"Add regression coverage",hint:"Test the vulnerability and the fix",icon:"bug",prompt_template:"Add regression coverage.\n\n{{finding}}"},
  ];
  const settings=(workspaceId)=>presetSettings.get(workspaceId)||{presets:defaults(),revision:0,customized:false};
  await page.route("**/native-task",async(route)=>{
    const input=route.request().postDataJSON();const task={id:`task-${tasks.size+1}`,workspace_id:input.workspaceId,title:input.title,state:"in_progress",description:input.description};tasks.set(task.id,task);await route.fulfill({json:task});
  });
  const timestamp = () => new Date(Date.UTC(2026, 0, 1, 0, 0, clock++)).toISOString();
  await page.route("**/actions/*", async (route) => {
    const key = new URL(route.request().url()).pathname.split("/").pop();
    const { workspaceId, body } = route.request().postDataJSON();
    const reply = (value, status = 200) => route.fulfill({ status, json: value });
    const owned = () => [...reports.values()].filter((report) => report.workspace_id === workspaceId);
    const retention=()=>retentionSettings.get(workspaceId)||{config:{enabled:false,default:{max_reports:0,max_age_days:0},overrides:[]},revision:0,scanners:[...new Set(owned().map(r=>r.tools))]};
    const plan=(config)=>{
      const pinned=owned().filter(r=>r.pinned).length,ranks=new Map();
      const candidates=config.enabled?owned().filter(r=>!r.pinned).sort((a,b)=>b.created_at.localeCompare(a.created_at)).filter(r=>{
        const rank=(ranks.get(r.tools)||0)+1;ranks.set(r.tools,rank);const policy=config.overrides.find(o=>o.tool===r.tools)||config.default;
        return policy.max_reports>0&&rank>policy.max_reports||policy.max_age_days>0&&new Date(r.created_at)<new Date(Date.now()-policy.max_age_days*86400000);
      }).map(report=>({report,reason:`${report.tools}: retention limit` })):[];
      return {eligible_reports:candidates.length,eligible_bytes:candidates.reduce((sum,c)=>sum+c.report.original.length,0),pinned_reports:pinned,candidates,has_more:false};
    };
    const applyRetention=()=>{
      const preview=plan(retention().config);
      for(const {report,reason} of preview.candidates){
        const sources=findingsOf(report).map(f=>({...f,message:"",purged_at:timestamp(),purge_reason:reason}));
        const {original,...metadata}=report;purgedReports.set(report.id,{...metadata,purged_at:timestamp(),purge_reason:reason,sources});reports.delete(report.id);
      }
      return {purged_count:preview.eligible_reports,purged_bytes:preview.eligible_bytes};
    };
    if(key==="retention.get")return reply(retention());
    if(key==="retention.preview")return reply(plan(body.config));
    if(key==="retention.save"){
      const old=retention();if(body.expected_revision!==old.revision)return reply({error:"Retention settings changed; reload before saving."},409);
      const next={...old,config:body.config,revision:old.revision+1};retentionSettings.set(workspaceId,next);return reply({settings:next,...applyRetention()});
    }
    if(key==="retention.run")return reply(applyRetention());
    if(key==="reports.purged.list"){
      const items=[...purgedReports.values()].filter(r=>r.workspace_id===workspaceId);return reply({items:items.slice(body.offset||0,(body.offset||0)+25),next_offset:(body.offset||0)+25<items.length?(body.offset||0)+25:0});
    }
    if(key==="reports.archive"){
      const report=reports.get(body.id);if(!report||report.workspace_id!==workspaceId)return reply({error:"Not found"},404);
      if(body.archived){report.archived_at ||= timestamp();report.archived_by ||= "actor";}
      else {delete report.archived_at;delete report.archived_by;}
      return reply({report});
    }
    if(key==="reports.pin"){
      const report=reports.get(body.id);if(!report||report.workspace_id!==workspaceId)return reply({error:"Not found"},404);report.pinned=body.pinned;
      const result=applyRetention();return reply({...result,pinned:body.pinned,retained:reports.has(report.id)});
    }
    if(key==="task_presets.get")return reply(settings(workspaceId));
    if(key==="task_presets.save"||key==="task_presets.reset"){
      const old=settings(workspaceId);if(body.expected_revision!==old.revision)return reply({error:"Task presets changed; reload before saving."},409);
      const value={presets:key==="task_presets.reset"?defaults():body.presets,revision:old.revision+1,customized:key!=="task_presets.reset",updated_by:"actor"};presetSettings.set(workspaceId,value);return reply(value);
    }
    if(key==="tasks.prepare"){
      const r=reports.get(body.id),f=r&&r.workspace_id===workspaceId?findingsOf(r).find((entry)=>entry.ordinal===body.ordinal):null;
      const preset=settings(workspaceId).presets.find((p)=>p.id===body.preset_id);
      if(!f||!preset)return reply({error:"Not found"},404);
      return reply({workspace_id:workspaceId,issue_id:f.issue_id,preset_id:preset.id,title:`[Security] ${f.message}`,description:`${preset.prompt_template}\nRule: ${f.rule_id}\nReport ID: ${r.id}\nFile: ${r.filename}\nOrdinal: ${f.ordinal}`,workflow_id:"workflow",default_step_id:"step",steps:[{id:"step",title:"Review",events:{on_enter:[]}}]});
    }
    if(key==="tasks.link"){
      if(failTaskLink>0){failTaskLink--;return reply({error:"Temporary link failure"},503);}
      const task=tasks.get(body.task_id);if(!task||task.workspace_id!==workspaceId)return reply({error:"Not found"},404);
      const links=taskLinks.get(body.issue_id)||[];if(!links.some((l)=>l.task_id===task.id))links.push({task_id:task.id,preset_id:body.preset_id});taskLinks.set(body.issue_id,links);return reply({linked:true});
    }
    if(key==="tasks.list"){
      const links=(taskLinks.get(body.issue_id)||[]).map((l)=>({...l,title:tasks.get(l.task_id)?.title,state:"in_progress",unavailable:false}));return reply({items:links,total:links.length,next_offset:0});
    }
    if (key === "tokens.create") {
      const token = { id: String(++next), workspace_id: workspaceId, actor_id: "actor", name: body.name,
        created_at: timestamp(), last_used_at: "", revoked_at: "", revoked_by: "" };
      tokens.set(token.id, token);
      return reply({ token, secret: `ksr_test_secret_${token.id}` });
    }
    if (key === "tokens.list") return reply({ items: [...tokens.values()].filter((t) => t.workspace_id === workspaceId), next_offset: 0 });
    if (key === "tokens.revoke") {
      const token = tokens.get(body.id);
      if (!token || token.workspace_id !== workspaceId) return reply({ error: "Not found" }, 404);
      token.revoked_at = timestamp(); token.revoked_by = "actor";
      return reply({ revoked: true });
    }
    const all = () => owned().flatMap(r => findingsOf(r).map(f => ({ ...f, archived_at:r.archived_at, archived_by:r.archived_by })));
    const active = () => all().filter(f => !f.archived_at);
    const issueFor = (f) => {
      const occurrences = all().filter((o) => o.issue_id === f.issue_id);
      const old = issues.get(f.issue_id);
      const value = { id: f.issue_id, identity_version: 1, identity_method: "scanner-fingerprint", identity_scope: "repository", identity_reason: "Scanner fingerprints and source scope match.",
        status: "open", history: [], first_seen_at: occurrences.map((o) => o.created_at).sort()[0], ...old, last_seen_at: occurrences.map((o) => o.updated_at).sort().at(-1) };
      issues.set(f.issue_id, value); return value;
    };
    if (key === "advisories.list" || key === "advisories.findings") {
      const ranks={critical:5,high:4,medium:3,low:2,informational:1};
      const source=active().filter(f=>/^CVE-\d{4}-\d{4,}$/i.test(f.rule_id||"")&&(!body.tool||f.tool===body.tool)&&(!body.search||(f.message+" "+f.rule_id).toLowerCase().includes(body.search.toLowerCase())));
      if(key==="advisories.findings"){
        const items=source.filter(f=>f.rule_id.toUpperCase()===body.id).sort((a,b)=>ranks[b.severity]-ranks[a.severity]);
        return reply({items:items.slice(body.offset||0,(body.offset||0)+25),total:items.length,next_offset:(body.offset||0)+25<items.length?(body.offset||0)+25:0});
      }
      const groups=new Map();for(const f of source){const id=f.rule_id.toUpperCase();groups.set(id,[...(groups.get(id)||[]),f]);}
      let items=[...groups].map(([id,fs])=>{fs.sort((a,b)=>ranks[b.severity]-ranks[a.severity]);return{key:id,id,namespace:"CVE",severity:fs[0].severity,title:`Description for ${id}`,occurrence_count:fs.length,issue_count:fs.length,report_count:new Set(fs.map(f=>f.report_id)).size,scanner_count:new Set(fs.map(f=>f.tool)).size,first_imported_at:fs.map(f=>f.created_at).sort()[0]};});
      items=items.filter(a=>!body.severity||a.severity===body.severity);
      items.sort((a,b)=>body.sort==="oldest"?a.first_imported_at.localeCompare(b.first_imported_at):body.sort==="newest"?b.first_imported_at.localeCompare(a.first_imported_at):ranks[b.severity]-ranks[a.severity]);
      return reply({items:items.slice(body.offset||0,(body.offset||0)+25),total:items.length,finding_count:items.reduce((sum,a)=>sum+a.occurrence_count,0),next_offset:(body.offset||0)+25<items.length?(body.offset||0)+25:0});
    }
    if (key === "issues.get" || key === "issues.set_status") {
      const archived=[...purgedReports.values()].filter(r=>r.workspace_id===workspaceId).flatMap(r=>r.sources);
      const occurrences = [...all(),...archived].filter((o) => o.issue_id === body.id);
      if (!occurrences.length) return reply({ error: "Not found" }, 404);
      const issue = issueFor(occurrences[0]);
      if (key === "issues.set_status") {
        issue.history.unshift({ id: issue.history.length + 1, old_status: issue.status, new_status: body.status, reason: body.reason, actor: "reviewer", created_at: timestamp() });
        issue.status = body.status; issue.status_reason=body.reason; issue.status_actor="reviewer"; return reply({ updated: true });
      }
      return reply({ issue, occurrences, total: occurrences.length, next_offset: 0, history: issue.history, history_next_offset: 0 });
    }
    if (key === "findings.list" || key === "issues.list") {
      const ranks = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 };
      let base = active().filter((f) =>
        (!body.language || f.language === body.language) && (!body.tool || f.tool === body.tool) &&
        (!body.rule || f.rule_id === body.rule) &&
        (!body.search || f.message.includes(body.search)));
      base = base.filter((f) => !body.status || issueFor(f).status === body.status);
      if (key === "issues.list") {
        base.sort((a, b) => ranks[b.severity] - ranks[a.severity]);
        base = [...new Map(base.map((f) => [f.issue_id, base.find((o) => o.issue_id === f.issue_id)])).values()]
          .map((f) => ({ ...f, issue: issueFor(f), occurrence_count: active().filter((o) => o.issue_id === f.issue_id).length }));
      }
      const severity_counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
      base.forEach((f) => severity_counts[f.severity]++);
      const items = base.filter((f) => !body.severity || f.severity === body.severity);
      items.sort((a, b) => {
        if (body.sort === "newest") return b.created_at.localeCompare(a.created_at);
        if (body.sort === "oldest") return a.created_at.localeCompare(b.created_at);
        if (body.sort === "recently_updated") return b.updated_at.localeCompare(a.updated_at);
        if (body.sort === "least_recently_updated") return a.updated_at.localeCompare(b.updated_at);
        return ranks[b.severity] - ranks[a.severity];
      });
      return reply({ items: items.slice(body.offset || 0, (body.offset || 0) + 25), total: items.length, severity_counts, latest_import_at: owned().filter(r=>!r.archived_at).map((r) => r.updated_at).sort().at(-1) || "", next_offset: (body.offset || 0) + 25 < items.length ? (body.offset || 0) + 25 : 0 });
    }
    if (key === "findings.facets") {
      const field = body.facet === "rule" ? "rule_id" : body.facet;
      const items = [...new Set(active().map((f) => f[field]))].filter((v) => v.toLowerCase().includes(body.search.toLowerCase())).sort();
      return reply({ items: items.slice(0, 25), next_offset: items.length > 25 ? 25 : 0 });
    }
    if (key === "reports.tools") {
      const tools=[...new Set(owned().flatMap(r=>JSON.parse(r.original).runs.map(run=>run.tool.driver.name)))].filter(tool=>tool&&tool.toLowerCase().includes((body.search||"").toLowerCase())).sort();
      const offset=body.offset||0;return reply({items:tools.slice(offset,offset+25),next_offset:offset+25<tools.length?offset+25:0});
    }
    if (key === "reports.list") {
      const base=owned().filter(r=>(!body.tool||JSON.parse(r.original).runs.some(run=>run.tool.driver.name===body.tool))&&(!body.search||r.filename.toLowerCase().includes(body.search.toLowerCase())));
      const archived=base.filter(r=>r.archived_at).length,status_counts={all:base.length,active:base.length-archived,archived};
      const items=base.filter(r => body.status === "all" || (body.status === "archived" ? !!r.archived_at : !r.archived_at)),offset=body.offset||0;
      return reply({items:items.slice(offset,offset+25),total:items.length,status_counts,next_offset:offset+25<items.length?offset+25:0});
    }
    if (key === "imports.start") {
      const id = String(++next); uploads.set(id, { workspaceId, ...body, chunks: [] }); return reply({ id, chunk_bytes: 192 * 1024 });
    }
    if (key === "imports.append") {
      const u = uploads.get(body.id); expect(u.workspaceId).toBe(workspaceId);
      const chunk = Buffer.from(body.data, "base64"); u.chunks.push(chunk); return reply({ offset: body.offset + chunk.length });
    }
    if (key === "imports.cancel") { uploads.delete(body.id); return reply({ cancelled: true }); }
    if (key === "imports.complete") {
      const u = uploads.get(body.id); const original = Buffer.concat(u.chunks).toString(); let doc;
      try { doc = JSON.parse(original); } catch { return reply({ error: "Invalid SARIF JSON" }, 400); }
      const existing = owned().find((r) => r.original === original);
      if (existing) { existing.updated_at = timestamp(); return reply({ report: existing, duplicate: true }); }
      const report = { id: String(++next), workspace_id: workspaceId, filename: u.filename, tools: doc.runs[0].tool.driver.name, finding_count: doc.runs[0].results.length,
        created_at: timestamp(), updated_at: "", actor_id: "actor", original };
      report.updated_at = report.created_at;
      reports.set(report.id, report); return reply({ report, duplicate: false });
    }
    const report = reports.get(body.id);
    if (!report || report.workspace_id !== workspaceId) return reply({ error: "Not found" }, 404);
    if (key === "findings.get") {
      const finding = findingsOf(report).find((f) => f.ordinal === body.ordinal);
      if (!finding) return reply({ error: "Not found" }, 404);
      const doc = JSON.parse(report.original); const rule = doc.runs[finding.run_index].tool.driver.rules?.find((r) => r.id === finding.rule_id);
      const entry = doc.runs[finding.run_index].results[body.ordinal].properties?.kandevSecurity;
      return reply({ report, agent_finding: entry, run: { tool: finding.tool, version: "1", agent_audit: doc.runs[finding.run_index].properties?.kandevSecurity }, title: entry?.finding.title || rule?.shortDescription?.text || "", description: entry?.finding.description || rule?.fullDescription?.text || "", guidance: entry?.finding.remediation || rule?.help?.text || "", fixes: markup ? ["Plain fix"] : [], markup, truncated: false, ...commonDetail, finding: { ...finding, ...commonDetail.finding } });
    }
    if (key === "reports.get") {
      const doc = JSON.parse(report.original);
      const findings = doc.runs[0].results.map((r, ordinal) => ({ ordinal, rule_id: r.ruleId, level: r.level, message: r.message.text, uri: ordinal === 0 ? "src/db.go" : "", line: 12, column: 3 }));
      const filtered = findings.filter((f) => (!body.level || f.level === body.level) && (!body.search || f.message.includes(body.search)));
      return reply({ report, runs: [{ index: 0, tool: "Scanner", repository: "https://example.com/repo", revision: "abc123", version: "1", agent_audit: doc.runs[0].properties?.kandevSecurity }], findings: filtered, total: filtered.length, next_offset: 0 });
    }
    if (key === "reports.source") return reply({ filename: report.filename, size: Buffer.byteLength(report.original), data: Buffer.from(report.original).toString("base64"), next_offset: 0 });
    if (key === "reports.delete") { reports.delete(body.id); return reply({ deleted: true }); }
  });
  return {tasks,presetSettings,taskLinks,reports,retentionSettings,purgedReports,issues};
}

test("import, browse, filter, export, workspace isolation and delete", async ({ page }) => {
  await mockActions(page);
  const errors = []; page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await expect(page.getByText("No findings match these filters.")).toBeVisible();
  await expect(page.locator("#security-import")).toHaveCount(0);
  await chooseView(page, "Import SARIF");
  await page.locator("#security-import").setInputFiles({ name: "scan.sarif", mimeType: "application/json", buffer: Buffer.from(raw) });
  await expect(page.locator("#security-import")).toBeEnabled();
  await chooseView(page, "Reports");
  await expect(page.getByRole("button", { name: /scan.sarif/ })).toBeVisible();
  await page.getByRole("button", { name: /scan.sarif/ }).click();
  await expect(page.getByText("SQL injection é😀 <script>alert(1)</script>", { exact: true })).toBeVisible();
  await page.getByLabel("Level", { exact: true }).selectOption("error");
  await page.getByRole("button", { name: "Filter", exact: true }).click();
  await expect(page.getByText("Review configuration", { exact: true })).toHaveCount(0);
  await page.evaluate(() => {
    const original = URL.createObjectURL.bind(URL);
    URL.createObjectURL = (blob) => { window.exportedBlobText = blob.text(); return original(blob); };
  });
  const downloading = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export original SARIF" }).click();
  const download = await downloading;
  expect(download.suggestedFilename()).toBe("scan.sarif");
  expect(await page.evaluate(() => window.exportedBlobText)).toBe(raw);
  const path = await download.path();
  const { readFile } = await import("node:fs/promises");
  expect((await readFile(path)).toString()).toBe(raw);
  await page.getByRole("button", { name: "Switch workspace" }).click();
  await expect(page.getByText("No active reports. Import a report or restore one from Archived.")).toBeVisible();
  await expect(page.getByText("SQL injection", { exact: false })).toHaveCount(0);
  await page.getByRole("button", { name: "Switch workspace" }).click();
  await page.getByRole("button", { name: /scan.sarif/ }).click();
  await page.getByRole("button", { name: "Delete report", exact: true }).click();
  await page.getByRole("button", { name: "Confirm deletion" }).click();
  await expect(page.getByText("No active reports. Import a report or restore one from Archived.")).toBeVisible();
  expect(errors).toEqual([]);
});

test("duplicate imports and malformed files show useful outcomes", async ({ page }) => {
  await mockActions(page); await page.goto("/");
  await chooseView(page, "Import SARIF");
  const input = page.locator("#security-import");
  const upload = { name: "scan.sarif", mimeType: "application/json", buffer: Buffer.from(raw) };
  await input.setInputFiles(upload);
  await expect(page.getByText("Report imported.", { exact: true })).toBeVisible();
  await input.setInputFiles(upload);
  await expect(page.getByText("This report was already imported into this workspace.")).toBeVisible();
  await input.setInputFiles({ name: "bad.sarif", mimeType: "application/json", buffer: Buffer.from("{") });
  await expect(page.getByRole("alert")).toHaveText("Invalid SARIF JSON");
  await chooseView(page, "Reports");
  await expect(page.getByRole("button", { name: /scan.sarif/ })).toHaveCount(1);
});

test("aggregates reports with combined filters and all sort modes", async ({ page }, testInfo) => {
  await mockActions(page); await page.goto("/");
  const first = JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "CodeQL", rules: [{ id: "GO1", properties: { "security-severity": "9.2" } }] } },
    artifacts: [{ location: { uri: "src/main.go" }, sourceLanguage: "Go" }],
    results: [{ ruleId: "GO1", level: "error", message: { text: "Go vulnerability" }, locations: [{ physicalLocation: { artifactLocation: { index: 0 } } }] }] }] });
  const second = JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "Semgrep" } }, artifacts: [{ location: { uri: "app.py" } }],
    results: [{ ruleId: "PY1", level: "warning", message: { text: "Python vulnerability" }, locations: [{ physicalLocation: { artifactLocation: { index: 0 } } }] }] }] });
  const upload = async (name, content) => {
    const restoreFindings = (await page.getByRole("button", { name: "Security views", exact: true }).textContent()).includes("All findings");
    await chooseView(page, "Import SARIF");
    await page.locator("#security-import").setInputFiles({ name, mimeType: "application/json", buffer: Buffer.from(content) });
    await expect(page.locator("#security-import")).toBeEnabled();
    if (restoreFindings) await chooseView(page, "All findings");
  };
  await upload("go.sarif", first); await upload("python.sarif", second);
  await chooseView(page, "All findings");
  const region = page.getByRole("region", { name: "Findings across reports" });
  const rows = region.getByRole("listitem");
  await expect(rows).toHaveCount(2);
  await expect(rows.first()).toContainText("Go vulnerability");
  await page.screenshot({ path: testInfo.outputPath("security-findings.png"), fullPage: true });
  await chooseFilter(page, "Language", "Python");
  await chooseFilter(page, "Scanner tool", "Semgrep");
  await chooseFilter(page, "Rule", "PY1");
  await chooseFilter(page, "Severity", "Medium");
  await expect(rows).toHaveCount(1); await expect(rows.first()).toContainText("Python vulnerability");
  await region.getByRole("button", { name: "View finding: PY1", exact: true }).click();
  await page.getByRole("dialog", { name: "PY1", exact: true }).getByRole("button", { name: "Open report: python.sarif" }).click();
  await expect(page.getByRole("heading", { name: "python.sarif" })).toBeVisible();
  await page.getByRole("button", { name: "Back to all findings" }).click();
  await expect(region.getByRole("button", { name: "Language: Python", exact: true })).toBeVisible();
  await region.getByRole("button", { name: "Clear filters" }).click(); await expect(rows).toHaveCount(2);
  const sort = async (value, firstMessage) => {
    await region.getByRole("button", { name: "Sort", exact: true }).click();
    const labels = { newest: "Newest", oldest: "Oldest", recently_updated: "Recently updated", least_recently_updated: "Least recently updated", severity: "Severity" };
    await page.getByRole("menuitemradio", { name: labels[value], exact: true }).click();
    await expect(rows.first()).toContainText(firstMessage);
  };
  await sort("newest", "Python vulnerability"); await sort("oldest", "Go vulnerability");
  await sort("recently_updated", "Python vulnerability"); await sort("least_recently_updated", "Go vulnerability");
  await upload("go.sarif", first);
  await sort("recently_updated", "Go vulnerability"); await sort("newest", "Python vulnerability"); await sort("severity", "Go vulnerability");
  await expect(rows).toHaveCount(2);
  await page.getByRole("button", { name: "Switch workspace" }).click();
  await expect(region.getByText("No findings match these filters.")).toBeVisible();
  await expect(region.getByRole("button", { name: "Language", exact: true })).toBeVisible();
  await expect(rows).toHaveCount(0);
});

test("creates, hides and revokes upload tokens within the current workspace", async ({ page }) => {
  await mockActions(page); await page.goto("/");
  await chooseView(page, "Upload tokens");
  const region = page.getByRole("region", { name: "Upload tokens" });
  await region.getByRole("textbox", { name: "Token name", exact: true }).fill("CI scanner");
  await region.getByRole("button", { name: "Create upload token" }).click();
  const secretField = region.getByRole("textbox", { name: "New upload token", exact: true });
  await expect(secretField).toBeVisible();
  const secret = await secretField.inputValue(); expect(secret).toMatch(/^ksr_/);
  const stored = await page.evaluate(() => JSON.stringify([Object.values(localStorage), Object.values(sessionStorage)]));
  expect(stored).not.toContain(secret);
  await region.getByRole("button", { name: "I saved the token" }).click();
  await expect(secretField).toHaveCount(0);
  await chooseView(page, "Reports");
  await chooseView(page, "Upload tokens");
  await expect(secretField).toHaveCount(0);
  await expect(region.getByText("CI scanner", { exact: true })).toBeVisible();
  await region.getByRole("button", { name: "Revoke", exact: true }).click();
  await region.getByRole("button", { name: "Confirm revocation" }).click();
  await expect(region.getByText("Revoked", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Switch workspace" }).click();
  await expect(region.getByText("No upload tokens in this workspace.")).toBeVisible();
  await expect(region.getByText("CI scanner", { exact: true })).toHaveCount(0);
});

test("import controls are confined to their own view", async ({ page }) => {
  await mockActions(page); await page.goto("/");
  await expect(page.locator("#security-import")).toHaveCount(0);
  await chooseView(page, "All findings");
  await expect(page.locator("#security-import")).toHaveCount(0);
  await chooseView(page, "Import SARIF");
  await expect(page.getByRole("heading", { name: "Import SARIF", exact: true })).toBeVisible();
  await expect(page.getByLabel("SARIF file", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Switch workspace" }).click();
  await expect(page.getByLabel("SARIF file", { exact: true })).toBeVisible();
  await chooseView(page, "Reports");
  await expect(page.locator("#security-import")).toHaveCount(0);
});

test("default findings view fills the page with a Jira-style toolbar and filter bar", async ({ page }, testInfo) => {
  await mockActions(page); await page.goto("/");
  const region = page.getByRole("region", { name: "Findings across reports" });
  await expect(region).toBeVisible();
  await expect(page.getByRole("button", { name: "Security views", exact: true })).toContainText("All findings");
  await expect(page.locator("header").getByRole("button", { name: "Security views", exact: true })).toBeVisible();
  const search = region.getByLabel("Search findings", { exact: true });
  const sort = region.getByLabel("Sort", { exact: true });
  const pills = ["Language", "Scanner tool", "Rule", "Severity", "Status"].map((name) => region.getByRole("button", { name, exact: true }));
  for (const pill of pills) await expect(pill).toBeVisible();
  const searchBox = await search.boundingBox(); const sortBox = await sort.boundingBox();
  const boxes = await Promise.all(pills.map((control) => control.boundingBox()));
  expect(boxes[0].y).toBeGreaterThan(searchBox.y);
  if (testInfo.project.name === "desktop") {
    expect(Math.abs(searchBox.y - sortBox.y)).toBeLessThan(2);
    expect(Math.max(...boxes.map((box) => box.y)) - Math.min(...boxes.map((box) => box.y))).toBeLessThan(2);
    // The report is not capped at the old 96rem width on large monitors.
    await page.setViewportSize({ width: 1920, height: 900 });
    const main = await page.locator("main").boundingBox(); const content = await region.boundingBox();
    expect(main.width).toBe(1920); expect(content.width).toBe(main.width);
    await page.locator("main").evaluate((node) => { node.style.width = "500px"; });
    const narrowSearch = await search.boundingBox(); const narrowSort = await sort.boundingBox();
    expect(narrowSort.y).toBeGreaterThan(narrowSearch.y);
  } else {
    expect(sortBox.y).toBeGreaterThan(searchBox.y);
    for (const box of boxes) { expect(box.x).toBeGreaterThanOrEqual(0); expect(box.x + box.width).toBeLessThanOrEqual(page.viewportSize().width); expect(box.height).toBeGreaterThanOrEqual(44); }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  }
});

test("search, filter clearing and keyboard navigation keep the displayed query in sync", async ({ page }) => {
  await mockActions(page); await page.goto("/");
  // Keyboard access to the host-header menu and popovers uses real Radix primitives.
  const menu = page.getByRole("button", { name: "Security views", exact: true });
  await menu.focus(); await page.keyboard.press("Enter");
  await page.getByRole("menuitem", { name: "Import SARIF", exact: true }).focus(); await page.keyboard.press("Enter");
  await page.locator("#security-import").setInputFiles({ name: "scan.sarif", mimeType: "application/json", buffer: Buffer.from(raw) });
  await expect(page.getByText("Report imported.", { exact: true })).toBeVisible();
  await chooseView(page, "All findings");
  const region = page.getByRole("region", { name: "Findings across reports" });
  const rows = region.getByRole("listitem"); const search = region.getByLabel("Search findings", { exact: true });
  await expect(rows).toHaveCount(2);
  await expect(rows.first().getByRole("button", { name: "View finding: SQL001", exact: true })).toBeVisible();
  await expect(region.getByRole("status")).toHaveText("2 issues");
  await search.fill("no-matching-message");
  await expect(rows).toHaveCount(0);
  await expect(region.getByRole("status")).toHaveText("0 issues");
  await expect(region.getByText("No findings match these filters.", { exact: true })).toBeVisible();
  await search.fill("Review"); await expect(rows).toHaveCount(1); await expect(rows.first()).toContainText("Review configuration");
  const severity = region.getByRole("button", { name: "Severity", exact: true });
  await severity.focus(); await page.keyboard.press("Enter");
  await page.getByRole("dialog", { name: "Severity", exact: true }).getByRole("button", { name: "Low", exact: true }).focus(); await page.keyboard.press("Enter");
  await expect(rows).toHaveCount(1);
  await region.getByRole("button", { name: "Clear Severity", exact: true }).click();
  await expect(search).toHaveValue("Review"); await expect(rows).toHaveCount(1);
  // Clearing also cancels a search debounce that has not yet fired.
  await search.fill("SQL"); await region.getByRole("button", { name: "Clear filters", exact: true }).click();
  await expect(search).toHaveValue(""); await expect(rows).toHaveCount(2);
  await page.waitForTimeout(400); // Past the 300ms debounce: the cleared search must stay cleared.
  await expect(search).toHaveValue(""); await expect(rows).toHaveCount(2);
  await search.fill("SQL"); await search.press("Enter"); await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("SQL injection");
  await chooseView(page, "Reports"); await chooseView(page, "All findings"); await expect(search).toHaveValue("SQL"); await expect(rows).toHaveCount(1);
  await region.getByRole("button", { name: "Language", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Language", exact: true })).toBeVisible();
  await page.keyboard.press("Escape"); await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(region.getByRole("button", { name: "Language", exact: true })).toBeFocused();
});


test("pagination stays at the bottom while results scroll and sort uses a checked menu", async ({ page }) => {
  await mockActions(page); await page.goto("/");
  await chooseView(page, "Import SARIF");
  const document = { version: "2.1.0", runs: [{ tool: { driver: { name: "Scanner" } }, results: Array.from({ length: 61 }, (_, i) => ({
    ruleId: `RULE-${i}`, level: "warning", message: { text: `Finding ${i} ` + "Long message ".repeat(30) },
  })) }] };
  await page.locator("#security-import").setInputFiles({ name: "many.sarif", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(document)) });
  await expect(page.getByText("Report imported.", { exact: true })).toBeVisible();
  await chooseView(page, "All findings");
  const region = page.getByRole("region", { name: "Findings across reports" });
  const footer = region.getByRole("navigation", { name: "Findings pagination" });
  const rows = region.getByRole("listitem");
  await expect(rows).toHaveCount(25);
  await expect(footer).toContainText("1–25 of 61");
  await expect(footer).toContainText("Page 1");
  await expect(footer.getByRole("button", { name: "Previous", exact: true })).toBeDisabled();
  const before = await footer.boundingBox();
  expect(before.y + before.height).toBeLessThanOrEqual(page.viewportSize().height);
  const scroller = region.locator(".kandev-security-results-scroll");
  await scroller.evaluate((node) => { node.scrollTop = node.scrollHeight; });
  expect(await scroller.evaluate((node) => node.scrollTop)).toBeGreaterThan(0);
  expect((await footer.boundingBox()).y).toBe(before.y);
  await footer.getByRole("button", { name: "Next", exact: true }).click();
  await expect(footer).toContainText("26–50 of 61");
  await expect(footer).toContainText("Page 2");
  expect(await scroller.evaluate((node) => node.scrollTop)).toBe(0);
  await footer.getByRole("button", { name: "Next", exact: true }).click();
  await expect(rows).toHaveCount(11);
  await expect(footer).toContainText("51–61 of 61");
  await expect(footer.getByRole("button", { name: "Next", exact: true })).toBeDisabled();
  await footer.getByRole("button", { name: "Previous", exact: true }).click();
  await expect(footer).toContainText("26–50 of 61");
  const sort = region.getByRole("button", { name: "Sort", exact: true });
  await sort.focus(); await page.keyboard.press("Enter");
  const selected = page.getByRole("menuitemradio", { name: "Severity", exact: true });
  await expect(selected).toHaveAttribute("aria-checked", "true");
  await page.getByRole("menuitemradio", { name: "Newest", exact: true }).focus();
  await page.keyboard.press("Enter");
  await expect(sort).toHaveText("Sort: Newest");
  await expect(footer).toContainText("1–25 of 61");
  await expect(footer).toContainText("Page 1");
  await sort.click();
  await expect(page.getByRole("menuitemradio", { name: "Newest", exact: true })).toHaveAttribute("aria-checked", "true");
  await page.keyboard.press("Escape");
  await expect(sort).toBeFocused();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test("severity overview counts all pages and finding drawer preserves page, scroll and filters", async ({ page }, testInfo) => {
  await mockActions(page); await page.goto("/"); await chooseView(page, "Import SARIF");
  const doc = { version: "2.1.0", runs: [{ tool: { driver: { name: "Scanner", rules: [{ id: "R-26", shortDescription: { text: "Selected rule" }, fullDescription: { text: "Detailed vulnerability description" }, help: { text: "Upgrade the package. Advisory: https://example.com/advisory\n<script>window.injected = true</script>" } }] } },
    artifacts: [{ location: { uri: "file:///home/user/project/src/app.py" }, sourceLanguage: "Python" }],
    results: Array.from({ length: 40 }, (_, i) => ({ ruleId: `R-${i}`, level: "warning", message: { text: `Finding ${String(i).padStart(2,"0")}` }, locations: [{ physicalLocation: { artifactLocation: { index: 0 } } }] })) }] };
  await page.locator("#security-import").setInputFiles({ name: "many.sarif", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(doc)) });
  await expect(page.getByText("Report imported.", { exact: true })).toBeVisible(); await chooseView(page, "All findings");
  const region = page.getByRole("region", { name: "Findings across reports" });
  const overview = region.getByRole("group", { name: "Severity overview" });
  await expect(overview.getByRole("button", { name: "Medium 40", exact: true })).toBeVisible();
  await overview.getByRole("button", { name: "Medium 40", exact: true }).click();
  await expect(region.getByRole("button", { name: "Severity: Medium", exact: true })).toBeVisible();
  const footer = region.getByRole("navigation", { name: "Findings pagination" });
  await footer.getByRole("button", { name: "Next", exact: true }).click(); await expect(footer).toContainText("26–40 of 40");
  const scroller = region.locator(".kandev-security-results-scroll");
  const trigger = region.getByRole("button", { name: "View finding: R-26", exact: true });
  await trigger.scrollIntoViewIfNeeded(); await trigger.focus();
  const scroll = await scroller.evaluate((node) => node.scrollTop);
  await page.keyboard.press("Enter");
  const drawer = page.getByRole("dialog", { name: "R-26", exact: true });
  await expect(drawer.getByText("Detailed vulnerability description", { exact: true })).toBeVisible();
  await expect(drawer.getByText("file:///home/user/project/src/app.py:12:3", { exact: true })).toBeVisible();
  await expect(drawer.getByRole("link", { name: "https://example.com/advisory", exact: true })).toHaveAttribute("rel", "noopener noreferrer");
  expect(await page.evaluate(() => window.injected)).toBeUndefined();
  await page.screenshot({ path: testInfo.outputPath("finding-drawer.png") });
  await page.keyboard.press("Escape"); await expect(drawer).toHaveCount(0);
  await expect(trigger).toBeFocused(); await expect(footer).toContainText("26–40 of 40");
  expect(await scroller.evaluate((node) => node.scrollTop)).toBe(scroll);
  await expect(region.getByRole("button", { name: "Severity: Medium", exact: true })).toBeVisible();
  await overview.getByRole("button", { name: "Critical 0", exact: true }).click();
  await expect(region.getByRole("listitem")).toHaveCount(0); await expect(overview.getByRole("button", { name: "Medium 40", exact: true })).toBeVisible();
  await overview.getByRole("button", { name: "All 40", exact: true }).click(); await expect(region.getByRole("listitem")).toHaveCount(25);
  await page.getByRole("button", { name: "Switch workspace" }).click();
  await expect(overview.getByRole("button", { name: "All 0", exact: true })).toBeVisible();
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("finding descriptions render Markdown with safe links, code, lists and tables", async ({ page }, testInfo) => {
  const text = (text) => ({ kind: "text", text });
  const markup = {
    description: [
      { kind: "h2", children: [text("Vulnerability details")] },
      { kind: "p", children: [{ kind: "strong", children: [text("Affected package")] }, text(" needs an "), { kind: "em", children: [text("upgrade")] }, text(" to "), { kind: "code", text: "2.0" }] },
      { kind: "ul", children: [{ kind: "li", children: [text("Review dependencies")] }, { kind: "li", children: [text("Apply the patch")] }] },
      { kind: "blockquote", children: [{ kind: "p", children: [text("Scanner recommendation")] }] },
      { kind: "table", children: [
        { kind: "thead", children: [{ kind: "tr", children: [{ kind: "th", children: [text("Package")] }, { kind: "th", children: [text("Fixed version")] }] }] },
        { kind: "tbody", children: [{ kind: "tr", children: [{ kind: "td", children: [text("example")] }, { kind: "td", children: [text("2.0")] }] }] },
      ] },
    ],
    guidance: [
      { kind: "p", children: [{ kind: "a", url: "https://example.com/advisory", children: [text("Read advisory")] }, text(" and "), { kind: "a", url: "javascript:window.injected=true", children: [text("unsafe link")] }] },
      { kind: "pre", text: "npm update example\n" },
      { kind: "img", url: "https://example.com/tracking.png", text: "Tracking image" },
      { kind: "script", text: "window.injected=true" },
    ],
    fixes: [[{ kind: "p", children: [text("Install "), { kind: "code", text: "example@2.0" }] }]],
  };
  await mockActions(page, { markup });
  let imageRequests = 0;
  await page.route("https://example.com/tracking.png", (route) => { imageRequests++; return route.abort(); });
  await page.goto("/"); await chooseView(page, "Import SARIF");
  const doc = { version: "2.1.0", runs: [{ tool: { driver: { name: "Scanner", rules: [{ id: "MARKDOWN", fullDescription: { text: "Plain description fallback", markdown: "**Affected package**" }, help: { text: "Plain guidance fallback", markdown: "Use the patched version." } }] } }, results: [{ ruleId: "MARKDOWN", level: "warning", message: { text: "Markdown finding" } }] }] };
  await page.locator("#security-import").setInputFiles({ name: "markdown.sarif", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(doc)) });
  await expect(page.getByText("Report imported.", { exact: true })).toBeVisible(); await chooseView(page, "All findings");
  await page.getByRole("button", { name: "View finding: MARKDOWN", exact: true }).click();
  const drawer = page.getByRole("dialog", { name: "MARKDOWN", exact: true });
  await expect(drawer.getByRole("heading", { name: "Vulnerability details", exact: true })).toBeVisible();
  await expect(drawer.locator("strong")).toHaveText("Affected package"); await expect(drawer.locator("em")).toHaveText("upgrade");
  await expect(drawer.getByRole("listitem").filter({ hasText: "Apply the patch" })).toBeVisible();
  await expect(drawer.getByRole("columnheader", { name: "Fixed version", exact: true })).toBeVisible();
  await expect(drawer.locator("pre code")).toHaveText("npm update example\n");
  await expect(drawer.locator("code").filter({ hasText: "example@2.0" })).toBeVisible();
  await expect(drawer.getByRole("link", { name: "Read advisory", exact: true })).toHaveAttribute("rel", "noopener noreferrer");
  await expect(drawer.locator('a[href^="javascript:"], img, script, iframe')).toHaveCount(0);
  await expect(drawer.getByText("Plain description fallback", { exact: true })).toHaveCount(0);
  expect(await page.evaluate(() => window.injected)).toBeUndefined(); expect(imageRequests).toBe(0);
  expect(await drawer.evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath("markdown-drawer.png") });
});

test("grouped issues preserve source occurrences and manual review status", async ({ page }) => {
  await mockActions(page); await page.goto("/");
  const scan = (message) => JSON.stringify({version:"2.1.0",runs:[{
    tool:{driver:{name:"Scanner"}},versionControlProvenance:[{repositoryUri:"https://example.com/repo"}],
    results:[{ruleId:"R-GROUP",level:"error",message:{text:message},partialFingerprints:{line:"stable"},locations:[{physicalLocation:{artifactLocation:{uri:"src/db.go"}}}]}]
  }]});
  for(const [name,message] of [["first.sarif","Original finding"],["second.sarif","Updated finding"]]) {
    await chooseView(page,"Import SARIF");
    await page.locator("#security-import").setInputFiles({name,mimeType:"application/json",buffer:Buffer.from(scan(message))});
    await expect(page.getByText("Report imported.",{exact:true})).toBeVisible();
  }
  await chooseView(page,"All findings");
  const region=page.getByRole("region",{name:"Findings across reports"});
  await expect(region.getByRole("status")).toHaveText("1 issue");
  await expect(region.getByRole("listitem")).toHaveCount(1);
  await expect(region.getByText("2 occurrences · Open")).toBeVisible();
  await region.getByRole("button",{name:"Grouped issues",exact:true}).click();
  await expect(region.getByRole("status")).toHaveText("2 occurrences");
  await expect(region.getByRole("listitem")).toHaveCount(2);
  await region.getByRole("button",{name:"Report occurrences",exact:true}).click();
  await region.getByRole("button",{name:"View finding: R-GROUP"}).click();
  const drawer=page.getByRole("dialog");
  await expect(drawer.getByRole("region",{name:"Issue history"})).toBeVisible();
  await expect(drawer.getByRole("button",{name:/first.sarif · #1/})).toBeVisible();
  await expect(drawer.getByRole("button",{name:/second.sarif · #1/})).toBeVisible();
  await drawer.getByRole("textbox",{name:"Reason for status change"}).fill("Reviewed patch and accepted closure");
  await drawer.getByRole("button",{name:"Close issue",exact:true}).click();
  await expect(drawer.getByText("Issue status: Closed",{exact:true})).toBeVisible();
  await expect(drawer.getByText(/Closed · reviewer ·/)).toContainText("Reviewed patch");
  await drawer.getByRole("button",{name:/second.sarif · #1/}).click();
  await expect(drawer.getByText("Updated finding",{exact:true})).toBeVisible();
  await expect(drawer.getByText("Issue status: Closed",{exact:true})).toBeVisible();
  await drawer.getByRole("button",{name:"Close finding",exact:true}).click();
  await expect(region.getByText("2 occurrences · Closed")).toBeVisible();
});

test("LLM reports show confidence, evidence, scope and reported limitations", async ({ page }) => {
 await mockActions(page);await page.goto("/");await chooseView(page,"Import SARIF");
 const finding={finding_id:"sql-1",title:"Unsafe query construction",description:"Request input reaches SQL.",severity:"critical",confidence:"medium",evidence:"db.Query concatenates request input.",remediation:"Use parameters.",rule_id:"CWE-89",cwes:["CWE-89"],uri:"src/db.go",line:12};
 const audit={origin:"llm",task_id:"task-audit",spec:{title:"Request audit",instructions:"Inspect SQL handlers.",scope:["src/handlers"],agent_label:"Audit agent"},completion:{summary:"One supported finding.",coverage:"Inspected database request handlers.",limitations:["No runtime exploit verification."]}};
 const original=JSON.stringify({version:"2.1.0",runs:[{tool:{driver:{name:"Kandev LLM audit"}},properties:{kandevSecurity:audit},results:[{ruleId:"CWE-89",level:"error",message:{text:finding.title},properties:{kandevSecurity:{finding,submission:{task_id:"task-audit",session_id:"session-audit"}}},locations:[{physicalLocation:{artifactLocation:{uri:"src/db.go"}}}]}]}]});
 await page.locator("#security-import").setInputFiles({name:"llm-audit.sarif",mimeType:"application/json",buffer:Buffer.from(original)});
 await expect(page.getByText("Report imported.",{exact:true})).toBeVisible();await chooseView(page,"All findings");
 const region=page.getByRole("region",{name:"Findings across reports"});
 await expect(region.getByText("LLM reported",{exact:true})).toBeVisible();
 await expect(region.locator('[data-severity="critical"]').last()).toBeVisible();
 await region.getByRole("button",{name:"View finding: CWE-89"}).click();
 const drawer=page.getByRole("dialog");
 await expect(drawer.locator("dt",{hasText:"Confidence"})).toBeVisible();
 await expect(drawer.getByText("db.Query concatenates request input.",{exact:true})).toBeVisible();
 await expect(drawer.getByText("CWE-89",{exact:true}).last()).toBeVisible();
 await expect(drawer.getByText("Inspected database request handlers.",{exact:true})).toBeVisible();
 await expect(drawer.getByText("No runtime exploit verification.",{exact:true})).toBeVisible();
 await drawer.getByRole("button",{name:"Open report: llm-audit.sarif"}).click();
 const report=page.getByRole("region",{name:"LLM audit report"});
 await expect(report.getByText("Inspect SQL handlers.",{exact:true})).toBeVisible();
 await expect(report.getByText("src/handlers",{exact:true})).toBeVisible();
 await expect(report.getByText("task-audit",{exact:true})).toBeVisible();
 await expect(report.getByText("No runtime exploit verification.",{exact:true})).toBeVisible();
});

test("workspace task presets configure finding launches and retain issue task links", async ({page})=>{
 const records=await mockActions(page);await page.goto("/");
 await chooseView(page,"Import SARIF");await page.locator("#security-import").setInputFiles({name:"scan.sarif",mimeType:"application/json",buffer:Buffer.from(raw)});await expect(page.getByText("Report imported.",{exact:true})).toBeVisible();
 await chooseView(page,"Task presets");
 const settings=page.getByRole("region",{name:"Task presets",exact:true});
 await expect(settings.getByText(/shared by everyone in this workspace/)).toBeVisible();
 let editor=settings.getByRole("group",{name:"Investigate",exact:true});
 await editor.getByLabel("Name",{exact:true}).fill("Team investigation");
 editor=settings.getByRole("group",{name:"Team investigation",exact:true});
 await editor.getByLabel("Description",{exact:true}).fill("Our shared investigation procedure");
 await editor.getByRole("combobox",{name:"Icon",exact:true}).selectOption("shield");
 await editor.getByLabel("Prompt template",{exact:true}).fill("Follow our team investigation procedure.\n\n{{finding}}");
 await settings.getByRole("button",{name:"Save presets",exact:true}).click();
 await expect(settings.getByRole("button",{name:"Save presets",exact:true})).toBeDisabled();
 await page.getByRole("button",{name:"Switch workspace"}).click();await expect(settings.getByRole("group",{name:"Investigate",exact:true})).toBeVisible();
 await expect(settings.getByRole("group",{name:"Team investigation",exact:true})).toHaveCount(0);
 await page.getByRole("button",{name:"Switch workspace"}).click();await expect(settings.getByRole("group",{name:"Team investigation",exact:true})).toBeVisible();
 await page.evaluate(()=>{history.pushState({},"","/");dispatchEvent(new PopStateEvent("popstate"));});await chooseView(page,"All findings");
 const region=page.getByRole("region",{name:"Findings across reports"});
 await region.getByRole("button",{name:"Start task for SQL001",exact:true}).click();
 await expect(page.getByRole("menuitem",{name:/Team investigation/})).toBeVisible();
 await page.getByRole("menuitem",{name:/Team investigation/}).click();
 const dialog=page.getByRole("dialog",{name:"Create security task"});
 await expect(dialog.getByRole("textbox",{name:"Task description",exact:true})).toHaveValue(/Follow our team investigation procedure/);
 await expect(dialog.getByRole("textbox",{name:"Task description",exact:true})).toHaveValue(/SQL001/);
 await dialog.getByLabel("Task title",{exact:true}).fill("Investigate this SQL risk");
 await dialog.getByRole("button",{name:"Start native task",exact:true}).click();
 await expect(dialog).toHaveCount(0);await expect(region.getByText("1 linked task",{exact:true})).toBeVisible();
 expect(records.tasks.size).toBe(1);
 await region.getByRole("button",{name:"Start task for SQL001",exact:true}).click();
 await expect(page.getByRole("menuitem",{name:/Investigate this SQL risk/})).toBeVisible();await page.keyboard.press("Escape");
 await region.getByRole("button",{name:"View finding: SQL001",exact:true}).click();
 const drawer=page.getByRole("dialog");await expect(drawer.getByRole("button",{name:"Start task for SQL001",exact:true})).toBeVisible();
 await expect(drawer.getByText("1 linked task",{exact:true})).toBeVisible();
});

test("workspace retention previews cleanup, exempts pins, preserves history and supports scanner overrides",async({page},testInfo)=>{
 const records=await mockActions(page);await page.goto("/");
 for(const name of ["old","middle","new"]){
  const doc=JSON.parse(raw);doc.runs[0].versionControlProvenance=[{repositoryUri:"https://example.com/repo"}];
  doc.runs[0].results.forEach((result,index)=>{result.partialFingerprints={stable:String(index)};result.message.text=`${name} finding ${index}`;});
  await chooseView(page,"Import SARIF");await page.locator("#security-import").setInputFiles({name:`${name}.sarif`,mimeType:"application/json",buffer:Buffer.from(JSON.stringify(doc))});await expect(page.getByText("Report imported.",{exact:true})).toBeVisible();
 }
 await chooseView(page,"All findings");await page.getByRole("button",{name:"View finding: SQL001",exact:true}).click();
 await page.getByRole("textbox",{name:"Reason for status change",exact:true}).fill("Reviewed independently of retention");await page.getByRole("button",{name:"Close issue",exact:true}).click();await expect(page.getByText("Issue status: Closed",{exact:true})).toBeVisible();await page.getByRole("button",{name:"Close finding",exact:true}).click();
 await chooseView(page,"Reports");let old=page.locator("li.kandev-security-report-row").filter({hasText:"old.sarif"});await old.getByRole("button",{name:"Pin report",exact:true}).click();await expect(old.getByRole("button",{name:"Unpin report",exact:true})).toBeVisible();
 await chooseView(page,"Report retention");const retention=page.getByRole("region",{name:"Report retention",exact:true});
 await expect(retention.getByRole("checkbox",{name:"Enable automatic report cleanup",exact:true})).not.toBeChecked();
 await retention.getByRole("checkbox",{name:"Enable automatic report cleanup",exact:true}).check();await retention.getByLabel("Maximum unpinned reports",{exact:true}).fill("1");
 await retention.getByRole("button",{name:"Preview cleanup",exact:true}).click();const preview=retention.getByRole("region",{name:"Cleanup preview",exact:true});
 await expect(preview).toContainText("Reports to remove: 1");await expect(preview).toContainText("Pinned reports kept: 1");await expect(preview).toContainText("middle.sarif");expect(records.reports.size).toBe(3);
 await retention.getByRole("button",{name:"Save and apply retention",exact:true}).click();await expect(retention.getByRole("status")).toHaveText("Retention applied. Reports removed: 1.");expect(records.reports.size).toBe(2);await expect(retention.getByText("middle.sarif",{exact:true})).toBeVisible();
 await chooseView(page,"Reports");old=page.locator("li.kandev-security-report-row").filter({hasText:"old.sarif"});await old.getByRole("button",{name:"Unpin report",exact:true}).click();await expect(old).toHaveCount(0);expect(records.reports.size).toBe(1);
 await chooseView(page,"All findings");await page.getByRole("button",{name:"View finding: SQL001",exact:true}).click();await expect(page.getByText("Issue status: Closed",{exact:true})).toBeVisible();await expect(page.getByText(/Source purged by retention/)).toHaveCount(2);await page.getByRole("button",{name:"Close finding",exact:true}).click();
 await chooseView(page,"Report retention");await retention.getByRole("button",{name:"Add scanner override",exact:true}).click();let override=retention.getByRole("group",{name:"Scanner override",exact:true});await override.getByLabel("Scanner",{exact:true}).fill("Scanner");override=retention.getByRole("group",{name:"Scanner",exact:true});await override.getByLabel("Maximum unpinned reports",{exact:true}).fill("0");
 await retention.getByRole("button",{name:"Save and apply retention",exact:true}).click();await expect(retention.getByRole("status")).toHaveText("Retention applied. Reports removed: 0.");
 await retention.screenshot({path:testInfo.outputPath("retention.png")});expect(await retention.evaluate(node=>node.scrollWidth<=node.clientWidth)).toBe(true);
 await page.getByRole("button",{name:"Switch workspace",exact:true}).click();await expect(retention.getByRole("checkbox",{name:"Enable automatic report cleanup",exact:true})).not.toBeChecked();await expect(retention.getByText("middle.sarif",{exact:true})).toHaveCount(0);
 await page.getByRole("button",{name:"Switch workspace",exact:true}).click();await expect(retention.getByRole("checkbox",{name:"Enable automatic report cleanup",exact:true})).toBeChecked();await expect(retention.getByText("middle.sarif",{exact:true})).toBeVisible();
});

test("retention settings preserve edits on revision conflicts and reload shared policy",async({page})=>{
 const records=await mockActions(page);await page.goto("/");await chooseView(page,"Report retention");const retention=page.getByRole("region",{name:"Report retention",exact:true});
 await retention.getByRole("checkbox",{name:"Enable automatic report cleanup",exact:true}).check();await retention.getByLabel("Maximum unpinned reports",{exact:true}).fill("2");await retention.getByRole("button",{name:"Save and apply retention",exact:true}).click();await expect(retention.getByRole("status")).toHaveText("Retention applied. Reports removed: 0.");
 records.retentionSettings.set("ws-a",{config:{enabled:true,default:{max_reports:1,max_age_days:0},overrides:[]},revision:2,scanners:[]});
 await retention.getByLabel("Maximum unpinned reports",{exact:true}).fill("3");await retention.getByRole("button",{name:"Save and apply retention",exact:true}).click();await expect(retention.getByRole("alert")).toContainText("Retention settings changed");await expect(retention.getByLabel("Maximum unpinned reports",{exact:true})).toHaveValue("3");
 await retention.getByRole("button",{name:"Reload retention settings",exact:true}).click();await expect(retention.getByLabel("Maximum unpinned reports",{exact:true})).toHaveValue("1");await expect(retention.getByRole("button",{name:"Save and apply retention",exact:true})).toBeDisabled();
});

test("advisory page groups reports and supports drill-down, filters, paging and task actions", async ({page},testInfo) => {
 await mockActions(page);await page.goto("/");
 const upload=async(name,tool,results)=>{await chooseView(page,"Import SARIF");await page.locator("#security-import").setInputFiles({name,mimeType:"application/json",buffer:Buffer.from(JSON.stringify({version:"2.1.0",runs:[{tool:{driver:{name:tool}},results}]}))});await expect(page.getByText("Report imported.",{exact:true})).toBeVisible();};
 const result=(id,message,level="warning")=>({ruleId:id,level,message:{text:message}});
 await upload("trivy.sarif","Trivy",[result("CVE-2026-12345","Package A","error"),result("CVE-2026-12345","Package B","note"),...Array.from({length:30},(_,i)=>result(`CVE-2026-${String(i).padStart(5,"0")}`,`Other package ${i}`)),result("10027","Ordinary scanner rule")]);
 await upload("osv.sarif","OSV",[result("CVE-2026-12345","Package C","note")]);
 await chooseView(page,"Advisories");await expect(page).toHaveURL(/\/security\/advisories$/);
 const region=page.getByRole("region",{name:"Security advisories",exact:true});
 await expect(region.getByRole("status")).toHaveText("Advisories: 31 · Findings: 33");await expect(region.getByText("Findings: 3 · Issues: 3 · Reports: 2 · Scanners: 2",{exact:true})).toBeVisible();
 await page.screenshot({path:testInfo.outputPath("advisories.png")});
 await region.getByRole("button",{name:"Open advisory: CVE-2026-12345",exact:true}).click();
 await expect(region.getByText("Package A",{exact:true})).toBeVisible();await expect(region.getByText("Package B",{exact:true})).toBeVisible();await expect(region.getByText("Package C",{exact:true})).toBeVisible();
 await region.getByRole("button",{name:"Start task for CVE-2026-12345",exact:true}).first().click();await page.getByRole("menuitem",{name:/^Investigate/}).click();
 const task=page.getByRole("dialog",{name:"Create security task"});await expect(task).toBeVisible();await task.getByRole("button",{name:"Cancel task",exact:true}).click();
 await region.getByRole("button",{name:"View finding: CVE-2026-12345",exact:true}).first().click();await expect(page.getByRole("dialog").getByText("Package A",{exact:true})).toBeVisible();await page.getByRole("button",{name:"Close finding",exact:true}).click();
 await region.getByRole("button",{name:"Back to advisories",exact:true}).click();await region.getByRole("button",{name:"Next",exact:true}).click();await expect(region.getByText("Page 2",{exact:true})).toBeVisible();
 await region.getByRole("button",{name:"Sort",exact:true}).click();await page.getByRole("menuitemradio",{name:"Oldest",exact:true}).click();await expect(region.getByText("Page 1",{exact:true})).toBeVisible();
 await region.getByRole("textbox",{name:"Search advisory IDs, titles, packages, or paths",exact:true}).fill("CVE-2026-12345");await expect(region.getByRole("button",{name:/^Open advisory:/})).toHaveCount(1);
 await chooseFilter(page,"Scanner tool","OSV","Security advisories");await chooseFilter(page,"Severity","Low","Security advisories");await expect(region.getByText("Findings: 1 · Issues: 1 · Reports: 1 · Scanners: 1",{exact:true})).toBeVisible();
 await region.getByRole("button",{name:"Clear filters",exact:true}).click();await expect(region.getByRole("status")).toHaveText("Advisories: 31 · Findings: 33");
 await page.reload();await expect(region.getByRole("status")).toHaveText("Advisories: 31 · Findings: 33");
 expect(await region.evaluate(node=>node.scrollWidth<=node.clientWidth)).toBe(true);
});

test("advisory route follows browser navigation and workspace isolation",async({page})=>{
 await mockActions(page);await page.goto("/");await chooseView(page,"Import SARIF");
 const source=JSON.stringify({version:"2.1.0",runs:[{tool:{driver:{name:"Scanner"}},results:[{ruleId:"CVE-2026-12345",level:"warning",message:{text:"Workspace A advisory"}}]}]});
 await page.locator("#security-import").setInputFiles({name:"scan.sarif",mimeType:"application/json",buffer:Buffer.from(source)});await expect(page.getByText("Report imported.",{exact:true})).toBeVisible();
 await chooseView(page,"Advisories");await expect(page.getByRole("button",{name:"Open advisory: CVE-2026-12345",exact:true})).toBeVisible();
 await chooseView(page,"All findings");await expect(page).toHaveURL(/\/security$/);await page.goBack();await expect(page).toHaveURL(/\/security\/advisories$/);
 await expect(page.getByRole("button",{name:"Open advisory: CVE-2026-12345",exact:true})).toBeVisible();
 await page.getByRole("button",{name:"Switch workspace",exact:true}).click();await expect(page.getByText(/No matching advisories/)).toBeVisible();await expect(page.getByRole("button",{name:"Open advisory: CVE-2026-12345",exact:true})).toHaveCount(0);
 await page.getByRole("button",{name:"Switch workspace",exact:true}).click();await expect(page.getByRole("button",{name:"Open advisory: CVE-2026-12345",exact:true})).toBeVisible();
});

test("standard SARIF context and HTTP evidence render safely", async ({page}) => {
 const unexpected=[];page.on("request",request=>{if(!request.url().startsWith("http://127.0.0.1:18843"))unexpected.push(request.url());});
 await mockActions(page,{commonDetail:{
  title:"Unsafe output", finding:{title:"Unsafe output",kind:"review",rank:0,severity_source:"result.level"},
  context:{automation_id:"web-audit/staging",analysis_target:{uri:"https://stage.example.com/"},first_detected_at:"2026-01-01T12:00:00Z",invocations:[{started_at:"2026-01-01T12:00:00Z",ended_at:"2026-01-01T12:01:00Z",execution_successful:false}]},
  locations:[{uri:"src/handler.php",resolved_uri:"file:///checkout/src/handler.php",line:12,snippet:"<script>window.evidenceExecuted=true</script>"}],
  related_locations:[{uri:"input.php",message:"Input source"}], evidence:[{kind:"attachment",text:"Supporting trace",artifact:{uri:"evidence.txt"}}],
  http:{request:{method:"GET",target:"https://stage.example.com/login",headers:{Authorization:"[redacted]"}},response:{status_code:403,reason:"Forbidden",body:"<img src=https://example.com/tracker onerror=alert(1)>"+"long".repeat(500)}},
  classifications:[{taxonomy:"CWE",id:"79",name:"Cross-site scripting"}],
  references:[{kind:"viewer",uri:"javascript:alert(1)"},{kind:"work_item",uri:"https://example.com/ticket/1"}],
  normalization_notes:["Credential headers are redacted."]
 }});
 await page.goto("/");await chooseView(page,"Import SARIF");await page.locator("#security-import").setInputFiles({name:"scan.sarif",mimeType:"application/json",buffer:Buffer.from(raw)});await expect(page.getByText("Report imported.",{exact:true})).toBeVisible();await chooseView(page,"All findings");
 await page.getByRole("button",{name:"View finding: SQL001",exact:true}).click();const drawer=page.getByRole("dialog");
 await expect(drawer.getByRole("heading",{name:"Analysis context",exact:true})).toBeVisible();
 await expect(drawer.getByText("Scanner result level",{exact:true})).toBeVisible();await expect(drawer.locator("dd").filter({hasText:/^0$/})).toBeVisible();
 await expect(drawer.getByText("file:///checkout/src/handler.php:12",{exact:true})).toBeVisible();await expect(drawer.getByText("Supporting trace",{exact:true})).toBeVisible();
 await drawer.getByText("Request",{exact:true}).click();await expect(drawer.getByText("Authorization: [redacted]",{exact:true})).toBeVisible();
 await drawer.getByText("Response",{exact:true}).click();await expect(drawer.getByText("403 Forbidden",{exact:true})).toBeVisible();
 await expect(drawer.locator('a[href^="javascript:"], img, script, iframe')).toHaveCount(0);
 await expect(drawer.getByRole("link",{name:"https://example.com/ticket/1",exact:true})).toHaveAttribute("rel","noopener noreferrer");
 expect(await page.evaluate(()=>window.evidenceExecuted)).toBeUndefined();expect(unexpected).toEqual([]);
 expect(await drawer.evaluate(node=>node.scrollWidth<=node.clientWidth)).toBe(true);
});

test("created tasks recover a failed issue association without duplicate tasks",async({page})=>{
 const records=await mockActions(page,{failTaskLink:1});await page.goto("/");await chooseView(page,"Import SARIF");await page.locator("#security-import").setInputFiles({name:"scan.sarif",mimeType:"application/json",buffer:Buffer.from(raw)});await expect(page.getByText("Report imported.",{exact:true})).toBeVisible();await chooseView(page,"All findings");
 await page.getByRole("button",{name:"Start task for SQL001",exact:true}).click();await page.getByRole("menuitem",{name:/^Fix/}).click();
 await page.getByRole("dialog",{name:"Create security task"}).getByRole("button",{name:"Start native task",exact:true}).click();
 await expect(page.getByText("Temporary link failure",{exact:false})).toBeVisible();expect(records.tasks.size).toBe(1);
 await page.getByRole("button",{name:"Retry linking",exact:true}).click();await expect(page.getByRole("button",{name:"Retry linking",exact:true})).toHaveCount(0);
 await expect(page.getByText("1 linked task",{exact:true})).toBeVisible();expect(records.tasks.size).toBe(1);
});

test("preset editing handles shared revision conflicts and explicit reset",async({page})=>{
 const records=await mockActions(page);await page.goto("/");await chooseView(page,"Task presets");
 const settings=page.getByRole("region",{name:"Task presets",exact:true});
 await settings.getByRole("group",{name:"Investigate",exact:true}).getByLabel("Name",{exact:true}).fill("My pending edit");
 records.presetSettings.set("ws-a",{presets:[{id:"other",label:"Other teammate preset",hint:"",icon:"check",prompt_template:"{{finding}}"}],revision:1,customized:true});
 await settings.getByRole("button",{name:"Save presets",exact:true}).click();await expect(settings.getByRole("alert")).toContainText("reload");
 await expect(settings.getByRole("group",{name:"My pending edit",exact:true})).toBeVisible();
 await settings.getByRole("button",{name:"Reload presets",exact:true}).click();await settings.getByRole("group",{name:"Confirm",exact:true}).getByRole("button",{name:"Confirm",exact:true}).click();
 await expect(settings.getByRole("group",{name:"Other teammate preset",exact:true})).toBeVisible();
 await settings.getByRole("button",{name:"Reset to defaults",exact:true}).click();await settings.getByRole("group",{name:"Confirm",exact:true}).getByRole("button",{name:"Confirm",exact:true}).click();
 await expect(settings.getByRole("group",{name:"Investigate",exact:true})).toBeVisible();expect(records.presetSettings.get("ws-a").revision).toBe(2);
});

test("workspace preset edits use the native settings save contributor",async({page})=>{
 const records=await mockActions(page);await page.goto("/?native-settings=1");await chooseView(page,"Task presets");
 const settings=page.getByRole("region",{name:"Task presets",exact:true});
 await expect(settings.getByRole("group",{name:"Investigate",exact:true})).toBeVisible();
 await expect(settings.getByRole("button",{name:"Save presets",exact:true})).toHaveCount(0);
 await settings.getByRole("group",{name:"Investigate",exact:true}).getByLabel("Name",{exact:true}).fill("Shared native preset");
 await page.getByRole("button",{name:"Native save presets",exact:true}).click();
 await expect(page.getByRole("button",{name:"Native save presets",exact:true})).toHaveCount(0);
 expect(records.presetSettings.get("ws-a").presets[0].label).toBe("Shared native preset");
 expect(records.presetSettings.get("ws-a").revision).toBe(1);
});

test("archive and restore preserve source and pins while filtering default views", async ({page},testInfo)=>{
 const records=await mockActions(page);const doc=JSON.parse(raw);doc.runs[0].results[0].ruleId="CVE-2026-12345";const original=JSON.stringify(doc);
 await page.goto("/");await chooseView(page,"Import SARIF");
 await page.locator("#security-import").setInputFiles({name:"archive.sarif",mimeType:"application/json",buffer:Buffer.from(original)});
 await expect(page.getByText("Report imported.",{exact:true})).toBeVisible();
 await chooseView(page,"Reports");await expect(page.getByRole("group",{name:"Report status",exact:true}).getByRole("button",{name:/^Active/})).toHaveAttribute("aria-pressed","true");
 let row=page.locator("li.kandev-security-report-row");
 await row.getByRole("button",{name:"Pin report",exact:true}).click();await expect(row.getByRole("button",{name:"Unpin report",exact:true})).toBeVisible();
 await row.getByRole("button",{name:"Archive report",exact:true}).click();await expect(row).toHaveCount(0);
 expect(records.reports.size).toBe(1);expect([...records.reports.values()][0].pinned).toBe(true);
 await chooseView(page,"All findings");await expect(page.getByText("No findings match these filters.",{exact:true})).toBeVisible();
 await chooseView(page,"Advisories");await expect(page.getByRole("button",{name:"Open advisory: CVE-2026-12345",exact:true})).toHaveCount(0);
 await chooseView(page,"Reports");await page.getByRole("group",{name:"Report status",exact:true}).getByRole("button",{name:/^Archived/}).click();
 await expect(row.getByRole("button",{name:"Restore report",exact:true})).toBeVisible();
 await expect(row.getByRole("button",{name:"Unpin report",exact:true})).toBeVisible();
 await page.screenshot({path:testInfo.outputPath("archived-reports.png")});
 expect(await page.locator("main").evaluate(node=>node.scrollWidth<=node.clientWidth)).toBe(true);
 await row.getByRole("button",{name:/archive.sarif/}).click();
 await expect(page.getByRole("note")).toContainText("Archived report.");
 const downloading=page.waitForEvent("download");await page.getByRole("button",{name:"Export original SARIF",exact:true}).click();
 const download=await downloading;const {readFile}=await import("node:fs/promises");expect((await readFile(await download.path())).toString()).toBe(original);
 await page.getByRole("button",{name:"Restore report",exact:true}).click();await expect(page.getByRole("note")).toHaveCount(0);
 await expect(page.getByRole("button",{name:"Archive report",exact:true})).toBeVisible();
 await page.getByRole("button",{name:"Back to reports",exact:true}).click();await expect(row).toHaveCount(0);
 await page.getByRole("group",{name:"Report status",exact:true}).getByRole("button",{name:/^All/}).click();await expect(row).toHaveCount(1);
 await row.getByRole("button",{name:"Archive report",exact:true}).click();await expect(row.getByRole("button",{name:"Restore report",exact:true})).toBeVisible();
 await chooseView(page,"Import SARIF");await page.locator("#security-import").setInputFiles({name:"archive.sarif",mimeType:"application/json",buffer:Buffer.from(original)});
 await expect(page.getByRole("status")).toContainText("remains archived");
 await chooseView(page,"Reports");await row.getByRole("button",{name:"Restore report",exact:true}).click();
 await chooseView(page,"All findings");await expect(page.getByRole("button",{name:"View finding: CVE-2026-12345",exact:true})).toBeVisible();
 await chooseView(page,"Advisories");await expect(page.getByRole("button",{name:"Open advisory: CVE-2026-12345",exact:true})).toBeVisible();
 await chooseView(page,"Reports");await page.getByRole("button",{name:"Switch workspace",exact:true}).click();
 await expect(row).toHaveCount(0);await expect(page.getByRole("group",{name:"Report status",exact:true}).getByRole("button",{name:/^Active/})).toHaveAttribute("aria-pressed","true");
});

test("reports share aggregate pagination, status chips, scanner filtering and upload shortcut",async({page},testInfo)=>{
 const records=await mockActions(page);
 for(let i=0;i<31;i++){
  const tool=i===30?"Empty scanner":"Scanner A",doc=JSON.parse(raw);doc.runs[0].tool.driver.name=tool;if(i===30)doc.runs[0].results=[];
  records.reports.set(`report-${i}`,{id:`report-${i}`,workspace_id:"ws-a",filename:`report-${i}.sarif`,tools:tool,finding_count:doc.runs[0].results.length,created_at:new Date(Date.UTC(2026,0,1,0,i)).toISOString(),updated_at:new Date(Date.UTC(2026,0,1,0,i)).toISOString(),actor_id:"actor",original:JSON.stringify(doc),archived_at:i>=26?"2026-11-01T00:00:00Z":undefined});
 }
 await page.goto("/");await chooseView(page,"Reports");
 const region=page.getByRole("region",{name:"Reports",exact:true}),status=region.getByRole("group",{name:"Report status",exact:true}),nav=region.getByRole("navigation",{name:"Reports pagination",exact:true});
 await expect(nav.getByText("1–25 of 26",{exact:true})).toBeVisible();
 await expect(status.getByRole("button",{name:/^Active/})).toContainText("26");await expect(status.getByRole("button",{name:/^All/})).toContainText("31");await expect(status.getByRole("button",{name:/^Archived/})).toContainText("5");
 await nav.getByRole("button",{name:"Next",exact:true}).click();await expect(nav.getByText("Page 2",{exact:true})).toBeVisible();await expect(nav.getByText("26–26 of 26",{exact:true})).toBeVisible();await expect(nav.getByRole("button",{name:"Next",exact:true})).toBeDisabled();
 await status.getByRole("button",{name:/^All/}).click();await expect(nav.getByText("Page 1",{exact:true})).toBeVisible();await expect(nav.getByText("1–25 of 31",{exact:true})).toBeVisible();
 await chooseFilter(page,"Scanner tool","Scanner A","Reports");await expect(nav.getByText("1–25 of 30",{exact:true})).toBeVisible();await expect(status.getByRole("button",{name:/^Archived/})).toContainText("4");
 await status.getByRole("button",{name:/^Archived/}).click();await expect(nav.getByText("1–4 of 4",{exact:true})).toBeVisible();
 await chooseFilter(page,"Scanner tool","Empty scanner","Reports");await expect(nav.getByText("1–1 of 1",{exact:true})).toBeVisible();await expect(region.getByRole("button",{name:/report-30.sarif/})).toBeVisible();
 await status.getByRole("button",{name:/^Active/}).click();await expect(page.getByText("No reports match these filters.",{exact:true})).toBeVisible();await expect(nav.getByText("0–0 of 0",{exact:true})).toBeVisible();
 await region.getByRole("button",{name:"Clear Scanner tool",exact:true}).click();await expect(nav.getByText("1–25 of 26",{exact:true})).toBeVisible();
 const scroller=region.locator(".kandev-security-results-scroll"),before=await nav.boundingBox();await scroller.evaluate(node=>node.scrollTop=node.scrollHeight);const after=await nav.boundingBox();expect(Math.abs(before.y-after.y)).toBeLessThan(2);
 expect(await region.evaluate(node=>node.scrollWidth<=node.clientWidth)).toBe(true);await page.screenshot({path:testInfo.outputPath("reports-toolbar.png")});
 await region.getByRole("button",{name:"Upload report",exact:true}).click();await expect(page.locator("#security-import")).toBeVisible();
});

test("report filename search combines filters and counts, clears and resets pagination",async({page},testInfo)=>{
 const records=await mockActions(page);
 for(let i=0;i<31;i++){
  const tool=i===30?"Scanner B":"Scanner A",doc=JSON.parse(raw);doc.runs[0].tool.driver.name=tool;
  const filename=i===30?"prod-other.sarif":i===29?"notes-only.sarif":`prod-${i}.sarif`;
  records.reports.set(`search-${i}`,{id:`search-${i}`,workspace_id:"ws-a",filename,tools:tool,finding_count:2,created_at:"2026-11-01T00:00:00Z",updated_at:"2026-11-01T00:00:00Z",actor_id:"actor",original:JSON.stringify(doc),archived_at:i>=26&&i<29?"2026-11-01T01:00:00Z":undefined});
 }
 await page.goto("/");await chooseView(page,"Reports");
 const region=page.getByRole("region",{name:"Reports",exact:true}),nav=region.getByRole("navigation",{name:"Reports pagination",exact:true}),status=region.getByRole("group",{name:"Report status",exact:true}),search=region.getByRole("textbox",{name:"Search report filenames",exact:true});
 await status.getByRole("button",{name:/^All/}).click();await nav.getByRole("button",{name:"Next",exact:true}).click();await expect(nav.getByText("Page 2",{exact:true})).toBeVisible();
 await search.fill("PROD-");await expect(nav.getByText("1–25 of 30",{exact:true})).toBeVisible();await expect(nav.getByText("Page 1",{exact:true})).toBeVisible();
 await chooseFilter(page,"Scanner tool","Scanner A","Reports");await expect(nav.getByText("1–25 of 29",{exact:true})).toBeVisible();await expect(search).toHaveValue("PROD-");
 await expect(status.getByRole("button",{name:/^Active/})).toContainText("26");await expect(status.getByRole("button",{name:/^All/})).toContainText("29");await expect(status.getByRole("button",{name:/^Archived/})).toContainText("3");
 await status.getByRole("button",{name:/^Archived/}).click();await expect(nav.getByText("1–3 of 3",{exact:true})).toBeVisible();
 await search.fill("prod-27");await expect(nav.getByText("1–1 of 1",{exact:true})).toBeVisible();await expect(region.getByRole("button",{name:/prod-27.sarif/})).toBeVisible();
 await page.screenshot({path:testInfo.outputPath("report-filename-search.png")});expect(await region.evaluate(node=>node.scrollWidth<=node.clientWidth)).toBe(true);
 await region.getByRole("button",{name:"Clear filename search",exact:true}).click();await expect(search).toHaveValue("");await expect(nav.getByText("1–3 of 3",{exact:true})).toBeVisible();await expect(status.getByRole("button",{name:/^Archived/})).toHaveAttribute("aria-pressed","true");
 await search.fill("Sensitive evidence");await search.press("Enter");await expect(nav.getByText("0–0 of 0",{exact:true})).toBeVisible();await expect(region.getByText("No reports match these filters.",{exact:true})).toBeVisible();
 await search.fill("prod-27");await expect(nav.getByText("1–1 of 1",{exact:true})).toBeVisible();
 await chooseView(page,"Import SARIF");await chooseView(page,"Reports");await expect(search).toHaveValue("prod-27");
 await page.getByRole("button",{name:"Switch workspace",exact:true}).click();await expect(search).toHaveValue("");await expect(region.getByText("No active reports. Import a report or restore one from Archived.",{exact:true})).toBeVisible();
});

test("review status dropdown filters grouped issues and occurrences with matching counts",async({page},testInfo)=>{
 await mockActions(page);await page.goto("/");
 const doc=JSON.parse(raw);doc.runs[0].versionControlProvenance=[{repositoryUri:"https://example.com/repo"}];
 doc.runs[0].results[0].partialFingerprints={line:"stable"};doc.runs[0].results[0].locations=[{physicalLocation:{artifactLocation:{uri:"src/db.go"}}}];
 for(const name of ["first.sarif","repeat.sarif"]){
  if(name==="repeat.sarif"){doc.runs[0].results=doc.runs[0].results.slice(0,1);doc.runs[0].results[0].message.text="Repeated SQL evidence";}
  await chooseView(page,"Import SARIF");await page.locator("#security-import").setInputFiles({name,mimeType:"application/json",buffer:Buffer.from(JSON.stringify(doc))});await expect(page.getByText("Report imported.",{exact:true})).toBeVisible();
 }
 await chooseView(page,"All findings");const region=page.getByRole("region",{name:"Findings across reports"}),overview=region.getByRole("group",{name:"Severity overview"});
 await expect(region.getByRole("status")).toHaveText("2 issues");
 await chooseFilter(page,"Status","Open");await expect(region.getByRole("button",{name:"Status: Open",exact:true})).toBeVisible();
 await region.getByRole("button",{name:"View finding: SQL001",exact:true}).click();const drawer=page.getByRole("dialog");
 await drawer.getByRole("textbox",{name:"Reason for status change",exact:true}).fill("Reviewed remediation evidence");await drawer.getByRole("button",{name:"Close issue",exact:true}).click();await expect(drawer.getByText("Issue status: Closed",{exact:true})).toBeVisible();
 await drawer.getByRole("button",{name:"Close finding",exact:true}).click();await expect(region.getByRole("status")).toHaveText("1 issue");await expect(region.getByRole("button",{name:"View finding: SQL001",exact:true})).toHaveCount(0);await expect(overview.getByRole("button",{name:/^High/})).toContainText("0");
 await chooseFilter(page,"Status","Closed");await expect(region.getByRole("status")).toHaveText("1 issue");await expect(region.getByText("2 occurrences · Closed",{exact:true})).toBeVisible();
 await region.getByRole("button",{name:"Grouped issues",exact:true}).click();await expect(region.getByRole("status")).toHaveText("2 occurrences");await expect(region.getByRole("button",{name:"Status: Closed",exact:true})).toBeVisible();
 await chooseFilter(page,"Rule","SQL001");await chooseFilter(page,"Severity","Low");await expect(region.getByRole("status")).toHaveText("0 occurrences");await expect(overview.getByRole("button",{name:/^High/})).toContainText("2");
 await overview.getByRole("button",{name:/^All/}).click();await expect(region.getByRole("status")).toHaveText("2 occurrences");await expect(region.getByRole("button",{name:"Status: Closed",exact:true})).toBeVisible();
 await page.screenshot({path:testInfo.outputPath("findings-review-status.png")});expect(await region.evaluate(node=>node.scrollWidth<=node.clientWidth)).toBe(true);
 await region.getByRole("button",{name:"Clear filters",exact:true}).click();await expect(region.getByRole("status")).toHaveText("3 occurrences");await expect(region.getByRole("button",{name:"Status",exact:true})).toBeVisible();
 await chooseFilter(page,"Status","Closed");await region.getByRole("button",{name:"Clear Status",exact:true}).click();await expect(region.getByRole("status")).toHaveText("3 occurrences");
 await chooseFilter(page,"Status","Closed");await page.getByRole("button",{name:"Switch workspace",exact:true}).click();await expect(region.getByRole("button",{name:"Status",exact:true})).toBeVisible();await expect(region.getByText("No findings match these filters.",{exact:true})).toBeVisible();
});

test("changing review status resets findings pagination",async({page})=>{
 const records=await mockActions(page);
 for(let i=0;i<31;i++){
  const doc=JSON.parse(raw);doc.runs[0].results=doc.runs[0].results.slice(0,1);
  records.reports.set(`status-${i}`,{id:`status-${i}`,workspace_id:"ws-a",filename:`status-${i}.sarif`,tools:"Scanner",finding_count:1,created_at:"2026-11-01T00:00:00Z",updated_at:"2026-11-01T00:00:00Z",actor_id:"actor",original:JSON.stringify(doc)});
  if(i>=26)records.issues.set(`status-${i}:0`,{status:"closed"});
 }
 await page.goto("/");const region=page.getByRole("region",{name:"Findings across reports"}),nav=region.getByRole("navigation",{name:"Findings pagination",exact:true});
 await nav.getByRole("button",{name:"Next",exact:true}).click();await expect(nav.getByText("Page 2",{exact:true})).toBeVisible();
 await chooseFilter(page,"Status","Closed");await expect(nav.getByText("Page 1",{exact:true})).toBeVisible();await expect(nav.getByText("1–5 of 5",{exact:true})).toBeVisible();
 await chooseFilter(page,"Status","Open");await expect(nav.getByText("1–25 of 26",{exact:true})).toBeVisible();await nav.getByRole("button",{name:"Next",exact:true}).click();await expect(nav.getByText("26–26 of 26",{exact:true})).toBeVisible();
 await region.getByRole("button",{name:"View finding: SQL001",exact:true}).click();const drawer=page.getByRole("dialog");await drawer.getByRole("textbox",{name:"Reason for status change",exact:true}).fill("Reviewed last item on page two");await drawer.getByRole("button",{name:"Close issue",exact:true}).click();await expect(drawer.getByText("Issue status: Closed",{exact:true})).toBeVisible();await drawer.getByRole("button",{name:"Close finding",exact:true}).click();await expect(nav.getByText("Page 1",{exact:true})).toBeVisible();await expect(nav.getByText("1–25 of 25",{exact:true})).toBeVisible();
 await chooseFilter(page,"Status","All");await expect(nav.getByText("1–25 of 31",{exact:true})).toBeVisible();
});

test("agent reason-only reviews display attribution while the UI retains close and reopen",async({page},testInfo)=>{
 const records=await mockActions(page);await page.goto("/");await chooseView(page,"Import SARIF");
 await page.locator("#security-import").setInputFiles({name:"review.sarif",mimeType:"application/json",buffer:Buffer.from(raw)});await expect(page.getByText("Report imported.",{exact:true})).toBeVisible();
 const report=[...records.reports.values()][0],reason="Expanded agent assessment <script>not executable</script>";
 records.issues.set(`${report.id}:0`,{status:"closed",status_reason:reason,status_actor:"agent:task:task-review",history:[
  {id:2,old_status:"closed",new_status:"closed",reason,actor:"agent:task:task-review",created_at:"2026-11-01T10:01:00Z",kind:"reason_updated",task_id:"task-review",session_id:"session-review",invocation_id:"call-2"},
  {id:1,old_status:"open",new_status:"closed",reason:"Initial agent assessment",actor:"agent:task:task-review",created_at:"2026-11-01T10:00:00Z",kind:"status_changed",task_id:"task-review",session_id:"session-review",invocation_id:"call-1"},
 ]});
 await chooseView(page,"All findings");await page.getByRole("button",{name:"View finding: SQL001",exact:true}).click();const drawer=page.getByRole("dialog"),history=drawer.getByRole("region",{name:"Issue history",exact:true});
 await expect(history.getByText("Issue status: Closed",{exact:true})).toBeVisible();await expect(history.getByText(`Review reason: ${reason}`,{exact:true})).toBeVisible();await expect(history.getByText(/^Reason updated · agent:task:task-review/)).toBeVisible();
 await expect(history.getByText("Agent review · Task: task-review · Session: session-review",{exact:true})).toHaveCount(2);await expect(history.getByRole("heading",{name:"Review history",exact:true})).toBeVisible();await expect(history.locator("script")).toHaveCount(0);
 await expect(history.getByRole("button",{name:"Reopen issue",exact:true})).toBeVisible();await expect(history.getByRole("button",{name:"Close issue",exact:true})).toHaveCount(0);
 await history.screenshot({path:testInfo.outputPath("agent-review-history.png")});
 await history.getByRole("textbox",{name:"Reason for status change",exact:true}).fill("Human review requests another check");await history.getByRole("button",{name:"Reopen issue",exact:true}).click();
 await expect(history.getByText("Issue status: Open",{exact:true})).toBeVisible();await expect(history.getByText("Review reason: Human review requests another check",{exact:true})).toBeVisible();await expect(history.getByRole("button",{name:"Close issue",exact:true})).toBeVisible();
 expect(JSON.parse(records.reports.get(report.id).original).runs[0].results[0].message.text).toContain("SQL injection");
});
