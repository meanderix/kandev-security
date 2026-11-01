import assert from "node:assert/strict";
import test from "node:test";
import { createReportsModel, MAX_REPORT_BYTES } from "../ui/bundle.js";

const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };
const file = (text = "{}") => Object.assign(new Blob([text]), { name: "scan.sarif" });

test("pin responses are fenced by workspace and purged reports leave the detail view",async()=>{
 const late=deferred();const model=createReportsModel({async invokeAction(key,{body}){
   if(key==="reports.pin")return body.id==="late"?late.promise:{retained:false,purged_count:1};
   if(key==="reports.get")return{report:{id:body.id},findings:[]};return{items:[],next_offset:0};
 }});
 await model.setWorkspace("a");await model.open("report");await model.pinReport({id:"report"},false);
 assert.equal(model.getSnapshot().selectedId,null);assert.match(model.getSnapshot().notice,/Retention removed 1/);
 const pending=model.pinReport({id:"late"},true);await model.setWorkspace("b");late.resolve({retained:true,purged_count:0});await pending;
 assert.equal(model.getSnapshot().workspaceId,"b");assert.equal(model.getSnapshot().notice,"");assert.equal(model.getSnapshot().pinning,false);model.destroy();
});

test("a late workspace response cannot replace the current workspace data", async () => {
  const old = deferred();
  const model = createReportsModel({ invokeAction: (_, input) => input.workspaceId === "a" ? old.promise : Promise.resolve({ items: [{ id: "b" }], next_offset: 0 }) });
  const pending = model.setWorkspace("a");
  await model.setWorkspace("b");
  old.resolve({ items: [{ id: "a" }], next_offset: 0 });
  await pending;
  assert.equal(model.getSnapshot().workspaceId, "b");
  assert.deepEqual(model.getSnapshot().aggregate.items, [{ id: "b" }]);
  model.destroy();
});

test("imports are chunked by bytes and always use the captured workspace", async () => {
  const chunks = []; const calls = [];
  const api = { async invokeAction(key, input) {
    calls.push({ key, input });
    if (key === "reports.list") return { items: [], next_offset: 0 };
    if (key === "imports.start") return { id: "upload", chunk_bytes: 1024 };
    if (key === "imports.append") { const raw = Buffer.from(input.body.data, "base64"); chunks.push(raw); return { offset: input.body.offset + raw.length }; }
    if (key === "imports.complete") return { report: { id: "report" }, duplicate: true };
  } };
  const model = createReportsModel(api); await model.setWorkspace("workspace");
  const text = "é😀".repeat(1000);
  await model.importFile(file(text));
  assert.equal(Buffer.concat(chunks).toString(), text);
  assert.ok(chunks.length > 1);
  assert.ok(calls.every((call) => call.input.workspaceId === "workspace"));
  assert.match(model.getSnapshot().notice, /already imported/);
  assert.equal(model.getSnapshot().importing, false);
});

test("switching workspace during a file read cancels the old import without publishing it", async () => {
  const read = deferred(); let reading; const reachedRead = new Promise((resolve) => { reading = resolve; });
  const calls = [];
  const model = createReportsModel({ async invokeAction(key, input) {
    calls.push({ key, input });
    if (key === "reports.list") return { items: [], next_offset: 0 };
    if (key === "imports.start") return { id: "old-upload", chunk_bytes: 1024 };
    return {};
  } });
  await model.setWorkspace("old");
  const importing = model.importFile({ name: "old.sarif", size: 2, slice() { reading(); return { arrayBuffer: () => read.promise }; } });
  await reachedRead;
  await model.setWorkspace("new"); read.resolve(new TextEncoder().encode("{}").buffer); await importing;
  assert.equal(calls.some((c) => c.key === "imports.append" || c.key === "imports.complete"), false);
  const cancelled = calls.find((c) => c.key === "imports.cancel");
  assert.equal(cancelled.input.workspaceId, "old");
  assert.equal(model.getSnapshot().workspaceId, "new");
  assert.equal(model.getSnapshot().notice, "");
});

test("import errors clean up staging and oversized files do not start requests", async () => {
  let cancelled = false;
  const model = createReportsModel({ async invokeAction(key) {
    if (key === "reports.list") return { items: [], next_offset: 0 };
    if (key === "imports.start") return { id: "upload", chunk_bytes: 1024 };
    if (key === "imports.append") throw new Error("Storage unavailable");
    if (key === "imports.cancel") cancelled = true;
  } });
  await model.setWorkspace("workspace"); await model.importFile(file());
  assert.equal(cancelled, true);
  assert.equal(model.getSnapshot().error, "Storage unavailable");
  await model.importFile({ size: MAX_REPORT_BYTES + 1 });
  assert.match(model.getSnapshot().error, /20 MiB/);
});

test("back and unload fence pending detail and list responses", async () => {
  const detail = deferred(); const list = deferred();
  const model = createReportsModel({ async invokeAction(key) { return key === "reports.get" ? detail.promise : list.promise; } });
  const loading = model.setWorkspace("workspace");
  const opening = model.open("report"); model.back();
  detail.resolve({ report: { id: "report" } }); await opening;
  assert.equal(model.getSnapshot().detail, null);
  let updates = 0; model.subscribe(() => updates++); model.destroy();
  list.resolve({ items: [], next_offset: 0 }); await loading;
  assert.equal(updates, 0);
});

test("export reconstructs exact bytes and refuses invalid offsets", async () => {
  const raw = Buffer.from("é😀security");
  const model = createReportsModel({ async invokeAction(key, { body }) {
    if (key === "reports.list") return { items: [], next_offset: 0 };
    const start = body.offset; const chunk = raw.subarray(start, start + 3);
    return { data: chunk.toString("base64"), size: raw.length, next_offset: start + chunk.length < raw.length ? start + chunk.length : 0, filename: "../scan.sarif" };
  } });
  await model.setWorkspace("workspace"); const result = await model.exportReport("id");
  assert.equal(result.filename, "scan.sarif");
  assert.deepEqual(Buffer.from(await result.blob.arrayBuffer()), raw);
});

test("rapid detail/filter changes discard stale results", async () => {
  const old = deferred();
  const model = createReportsModel({ async invokeAction(key, { body }) {
    if (key === "reports.list") return { items: [], next_offset: 0 };
    if (body.search === "old") return old.promise;
    return { report: { id: "report" }, findings: [{ message: "current" }] };
  } });
  await model.setWorkspace("workspace");
  const first = model.open("report", { search: "old", offset: 0, level: "" });
  await model.open("report", { search: "new", offset: 0, level: "error" });
  old.resolve({ report: { id: "report" }, findings: [{ message: "old" }] }); await first;
  assert.equal(model.getSnapshot().detail.findings[0].message, "current");
  assert.equal(model.getSnapshot().query.level, "error");
});

test("aggregate requests include all filters, sort and pagination", async () => {
  const calls = [];
  const model = createReportsModel({ async invokeAction(key, input) {
    calls.push({ key, input });
    if (key === "reports.list") return { items: [], next_offset: 0 };
    return { items: [], total: 0, next_offset: 0 };
  } });
  await model.setWorkspace("workspace"); await model.setView("findings");
  const query = { language: "Python", tool: "Semgrep", rule: "RULE", severity: "high", sort: "recently_updated", offset: 25, search: "injection" };
  await model.aggregate(query);
  assert.deepEqual(calls.at(-1), { key: "issues.list", input: { workspaceId: "workspace", body: query } });
  await model.suggest("rule", "RULE");
  assert.deepEqual(calls.at(-1).input.body, { facet: "rule", search: "RULE" });
  assert.equal(model.getSnapshot().view, "findings");
});

test("aggregate view is preserved across workspaces and late results cannot leak", async () => {
  const old = deferred(); let delay = false;
  const model = createReportsModel({ async invokeAction(key, { workspaceId }) {
    if (key === "reports.list") return { items: [], next_offset: 0 };
    if (delay && workspaceId === "old") return old.promise;
    return { items: [{ report_id: workspaceId }], total: 1, next_offset: 0 };
  } });
  await model.setWorkspace("old"); await model.setView("findings");
  delay = true; const pending = model.aggregate();
  await model.setWorkspace("new"); old.resolve({ items: [{ report_id: "old" }], total: 1, next_offset: 0 }); await pending;
  assert.equal(model.getSnapshot().view, "findings");
  assert.equal(model.getSnapshot().aggregate.items[0].report_id, "new");
  assert.equal(model.getSnapshot().aggregateQuery.language, "");
});

test("stale aggregate and facet requests cannot overwrite newer filters", async () => {
  const old = deferred();
  const model = createReportsModel({ async invokeAction(key, { body }) {
    if (key === "reports.list") return { items: [], next_offset: 0 };
    if (body.search === "old") return old.promise;
    return { items: key === "findings.facets" ? ["NewRule"] : [{ message: "new" }], total: 1, next_offset: 0 };
  } });
  await model.setWorkspace("workspace");
  const aggregate = model.aggregate({ search: "old" });
  const facet = model.suggest("rule", "old");
  await model.aggregate({ search: "new" }); await model.suggest("rule", "new");
  old.resolve({ items: [], total: 0, next_offset: 0 }); await Promise.all([aggregate, facet]);
  assert.equal(model.getSnapshot().aggregate.items[0].message, "new");
  assert.deepEqual(model.getSnapshot().facets.rule, ["NewRule"]);
});

test("upload token secrets are cleared on navigation, workspace switch and unload", async () => {
  const model = createReportsModel({ async invokeAction(key) {
    if (key === "tokens.create") return { token: { id: "id" }, secret: "ksr_secret" };
    return { items: [], next_offset: 0 };
  } });
  await model.setWorkspace("a"); await model.setView("tokens"); await model.createToken("CI");
  assert.equal(model.getSnapshot().createdToken.secret, "ksr_secret");
  await model.setView("reports"); assert.equal(model.getSnapshot().createdToken, null);
  await model.setView("tokens"); await model.createToken("CI");
  await model.setWorkspace("b"); assert.equal(model.getSnapshot().createdToken, null);
  assert.equal(model.getSnapshot().view, "tokens");
  await model.createToken("CI"); model.destroy(); assert.equal(model.getSnapshot().createdToken, null);
});

test("late token creation cannot reveal a secret in a different workspace or view", async () => {
  const delayed = deferred();
  const model = createReportsModel({ async invokeAction(key) {
    if (key === "tokens.create") return delayed.promise;
    return { items: [], next_offset: 0 };
  } });
  await model.setWorkspace("a"); await model.setView("tokens");
  const creating = model.createToken("CI"); await model.setView("reports");
  delayed.resolve({ token: { id: "a" }, secret: "private" }); await creating;
  assert.equal(model.getSnapshot().createdToken, null);
  assert.equal(model.getSnapshot().tokenBusy, false);
});

test("import has a dedicated view and switching its workspace does not fetch reports", async () => {
  const calls = [];
  const model = createReportsModel({ async invokeAction(key, input) {
    calls.push({ key, input }); return { items: [], next_offset: 0 };
  } });
  await model.setWorkspace("a"); calls.length = 0;
  await model.setView("import");
  assert.equal(model.getSnapshot().view, "import");
  assert.equal(calls.length, 0);
  await model.setWorkspace("b");
  assert.equal(model.getSnapshot().view, "import");
  assert.equal(calls.length, 0);
  await model.setView("reports");
  assert.equal(calls.at(-1).key, "reports.list");
});

test("finding requests retain the query and fence stale detail after closing or switching workspace", async () => {
 const delayed = deferred();
 const model = createReportsModel({ async invokeAction(key) {
  if (key === "findings.get") return delayed.promise;
  return { items: [], total: 0, next_offset: 0 };
 } });
 await model.setWorkspace("a");
 const query = { language: "Go", tool: "", rule: "", severity: "high", search: "", sort: "newest", offset: 25 };
 await model.aggregate(query);
 const loading = model.openFinding({ report_id: "r", ordinal: 7 });
 model.closeFinding();
 delayed.resolve({ finding: { message: "private" } }); await loading;
 assert.equal(model.getSnapshot().findingDetail, null);
 assert.deepEqual(model.getSnapshot().aggregateQuery, query);
 await model.openFinding({ report_id: "r", ordinal: 8 });
 assert.equal(model.getSnapshot().findingDetail.finding.message, "private");
 await model.setWorkspace("b");
 assert.equal(model.getSnapshot().selectedFinding, null);
 assert.equal(model.getSnapshot().findingDetail, null);
 model.destroy();
});

test("finding helpers shorten only display paths and accept only safe advisory URLs", async () => {
 const { compactLocation, safeAdvisoryURL } = await import("../ui/bundle.js");
 assert.equal(compactLocation("file:///home/user/project/src/composer.lock"), "…/src/composer.lock");
 assert.equal(compactLocation("src/db.go"), "src/db.go");
 assert.equal(compactLocation("file:///home/user/my%20project/yarn.lock"), "…/my project/yarn.lock");
 for (const url of ["javascript:alert(1)", "data:text/html,test", "file:///etc/passwd", "https://user:pass@example.com", "https://example.com/\n"]) assert.equal(safeAdvisoryURL(url), null);
 assert.equal(safeAdvisoryURL("https://example.com/advisory"), "https://example.com/advisory");
});

test("late finding details cannot replace another workspace's selected finding", async () => {
 const old = deferred();
 const model = createReportsModel({ async invokeAction(key, { workspaceId, body }) {
  if (key === "findings.get") return workspaceId === "a" ? old.promise : { finding: { ordinal: body.ordinal, message: "current" } };
  return { items: [], total: 0, next_offset: 0 };
 } });
 await model.setWorkspace("a"); const pending = model.openFinding({ report_id: "private", ordinal: 9 });
 await model.setWorkspace("b"); await model.openFinding({ report_id: "other", ordinal: 3 });
 old.resolve({ finding: { message: "stale private finding" } }); await pending;
 assert.equal(model.getSnapshot().findingDetail.finding.message, "current");
 assert.equal(model.getSnapshot().selectedFinding.report_id, "other");
 await model.setView("reports"); assert.equal(model.getSnapshot().selectedFinding, null);
 model.destroy();
});

test("Markdown documents render only allowlisted elements and safe links", async () => {
 const { renderMarkdownDocument } = await import("../ui/bundle.js");
 const h = (type, props, ...children) => ({ type, props, children });
 const host = { jsx: h, React: { Fragment: "fragment" } };
 const tree = renderMarkdownDocument(host, [
  { kind: "p", children: [{ kind: "strong", text: "Upgrade" }, { kind: "a", url: "https://example.com/fix", text: "Advisory" }] },
  { kind: "a", url: "javascript:alert(1)", text: "Unsafe link" },
  { kind: "img", url: "https://example.com/tracker", text: "Image alt text" },
  { kind: "script", text: "Literal text" },
 ]);
 const elements = [];
 const collect = (node) => { if (node && typeof node === "object") { elements.push(node); node.children.flat(Infinity).forEach(collect); } };
 collect(tree);
 assert.equal(elements.filter((n) => n.type === "a").length, 1);
 assert.equal(elements.find((n) => n.type === "a").props.rel, "noopener noreferrer");
 assert.equal(elements.some((n) => n.type === "img" || n.type === "script" || n.props?.dangerouslySetInnerHTML), false);
});

test("grouping defaults to issues and the occurrence toggle preserves filters", async () => {
  const calls = [];
  const model = createReportsModel({ async invokeAction(key, input) { calls.push({key, input}); return {items: [],total:0,next_offset:0}; } });
  await model.setWorkspace("ws");
  assert.equal(calls.at(-1).key, "issues.list");
  await model.aggregate({search:"rule",sort:"oldest",offset:25});
  await model.setGrouped(false);
  assert.equal(calls.at(-1).key,"findings.list");
  assert.deepEqual(calls.at(-1).input.body,{search:"rule",sort:"oldest",offset:0});
  await model.setGrouped(true);
  assert.equal(calls.at(-1).key,"issues.list");
  model.destroy();
});

test("issue history is workspace fenced and status changes use the captured issue", async () => {
  const old = deferred(); let pending = false; const writes=[];
  const model = createReportsModel({ async invokeAction(key, {workspaceId,body}) {
    if(key==="findings.get") return {finding:{issue_id:body.id, ordinal:body.ordinal}};
    if(key==="issues.get") return pending ? old.promise : {issue:{id:body.id,status:"open"},occurrences:[],history:[]};
    if(key==="issues.set_status") {writes.push({workspaceId,...body});return {updated:true};}
    return {items:[],total:0,next_offset:0};
  } });
  await model.setWorkspace("a"); await model.openFinding({report_id:"issue-a",ordinal:0});
  await model.setIssueStatus("closed","Reviewed");
  assert.deepEqual(writes,[{workspaceId:"a",id:"issue-a",status:"closed",reason:"Reviewed"}]);
  pending=true;const loading=model.loadIssue("issue-a");
  await model.setWorkspace("b");old.resolve({issue:{id:"private"}});await loading;
  assert.equal(model.getSnapshot().issueDetail,null);
  assert.equal(model.getSnapshot().issueBusy,false);
  model.destroy();
});

test("archive refresh preserves detail and current filter, and workspace changes fence late writes", async () => {
  const late=deferred(), calls=[];
  const model=createReportsModel({async invokeAction(key,{workspaceId,body}){
    calls.push({key,workspaceId,body});
    if(key==="reports.archive") return body.id==="late"?late.promise:{report:{id:body.id,archived_at:body.archived?"now":""}};
    if(key==="reports.get") return {report:{id:body.id},findings:[]};
    return {items:[],next_offset:0};
  }});
  await model.setWorkspace("a");await model.setView("reports");await model.setReportStatus("all");
  await model.open("report");await model.archiveReport({id:"report"},true);
  assert.equal(model.getSnapshot().detail.report.archived_at,"now");
  assert.equal(model.getSnapshot().reportStatus,"all");
  assert.deepEqual(calls.filter(c=>c.key==="reports.list").at(-1).body,{offset:0,status:"all",tool:"",search:""});
  await model.archiveReport({id:"report"},false);assert.equal(model.getSnapshot().detail.report.archived_at,"");
  const pending=model.archiveReport({id:"late"},true);await model.setWorkspace("b");
  late.resolve({report:{id:"late",archived_at:"old"}});await pending;
  assert.equal(model.getSnapshot().workspaceId,"b");assert.equal(model.getSnapshot().notice,"");assert.equal(model.getSnapshot().archiving,false);assert.equal(model.getSnapshot().reportStatus,"active");model.destroy();
});

test("report visibility changes reset pagination and fence older list responses", async () => {
  const late=deferred();let deferList=false;const calls=[];
  const model=createReportsModel({async invokeAction(key,{body}){
    if(key!=="reports.list")return {items:[]};
    calls.push(body);if(deferList&&body.status==="active")return late.promise;
    return {items:[{id:body.status}],next_offset:0};
  }});
  await model.setWorkspace("ws");await model.setView("reports");deferList=true;
  const pending=model.list(25);await model.setReportStatus("archived");late.resolve({items:[{id:"stale"}],next_offset:50});await pending;
  assert.equal(model.getSnapshot().offset,0);assert.equal(model.getSnapshot().reports[0].id,"archived");
  assert.deepEqual(calls.at(-1),{offset:0,status:"archived",tool:"",search:""});model.destroy();
});

test("report scanner filtering resets pagination, preserves status and fences stale tools", async () => {
  const late=deferred();const calls=[];
  const model=createReportsModel({async invokeAction(key,{workspaceId,body}){
    calls.push({key,workspaceId,body});
    if(key==="reports.tools") return workspaceId==="old"?late.promise:{items:["Current scanner"],next_offset:0};
    return {items:[],total:0,status_counts:{active:0,archived:0,all:0},next_offset:0};
  }});
  await model.setWorkspace("old");await model.setView("reports");await model.setReportStatus("all");await model.list(25);
  await model.setReportTool("Scanner, A");
  assert.equal(model.getSnapshot().offset,0);assert.equal(model.getSnapshot().reportStatus,"all");
  assert.deepEqual(calls.filter(c=>c.key==="reports.list").at(-1).body,{offset:0,status:"all",tool:"Scanner, A",search:""});
  const pending=model.suggestReportTools();await model.setWorkspace("new");await model.suggestReportTools();
  late.resolve({items:["Private scanner"],next_offset:25});await pending;
  assert.equal(model.getSnapshot().reportTool,"");assert.deepEqual(model.getSnapshot().reportTools,["Current scanner"]);assert.equal(model.getSnapshot().reportToolsMore,false);model.destroy();
});

test("filename search preserves other filters, resets pagination and fences late responses",async()=>{
 const late=deferred(),calls=[];
 const model=createReportsModel({async invokeAction(key,{body}){
  if(key!=="reports.list")return {items:[]};calls.push(body);
  if(body.search==="old")return late.promise;
  return {items:[{id:body.search}],total:1,next_offset:0};
 }});
 await model.setWorkspace("a");await model.setView("reports");await model.setReportStatus("all");await model.setReportTool("Scanner");await model.list(25);
 const pending=model.setReportSearch("old");await model.setReportSearch("Prod");late.resolve({items:[{id:"stale"}],total:1,next_offset:0});await pending;
 assert.equal(model.getSnapshot().offset,0);assert.equal(model.getSnapshot().reports[0].id,"Prod");
 assert.deepEqual(calls.at(-1),{offset:0,status:"all",tool:"Scanner",search:"Prod"});
 await model.setReportSearch("");assert.equal(calls.at(-1).tool,"Scanner");assert.equal(calls.at(-1).status,"all");
 await model.setReportSearch("Prod");await model.setWorkspace("b");assert.equal(model.getSnapshot().reportSearch,"");model.destroy();
});

test("review status survives grouping, sort and paging and resets with workspace",async()=>{
 const calls=[];const model=createReportsModel({async invokeAction(key,{body}){calls.push({key,body});return {items:[],total:0,next_offset:0};}});
 await model.setWorkspace("a");assert.equal(model.getSnapshot().aggregateQuery.status,"");
 await model.aggregate({...model.getSnapshot().aggregateQuery,status:"closed",tool:"Scanner",severity:"high",sort:"oldest",offset:0});
 await model.setGrouped(false);assert.equal(calls.at(-1).key,"findings.list");assert.equal(calls.at(-1).body.status,"closed");
 await model.aggregate({...model.getSnapshot().aggregateQuery,offset:25});assert.equal(calls.at(-1).body.status,"closed");
 await model.setGrouped(true);assert.equal(calls.at(-1).key,"issues.list");assert.equal(calls.at(-1).body.status,"closed");assert.equal(calls.at(-1).body.offset,0);
 await model.setWorkspace("b");assert.equal(model.getSnapshot().aggregateQuery.status,"");model.destroy();
});
