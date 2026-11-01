// Native UI bundle. React and all host components come from Kandev.
const emptyAggregateQuery = () => ({ language: "", tool: "", rule: "", severity: "", search: "", sort: "severity", offset: 0 });

const emptyFindingQuery = () => ({ ...emptyAggregateQuery(), status: "" });

export const MAX_REPORT_BYTES = 20 * 1024 * 1024;

function initialState(workspaceId) {
  return { workspaceId, grouped: true, issueDetail: null, issueError: "", issueLoading: false, issueBusy: false, selectedFinding: null, findingDetail: null, findingLoading: false, findingError: "", view: "findings", tokens: [], tokenOffset: 0, tokensNextOffset: 0,
    tokenLoading: false, tokenBusy: false, createdToken: null, aggregate: null, aggregateQuery: emptyFindingQuery(), aggregateLoading: false,
    facets: { language: [], tool: [], rule: [] }, facetMore: {}, reports: [], reportStatus: "active", reportTool: "", reportSearch: "", reportPage: null, reportTools: [], reportToolsMore: false, nextOffset: 0, offset: 0, detail: null, selectedId: null,
    query: { level: "", search: "", offset: 0 }, loading: false, importing: false,
    advisories: null, advisoryQuery: emptyAggregateQuery(), advisoryLoading: false, selectedAdvisory: null, advisoryFindings: null, advisoryOffset: 0, advisoryFindingsLoading: false,
    progress: 0, exporting: false, deleting: false, pinning: false, archiving: false, error: "", notice: "" };
}

// Each operation captures its workspace and generation. A workspace switch or
// unload aborts requests and fences late results, including file reads.
export function createReportsModel(api) {
  let state = initialState(undefined);
  let generation = 0;
  let listSequence = 0;
  let reportToolSequence = 0;
  let detailSequence = 0;
  let findingSequence = 0;
  let issueSequence = 0;
  let findingController;
  let aggregateSequence = 0;
  let advisorySequence = 0, advisoryFindingSequence = 0;
  let tokenListSequence = 0;
  let tokenViewEpoch = 0;
  const facetSequences = { language: 0, tool: 0, rule: 0 };
  let upload;
  let disposed = false;
  const listeners = new Set();
  const requests = new Set();
  const publish = (patch) => {
    if (disposed) return;
    state = { ...state, ...patch };
    listeners.forEach((listener) => listener(state));
  };
  const current = (epoch) => !disposed && epoch === generation;
  const call = async (key, workspaceId, body, signal) => {
    const controller = new AbortController();
    requests.add(controller);
    const abort = () => controller.abort();
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) controller.abort();
    try {
      return await api.invokeAction(key, { workspaceId, body }, { signal: controller.signal });
    } finally {
      requests.delete(controller);
      signal?.removeEventListener("abort", abort);
    }
  };
  const showError = (error, epoch) => {
    if (current(epoch) && error?.name !== "AbortError") {
      publish({ error: error?.message || "The request failed. Please try again." });
    }
  };
  const cancelUpload = () => {
    upload?.controller.abort();
  };
  const model = {
    getSnapshot: () => state,
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
    async setWorkspace(workspaceId) {
      if (disposed || state.workspaceId === workspaceId) return;
      generation++;
      requests.forEach((controller) => controller.abort());
      cancelUpload();
      const view = state.view;
      state = { ...initialState(workspaceId), view };
      publish({});
      if (workspaceId) {
        if (view === "findings") await model.aggregate();
        else if (view === "advisories") await model.advisories();
        else if (view === "tokens") await model.listTokens(0);
        else if (view === "reports") await model.list(0);
      }
    },
    async list(offset = state.offset) {
      const workspaceId = state.workspaceId;
      if (!workspaceId || disposed) return;
      const epoch = generation;
      const sequence = ++listSequence;
      publish({ loading: true, error: "" });
      try {
        const response = await call("reports.list", workspaceId, { offset, status: state.reportStatus, tool: state.reportTool, search: state.reportSearch });
        if (current(epoch) && sequence === listSequence) {
          publish({ reports: response.items, reportPage: response, nextOffset: response.next_offset, offset });
        }
      } catch (error) { if (sequence === listSequence) showError(error, epoch); }
      finally { if (current(epoch) && sequence === listSequence) publish({ loading: false }); }
    },
    async setReportStatus(status) {
      if (!["active", "archived", "all"].includes(status) || disposed) return;
      publish({ reportStatus: status, reportPage: null, reports: [], nextOffset: 0, offset: 0 });
      await model.list(0);
    },
    async setReportTool(tool) {
      if (disposed) return;
      publish({ reportTool: tool, reportPage: null, reports: [], nextOffset: 0, offset: 0 });
      await model.list(0);
    },
    async setReportSearch(search) {
      if (disposed) return;
      publish({ reportSearch: search, reportPage: null, reports: [], nextOffset: 0, offset: 0 });
      await model.list(0);
    },
    async suggestReportTools(search = "") {
      const workspaceId = state.workspaceId, epoch = generation, sequence = ++reportToolSequence;
      if (!workspaceId || disposed) return;
      try {
        const response = await call("reports.tools", workspaceId, { search: search.slice(0, 256) });
        if (current(epoch) && sequence === reportToolSequence) publish({ reportTools: response.items, reportToolsMore: response.next_offset > 0 });
      } catch (error) { if (sequence === reportToolSequence) showError(error, epoch); }
    },
    async setView(view) {
      if (disposed || !["reports", "findings", "advisories", "import", "tokens"].includes(view)) return;
      reportToolSequence++;
      advisorySequence++; advisoryFindingSequence++;
      detailSequence++;
      model.closeFinding();
      if (view !== state.view) {
        tokenViewEpoch++;
        tokenListSequence++;
        publish({ createdToken: null, tokenBusy: false, tokenLoading: false });
      }
      if (view !== "findings") {
        aggregateSequence++;
        for (const facet of Object.keys(facetSequences)) facetSequences[facet]++;
      } else listSequence++;
      publish({ aggregateLoading: false, advisoryLoading: false, advisoryFindingsLoading: false, view, detail: null, selectedId: null, loading: false, error: "", notice: "" });
      if (view === "findings") await model.aggregate({ ...state.aggregateQuery, offset: 0 });
      else if (view === "advisories") await model.advisories({ ...state.advisoryQuery, offset: 0 });
      else if (view === "tokens") await model.listTokens();
      else if (view === "reports") await model.list();
    },
    async listTokens(offset = state.tokenOffset) {
      const workspaceId = state.workspaceId;
      if (!workspaceId || disposed) return;
      const epoch = generation;
      const sequence = ++tokenListSequence;
      publish({ tokenLoading: true, error: "" });
      try {
        const response = await call("tokens.list", workspaceId, { offset });
        if (current(epoch) && sequence === tokenListSequence) publish({ tokens: response.items, tokenOffset: offset, tokensNextOffset: response.next_offset });
      } catch (error) { if (sequence === tokenListSequence) showError(error, epoch); }
      finally { if (current(epoch) && sequence === tokenListSequence) publish({ tokenLoading: false }); }
    },
    async createToken(name) {
      const workspaceId = state.workspaceId;
      if (!workspaceId || state.tokenBusy || state.view !== "tokens" || disposed) return;
      const epoch = generation;
      const viewEpoch = tokenViewEpoch;
      publish({ tokenBusy: true, createdToken: null, error: "" });
      try {
        const response = await call("tokens.create", workspaceId, { name });
        if (current(epoch) && viewEpoch === tokenViewEpoch) {
          publish({ createdToken: response });
          await model.listTokens(0);
        }
      } catch (error) { if (viewEpoch === tokenViewEpoch) showError(error, epoch); }
      finally { if (current(epoch) && viewEpoch === tokenViewEpoch) publish({ tokenBusy: false }); }
    },
    dismissToken() { publish({ createdToken: null }); },
    async revokeToken(id) {
      const workspaceId = state.workspaceId;
      if (!workspaceId || state.tokenBusy || disposed) return;
      const epoch = generation;
      const viewEpoch = tokenViewEpoch;
      publish({ tokenBusy: true, error: "" });
      try {
        await call("tokens.revoke", workspaceId, { id });
        if (current(epoch) && viewEpoch === tokenViewEpoch) {
          if (state.createdToken?.token.id === id) publish({ createdToken: null });
          await model.listTokens();
        }
      } catch (error) { if (viewEpoch === tokenViewEpoch) showError(error, epoch); }
      finally { if (current(epoch) && viewEpoch === tokenViewEpoch) publish({ tokenBusy: false }); }
    },
    async aggregate(query = state.aggregateQuery) {
      const workspaceId = state.workspaceId;
      if (!workspaceId || disposed) return;
      const epoch = generation;
      const sequence = ++aggregateSequence;
      publish({ aggregateLoading: true, aggregate: null, aggregateQuery: query, error: "" });
      try {
        const response = await call(state.grouped ? "issues.list" : "findings.list", workspaceId, query);
        if (current(epoch) && sequence === aggregateSequence) publish({ aggregate: response });
      } catch (error) { if (sequence === aggregateSequence) showError(error, epoch); }
      finally { if (current(epoch) && sequence === aggregateSequence) publish({ aggregateLoading: false }); }
    },
    async advisories(query = state.advisoryQuery) {
      const workspaceId = state.workspaceId;
      if (!workspaceId || disposed) return;
      model.closeFinding(); advisoryFindingSequence++;
      const epoch = generation, sequence = ++advisorySequence;
      publish({ advisories: null, advisoryQuery: query, advisoryLoading: true, selectedAdvisory: null, advisoryFindings: null, advisoryFindingsLoading: false, error: "" });
      try {
        const response = await call("advisories.list", workspaceId, query);
        if (current(epoch) && sequence === advisorySequence) publish({ advisories: response });
      } catch (error) { if (sequence === advisorySequence) showError(error, epoch); }
      finally { if (current(epoch) && sequence === advisorySequence) publish({ advisoryLoading: false }); }
    },
    async openAdvisory(advisory, offset = 0) {
      const workspaceId = state.workspaceId;
      if (!workspaceId || disposed) return;
      model.closeFinding();
      const epoch = generation, sequence = ++advisoryFindingSequence;
      publish({ selectedAdvisory: advisory, advisoryFindings: null, advisoryOffset: offset, advisoryFindingsLoading: true, error: "" });
      try {
        const response = await call("advisories.findings", workspaceId, { ...state.advisoryQuery, id: advisory.key, severity: "", offset });
        if (current(epoch) && sequence === advisoryFindingSequence) publish({ advisoryFindings: response });
      } catch (error) { if (sequence === advisoryFindingSequence) showError(error, epoch); }
      finally { if (current(epoch) && sequence === advisoryFindingSequence) publish({ advisoryFindingsLoading: false }); }
    },
    backAdvisories() { advisoryFindingSequence++; model.closeFinding(); publish({ selectedAdvisory: null, advisoryFindings: null, advisoryFindingsLoading: false, error: "" }); },
    async setGrouped(grouped) {
      model.closeFinding();
      publish({ grouped });
      await model.aggregate({ ...state.aggregateQuery, offset: 0 });
    },
    async suggest(facet, search = "") {
      const workspaceId = state.workspaceId;
      if (!workspaceId || disposed || !Object.hasOwn(facetSequences, facet)) return;
      const epoch = generation;
      const sequence = ++facetSequences[facet];
      try {
        const response = await call("findings.facets", workspaceId, { facet, search: search.slice(0, 256) });
        if (current(epoch) && sequence === facetSequences[facet]) {
          publish({ facets: { ...state.facets, [facet]: response.items }, facetMore: { ...state.facetMore, [facet]: response.next_offset > 0 } });
        }
      } catch (error) { if (sequence === facetSequences[facet]) showError(error, epoch); }
    },
    async openFinding(finding) {
      const workspaceId = state.workspaceId;
      if (!workspaceId || disposed) return;
      findingController?.abort();
      findingController = new AbortController();
      const epoch = generation;
      const sequence = ++findingSequence;
      publish({ selectedFinding: finding, findingDetail: null, findingLoading: true, findingError: "", issueDetail: null, issueError: "", issueLoading: false, issueBusy: false });
      try {
        const response = await call("findings.get", workspaceId, { id: finding.report_id, ordinal: finding.ordinal }, findingController.signal);
        if (current(epoch) && sequence === findingSequence) {
          publish({ findingDetail: response });
          const id = response.finding?.issue_id || finding.issue_id;
          if (id) await model.loadIssue(id);
        }
      } catch (error) {
        if (current(epoch) && sequence === findingSequence && error?.name !== "AbortError") publish({ findingError: error?.message || "The request failed. Please try again." });
      } finally {
        if (current(epoch) && sequence === findingSequence) publish({ findingLoading: false });
      }
    },
    async loadIssue(id, offset = 0, historyOffset = 0) {
      const workspaceId = state.workspaceId;
      const epoch = generation, findingEpoch = findingSequence, sequence = ++issueSequence;
      if (!workspaceId || disposed || !state.selectedFinding) return;
      publish({ issueLoading: true, issueError: "" });
      try {
        const response = await call("issues.get", workspaceId, { id, offset, history_offset: historyOffset }, findingController?.signal);
        if (current(epoch) && findingEpoch === findingSequence && sequence === issueSequence) publish({ issueDetail: {
          ...response,
          occurrences: offset ? [...(state.issueDetail?.occurrences || []), ...response.occurrences] : historyOffset ? state.issueDetail?.occurrences || response.occurrences : response.occurrences,
          history: historyOffset ? [...(state.issueDetail?.history || []), ...response.history] : offset ? state.issueDetail?.history || response.history : response.history,
          next_offset: historyOffset ? state.issueDetail?.next_offset || 0 : response.next_offset,
          history_next_offset: offset ? state.issueDetail?.history_next_offset || 0 : response.history_next_offset,
        } });
      } catch (error) {
        if (current(epoch) && findingEpoch === findingSequence && sequence === issueSequence && error?.name !== "AbortError") publish({ issueError: error.message || "Unable to load issue history." });
      } finally { if (current(epoch) && findingEpoch === findingSequence && sequence === issueSequence) publish({ issueLoading: false }); }
    },
    async setIssueStatus(status, reason) {
      const id = state.issueDetail?.issue.id, workspaceId = state.workspaceId;
      const epoch = generation, sequence = findingSequence;
      if (!id || !workspaceId || state.issueBusy || disposed) return;
      publish({ issueBusy: true, issueError: "" });
      try {
        await call("issues.set_status", workspaceId, { id, status, reason }, findingController?.signal);
        if (current(epoch) && sequence === findingSequence) {
          await model.loadIssue(id);
          if (current(epoch) && sequence === findingSequence && state.view === "findings") await model.aggregate({ ...state.aggregateQuery, offset: state.aggregateQuery.status ? 0 : state.aggregateQuery.offset });
        }
      } catch (error) {
        if (current(epoch) && sequence === findingSequence && error?.name !== "AbortError") publish({ issueError: error.message || "Unable to update issue status." });
      } finally { if (current(epoch) && sequence === findingSequence) publish({ issueBusy: false }); }
    },
    closeFinding() {
      findingSequence++;
      findingController?.abort();
      publish({ selectedFinding: null, findingDetail: null, findingLoading: false, findingError: "", issueDetail: null, issueError: "", issueLoading: false, issueBusy: false });
    },
    async open(id, query = { level: "", search: "", offset: 0 }) {
      model.closeFinding();
      const workspaceId = state.workspaceId;
      if (!workspaceId || disposed) return;
      const epoch = generation;
      const sequence = ++detailSequence;
      publish({ loading: true, detail: null, selectedId: id, query, error: "" });
      try {
        const response = await call("reports.get", workspaceId, { id, ...query });
        if (current(epoch) && sequence === detailSequence) publish({ detail: response });
      } catch (error) { if (sequence === detailSequence) showError(error, epoch); }
      finally { if (current(epoch) && sequence === detailSequence) publish({ loading: false }); }
    },
    back() { detailSequence++; publish({ detail: null, selectedId: null, error: "", loading: false }); },
    cancelImport: cancelUpload,
    async importFile(file) {
      if (!state.workspaceId || state.importing || disposed) return;
      const epoch = generation;
      const workspaceId = state.workspaceId;
      if (!file || file.size < 1 || file.size > MAX_REPORT_BYTES) {
        publish({ error: "Choose a SARIF file between 1 byte and 20 MiB." });
        return;
      }
      const operation = { controller: new AbortController(), workspaceId, id: undefined };
      upload = operation;
      publish({ importing: true, progress: 0, error: "", notice: "" });
      let completed = false;
      try {
        const started = await call("imports.start", workspaceId, { filename: file.name, size: file.size }, operation.controller.signal);
        operation.id = started.id;
        const chunkBytes = started.chunk_bytes;
        if (!Number.isInteger(chunkBytes) || chunkBytes < 1 || chunkBytes > 192 * 1024) throw new Error("Unsupported upload chunk size.");
        for (let offset = 0; offset < file.size;) {
          const raw = new Uint8Array(await file.slice(offset, offset + chunkBytes).arrayBuffer());
          if (!current(epoch) || operation.controller.signal.aborted) throw new DOMException("Import cancelled", "AbortError");
          let binary = "";
          for (let i = 0; i < raw.length; i += 8192) binary += String.fromCharCode(...raw.subarray(i, i + 8192));
          const response = await call("imports.append", workspaceId, { id: operation.id, offset, data: btoa(binary) }, operation.controller.signal);
          if (response.offset !== offset + raw.length) throw new Error("The upload offset did not match. Please import the file again.");
          offset = response.offset;
          if (current(epoch)) publish({ progress: Math.round(offset * 100 / file.size) });
        }
        const response = await call("imports.complete", workspaceId, { id: operation.id }, operation.controller.signal);
        completed = true;
        if (current(epoch)) {
          detailSequence++;
          publish({ selectedId: null, notice: response.report?.purged_at ? "Report received, but its original import date places it outside the workspace retention policy. Only source metadata remains." : response.report?.archived_at ? "This report was already imported and remains archived. Restore it from Reports to include its findings." : response.duplicate ? "This report was already imported into this workspace." : "Report imported.", detail: null });
          await model.list(0);
          if (current(epoch) && state.view === "findings") await model.aggregate({ ...state.aggregateQuery, offset: 0 });
          if (current(epoch) && state.view === "advisories") await model.advisories({ ...state.advisoryQuery, offset: 0 });
        }
      } catch (error) { showError(error, epoch); }
      finally {
        if (!completed && operation.id && !disposed) {
          // Use the captured workspace even after switching away. Cancellation
          // is best-effort; the backend expires abandoned uploads after 24h.
          call("imports.cancel", workspaceId, { id: operation.id }).catch(() => {});
        }
        if (upload === operation) upload = undefined;
        if (current(epoch)) publish({ importing: false });
      }
    },
    async pinReport(report, pinned) {
      const workspaceId = state.workspaceId, epoch = generation;
      if (!workspaceId || state.pinning || state.archiving || state.deleting || disposed) return;
      publish({ pinning: true, error: "", notice: "" });
      try {
        const result = await call("reports.pin", workspaceId, { id: report.id, pinned });
        if (!current(epoch)) return;
        if (state.detail?.report.id === report.id) {
          if (result.retained === false) model.back();
          else publish({ detail: { ...state.detail, report: { ...state.detail.report, pinned } } });
        }
        publish({ notice: result.purged_count ? `Retention removed ${result.purged_count} report(s). Source metadata remains in retention history.` : pinned ? "Report pinned. Automatic retention will keep it." : "Report unpinned." });
        await model.list(0);
        if (current(epoch) && result.purged_count && state.view === "advisories") await model.advisories();
      } catch (error) { showError(error, epoch); }
      finally { if (current(epoch)) publish({ pinning: false }); }
    },
    async archiveReport(report, archived) {
      const workspaceId = state.workspaceId, epoch = generation;
      if (!workspaceId || state.archiving || state.pinning || state.deleting || disposed) return;
      publish({ archiving: true, error: "", notice: "" });
      try {
        const result = await call("reports.archive", workspaceId, { id: report.id, archived });
        if (!current(epoch)) return;
        if (state.detail?.report.id === report.id) publish({ detail: { ...state.detail, report: result.report } });
        publish({ notice: archived ? "Report archived. Its findings are hidden from the default views. Automatic retention still applies unless pinned." : "Report restored. Its findings are included in the default views." });
        await model.list(0);
        if (current(epoch) && state.view === "findings") await model.aggregate({ ...state.aggregateQuery, offset: 0 });
        if (current(epoch) && state.view === "advisories") await model.advisories({ ...state.advisoryQuery, offset: 0 });
      } catch (error) { showError(error, epoch); }
      finally { if (current(epoch)) publish({ archiving: false }); }
    },
    async remove(id) {
      const workspaceId = state.workspaceId;
      if (!workspaceId || state.deleting || state.pinning || state.archiving || disposed) return;
      const epoch = generation;
      publish({ deleting: true, error: "" });
      try {
        await call("reports.delete", workspaceId, { id });
        if (current(epoch)) {
          detailSequence++; publish({ detail: null, selectedId: null, notice: "Report deleted." });
          await model.list(0);
          if (current(epoch) && state.view === "findings") await model.aggregate({ ...state.aggregateQuery, offset: 0 });
          if (current(epoch) && state.view === "advisories") await model.advisories({ ...state.advisoryQuery, offset: 0 });
        }
      } catch (error) { showError(error, epoch); }
      finally { if (current(epoch)) publish({ deleting: false }); }
    },
    async exportReport(id) {
      if (!state.workspaceId || state.exporting || disposed) return;
      const epoch = generation;
      const workspaceId = state.workspaceId;
      publish({ exporting: true, error: "" });
      try {
        const chunks = [];
        let offset = 0;
        let filename;
        let size;
        do {
          const chunk = await call("reports.source", workspaceId, { id, offset });
          if (!current(epoch)) return;
          if (!Number.isInteger(chunk.size) || chunk.size < 1 || chunk.size > MAX_REPORT_BYTES || (size !== undefined && size !== chunk.size)) throw new Error("Invalid export size.");
          size = chunk.size;
          const data = Uint8Array.from(atob(chunk.data), (c) => c.charCodeAt(0));
          if (data.length < 1 || offset + data.length > size || (chunk.next_offset !== 0 && chunk.next_offset !== offset + data.length)) throw new Error("Invalid export chunk.");
          chunks.push(data);
          filename = chunk.filename;
          offset += data.length;
          if (chunk.next_offset === 0) break;
        } while (offset < size);
        if (offset !== size) throw new Error("Incomplete report export.");
        return { blob: new Blob(chunks, { type: "application/sarif+json" }), filename: filename.split(/[\\/]/).pop() || "report.sarif" };
      } catch (error) { showError(error, epoch); }
      finally { if (current(epoch)) publish({ exporting: false }); }
    },
    destroy() {
      generation++;
      disposed = true;
      state = { ...state, createdToken: null, selectedFinding: null, findingDetail: null };
      cancelUpload();
      requests.forEach((controller) => controller.abort());
      listeners.clear();
    },
  };
  return model;
}

// Workspace task configuration and launch state are separate from report queries.
export function createTaskLaunchModel(api) {
  let state = { workspaceId: null, presets: [], presetsLoading: false, preparing: false, launch: null, error: "", links: {}, pending: [] };
  let epoch = 0, presetSequence = 0, prepareSequence = 0, disposed = false;
  const listeners = new Set(), requests = new Set(), pending = new Map(), linkSequences = new Map();
  const publish = (patch) => { if (!disposed) { state = { ...state, ...patch }; listeners.forEach((fn) => fn(state)); } };
  const current = (generation) => !disposed && generation === epoch;
  const publishPending = () => publish({ pending: [...pending.values()].filter((p) => p.workspaceId === state.workspaceId) });
  const call = async (key, workspaceId, body, durable = false) => {
    const controller = new AbortController(); if (!durable) requests.add(controller);
    try { return await api.invokeAction(key, { workspaceId, body }, { signal: controller.signal }); }
    finally { requests.delete(controller); }
  };
  const model = {
    getSnapshot: () => state,
    subscribe(fn) { listeners.add(fn); return () => listeners.delete(fn); },
    async setWorkspace(workspaceId) {
      if (disposed || workspaceId === state.workspaceId) return;
      epoch++; requests.forEach((c) => c.abort());
      state = { workspaceId, presets: [], presetsLoading: false, preparing: false, launch: null, error: "", links: {}, pending: [] };
      publishPending(); if (workspaceId) await model.loadPresets();
    },
    async loadPresets() {
      const workspaceId = state.workspaceId, generation = epoch, sequence = ++presetSequence;
      if (!workspaceId || disposed) return;
      publish({ presetsLoading: true });
      try { const value = await call("task_presets.get", workspaceId, {}); if (current(generation) && sequence === presetSequence) publish({ presets: value.presets }); }
      catch (error) { if (current(generation) && sequence === presetSequence && error.name !== "AbortError") publish({ error: error.message }); }
      finally { if (current(generation) && sequence === presetSequence) publish({ presetsLoading: false }); }
    },
    async loadTasks(issueId, offset = 0) {
      if (!issueId || !state.workspaceId || disposed) return;
      const workspaceId = state.workspaceId, generation = epoch, sequence = (linkSequences.get(issueId) || 0) + 1;
      linkSequences.set(issueId, sequence);
      try {
        const value = await call("tasks.list", workspaceId, { issue_id: issueId, offset });
        if (current(generation) && linkSequences.get(issueId) === sequence) publish({ links: { ...state.links, [issueId]: { ...value, items: offset ? [...(state.links[issueId]?.items || []), ...value.items] : value.items } } });
      } catch (error) { if (current(generation) && linkSequences.get(issueId) === sequence && error.name !== "AbortError") publish({ error: error.message }); }
    },
    async prepare(finding, presetId) {
      if (!state.workspaceId || state.preparing || disposed) return;
      const workspaceId = state.workspaceId, generation = epoch, sequence = ++prepareSequence;
      publish({ preparing: true, error: "" });
      try {
        const launch = await call("tasks.prepare", workspaceId, { id: finding.report_id, ordinal: finding.ordinal, preset_id: presetId });
        if (current(generation) && sequence === prepareSequence) {
          if (launch.workspace_id !== workspaceId) throw new Error("Task workspace verification failed.");
          publish({ launch: { ...launch, workspaceId, generation } });
        }
      } catch (error) { if (current(generation) && sequence === prepareSequence && error.name !== "AbortError") publish({ error: error.message }); }
      finally { if (current(generation) && sequence === prepareSequence) publish({ preparing: false }); }
    },
    isCurrent: (launch) => current(launch.generation) && state.workspaceId === launch.workspaceId,
    closeLaunch() { prepareSequence++; publish({ launch: null, preparing: false }); },
    dismissError() { publish({ error: "" }); },
    async completed(launch, task) {
      const item = { workspaceId: launch.workspaceId, issueId: launch.issue_id, presetId: launch.preset_id, taskId: task.id, busy: false };
      // Keep recovery data independently of the dialog: native creation can
      // succeed even if saving the plugin association fails or navigation occurs.
      pending.set(task.id, item); publishPending();
      if (state.launch === launch) publish({ launch: null });
      return model.retryLink(task.id);
    },
    async retryLink(taskId) {
      const item = pending.get(taskId); if (!item || item.busy) return false;
      item.busy = true; publishPending();
      try {
        await call("tasks.link", item.workspaceId, { issue_id: item.issueId, task_id: item.taskId, preset_id: item.presetId }, true);
        pending.delete(taskId); publishPending();
        if (!disposed && state.workspaceId === item.workspaceId) await model.loadTasks(item.issueId);
        return true;
      } catch (error) { item.busy = false; item.error = error.message; publishPending(); return false; }
    },
    destroy() { disposed = true; epoch++; requests.forEach((c) => c.abort()); listeners.clear(); },
  };
  return model;
}

function useTaskState(host, model) {
  const [state, setState] = host.React.useState(model.getSnapshot);
  host.React.useEffect(() => { setState(model.getSnapshot()); return model.subscribe(setState); }, []);
  return state;
}

function makeStartTaskMenu(host, tasks) {
  const h = host.jsx;
  const { Button, DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem } = host.ui;
  return function StartTaskMenu({ finding, t, drawer = false }) {
    const state = useTaskState(host, tasks);
    const issueId = finding.issue_id;
    host.React.useEffect(() => { if (drawer && issueId) tasks.loadTasks(issueId); }, [drawer, issueId, state.workspaceId]);
    const links = state.links[issueId];
    const count = links?.total ?? finding.task_count ?? 0;
    return h("div", { className: "kandev-security-task-actions" },
      count ? h("span", { className: "kandev-security-task-count" }, t(count === 1 ? "linkedTaskOne" : "linkedTasksCount", { count })) : null,
      h(DropdownMenu, { onOpenChange: (open) => { if (open) { tasks.loadPresets(); tasks.loadTasks(issueId); } } },
        h(DropdownMenuTrigger, { asChild: true }, h(Button, { type: "button", variant: "outline", size: "sm", disabled: state.preparing || !issueId,
          "aria-label": t("startTaskFor", { rule: finding.rule_id || t("unknown") }), className: "kandev-security-start-task" }, t("startTask"), icon(host, "chevron"))),
        h(DropdownMenuContent, { align: "end", className: "kandev-security-task-menu" },
          ...state.presets.map((p) => h(DropdownMenuItem, { key: p.id, disabled: state.preparing, onSelect: () => tasks.prepare(finding, p.id) },
            h("span", { className: "kandev-security-preset-icon", "data-icon": p.icon, "aria-hidden": true }, presetIcon(host, p.icon)),
            h("span", null, h("span", { className: "block" }, p.label), p.hint ? h("small", { className: "block text-muted-foreground" }, p.hint) : null))),
          !state.presets.length ? h(DropdownMenuItem, { disabled: true }, t(state.presetsLoading ? "loadingTaskPresets" : "noTaskPresets")) : null,
          links?.items.length ? h("div", { className: "kandev-security-linked-task-label" }, t("linkedTasks")) : null,
          ...(links?.items || []).map((link) => h(DropdownMenuItem, { key: link.task_id, disabled: link.unavailable,
            onSelect: () => host.navigate(`/t/${encodeURIComponent(link.task_id)}`) }, link.unavailable ? t("taskUnavailable") : `${link.title} · ${link.state}`)),
          links?.next_offset ? h(DropdownMenuItem, { onSelect: (event) => { event.preventDefault(); tasks.loadTasks(issueId, links.next_offset); } }, t("moreTasks")) : null,
          h(DropdownMenuItem, { onSelect: () => host.navigate(taskSettingsPath(state.workspaceId)) }, t("taskPresets")))));
  };
}

function presetIcon(host, name) {
  if (name === "shield") return host.jsx(makeSecurityIcon(host), { width: 14, height: 14 });
  const paths = { search: "m21 21-4.4-4.4 M19 11a8 8 0 1 1-16 0 8 8 0 0 1 16 0", tool: "m14 5 5 5m-9 4L3 21l-2-2 7-7m6-7 3-3 5 5-3 3", bug: "M9 9h6v7a3 3 0 0 1-6 0V9Zm-4 2h4m6 0h4M5 15h4m6 0h4M9 5l3 4 3-4", check: "m5 12 4 4L19 6", code: "m8 5-6 7 6 7m8-14 6 7-6 7" };
  return host.jsx("svg", { width: 14, height: 14, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.6, "aria-hidden": true }, host.jsx("path", { d: paths[name] || paths.search }));
}
function taskSettingsPath(workspaceId) { return `/settings/workspaces/${encodeURIComponent(workspaceId)}/integrations/kandev-security`; }

function makeSecurityTaskDialog(host, tasks) {
  const h = host.jsx;
  return function SecurityTaskDialog({ t }) {
    const state = useTaskState(host, tasks), launch = state.launch;
    const Dialog = host.ui.TaskCreateDialog;
    return h(host.React.Fragment, null,
      state.error ? h("div", { role: "alert", className: "kandev-security-message" }, state.error, h(host.ui.Button, { variant: "ghost", onClick: tasks.dismissError }, t("dismiss"))) : null,
      state.preparing ? h("p", { role: "status", className: "kandev-security-message" }, t("preparingTask")) : null,
      ...state.pending.map((item) => h("div", { key: item.taskId, role: "status", className: "kandev-security-message" }, t("taskCreatedLinkPending"),
        item.error ? h("span", null, ` ${item.error}`) : null,
        h(host.ui.Button, { variant: "outline", disabled: item.busy, onClick: () => tasks.retryLink(item.taskId) }, t("retryTaskLink")),
        h(host.ui.Button, { variant: "ghost", onClick: () => host.navigate(`/t/${encodeURIComponent(item.taskId)}`) }, t("openTask")))),
      launch && Dialog ? h(Dialog, { key: `${launch.workspaceId}:${launch.issue_id}:${launch.preset_id}`, open: true, mode: "create", workspaceId: launch.workspaceId,
        workflowId: launch.workflow_id, defaultStepId: launch.default_step_id, steps: launch.steps,
        initialValues: { title: launch.title, description: launch.description },
        onOpenChange: (open) => { if (!open) tasks.closeLaunch(); },
        onSuccess: async (task, _mode, meta) => { const linked = await tasks.completed(launch, task); if (linked && tasks.isCurrent(launch) && meta?.autoFocus !== false) host.navigate(`/t/${encodeURIComponent(task.id)}`); },
      }) : null);
  };
}

function makeTaskPresetsSettings(host) {
  const h = host.jsx, { useState, useEffect, useRef } = host.React;
  const { Button, Input } = host.ui;
  const Textarea = host.ui.Textarea || "textarea";
  return function TaskPresetsSettings({ workspaceId }) {
    const translate = host.i18n?.useTranslation().t;
    const t = (key, values) => translate ? translate(key, { defaultValue: english[key], count: values?.count, values }) : english[key]?.replace(/\{\{(\w+)\}\}/g, (_, name) => String(values?.[name] ?? ""));
    const [form, setForm] = useState({ workspaceId: null, settings: null, draft: [], loading: false, busy: false, error: "" });
    const [confirmation, setConfirmation] = useState("");
    const live = useRef(form), generation = useRef(0);
    live.current = form;
    const load = async (id, signal) => {
      const request = ++generation.current;
      setConfirmation(""); setForm({ workspaceId: id, settings: null, draft: [], loading: true, busy: false, error: "" });
      if (!id) { setForm((s) => ({ ...s, loading: false })); return; }
      try {
        const settings = await host.api.invokeAction("task_presets.get", { workspaceId: id, body: {} }, { signal });
        if (generation.current === request) setForm({ workspaceId: id, settings, draft: settings.presets, loading: false, busy: false, error: "" });
      } catch (error) { if (generation.current === request && error.name !== "AbortError") setForm((s) => ({ ...s, loading: false, error: error.message })); }
    };
    useEffect(() => { const controller = new AbortController(); load(workspaceId, controller.signal); return () => { generation.current++; controller.abort(); }; }, [workspaceId]);
    const dirty = Boolean(form.workspaceId === workspaceId && form.settings && JSON.stringify(form.draft) !== JSON.stringify(form.settings.presets));
    const revision = JSON.stringify({ workspaceId, revision: form.settings?.revision, draft: form.draft });
    const mutate = async (reset, requestedRevision) => {
      const value = live.current, request = generation.current;
      if (!value.settings || value.workspaceId !== workspaceId || value.busy) return;
      const currentRevision = JSON.stringify({ workspaceId, revision: value.settings.revision, draft: value.draft });
      if (requestedRevision !== undefined && requestedRevision !== currentRevision) throw new Error(t("presetsChangedDuringSave"));
      setForm((s) => ({ ...s, busy: true, error: "" }));
      try {
        const settings = await host.api.invokeAction(reset ? "task_presets.reset" : "task_presets.save", { workspaceId, body: {
          expected_revision: value.settings.revision, ...(reset ? {} : { presets: value.draft }),
        } });
        if (generation.current === request) { setConfirmation(""); setForm({ workspaceId, settings, draft: settings.presets, loading: false, busy: false, error: "" }); }
      } catch (error) { if (generation.current === request) setForm((s) => ({ ...s, busy: false, error: error.message })); throw error; }
    };
    if (host.useSettingsSaveContributor) host.useSettingsSaveContributor({ id: `security-task-presets:${workspaceId || "none"}`, revision,
      isDirty: dirty, canSave: Boolean(form.settings) && !form.busy && !form.loading && form.workspaceId === workspaceId,
      save: (requestedRevision) => mutate(false, requestedRevision),
      discard: () => { const current = live.current; setForm((s) => ({ ...s, draft: current.settings?.presets || [], error: "" })); },
    });
    const patch = (index, value) => setForm((s) => ({ ...s, draft: s.draft.map((p, i) => i === index ? { ...p, ...value } : p) }));
    const move = (index, delta) => setForm((s) => { const draft = [...s.draft]; [draft[index], draft[index + delta]] = [draft[index + delta], draft[index]]; return { ...s, draft }; });
    const content = h("div", { className: "kandev-security-presets-settings", "data-settings-dirty": dirty, "aria-busy": form.loading || form.busy },
      !host.ui.SettingsSection ? h("p", null, t("workspacePresetHelp")) : null,
      form.loading ? h("p", { role: "status" }, t("loadingTaskPresets")) : null,
      form.error ? h("p", { role: "alert" }, form.error) : null,
      ...form.draft.map((preset, index) => h("fieldset", { key: preset.id, disabled: form.busy, className: "kandev-security-preset-editor" },
        h("legend", null, preset.label || t("newPreset")),
        h("label", null, t("presetLabel"), h(Input, { value: preset.label, maxLength: 80, onChange: (e) => patch(index, { label: e.target.value }) })),
        h("label", null, t("presetHint"), h(Input, { value: preset.hint, maxLength: 160, onChange: (e) => patch(index, { hint: e.target.value }) })),
        h("label", null, t("presetIcon"), presetIcon(host, preset.icon), h("select", { "aria-label": t("presetIcon"), value: preset.icon, className: "kandev-security-native-select", onChange: (e) => patch(index, { icon: e.target.value }) },
          ...["search", "tool", "bug", "check", "code", "shield"].map((key) => h("option", { key, value: key }, t(`presetIcon_${key}`))))),
        h("label", null, t("presetPrompt"), h(Textarea, { "aria-label": t("presetPrompt"), value: preset.prompt_template, maxLength: 8192, rows: 7, className: "kandev-security-preset-template", onChange: (e) => patch(index, { prompt_template: e.target.value }) })),
        h("div", { className: "flex flex-wrap gap-2" },
          h(Button, { type: "button", variant: "outline", disabled: index === 0 || form.busy, onClick: () => move(index, -1), "aria-label": t("movePresetUp", { label: preset.label }) }, t("moveUp")),
          h(Button, { type: "button", variant: "outline", disabled: index === form.draft.length - 1 || form.busy, onClick: () => move(index, 1), "aria-label": t("movePresetDown", { label: preset.label }) }, t("moveDown")),
          h(Button, { type: "button", variant: "outline", disabled: form.busy, onClick: () => setForm((s) => ({ ...s, draft: s.draft.filter((_, i) => i !== index) })), "aria-label": t("removePreset", { label: preset.label }) }, t("remove"))))),
      form.settings ? h("div", { className: "flex flex-wrap gap-2" },
        h(Button, { type: "button", variant: "outline", disabled: form.busy || form.draft.length >= 20, onClick: () => setForm((s) => ({ ...s, draft: [...s.draft, { id: globalThis.crypto.randomUUID(), label: "", hint: "", icon: "search", prompt_template: "{{finding}}" }] })) }, t("addPreset")),
        !host.useSettingsSaveContributor ? h(Button, { type: "button", disabled: !dirty || form.busy, onClick: () => mutate(false).catch(() => {}) }, t("savePresets")) : null,
        h(Button, { type: "button", variant: "outline", disabled: form.busy, onClick: () => setConfirmation("reset") }, t("resetPresets"))) : null,
      h(Button, { type: "button", variant: "outline", disabled: form.busy || form.loading, onClick: () => dirty ? setConfirmation("reload") : load(workspaceId) }, t("reloadPresets")),
      confirmation ? h("div", { role: "group", "aria-label": t("confirmPresetAction"), className: "space-y-2" }, h("p", null, t(confirmation === "reset" ? "confirmResetPresets" : "confirmReloadPresets")),
        h(Button, { type: "button", disabled: form.busy, onClick: () => confirmation === "reset" ? mutate(true).catch(() => {}) : load(workspaceId) }, t("confirmPresetAction")),
        h(Button, { type: "button", variant: "outline", disabled: form.busy, onClick: () => setConfirmation("") }, t("cancel"))) : null,
      h("p", null, t("presetPlaceholders")),
      h("code", { className: "kandev-security-preset-tokens" }, "{{finding}}, {{title}}, {{rule}}, {{severity}}, {{scanner}}, {{language}}, {{location}}, {{description}}, {{evidence}}, {{remediation}}, {{repository}}, {{revision}}, {{issue_id}}, {{report_id}}, {{sha256}}, {{ordinal}}"));
    if (!workspaceId) return h("p", null, t("chooseWorkspace"));
    const card = host.ui.SettingsCard ? h(host.ui.SettingsCard, { isDirty: dirty, className: "space-y-4 p-4" }, content) : content;
    return h(host.React.Fragment, null, h("style", null, layoutStyles), host.ui.SettingsSection ? h(host.ui.SettingsSection, { title: t("taskPresets"), description: t("workspacePresetHelp"), framed: !host.ui.SettingsCard }, card)
      : h("section", { "aria-label": t("taskPresets"), className: "kandev-security-content" }, h("h2", null, t("taskPresets")), card));
  };
}

function makeRetentionSettings(host) {
  const h = host.jsx, { useState, useEffect, useRef } = host.React, { Button, Input } = host.ui;
  return function RetentionSettings({ workspaceId }) {
    const translate = host.i18n?.useTranslation().t;
    const t = (key, values) => translate ? translate(key, { defaultValue: english[key], count: values?.count, values }) : english[key]?.replace(/\{\{(\w+)\}\}/g, (_, name) => String(values?.[name] ?? ""));
    const generation = useRef(0), historySequence = useRef(0);
    const [form, setForm] = useState({ workspaceId: null, settings: null, config: null, loading: false, busy: false, error: "", notice: "", preview: null, history: [], historyBack: [], historyOffset: 0, historyNext: 0, historyLoading: false });
    const load = async (id, signal) => {
      const epoch = ++generation.current; historySequence.current++;
      setForm({ workspaceId: id, settings: null, config: null, loading: true, busy: false, error: "", notice: "", preview: null, history: [], historyBack: [], historyOffset: 0, historyNext: 0, historyLoading: false });
      if (!id) return;
      const results = await Promise.allSettled([host.api.invokeAction("retention.get", { workspaceId: id, body: {} }, { signal }), host.api.invokeAction("reports.purged.list", { workspaceId: id, body: { offset: 0 } }, { signal })]);
      if (epoch !== generation.current) return;
      const [settings, history] = results;
      setForm((s) => ({ ...s, loading: false,
        settings: settings.status === "fulfilled" ? settings.value : null, config: settings.status === "fulfilled" ? settings.value.config : null,
        history: history.status === "fulfilled" ? history.value.items : [], historyNext: history.status === "fulfilled" ? history.value.next_offset : 0,
        error: settings.status === "rejected" && settings.reason.name !== "AbortError" ? settings.reason.message : history.status === "rejected" && history.reason.name !== "AbortError" ? history.reason.message : "" }));
    };
    useEffect(() => { const controller = new AbortController(); load(workspaceId, controller.signal); return () => { generation.current++; historySequence.current++; controller.abort(); }; }, [workspaceId]);
    useEffect(() => { if (!form.loading && form.workspaceId === workspaceId && window.location.hash === "#report-retention") document.getElementById("report-retention")?.scrollIntoView({ block: "start" }); }, [workspaceId, form.loading]);
    const history = async (offset = 0, backwards = false) => {
      const epoch = generation.current, sequence = ++historySequence.current;
      setForm((s) => ({ ...s, historyLoading: true }));
      try {
        const response = await host.api.invokeAction("reports.purged.list", { workspaceId, body: { offset } });
        if (epoch === generation.current && sequence === historySequence.current) setForm((s) => ({ ...s, history: response.items,
          historyBack: backwards ? s.historyBack.slice(0, -1) : offset === 0 ? [] : offset > s.historyOffset ? [...s.historyBack, s.historyOffset] : s.historyBack,
          historyOffset: offset, historyNext: response.next_offset }));
      } catch (error) { if (epoch === generation.current && sequence === historySequence.current) setForm((s) => ({ ...s, error: error.message })); }
      finally { if (epoch === generation.current && sequence === historySequence.current) setForm((s) => ({ ...s, historyLoading: false })); }
    };
    const act = async (action) => {
      if (!form.settings || form.busy || form.workspaceId !== workspaceId) return;
      const epoch = generation.current;
      setForm((s) => ({ ...s, busy: true, error: "", notice: "" }));
      try {
        const body = action === "retention.run" ? {} : { config: form.config, ...(action === "retention.save" ? { expected_revision: form.settings.revision } : {}) };
        const response = await host.api.invokeAction(action, { workspaceId, body });
        if (epoch !== generation.current) return;
        if (action === "retention.preview") setForm((s) => ({ ...s, preview: response }));
        else {
          setForm((s) => ({ ...s, ...(response.settings ? { settings: { ...response.settings, scanners: s.settings.scanners }, config: response.settings.config } : {}), preview: null, notice: t("retentionApplied", { count: response.purged_count }) }));
          await history(0);
        }
      } catch (error) { if (epoch === generation.current) setForm((s) => ({ ...s, error: error.message })); }
      finally { if (epoch === generation.current) setForm((s) => ({ ...s, busy: false })); }
    };
    const patch = (change) => setForm((s) => ({ ...s, config: { ...s.config, ...change }, preview: null, notice: "" }));
    if (!workspaceId) return h("p", null, t("chooseWorkspace"));
    if (form.workspaceId !== workspaceId || form.loading) return h("p", { role: "status" }, t("loadingRetention"));
    const disabled = form.busy || !form.config;
    const dirty = Boolean(form.settings && JSON.stringify(form.config) !== JSON.stringify(form.settings.config));
    const limits = (policy, change) => h("div", { className: "kandev-security-retention-limits" },
      ...[["max_reports", "maxReports", 100000], ["max_age_days", "maxAgeDays", 36500]].map(([key, label, max]) => h("label", { key }, t(label), h(Input, { type: "number", min: 0, max, step: 1, required: true, disabled, value: policy[key], onChange: (event) => change({ ...policy, [key]: Number(event.target.value) }) }))));
    return h("section", { id: "report-retention", "aria-label": t("reportRetention"), className: "kandev-security-content kandev-security-retention-settings" },
      h("style", null, layoutStyles), h("h2", null, t("reportRetention")), h("p", null, t("retentionHelp")),
      form.error ? h("p", { role: "alert" }, form.error) : null, form.notice ? h("p", { role: "status" }, form.notice) : null,
      form.config ? h("form", { onSubmit: (event) => { event.preventDefault(); act("retention.save"); } },
        h("label", { className: "kandev-security-retention-enable" }, h("input", { type: "checkbox", disabled, checked: form.config.enabled, onChange: (event) => patch({ enabled: event.target.checked }) }), t("enableRetention")),
        h("fieldset", null, h("legend", null, t("retentionDefaults")), limits(form.config.default, (value) => patch({ default: value }))),
        h("p", null, t("retentionZero")), h("h3", null, t("scannerOverrides")),
        h("datalist", { id: `security-retention-scanners-${workspaceId}` }, ...(form.settings.scanners || []).map((tool) => h("option", { key: tool, value: tool }))),
        ...form.config.overrides.map((override, index) => h("fieldset", { key: index, "aria-label": override.tool || t("scannerOverride") }, h("legend", null, override.tool || t("scannerOverride")),
          h("label", null, t("scanner"), h(Input, { value: override.tool, list: `security-retention-scanners-${workspaceId}`, maxLength: 256, required: true, disabled,
            onChange: (event) => patch({ overrides: form.config.overrides.map((old, i) => i === index ? { ...old, tool: event.target.value } : old) }) })),
          limits(override, (value) => patch({ overrides: form.config.overrides.map((old, i) => i === index ? value : old) })),
          h(Button, { type: "button", variant: "outline", disabled, onClick: () => patch({ overrides: form.config.overrides.filter((_, i) => i !== index) }) }, t("remove")))),
        h("div", { className: "kandev-security-retention-buttons" },
          h(Button, { type: "button", variant: "outline", disabled: disabled || form.config.overrides.length >= 100, onClick: () => patch({ overrides: [...form.config.overrides, { tool: "", ...form.config.default }] }) }, t("addScannerOverride")),
          h(Button, { type: "button", variant: "outline", disabled, onClick: () => act("retention.preview") }, t("previewRetention")),
          h(Button, { type: "submit", disabled: disabled || !dirty }, t("saveRetention")),
          h(Button, { type: "button", variant: "outline", disabled: disabled || dirty || !form.settings.config.enabled, onClick: () => act("retention.run") }, t("runRetention"))),
        form.preview ? h("div", { role: "region", "aria-label": t("retentionPreview") }, h("p", null, t("retentionPreviewCount", { count: form.preview.eligible_reports, bytes: form.preview.eligible_bytes, pinned: form.preview.pinned_reports })),
          h("ul", null, ...form.preview.candidates.map((candidate) => h("li", { key: candidate.report.id }, `${candidate.report.filename} · ${candidate.reason}`))), form.preview.has_more ? h("p", null, t("retentionPreviewMore")) : null) : null) : null,
      h(Button, { type: "button", variant: "outline", disabled: form.busy, onClick: () => load(workspaceId) }, t("reloadRetention")),
      h("h3", null, t("purgedHistory")), h("p", null, t("purgedHistoryHelp")),
      h(Button, { type: "button", variant: "outline", disabled: form.historyLoading || form.busy, onClick: () => history(form.historyOffset) }, t("refresh")),
      form.history.length ? h("ul", { className: "kandev-security-results" }, ...form.history.map((report) => h("li", { key: report.id, className: "kandev-security-result-row" },
        h("strong", null, report.filename), h("p", null, `${report.tools} · ${t("findings")}: ${report.finding_count}`),
        h("p", null, `${t("imported")}: ${report.created_at} · ${t("sourcePurged")}: ${report.purged_at}`), h("p", null, report.purge_reason),
        h("p", { className: "kandev-security-detail-text" }, `Report ID: ${report.id}\nSHA-256: ${report.sha256}`)))) : h("p", null, t("noPurgedReports")),
      h("nav", { "aria-label": t("purgedHistory"), className: "kandev-security-retention-buttons" },
        h(Button, { type: "button", variant: "outline", disabled: form.historyLoading || !form.historyBack.length, onClick: () => history(form.historyBack.at(-1) || 0, true) }, t("previous")),
        h(Button, { type: "button", variant: "outline", disabled: form.historyLoading || !form.historyNext, onClick: () => history(form.historyNext) }, t("next"))));
  };
}

const english = {
  reasonUpdated: "Reason updated", reviewReason: "Review reason", agentReviewSource: "Agent review · Task: {{task}} · Session: {{session}}",
  status: "Status",
  searchReports: "Search report filenames", clearReportSearch: "Clear filename search",
  reportCount: "Reports: {{count}}", reportPagination: "Reports pagination", uploadReport: "Upload report", noMatchingReports: "No reports match these filters.",
  archiveReport: "Archive report", restoreReport: "Restore report", archived: "Archived", reportStatus: "Report status", activeReports: "Active", archivedReports: "Archived", allReports: "All", archiveNotice: "Archived report. Findings are hidden from the default views. Automatic retention still applies unless pinned.", emptyArchived: "No archived reports.", emptyActive: "No active reports. Import a report or restore one from Archived.",
  reportRetention: "Report retention", pinReport: "Pin report", unpinReport: "Unpin report", pinned: "Pinned", sourcePurged: "Source purged by retention", loadingRetention: "Loading retention settings…",
  retentionHelp: "Workspace-wide limits apply independently to each scanner. Cleanup runs after imports, on startup, hourly, and when settings are applied. Pinned reports are exempt and do not consume the count limit. A report containing multiple scanners is kept while any scanner policy requires it. Removing reports never resolves issues.",
  enableRetention: "Enable automatic report cleanup", retentionDefaults: "Default limits per scanner", maxReports: "Maximum unpinned reports", maxAgeDays: "Maximum age in days", retentionZero: "0 means unlimited. Age uses first import time; reimporting does not reset it. Scanner overrides replace both default limits.", scannerOverrides: "Scanner overrides", scannerOverride: "Scanner override", addScannerOverride: "Add scanner override", previewRetention: "Preview cleanup", saveRetention: "Save and apply retention", runRetention: "Clean up now", reloadRetention: "Reload retention settings", retentionPreview: "Cleanup preview", retentionPreviewCount: "Reports to remove: {{count}} · Source bytes: {{bytes}} · Pinned reports kept: {{pinned}}", retentionPreviewMore: "Only the first candidates are listed; the total includes all eligible reports.", retentionApplied: "Retention applied. Reports removed: {{count}}.", purgedHistory: "Purged report history", purgedHistoryHelp: "Original files and full findings are no longer available. Report hashes and compact issue source references remain; issue decisions and task links are preserved.", noPurgedReports: "No reports have been removed by retention in this workspace.",
  advisories: "Advisories", advisoryView: "Security advisories", searchAdvisories: "Search advisory IDs, titles, packages, or paths", backAdvisories: "Back to advisories", advisoryMembers: "Affected findings", openAdvisory: "Open advisory: {{id}}", advisoryTotals: "Advisories: {{count}} · Findings: {{findings}}", advisoryCounts: "Findings: {{findings}} · Issues: {{issues}} · Reports: {{reports}} · Scanners: {{scanners}}", noAdvisories: "No matching advisories. Findings without recognized advisory identifiers remain in All findings.", advisoryHelp: "Advisory groups organize source findings across reports and targets. They do not merge issues or change review status. Scanner rules without an advisory identifier remain in All findings.", advisoryMembersHelp: "All severities for this advisory are shown within the selected scanner and search filters. Open a finding for package details, evidence, and task actions.",
  agentReport: "LLM audit report", auditTitle: "Report title", agentReported: "LLM reported", confidence: "Confidence", evidence: "Evidence", classifications: "Classifications",
  severitySource: "Severity source", severityDefault: "SARIF default level", severityResultLevel: "Scanner result level", severityRuleLevel: "Scanner rule default level", severityRuleScore: "Scanner rule security score", severityAgent: "Agent assessment",
  resultKind: "Result kind", priorityRank: "Scanner priority (0–100)", analysisContext: "Analysis context", analysisTarget: "Analysis target", automationID: "Analysis identifier", firstDetected: "Scanner first detection", lastDetected: "Scanner last detection", reportedBaseline: "Scanner baseline state", scanInvocation: "Scanner invocation", scannerSucceeded: "Execution succeeded", scannerFailed: "Execution failed", sourceLocations: "Locations and snippets", relatedLocations: "Related locations", httpEvidence: "HTTP evidence", httpRequest: "Request", httpResponse: "Response", noHTTPResponse: "No response received", importNotes: "Import notes",
  declaredScope: "Declared scope", auditInstructions: "Audit instructions", reportedCoverage: "Reported coverage", auditSummary: "Audit summary", auditLimitations: "Reported limitations", auditTask: "Kandev task", agentLabel: "Agent label (self-reported)",
  llmNotice: "Findings, severity, confidence and coverage are agent claims. Completion does not establish a complete scan or verified remediation.", noLimitationsDeclared: "No limitations were declared by the agent.",
  startTask: "Start task", startTaskFor: "Start task for {{rule}}", taskPresets: "Task presets", loadingTaskPresets: "Loading task presets…", noTaskPresets: "No task presets configured", preparingTask: "Preparing task…",
  linkedTasks: "Linked tasks", linkedTaskOne: "1 linked task", linkedTasksCount: "{{count}} linked tasks", taskUnavailable: "Task details unavailable", moreTasks: "More linked tasks",
  taskCreatedLinkPending: "Task created. Its security-issue link is pending.", retryTaskLink: "Retry linking", openTask: "Open task", dismiss: "Dismiss",
  workspacePresetHelp: "These task presets are shared by everyone in this workspace. Changes affect the Start task menus for security findings.",
  presetLabel: "Name", presetHint: "Description", presetIcon: "Icon", presetPrompt: "Prompt template", newPreset: "New preset", addPreset: "Add preset", savePresets: "Save presets", resetPresets: "Reset to defaults", reloadPresets: "Reload presets",
  moveUp: "Move up", moveDown: "Move down", remove: "Remove", movePresetUp: "Move {{label}} up", movePresetDown: "Move {{label}} down", removePreset: "Remove {{label}}",
  presetIcon_search: "Search", presetIcon_tool: "Tool", presetIcon_bug: "Bug", presetIcon_check: "Check", presetIcon_code: "Code", presetIcon_shield: "Shield",
  confirmPresetAction: "Confirm", confirmResetPresets: "Reset this workspace’s shared presets to the defaults? Unsaved edits will be discarded.", confirmReloadPresets: "Discard unsaved edits and reload the workspace presets?",
  presetsChangedDuringSave: "The preset draft changed. Save the current version again.", presetPlaceholders: "Available placeholders. Source evidence and exact report references are always included in the prepared task.",
  title: "Kandev Security", navigation: "Security", subtitle: "Workspace security reports",
  chooseWorkspace: "Select a workspace to view and import security reports.",
  import: "Import SARIF", sarifFile: "SARIF file", importHelp: "SARIF 2.1.0. Maximum 20 MiB and 50,000 findings per report.",
  cancel: "Cancel", loading: "Loading reports...", empty: "No security reports in this workspace.",
  refresh: "Refresh", back: "Back to reports", previous: "Previous", next: "Next",
  export: "Export original SARIF", delete: "Delete report", confirmDelete: "Permanently delete this report and its findings?",
  confirm: "Confirm deletion", search: "Search findings", searchHelp: "Search messages, rule IDs, or paths",
  allLevels: "All levels", error: "Error", warning: "Warning", note: "Note", none: "None",
  noFindings: "No findings match these filters.", imported: "Imported", findings: "Findings",
  scanner: "Scanner", repository: "Repository", revision: "Revision", importer: "Importer",
  location: "Location", noLocation: "No physical location", rule: "Rule", securitySeverity: "Security severity",
  run: "Run", openSecurityPage: "Security: open page", uploading: "Uploading: {{progress}}%",
  tokens: "Upload tokens", tokenHelp: "Create a token for a scanner or CI job. It can only import reports into this workspace. Kandev authentication also requires a PAT on the request.",
  tokenName: "Token name", createToken: "Create upload token", tokenOnce: "Save this token now. It is shown once and cannot be retrieved after leaving this view.",
  newToken: "New upload token", savedToken: "I saved the token", noTokens: "No upload tokens in this workspace.",
  revokeToken: "Revoke", revokeQuestion: "Revoke this token? Uploads using it will be rejected.", confirmRevoke: "Confirm revocation",
  revoked: "Revoked", active: "Active", lastUsed: "Last used", never: "Never", tokenIssuer: "Issuer", loadingTokens: "Loading upload tokens...",
  allFindings: "All findings", aggregateTitle: "Findings across reports", language: "Language", tool: "Scanner tool",
  severity: "Severity", sort: "Sort", critical: "Critical", high: "High", medium: "Medium", low: "Low", informational: "Informational",
  newest: "Newest", oldest: "Oldest", recently_updated: "Recently updated", least_recently_updated: "Least recently updated",
  clearFilters: "Clear filters", unknown: "Unknown",
  moreValues: "More values match. Keep typing to narrow the suggestions.", updated: "Updated",
  openReport: "Open report: {{filename}}", aggregateBack: "Back to all findings", sourceReport: "Source report",
  aggregateHelp: "Dates show import times. Grouped issues use the highest severity among retained matching occurrences. Retention history records removed sources.",
  groupedIssues: "Grouped issues", rawOccurrences: "Report occurrences", issueCount: "{{count}} issues", issueCountOne: "1 issue", occurrenceCountOne: "1 occurrence", occurrencesCount: "{{count}} occurrences",
  issueHistory: "Issue history", identityMethod: "Matching method", identityScope: "Matching scope", firstSeen: "First imported", lastSeen: "Last imported",
  issueStatus: "Issue status", statusReason: "Reason for status change", closeIssue: "Close issue", reopenIssue: "Reopen issue", open: "Open", closed: "Closed",
  statusHistory: "Review history", moreOccurrences: "More occurrences", moreStatusHistory: "More review history",
  manualStatusHelp: "Status is manual. Imports do not close or reopen issues, and closed does not mean a fix has been verified.",
  reports: "Reports", filter: "Filter", level: "Level", working: "Working...",
  viewMenu: "Security views", all: "All", searchValues: "Search {{field}}", noValues: "No matching values.",
  clearField: "Clear {{field}}", findingsCount: "{{count}} findings", loadingFindings: "Loading findings...",
  findingDetails: "Finding details", closeFinding: "Close finding", loadingFinding: "Loading finding...", retry: "Retry",
  description: "Description", guidance: "Remediation guidance", suggestedFixes: "Suggested fixes", advisoryLinks: "Advisory links",
  noGuidance: "No remediation guidance was provided.", truncatedDetail: "Some detail text was shortened. Export the original SARIF for the complete content.",
  severityOverview: "Severity overview", latestImport: "Latest workspace import", noImports: "No reports imported", matchingSeverities: "Counts include all severities matching the other filters.",
  viewFinding: "View finding: {{rule}}", pageNumber: "Page {{page}}", findingRange: "{{start}}–{{end}} of {{total}}", pagination: "Findings pagination",
};

function icon(host, name) {
  const paths = {
    search: "m21 21-4.4-4.4 M19 11a8 8 0 1 1-16 0 8 8 0 0 1 16 0",
    chevron: "m6 9 6 6 6-6", sort: "M8 4v16m-4-4 4 4 4-4M16 20V4m-4 4 4-4 4 4",
    refresh: "M20 7v5h-5M4 17v-5h5 M6.1 7a7 7 0 0 1 11.6-1L20 9M4 15l2.3 3A7 7 0 0 0 17.9 17",
    previous: "m15 18-6-6 6-6", next: "m9 18 6-6-6-6",
    check: "m5 12 4 4L19 6", close: "m6 6 12 12M6 18 18 6",
  };
  return host.jsx("svg", { width: 14, height: 14, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.6,
    strokeLinecap: "round", strokeLinejoin: "round", "aria-hidden": true, style: { flexShrink: 0 } }, host.jsx("path", { d: paths[name] }));
}

function makeSecurityIcon(host) {
  return function SecurityIcon(props = {}) {
    return host.jsx("svg", { width: 24, height: 24, viewBox: "0 0 24 24", fill: "none",
      stroke: "currentColor", strokeWidth: 1.75, strokeLinecap: "round", strokeLinejoin: "round",
      ...props, "aria-hidden": true, focusable: false },
    host.jsx("path", { d: "M12 3 20 6v5c0 4.8-3.2 8.2-8 10-4.8-1.8-8-5.2-8-10V6l8-3Z" }));
  };
}

function makeNavigationMenu(host, model) {
  const h = host.jsx;
  const { Button, DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem } = host.ui;
  return function NavigationMenu() {
    const [state, setState] = host.React.useState(model.getSnapshot);
    host.React.useEffect(() => { setState(model.getSnapshot()); return model.subscribe(setState); }, []);
    const translate = host.i18n?.useTranslation().t;
    const t = (key) => translate ? translate(key, { defaultValue: english[key] }) : english[key];
    return h(DropdownMenu, null,
      h(DropdownMenuTrigger, { asChild: true }, h(Button, { variant: "outline", size: "sm", disabled: !state.workspaceId,
        "aria-label": t("viewMenu"), className: "kandev-security-view-trigger gap-2 text-xs" },
      t(state.view === "findings" ? "allFindings" : state.view), icon(host, "chevron"))),
      h(DropdownMenuContent, { align: "end", className: "kandev-security-view-menu" },
        ...["findings", "advisories", "reports", "import", "tokens"].map((view) => h(DropdownMenuItem, { key: view,
          "aria-current": state.view === view ? "page" : undefined,
          onSelect: () => { model.setView(view); host.navigate(view === "advisories" ? "/security/advisories" : "/security"); }, className: "cursor-pointer gap-2 text-xs" },
        h("span", { style: { width: 14 } }, state.view === view ? icon(host, "check") : null), t(view === "findings" ? "allFindings" : view))),
        h(DropdownMenuItem, { onSelect: () => host.navigate(taskSettingsPath(state.workspaceId)) }, t("taskPresets")),
        h(DropdownMenuItem, { onSelect: () => host.navigate(`${taskSettingsPath(state.workspaceId)}#report-retention`) }, t("reportRetention"))));
  };
}

function makeReportsView(host, model) {
  const h = host.jsx, { Button, Input } = host.ui;
  const ToolFilter = makeFacetFilter(host, { suggest: (_field, search) => model.suggestReportTools(search) });
  return function ReportsView({ state, t }) {
    const [search, setSearch] = host.React.useState(state.reportSearch);
    const resultsRef = host.React.useRef(null);
    host.React.useEffect(() => { setSearch(state.reportSearch); }, [state.reportSearch]);
    host.React.useEffect(() => {
      if (search === state.reportSearch) return;
      const timer = setTimeout(() => model.setReportSearch(search), 300);
      return () => clearTimeout(timer);
    }, [search, state.reportSearch]);
    host.React.useEffect(() => { resultsRef.current?.scrollTo({ top: 0 }); }, [state.offset, state.reportStatus, state.reportTool, state.reportSearch]);
    const page = state.reportPage, loading = state.loading;
    return h("section", { className: "kandev-security-aggregate kandev-security-reports", "aria-label": t("reports") },
      h("form", { className: "kandev-security-toolbar", role: "search", "aria-label": t("searchReports"), onSubmit: (event) => { event.preventDefault(); model.setReportSearch(search); } },
        h("div", { className: "kandev-security-search" }, icon(host, "search"),
          h(Input, { "aria-label": t("searchReports"), placeholder: t("searchReports"), value: search, maxLength: 256, className: "kandev-security-search-with-clear", onChange: (event) => setSearch(event.target.value) }),
          search ? h(Button, { type: "button", variant: "ghost", size: "icon", className: "kandev-security-search-clear", "aria-label": t("clearReportSearch"), onClick: () => { setSearch(""); model.setReportSearch(""); } }, icon(host, "close")) : null),
        h("div", { className: "kandev-security-toolbar-actions" },
          h("span", { role: "status", className: "kandev-security-count" }, loading ? t("loading") : page ? t("reportCount", { count: page.total }) : ""),
          h(Button, { type: "button", variant: "outline", size: "sm", onClick: () => model.setView("import") }, t("uploadReport")),
          h(Button, { type: "button", variant: "ghost", size: "icon", className: "kandev-security-refresh", "aria-label": t("refresh"), disabled: loading, onClick: () => model.list() }, icon(host, "refresh")))),
      h("div", { className: "kandev-security-overview", role: "group", "aria-label": t("reportStatus") },
        ...["active", "all", "archived"].map((status) => h("button", { key: status, type: "button", className: "kandev-security-summary-chip", "aria-pressed": state.reportStatus === status,
          disabled: loading, onClick: () => model.setReportStatus(status) }, t(`${status}Reports`), h("span", null, page?.status_counts?.[status] ?? "–")))),
      h("div", { className: "kandev-security-filter-bar", role: "group", "aria-label": t("filter") },
        h(ToolFilter, { field: "tool", state: { ...state, facets: { tool: state.reportTools }, facetMore: { tool: state.reportToolsMore } }, query: { tool: state.reportTool }, onChange: (next) => model.setReportTool(next.tool), t })),
      h("div", { className: "kandev-security-results-scroll", ref: resultsRef, "aria-busy": loading },
        loading ? null : !state.reports.length ? h("p", { className: "kandev-security-empty" }, t(state.reportTool || state.reportSearch ? "noMatchingReports" : state.reportStatus === "archived" ? "emptyArchived" : state.reportStatus === "active" ? "emptyActive" : "empty"))
          : h("ul", { className: "kandev-security-results", "aria-label": t("reports") }, ...state.reports.map((report) => h("li", { key: report.id, className: "kandev-security-result-row kandev-security-report-row" },
            h("button", { type: "button", className: "kandev-security-report-link", onClick: () => model.open(report.id) },
              h("span", { id: `security-report-${report.id}`, className: "block break-words font-medium" }, report.filename),
              h("span", { className: "block break-words text-sm text-muted-foreground" }, `${report.tools} · ${t("findings")}: ${report.finding_count} · ${new Date(report.created_at).toLocaleString()}${report.pinned ? ` · ${t("pinned")}` : ""}${report.archived_at ? ` · ${t("archived")}` : ""}`)),
            h("div", { className: "kandev-security-report-actions" },
              h(Button, { variant: "outline", size: "sm", disabled: state.pinning || state.archiving || state.deleting, "aria-label": t(report.pinned ? "unpinReport" : "pinReport"), "aria-describedby": `security-report-${report.id}`, onClick: () => model.pinReport(report, !report.pinned) }, t(report.pinned ? "unpinReport" : "pinReport")),
              h(Button, { variant: "outline", size: "sm", disabled: state.archiving || state.pinning || state.deleting, "aria-label": t(report.archived_at ? "restoreReport" : "archiveReport"), "aria-describedby": `security-report-${report.id}`, onClick: () => model.archiveReport(report, !report.archived_at) }, t(report.archived_at ? "restoreReport" : "archiveReport"))))))),
      renderResultPagination(host, { t, label: t("reportPagination"), loading, loadingLabel: t("loading"), offset: state.offset, total: page?.total, count: state.reports.length, next: state.nextOffset, load: (offset) => model.list(offset) }));
  };
}

function renderResultPagination(host, { t, label, loading, loadingLabel, offset, total, count, next, load }) {
  const h = host.jsx, { Button } = host.ui;
  return h("nav", { "aria-label": label, className: "kandev-security-pagination" },
    h("span", { className: "kandev-security-page-range" }, loading ? loadingLabel : total != null ? t("findingRange", { start: total ? offset + 1 : 0, end: offset + count, total }) : ""),
    h("div", { className: "kandev-security-page-controls" },
      h(Button, { type: "button", variant: "ghost", size: "sm", disabled: loading || !offset, onClick: () => load(Math.max(0, offset - 25)) }, icon(host, "previous"), t("previous")),
      h("span", { className: "kandev-security-page-number" }, t("pageNumber", { page: Math.floor(offset / 25) + 1 })),
      h(Button, { type: "button", variant: "ghost", size: "sm", disabled: loading || !next, onClick: () => load(next) }, t("next"), icon(host, "next"))));
}

function makePage(host, model, tasks, advisoryRoute = false) {
  const h = host.jsx;
  const { useState, useEffect } = host.React;
  const { Button, Input } = host.ui;
  const ReportsView = makeReportsView(host, model);
  const AggregateView = makeAggregateView(host, model, tasks);
  const AdvisoryView = makeAdvisoryView(host, model, tasks);
  const TokensView = makeTokensView(host, model);
  const ImportView = makeImportView(host, model);
  const FindingDrawer = makeFindingDrawer(host, model, tasks);
  const TaskDialog = makeSecurityTaskDialog(host, tasks);
  return function SecurityPage() {
    const [state, setState] = useState(model.getSnapshot);
    const [search, setSearch] = useState("");
    const [level, setLevel] = useState("");
    const [confirmDelete, setConfirmDelete] = useState(false);
    const translate = host.i18n?.useTranslation().t;
    const t = (key, values) => translate ? translate(key, { defaultValue: english[key], count: values?.count, values }) : english[key]?.replace(/\{\{(\w+)\}\}/g, (_, name) => String(values?.[name] ?? ""));
    useEffect(() => { setState(model.getSnapshot()); return model.subscribe(setState); }, []);
    useEffect(() => {
      const view = model.getSnapshot().view;
      if (advisoryRoute && view !== "advisories") model.setView("advisories");
      else if (!advisoryRoute && view === "advisories") model.setView("findings");
    }, []);
    useEffect(() => { setConfirmDelete(false); setSearch(""); setLevel(""); }, [state.workspaceId, state.selectedId]);
    const detail = state.detail;
    const pagination = (offset, next, load) => h("nav", { "aria-label": t("reports"), className: "flex gap-2 pt-4" },
      h(Button, { variant: "outline", className: "min-h-11", disabled: state.loading || !offset, onClick: () => load(Math.max(0, offset - 25)) }, t("previous")),
      h(Button, { variant: "outline", className: "min-h-11", disabled: state.loading || !next, onClick: () => load(next) }, t("next")));
    const summary = (label, value) => value ? h("div", { className: "min-w-0" }, h("dt", { className: "text-sm text-muted-foreground" }, label), h("dd", { className: "break-words text-sm" }, value)) : null;
    const download = async () => {
      const exported = await model.exportReport(detail.report.id);
      if (!exported) return;
      const url = URL.createObjectURL(exported.blob);
      const a = document.createElement("a"); a.href = url; a.download = exported.filename; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    };
    return h("main", { className: `kandev-security-page${["findings", "advisories", "reports"].includes(state.view) && !detail ? " kandev-security-page-findings" : ""}`, "aria-label": t("title") },
      h("style", null, layoutStyles),
      h(FindingDrawer, { state, t }),
      h(TaskDialog, { t }),
      !state.workspaceId ? h("p", { className: "kandev-security-content" }, t("chooseWorkspace")) : h(host.React.Fragment, null,
        state.view === "import" ? h(ImportView, { state, t }) : null,
        state.error ? h("p", { role: "alert", className: "kandev-security-message break-words rounded border border-destructive p-3 text-destructive" }, state.error) : null,
        state.notice ? h("p", { role: "status", className: "kandev-security-message" }, state.notice) : null,
        state.loading && (state.view !== "reports" || state.selectedId) ? h("p", { role: "status", className: "kandev-security-message" }, t("loading")) : null,
        state.selectedId && !detail && !state.loading ? h(Button, { variant: "outline", onClick: () => model.back() }, t("back")) : null,
        state.view === "tokens" ? h(TokensView, { key: state.workspaceId, state, t }) : null,
        !detail && state.view === "findings" ? h(AggregateView, { key: state.workspaceId, state, t }) : null,
        !detail && state.view === "advisories" ? h(AdvisoryView, { key: state.workspaceId, state, t }) : null,
        detail ? h("section", { className: "kandev-security-content space-y-4" },
          h(Button, { variant: "outline", className: "min-h-11", onClick: () => model.back() }, t(state.view === "findings" ? "aggregateBack" : "back")),
          h("h2", { className: "break-words text-lg font-medium" }, detail.report.filename),
          detail.report.archived_at ? h("p", { role: "note" }, t("archiveNotice")) : null,
          h("dl", { className: "grid gap-3 sm:grid-cols-2" },
            summary(t("scanner"), detail.report.tools), summary(t("findings"), String(detail.report.finding_count)),
            summary(t("imported"), new Date(detail.report.created_at).toLocaleString()), summary(t("importer"), detail.report.actor_id)),
          ...detail.runs.map((run) => h("dl", { key: run.index, className: "grid gap-2 rounded border p-3 sm:grid-cols-2" },
            summary(t("run"), `${run.index + 1}: ${run.tool} ${run.version}`), summary(t("repository"), run.repository), summary(t("revision"), run.revision))),
          ...detail.runs.filter((run) => run.agent_audit).map((run) => h("div", { key: `audit-${run.index}` }, renderAgentAudit(host, run.agent_audit, t))),
          h("div", { className: "flex flex-wrap gap-2" },
            h(Button, { variant: "outline", className: "min-h-11", disabled: state.pinning || state.archiving || state.deleting, onClick: () => model.pinReport(detail.report, !detail.report.pinned) }, t(detail.report.pinned ? "unpinReport" : "pinReport")),
            h(Button, { variant: "outline", className: "min-h-11", disabled: state.archiving || state.pinning || state.deleting, onClick: () => model.archiveReport(detail.report, !detail.report.archived_at) }, t(detail.report.archived_at ? "restoreReport" : "archiveReport")),
            h(Button, { variant: "outline", className: "min-h-11", disabled: state.exporting, onClick: download }, state.exporting ? t("working") : t("export")),
            h(Button, { variant: "destructive", className: "min-h-11", disabled: state.deleting || state.archiving || state.pinning, onClick: () => setConfirmDelete(true) }, t("delete"))),
          confirmDelete ? h("div", { className: "space-y-3 rounded border p-3", role: "group", "aria-label": t("confirmDelete") },
            h("p", null, t("confirmDelete")),
            h("div", { className: "flex flex-wrap gap-2" },
              h(Button, { variant: "destructive", className: "min-h-11", disabled: state.deleting || state.archiving || state.pinning, onClick: () => model.remove(detail.report.id) }, t("confirm")),
              h(Button, { variant: "outline", className: "min-h-11", disabled: state.deleting || state.archiving || state.pinning, onClick: () => setConfirmDelete(false) }, t("cancel")))) : null,
          h("form", { className: "flex flex-col gap-2 sm:flex-row", onSubmit: (event) => { event.preventDefault(); model.open(detail.report.id, { level, search, offset: 0 }); } },
            h(Input, { "aria-label": t("search"), placeholder: t("searchHelp"), maxLength: 256, value: search, className: "min-h-11 min-w-0 flex-1", onChange: (event) => setSearch(event.target.value) }),
            h("select", { "aria-label": t("level"), value: level, className: "min-h-11 rounded border bg-background px-3", onChange: (event) => setLevel(event.target.value) },
              ...["", "error", "warning", "note", "none"].map((value) => h("option", { key: value, value }, t(value || "allLevels")))),
            h(Button, { type: "submit", className: "min-h-11" }, t("filter"))),
          detail.findings.length === 0 ? h("p", null, t("noFindings")) : h("ol", { className: "kandev-security-results", "aria-label": t("findings") },
            ...detail.findings.map((finding) => h("li", { key: finding.ordinal, className: "kandev-security-result-row" },
              h("div", { className: "kandev-security-result-meta" },
                h("span", { className: "rounded bg-muted px-2 py-1 font-medium" }, t(finding.level)),
                h("span", { className: "break-all font-mono" }, finding.rule_id),
                finding.security_severity > 0 ? h("span", null, `${t("securitySeverity")}: ${finding.security_severity}`) : null),
              // SARIF markdown and URIs remain plain text. Imported content is never HTML.
              h("p", { className: "kandev-security-finding-message" }, finding.message),
              h("p", { className: "break-all font-mono text-sm text-muted-foreground" }, finding.uri ? `${finding.uri}${finding.line ? `:${finding.line}${finding.column ? `:${finding.column}` : ""}` : ""}` : t("noLocation"))))),
          pagination(state.query.offset, detail.next_offset, (offset) => model.open(detail.report.id, { ...state.query, offset }))) : !state.selectedId && state.view === "reports" ? h(ReportsView, { key: state.workspaceId, state, t }) : null));
  };
}

// Layout is scoped to this page and based on its available content width, so
// the host sidebar and split panes do not force desktop-width controls to clip.
const layoutStyles = `
.kandev-security-page { width: 100%; max-width: none; min-width: 0; margin: 0; padding: 0; box-sizing: border-box; container-type: inline-size; }
.kandev-security-page-findings { display: flex; flex-direction: column; height: 100%; min-height: 0; overflow: hidden; }
.kandev-security-aggregate { display: flex; flex: 1; flex-direction: column; min-height: 0; }
.kandev-security-results-scroll { flex: 1; min-height: 0; overflow-y: auto; overscroll-behavior: contain; }
.kandev-security-aggregate > .kandev-security-toolbar, .kandev-security-aggregate > .kandev-security-filter-bar, .kandev-security-overview { flex-shrink: 0; }
.kandev-security-page *, .kandev-security-filter-popover *, .kandev-security-sort-menu * { box-sizing: border-box; }
.kandev-security-content { padding: 1.5rem; min-width: 0; }
.kandev-security-advisory-header { flex-shrink: 0; padding: .75rem 1.5rem; border-bottom: 1px solid var(--border, #e5e7eb); overflow-wrap: anywhere; }
.kandev-security-advisory-header h2 { display: inline; margin: 0 .75rem; font-size: 1rem; }
.kandev-security-advisory-header p { margin: .375rem 0; font-size: .75rem; }
.kandev-security-message { margin: .75rem 1.5rem; }
.kandev-security-toolbar, .kandev-security-filter-bar { display: flex; align-items: center; flex-wrap: wrap; gap: .5rem; padding: .625rem 1.5rem; border-bottom: 1px solid var(--border, #e5e7eb); }
.kandev-security-toolbar { min-width: 0; }
.kandev-security-search { position: relative; flex: 1; max-width: 28rem; min-width: 12.5rem; }
.kandev-security-search > svg { position: absolute; left: .625rem; top: 50%; transform: translateY(-50%); color: var(--muted-foreground, #6b7280); pointer-events: none; }
.kandev-security-page .kandev-security-search input { width: 100%; min-width: 0; height: 2rem; min-height: 2rem; padding-left: 2rem; border: 1px solid var(--input, #d1d5db); border-radius: .375rem; background: transparent; font-size: .75rem; }
.kandev-security-page .kandev-security-search input.kandev-security-search-with-clear { padding-right: 2.75rem; }
.kandev-security-page .kandev-security-search-clear { position: absolute; right: .125rem; top: 50%; transform: translateY(-50%); width: 1.75rem; height: 1.75rem; min-height: 1.75rem; padding: 0; display: flex; align-items: center; justify-content: center; }
.kandev-security-toolbar-actions { display: flex; align-items: center; flex-wrap: wrap; gap: .25rem; margin-left: auto; }
.kandev-security-count { margin-right: .5rem; color: var(--muted-foreground, #6b7280); font-size: .75rem; font-variant-numeric: tabular-nums; }
.kandev-security-page .kandev-security-sort { display: inline-flex; align-items: center; gap: .375rem; font-size: .75rem; min-height: 2rem; cursor: pointer; }
.kandev-security-sort-menu { min-width: 10rem; }
.kandev-security-sort-option { display: flex; align-items: center; gap: .5rem; cursor: pointer; }
.kandev-security-sort-check { display: inline-flex; width: .875rem; flex-shrink: 0; }
.kandev-security-page .kandev-security-refresh { width: 2rem; height: 2rem; min-height: 2rem; padding: 0; }
.kandev-security-filter-bar { background: color-mix(in srgb, var(--muted, #f3f4f6) 20%, transparent); }
.kandev-security-pill { display: inline-flex; align-items: stretch; max-width: 100%; border: 1px solid var(--border, #e5e7eb); border-radius: .375rem; background: var(--background, #fff); }
.kandev-security-pill[data-active="true"] { border-color: color-mix(in srgb, var(--primary, #374151) 40%, transparent); background: color-mix(in srgb, var(--primary, #374151) 5%, var(--background, #fff)); }
.kandev-security-pill button { display: inline-flex; align-items: center; gap: .375rem; min-width: 0; min-height: 2rem; border: 0; padding: .375rem .625rem; background: transparent; color: inherit; font-size: .75rem; cursor: pointer; }
.kandev-security-pill-label { color: var(--muted-foreground, #6b7280); }
.kandev-security-pill-value { max-width: 12rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 500; }
.kandev-security-pill .kandev-security-pill-clear { border-left: 1px solid var(--border, #e5e7eb); padding-inline: .375rem; flex-shrink: 0; }
.kandev-security-pill button:hover, .kandev-security-option:hover { background: color-mix(in srgb, var(--muted, #f3f4f6) 50%, transparent); }
.kandev-security-page .kandev-security-clear { min-height: 2rem; padding: .375rem .5rem; font-size: .75rem; }
.kandev-security-filter-popover { width: 18rem; max-width: calc(100vw - 2rem); padding: 0; gap: 0; background: var(--popover, #fff); color: var(--popover-foreground, #111827); border: 1px solid var(--border, #e5e7eb); border-radius: .5rem; box-shadow: 0 4px 12px #0002; z-index: 50; }
.kandev-security-facet-search { padding: .5rem; border-bottom: 1px solid var(--border, #e5e7eb); }
.kandev-security-facet-search input { width: 100%; min-width: 0; min-height: 2rem; height: 2rem; font-size: .75rem; }
.kandev-security-options { max-height: 16rem; overflow-y: auto; padding: .25rem 0; }
.kandev-security-option { display: flex; align-items: center; gap: .5rem; width: 100%; min-height: 2rem; padding: .375rem .75rem; border: 0; text-align: left; background: transparent; color: inherit; font-size: .75rem; overflow-wrap: anywhere; cursor: pointer; }
.kandev-security-option[aria-pressed="true"] { font-weight: 600; }
.kandev-security-option > span { min-width: 0; }
.kandev-security-option > svg { margin-left: auto; }
.kandev-security-filter-hint { padding: .5rem .75rem; margin: 0; color: var(--muted-foreground, #6b7280); font-size: .75rem; }
.kandev-security-results { list-style: none; margin: 0; padding: 0; }
.kandev-security-result-row { min-width: 0; padding: .75rem 1.5rem; border-bottom: 1px solid var(--border, #e5e7eb); }
.kandev-security-result-meta { display: flex; flex-wrap: wrap; align-items: center; gap: .25rem .75rem; color: var(--muted-foreground, #6b7280); font-size: .75rem; overflow-wrap: anywhere; }
.kandev-security-finding-message { margin: .375rem 0; font-size: .875rem; font-weight: 500; white-space: pre-wrap; overflow-wrap: anywhere; }
.kandev-security-result-footer { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: .25rem 1rem; }
.kandev-security-result-path { min-width: 0; margin: .25rem 0; font-size: .75rem; overflow-wrap: anywhere; }
/* Set colours on each indicator so portalled finding drawers share the palette. */
:is(.kandev-security-severity, .kandev-security-summary-chip)[data-severity="critical"] { --security-severity-color: #be123c; --security-severity-background: #fff1f2; }
:is(.kandev-security-severity, .kandev-security-summary-chip)[data-severity="high"] { --security-severity-color: #c2410c; --security-severity-background: #fff7ed; }
:is(.kandev-security-severity, .kandev-security-summary-chip)[data-severity="medium"] { --security-severity-color: #a16207; --security-severity-background: #fefce8; }
:is(.kandev-security-severity, .kandev-security-summary-chip)[data-severity="low"] { --security-severity-color: #1d4ed8; --security-severity-background: #eff6ff; }
:is(.kandev-security-severity, .kandev-security-summary-chip)[data-severity="informational"] { --security-severity-color: #525252; --security-severity-background: #f5f5f5; }
.dark :is(.kandev-security-severity, .kandev-security-summary-chip)[data-severity="critical"] { --security-severity-color: #fda4af; --security-severity-background: #4c0519; }
.dark :is(.kandev-security-severity, .kandev-security-summary-chip)[data-severity="high"] { --security-severity-color: #fdba74; --security-severity-background: #431407; }
.dark :is(.kandev-security-severity, .kandev-security-summary-chip)[data-severity="medium"] { --security-severity-color: #fde047; --security-severity-background: #422006; }
.dark :is(.kandev-security-severity, .kandev-security-summary-chip)[data-severity="low"] { --security-severity-color: #93c5fd; --security-severity-background: #172554; }
.dark :is(.kandev-security-severity, .kandev-security-summary-chip)[data-severity="informational"] { --security-severity-color: #d4d4d4; --security-severity-background: #262626; }
.kandev-security-severity { display: inline-block; border: 1px solid color-mix(in srgb, var(--security-severity-color, #475569) 25%, var(--security-severity-background, transparent)); border-radius: .25rem; padding: .125rem .375rem; font-weight: 500; color: var(--security-severity-color, var(--muted-foreground, #475569)); background: var(--security-severity-background, transparent); }
.kandev-security-report-row { padding: 0; display: flex; flex-wrap: wrap; align-items: center; gap: .75rem; }
.kandev-security-report-row > .kandev-security-report-link { flex: 1; min-width: 0; }
.kandev-security-report-actions { display: flex; flex-wrap: wrap; gap: .5rem; padding: .5rem; }
.kandev-security-report-row > .kandev-security-report-link { flex-basis: 14rem; }
.kandev-security-reports .kandev-security-report-row { padding-inline: 1rem; }
.kandev-security-report-link { display: block; width: 100%; min-height: 44px; padding: .75rem .5rem; text-align: left; border: 0; border-radius: .25rem; background: transparent; color: inherit; cursor: pointer; }
.kandev-security-report-link:hover { background: var(--muted, #f3f4f6); }
.kandev-security-page button:focus-visible, .kandev-security-page input:focus-visible, .kandev-security-page select:focus-visible, .kandev-security-filter-popover button:focus-visible, .kandev-security-filter-popover input:focus-visible { outline: 2px solid var(--ring, #6b7280); outline-offset: 2px; }
.kandev-security-report-link > span { display: block; margin: .25rem 0; overflow-wrap: anywhere; }
.kandev-security-pagination { display: flex; gap: .5rem; align-items: center; justify-content: space-between; flex-wrap: wrap; flex-shrink: 0; padding: .75rem 1.5rem; border-top: 1px solid var(--border, #e5e7eb); background: var(--background, #fff); }
.kandev-security-page-range { color: var(--muted-foreground, #6b7280); font-size: .75rem; font-variant-numeric: tabular-nums; }
.kandev-security-page-controls { display: flex; align-items: center; gap: .25rem; margin-left: auto; }
.kandev-security-page-number { padding-inline: .75rem; font-size: .875rem; font-variant-numeric: tabular-nums; }
.kandev-security-page-controls button { gap: .25rem; cursor: pointer; }
.kandev-security-page-controls button:disabled { cursor: default; }
.kandev-security-aggregate-help { padding: .75rem 1.5rem; margin: 0; font-size: .75rem; color: var(--muted-foreground, #6b7280); }
.kandev-security-empty { padding: 2rem 1.5rem; margin: 0; text-align: center; color: var(--muted-foreground, #6b7280); font-size: .875rem; }
.kandev-security-view-menu { min-width: 11rem; }
@container (max-width: 600px) {
  .kandev-security-toolbar, .kandev-security-filter-bar { padding-inline: 1rem; }
  .kandev-security-reports .kandev-security-report-row { padding-inline: .5rem; }
  .kandev-security-search { flex-basis: 100%; max-width: none; min-width: 0; }
  .kandev-security-toolbar-actions { margin-left: 0; width: 100%; }
  .kandev-security-count { margin-right: auto; }
  .kandev-security-page .kandev-security-search input, .kandev-security-page .kandev-security-sort, .kandev-security-pill button, .kandev-security-page .kandev-security-clear, .kandev-security-page .kandev-security-refresh { min-height: 44px; }
  .kandev-security-result-row, .kandev-security-pagination, .kandev-security-aggregate-help, .kandev-security-content { padding-inline: 1rem; }
}
@media (pointer: coarse) {
  .kandev-security-page .kandev-security-search-clear { min-height: 44px; height: 44px; width: 44px; right: 0; }
  .kandev-security-option, .kandev-security-facet-search input, .kandev-security-view-trigger, .kandev-security-page-controls button, .kandev-security-sort-option { min-height: 44px; }
}
.kandev-security-overview { display: flex; flex-wrap: wrap; align-items: center; gap: .375rem; padding: .5rem 1.5rem; border-bottom: 1px solid var(--border, #e5e7eb); }
.kandev-security-summary-chip { display: inline-flex; gap: .5rem; align-items: center; padding: .25rem .5rem; min-height: 30px; border: 1px solid transparent; border-radius: .375rem; font-size: .75rem; background: transparent; color: var(--muted-foreground, #6b7280); cursor: pointer; }
.kandev-security-summary-chip > span { font-variant-numeric: tabular-nums; font-weight: 600; color: var(--foreground, #111827); }
.kandev-security-summary-chip[aria-pressed="true"] { background: var(--muted, #f3f4f6); border-color: var(--border, #e5e7eb); color: var(--foreground, #111827); }
.kandev-security-summary-chip:not([data-severity=""]) { color: var(--security-severity-color); }
.kandev-security-summary-chip:not([data-severity=""]):hover { background: var(--muted, #f3f4f6); border-color: var(--border, #e5e7eb); }
.kandev-security-summary-chip:not([data-severity=""])[aria-pressed="true"] { background: var(--security-severity-background); border-color: var(--security-severity-color); }
.kandev-security-freshness { margin-left: auto; font-size: .75rem; color: var(--muted-foreground, #6b7280); }
.kandev-security-compact-row { padding-block: 0; display: flex; align-items: center; gap: .75rem; }
.kandev-security-compact-row > .kandev-security-finding-link { flex: 1; }
.kandev-security-task-actions { display: flex; flex-shrink: 0; align-items: center; gap: .5rem; padding-block: .5rem; flex-wrap: wrap; }
.kandev-security-task-count { font-size: .75rem; color: var(--muted-foreground, #6b7280); }
.kandev-security-retention-settings { display: flex; flex-direction: column; gap: .75rem; min-width: 0; }
.kandev-security-content.kandev-security-retention-settings { padding-inline: 0; }
.kandev-security-retention-settings h2 { margin: 0; font-size: 1.125rem; line-height: 1.75rem; font-weight: 600; }
.kandev-security-retention-settings h3 { margin: .5rem 0 0; font-size: 1rem; line-height: 1.5rem; font-weight: 600; }
.kandev-security-retention-settings legend { padding-inline: .25rem; font-size: .875rem; line-height: 1.25rem; font-weight: 500; }
.kandev-security-retention-settings form, .kandev-security-retention-settings fieldset { display: flex; flex-direction: column; gap: .75rem; min-width: 0; }
.kandev-security-retention-settings fieldset { padding: .75rem; border: 1px solid var(--border, #ddd); border-radius: .375rem; }
.kandev-security-retention-settings label { display: flex; flex-direction: column; gap: .375rem; }
.kandev-security-retention-settings .kandev-security-retention-enable { flex-direction: row; align-items: center; }
.kandev-security-retention-limits, .kandev-security-retention-buttons { display: flex; flex-wrap: wrap; gap: .75rem; }
.kandev-security-retention-limits > label { flex: 1; min-width: 10rem; }
.kandev-security-retention-settings p, .kandev-security-retention-settings li { overflow-wrap: anywhere; }
.kandev-security-evidence-code { white-space: pre-wrap; overflow-wrap: anywhere; max-width: 100%; padding: .5rem; border-radius: .375rem; background: var(--muted, #f3f4f6); font-size: .75rem; }
.kandev-security-start-task { font-size: .75rem; min-height: 2rem; }
.kandev-security-task-menu { width: max(12rem, calc(var(--radix-dropdown-menu-trigger-width, 8rem) * 1.5)); max-width: min(24rem, calc(100vw - 2rem)); max-height: 24rem; overflow-y: auto; }
.kandev-security-preset-icon { display: inline-flex; flex-shrink: 0; margin-right: .5rem; }
.kandev-security-linked-task-label { padding: .5rem; font-size: .75rem; color: var(--muted-foreground, #6b7280); border-top: 1px solid var(--border, #ddd); }
.kandev-security-presets-settings { display: flex; flex-direction: column; gap: 1rem; min-width: 0; }
.kandev-security-preset-editor { display: flex; flex-direction: column; gap: .75rem; padding: 1rem; border: 1px solid var(--border, #ddd); border-radius: .5rem; min-width: 0; }
.kandev-security-preset-editor label { display: flex; flex-direction: column; gap: .375rem; }
.kandev-security-preset-editor input, .kandev-security-preset-template { width: 100%; }
.kandev-security-preset-template, .kandev-security-native-select { border: 1px solid var(--border, #ddd); border-radius: .375rem; padding: .5rem; color: inherit; background: transparent; }
.kandev-security-preset-tokens { overflow-wrap: anywhere; }
@media (max-width: 600px) { .kandev-security-compact-row { flex-wrap: wrap; gap: 0; } .kandev-security-compact-row > .kandev-security-finding-link { flex-basis: 100%; } .kandev-security-start-task { min-height: 44px; } }

.kandev-security-finding-link { display: block; width: 100%; min-width: 0; padding: .625rem 0; border: 0; background: transparent; color: inherit; text-align: left; cursor: pointer; }
.kandev-security-compact-row:hover { background: color-mix(in srgb, var(--muted, #f3f4f6) 40%, transparent); }
.kandev-security-compact-message { display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2; overflow: hidden; margin: .25rem 0; font-size: .875rem; font-weight: 500; line-height: 1.25rem; overflow-wrap: anywhere; }
.kandev-security-compact-path { overflow: hidden; white-space: nowrap; text-overflow: ellipsis; min-width: 0; max-width: 100%; font-family: monospace; }
.kandev-security-compact-source { margin-left: auto; max-width: 100%; overflow-wrap: anywhere; }
.kandev-security-finding-drawer { position: fixed; inset: 0 0 0 auto; width: min(40rem, 100vw) !important; max-width: none !important; height: 100dvh; display: flex; flex-direction: column; gap: 0; padding: 0; background: var(--background, #fff); color: var(--foreground, #111827); border-left: 1px solid var(--border, #e5e7eb); z-index: 50; }
.kandev-security-finding-drawer * { box-sizing: border-box; }
.kandev-security-drawer-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; padding: 1rem 1.5rem; border-bottom: 1px solid var(--border, #e5e7eb); }
.kandev-security-drawer-header > div { min-width: 0; overflow-wrap: anywhere; }
.kandev-security-drawer-body { padding: 1.5rem; overflow-y: auto; min-height: 0; flex: 1; font-size: .875rem; }
.kandev-security-drawer-message { font-weight: 500; }
.kandev-security-detail-text { white-space: pre-wrap; overflow-wrap: anywhere; line-height: 1.6; }
.kandev-security-drawer-rule-title { font-size: 1rem; font-weight: 600; overflow-wrap: anywhere; }
.kandev-security-drawer-metadata { display: grid; gap: .75rem; font-size: .75rem; padding-block: .75rem; }
.kandev-security-drawer-metadata dt { color: var(--muted-foreground, #6b7280); }
.kandev-security-drawer-metadata dd { margin: .125rem 0 0; overflow-wrap: anywhere; }
.kandev-security-drawer-section { margin: 1.25rem 0; }
.kandev-security-drawer-section h3 { font-size: .875rem; font-weight: 600; }
.kandev-security-drawer-section a { color: var(--primary, #2563eb); text-decoration: underline; overflow-wrap: anywhere; }
.kandev-security-finding-drawer button:focus-visible, .kandev-security-finding-drawer a:focus-visible { outline: 2px solid var(--ring, #6b7280); outline-offset: 2px; }
@media (max-width: 600px) { .kandev-security-overview { padding-inline: 1rem; } .kandev-security-freshness { width: 100%; margin: .25rem 0 0; } .kandev-security-drawer-header, .kandev-security-drawer-body { padding: 1rem; } }
@media (pointer: coarse) { .kandev-security-summary-chip, .kandev-security-finding-drawer button, .kandev-security-finding-drawer a { min-height: 44px; } }

.kandev-security-markdown { line-height: 1.6; overflow-wrap: anywhere; }
.kandev-security-markdown > :first-child { margin-top: 0; }
.kandev-security-markdown > :last-child { margin-bottom: 0; }
.kandev-security-markdown p { margin: .625rem 0; }
.kandev-security-markdown h1, .kandev-security-markdown h2, .kandev-security-markdown h3, .kandev-security-markdown h4, .kandev-security-markdown h5, .kandev-security-markdown h6 { margin: 1rem 0 .5rem; font-size: 1rem; font-weight: 600; line-height: 1.4; }
.kandev-security-markdown h1 { font-size: 1.125rem; }
.kandev-security-markdown ul, .kandev-security-markdown ol { margin: .5rem 0; padding-left: 1.5rem; }
.kandev-security-markdown ul { list-style-type: disc; }
.kandev-security-markdown ol { list-style-type: decimal; }
.kandev-security-markdown li { margin: .25rem 0; }
.kandev-security-markdown blockquote { margin: .75rem 0; padding-left: .875rem; border-left: 3px solid var(--border, #e5e7eb); color: var(--muted-foreground, #6b7280); }
.kandev-security-markdown code { font-family: monospace; background: var(--muted, #f3f4f6); border-radius: .25rem; padding: .125rem .25rem; font-size: .85em; }
.kandev-security-markdown pre { overflow-x: auto; max-width: 100%; padding: .75rem; margin: .75rem 0; border: 1px solid var(--border, #e5e7eb); border-radius: .375rem; background: var(--muted, #f3f4f6); white-space: pre; }
.kandev-security-markdown pre code { padding: 0; background: transparent; font-size: .75rem; }
.kandev-security-markdown strong { font-weight: 600; }
.kandev-security-markdown em { font-style: italic; }
.kandev-security-markdown del { text-decoration: line-through; }
.kandev-security-markdown hr { margin: 1rem 0; border: 0; border-top: 1px solid var(--border, #e5e7eb); }
.kandev-security-markdown-table { max-width: 100%; overflow-x: auto; margin: .75rem 0; }
.kandev-security-markdown table { border-collapse: collapse; width: 100%; font-size: .75rem; }
.kandev-security-markdown th, .kandev-security-markdown td { border: 1px solid var(--border, #e5e7eb); padding: .375rem .5rem; text-align: left; }
.kandev-security-markdown th { font-weight: 600; background: var(--muted, #f3f4f6); }

`;

function makeImportView(host, model) {
  const h = host.jsx;
  const { Button, Input } = host.ui;
  return function ImportView({ state, t }) {
    return h("section", { className: "kandev-security-content space-y-3", "aria-label": t("import") },
      h("h2", { className: "text-lg font-medium" }, t("import")),
      h("label", { htmlFor: "security-import", className: "block font-medium" }, t("sarifFile")),
      h(Input, { id: "security-import", type: "file", accept: ".sarif,.json,application/json,application/sarif+json", className: "min-h-11 w-full", disabled: state.importing,
        onChange: (event) => { const file = event.target.files?.[0]; event.target.value = ""; if (file) model.importFile(file); } }),
      h("p", { className: "text-sm text-muted-foreground" }, t("importHelp")),
      state.importing ? h("div", { className: "flex flex-wrap items-center gap-3" },
        h("progress", { value: state.progress, max: 100, "aria-label": t("import") }),
        h("span", { role: "status" }, t("uploading", { progress: state.progress })),
        h(Button, { variant: "outline", className: "min-h-11", onClick: () => model.cancelImport() }, t("cancel"))) : null);
  };
}

function makeFacetFilter(host, model) {
  const h = host.jsx;
  const { useState, useEffect } = host.React;
  const { Popover, PopoverTrigger, PopoverContent, Input } = host.ui;
  return function FacetFilter({ field, state, t, query = state.aggregateQuery, onChange = (next) => model.aggregate(next) }) {
    const [open, setOpen] = useState(false);
    const [search, setSearch] = useState("");
    const value = query[field];
    const fixedOptions = { severity: ["critical", "high", "medium", "low", "informational"], status: ["open", "closed"] };
    const isFacet = !Object.hasOwn(fixedOptions, field);
    useEffect(() => {
      if (!open || !isFacet) return;
      const timer = setTimeout(() => model.suggest(field, search), 150);
      return () => clearTimeout(timer);
    }, [open, search, state.workspaceId, field]);
    const choose = (next) => {
      onChange({ ...query, [field]: next, offset: 0 });
      setOpen(false);
    };
    const values = isFacet ? state.facets[field] : fixedOptions[field];
    return h(Popover, { open, onOpenChange: (next) => { setOpen(next); if (next) setSearch(""); } },
      h("div", { className: "kandev-security-pill", "data-active": Boolean(value) },
        h(PopoverTrigger, { asChild: true }, h("button", { type: "button", "aria-label": value ? `${t(field)}: ${isFacet ? value : t(value)}` : t(field) },
          h("span", { className: "kandev-security-pill-label" }, t(field)),
          value ? h("span", { className: "kandev-security-pill-value" }, isFacet ? value : t(value)) : null,
          icon(host, "chevron"))),
        value ? h("button", { type: "button", className: "kandev-security-pill-clear", "aria-label": t("clearField", { field: t(field) }), onClick: () => choose("") }, icon(host, "close")) : null),
      h(PopoverContent, { align: "start", className: "kandev-security-filter-popover", "aria-label": t(field) },
        isFacet ? h("div", { className: "kandev-security-facet-search" }, h(Input, { "aria-label": t("searchValues", { field: t(field) }),
          placeholder: t("searchValues", { field: t(field) }), value: search, maxLength: 256, onChange: (event) => setSearch(event.target.value) })) : null,
        h("div", { className: "kandev-security-options", role: "group", "aria-label": t(field) },
          ...["", ...values].map((option) => h("button", { key: option, type: "button", className: "kandev-security-option",
            "aria-pressed": option === value, onClick: () => choose(option) },
            h("span", null, option ? isFacet ? option : t(option) : t("all")), option === value ? icon(host, "check") : null)),
          isFacet && !values.length ? h("p", { className: "kandev-security-filter-hint" }, t("noValues")) : null),
        isFacet && state.facetMore[field] ? h("p", { className: "kandev-security-filter-hint" }, t("moreValues")) : null));
  };
}

function makeAdvisoryView(host, model, tasks) {
  const h = host.jsx, { useState, useEffect } = host.React;
  const { Button, Input, DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem } = host.ui;
  const FacetFilter = makeFacetFilter(host, model), StartTaskMenu = makeStartTaskMenu(host, tasks);
  return function AdvisoryView({ state, t }) {
    const query = state.advisoryQuery, selected = state.selectedAdvisory;
    const [search, setSearch] = useState(query.search);
    const resultsRef = host.React.useRef(null);
    useEffect(() => { setSearch(query.search); }, [query.search]);
    useEffect(() => { resultsRef.current?.scrollTo({ top: 0 }); }, [query, selected, state.advisoryOffset]);
    useEffect(() => {
      if (search === query.search || selected) return;
      const timer = setTimeout(() => model.advisories({ ...model.getSnapshot().advisoryQuery, search, offset: 0 }), 300);
      return () => clearTimeout(timer);
    }, [search, query.search, selected]);
    const page = selected ? state.advisoryFindings : state.advisories;
    const loading = selected ? state.advisoryFindingsLoading : state.advisoryLoading;
    const offset = selected ? state.advisoryOffset : query.offset;
    const load = (next) => selected ? model.openAdvisory(selected, next) : model.advisories({ ...query, offset: next });
    return h("section", { className: "kandev-security-aggregate", "aria-label": t("advisoryView") },
      selected ? h("header", { className: "kandev-security-advisory-header" },
        h(Button, { variant: "outline", size: "sm", onClick: () => model.backAdvisories() }, t("backAdvisories")),
        h("h2", null, selected.id), h("span", null, selected.namespace),
        h("p", { className: "kandev-security-detail-text" }, selected.title),
        h("p", null, t("advisoryMembersHelp"))) : h(host.React.Fragment, null,
        h("form", { className: "kandev-security-toolbar", role: "search", onSubmit: (event) => { event.preventDefault(); model.advisories({ ...query, search, offset: 0 }); } },
          h("div", { className: "kandev-security-search" }, icon(host, "search"), h(Input, { "aria-label": t("searchAdvisories"), placeholder: t("searchAdvisories"), value: search, maxLength: 256, onChange: (event) => setSearch(event.target.value) })),
          h("div", { className: "kandev-security-toolbar-actions" },
            h("span", { role: "status", className: "kandev-security-count" }, loading ? t("loading") : page ? t("advisoryTotals", { count: page.total, findings: page.finding_count }) : ""),
            h(DropdownMenu, null,
              h(DropdownMenuTrigger, { asChild: true }, h(Button, { variant: "ghost", className: "kandev-security-sort text-xs", "aria-label": t("sort") }, `${t("sort")}: ${t(query.sort)}`)),
              h(DropdownMenuContent, { align: "end", className: "kandev-security-sort-menu", "aria-label": t("sort") },
                ...["severity", "newest", "oldest", "recently_updated", "least_recently_updated"].map((sort) => h(DropdownMenuItem, { key: sort, role: "menuitemradio", "aria-checked": query.sort === sort, onSelect: () => model.advisories({ ...query, sort, offset: 0 }) }, t(sort))))),
            h(Button, { variant: "ghost", size: "icon", "aria-label": t("refresh"), disabled: loading, onClick: () => model.advisories() }, icon(host, "refresh")))),
        h("div", { className: "kandev-security-filter-bar" },
          ...["tool", "severity"].map((field) => h(FacetFilter, { key: field, field, state, query, onChange: (next) => model.advisories(next), t })),
          query.tool || query.severity || query.search || search ? h(Button, { variant: "ghost", size: "sm", onClick: () => { setSearch(""); model.advisories({ ...emptyAggregateQuery(), sort: query.sort }); } }, t("clearFilters")) : null)),
      h("div", { className: "kandev-security-results-scroll", ref: resultsRef, "aria-busy": loading },
        page?.items.length ? h("ol", { className: "kandev-security-results", "aria-label": t(selected ? "advisoryMembers" : "advisories") },
          ...page.items.map((item) => selected ? renderAggregateRow(host, model, { ...item, title: "" }, t, StartTaskMenu)
            : h("li", { key: item.key, className: "kandev-security-result-row" },
              h("button", { type: "button", className: "kandev-security-finding-link", "aria-label": t("openAdvisory", { id: item.id }), onClick: () => model.openAdvisory(item) },
                h("span", { className: "kandev-security-result-meta" }, h("span", { className: "kandev-security-severity", "data-severity": item.severity }, t(item.severity)), h("strong", null, item.id), h("span", null, item.namespace)),
                h("span", { className: "kandev-security-compact-message" }, item.title),
                h("span", { className: "kandev-security-result-meta" }, t("advisoryCounts", { findings: item.occurrence_count, issues: item.issue_count, reports: item.report_count, scanners: item.scanner_count }))))))
          : !loading && page ? h("p", { className: "kandev-security-empty" }, t(selected ? "noFindings" : "noAdvisories")) : null,
        loading ? h("p", { role: "status", className: "kandev-security-empty" }, t("loading")) : null,
        state.error ? h(Button, { variant: "outline", onClick: () => load(offset) }, t("retry")) : null,
        h("p", { className: "kandev-security-aggregate-help" }, t("advisoryHelp"))),
      h("nav", { className: "kandev-security-pagination", "aria-label": t("pagination") },
        h("span", { className: "kandev-security-page-range" }, page ? t("findingRange", { start: page.total ? offset + 1 : 0, end: offset + page.items.length, total: page.total }) : ""),
        h("div", { className: "kandev-security-page-controls" },
          h(Button, { variant: "ghost", size: "sm", disabled: loading || !offset, onClick: () => load(Math.max(0, offset - 25)) }, t("previous")),
          h("span", null, t("pageNumber", { page: Math.floor(offset / 25) + 1 })),
          h(Button, { variant: "ghost", size: "sm", disabled: loading || !page?.next_offset, onClick: () => load(page.next_offset) }, t("next")))));
  };
}

function makeAggregateView(host, model, tasks) {
  const StartTaskMenu = makeStartTaskMenu(host, tasks);
  const h = host.jsx;
  const { useState, useEffect } = host.React;
  const { Button, Input, DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem } = host.ui;
  const FacetFilter = makeFacetFilter(host, model);
  return function AggregateView({ state, t }) {
    const [search, setSearch] = useState(state.aggregateQuery.search);
    const resultsRef = host.React.useRef(null);
    useEffect(() => { resultsRef.current?.scrollTo({ top: 0 }); }, [state.aggregateQuery]);
    useEffect(() => { setSearch(state.aggregateQuery.search); }, [state.aggregateQuery.search]);
    useEffect(() => {
      if (search === state.aggregateQuery.search) return;
      const timer = setTimeout(() => model.aggregate({ ...model.getSnapshot().aggregateQuery, search, offset: 0 }), 300);
      return () => clearTimeout(timer);
    }, [search, state.aggregateQuery.search]);
    const page = state.aggregate;
    const active = ["language", "tool", "rule", "severity", "status", "search"].some((key) => state.aggregateQuery[key]) || search;
    return h("section", { className: "kandev-security-aggregate", "aria-label": t("aggregateTitle") },
      h("form", { className: "kandev-security-toolbar", role: "search", onSubmit: (event) => {
        event.preventDefault(); model.aggregate({ ...state.aggregateQuery, search, offset: 0 });
      } },
        h("div", { className: "kandev-security-search" }, icon(host, "search"), h(Input, {
          "aria-label": t("search"), placeholder: t("searchHelp"), maxLength: 256, value: search,
          onChange: (event) => setSearch(event.target.value) })),
        h("div", { className: "kandev-security-toolbar-actions" },
          h("span", { role: "status", className: "kandev-security-count" }, state.aggregateLoading ? t("loadingFindings") : page ? t(state.grouped ? page.total === 1 ? "issueCountOne" : "issueCount" : page.total === 1 ? "occurrenceCountOne" : "occurrencesCount", { count: page.total }) : ""),
          h(DropdownMenu, null,
            h(DropdownMenuTrigger, { asChild: true }, h(Button, { type: "button", variant: "ghost", className: "kandev-security-sort cursor-pointer text-xs gap-1.5", "aria-label": t("sort") },
              icon(host, "sort"), `${t("sort")}: ${t(state.aggregateQuery.sort)}`)),
            h(DropdownMenuContent, { align: "end", className: "kandev-security-sort-menu w-40", "aria-label": t("sort") },
              ...["severity", "newest", "oldest", "recently_updated", "least_recently_updated"].map((value) => h(DropdownMenuItem, {
                key: value, role: "menuitemradio", "aria-checked": state.aggregateQuery.sort === value, className: "kandev-security-sort-option cursor-pointer",
                onSelect: () => model.aggregate({ ...model.getSnapshot().aggregateQuery, sort: value, offset: 0 }),
              }, h("span", { className: "kandev-security-sort-check" }, state.aggregateQuery.sort === value ? icon(host, "check") : null), t(value))))),
          h(Button, { type: "button", variant: "ghost", size: "icon", className: "kandev-security-refresh", "aria-label": t("refresh"), title: t("refresh"), disabled: state.aggregateLoading, onClick: () => model.aggregate() }, icon(host, "refresh")))),
      h("div", { className: "kandev-security-overview", role: "group", "aria-label": t("severityOverview"), title: t("matchingSeverities") },
        ...["", "critical", "high", "medium", "low", "informational"].map((severity) => {
          const counts = page?.severity_counts;
          const count = counts ? severity ? counts[severity] : Object.values(counts).reduce((sum, n) => sum + n, 0) : null;
          return h("button", { key: severity, type: "button", "aria-pressed": state.aggregateQuery.severity === severity,
            className: "kandev-security-summary-chip", "data-severity": severity, disabled: state.aggregateLoading || count === null,
            onClick: () => model.aggregate({ ...model.getSnapshot().aggregateQuery, severity, offset: 0 }) }, t(severity || "all"), h("span", null, count ?? "–"));
        }),
        h("span", { className: "kandev-security-freshness" }, page?.latest_import_at ? h("time", { dateTime: page.latest_import_at }, `${t("latestImport")}: ${new Date(page.latest_import_at).toLocaleString()}`) : state.aggregateLoading || !page ? "" : t("noImports"))),
      h("div", { className: "kandev-security-filter-bar", role: "group", "aria-label": t("filter") },
        h(Button, { type: "button", variant: "outline", size: "sm", "aria-pressed": state.grouped, onClick: () => model.setGrouped(!state.grouped) }, t(state.grouped ? "groupedIssues" : "rawOccurrences")),
        ...["language", "tool", "rule", "severity", "status"].map((field) => h(FacetFilter, { key: field, field, state, t })),
        active ? h(Button, { type: "button", variant: "ghost", size: "sm", className: "kandev-security-clear", onClick: () => {
          setSearch(""); model.aggregate({ ...emptyFindingQuery(), sort: state.aggregateQuery.sort });
        } }, t("clearFilters")) : null),
      h("div", { className: "kandev-security-results-scroll", ref: resultsRef, "aria-busy": state.aggregateLoading },
        page ? h(host.React.Fragment, null,
          page.items.length === 0 ? h("p", { className: "kandev-security-empty" }, t("noFindings")) : h("ol", { className: "kandev-security-results", "aria-label": t("allFindings") },
            ...page.items.map((finding) => renderAggregateRow(host, model, finding, t, StartTaskMenu))),
          h("p", { className: "kandev-security-aggregate-help" }, t("aggregateHelp"))) : null),
      renderResultPagination(host, { t, label: t("pagination"), loading: state.aggregateLoading, loadingLabel: t("loadingFindings"), offset: state.aggregateQuery.offset, total: page?.total, count: page?.items.length || 0, next: page?.next_offset, load: (offset) => model.aggregate({ ...model.getSnapshot().aggregateQuery, offset }) }));
  };
}

// Shorten absolute paths for scanning; the drawer always retains the exact URI.
export function compactLocation(uri) {
  if (!uri) return "";
  let path = uri;
  try { const url = new URL(uri); if (url.protocol === "file:") path = decodeURIComponent(url.pathname); } catch {}
  path = path.replace(/\\/g, "/");
  if (path.startsWith("/") || /^[A-Za-z]:\//.test(path)) {
    const parts = path.split("/").filter(Boolean);
    return parts.length > 2 ? `…/${parts.slice(-2).join("/")}` : path;
  }
  return path;
}
export function safeAdvisoryURL(value) {
  if (!value || /[\u0000-\u0020\u007f]/.test(value)) return null;
  try {
    const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol) && !url.username && !url.password ? url.href : null;
  } catch { return null; }
}

// Render the backend's Markdown document through an explicit element allowlist.
// No HTML strings, imported attributes, images, or executable content are used.
export function renderMarkdownDocument(host, nodes) {
  const h = host.jsx;
  const tags = new Set(["p", "span", "h1", "h2", "h3", "h4", "h5", "h6", "strong", "em", "del", "code", "ul", "ol", "li", "blockquote", "thead", "tbody", "tr", "th", "td"]);
  let remaining = 4096;
  const render = (node, index, depth = 0) => {
    if (!node || depth > 34 || --remaining < 0) return null;
    if (node.kind === "text") return typeof node.text === "string" ? node.text : "";
    const children = typeof node.text === "string" ? [node.text] : (Array.isArray(node.children) ? node.children.map((child, i) => render(child, i, depth + 1)) : []);
    const props = { key: index };
    if (node.kind === "br" || node.kind === "hr") return h(node.kind, props);
    if (node.kind === "pre") return h("pre", props, h("code", null, ...children));
    if (node.kind === "table") return h("div", { ...props, className: "kandev-security-markdown-table", tabIndex: 0 }, h("table", null, ...children));
    if (node.kind === "a") {
      const url = safeAdvisoryURL(node.url);
      return url ? h("a", { ...props, href: url, target: "_blank", rel: "noopener noreferrer" }, ...children) : h("span", props, ...children);
    }
    if (!tags.has(node.kind)) return h(host.React.Fragment, props, ...children);
    if (node.kind === "ol" && Number.isInteger(node.start) && node.start >= 0) props.start = node.start;
    if (["td", "th"].includes(node.kind) && ["left", "center", "right"].includes(node.align)) props.style = { textAlign: node.align };
    return h(node.kind, props, ...children);
  };
  return h("div", { className: "kandev-security-markdown" }, ...nodes.map((node, index) => render(node, index)));
}

function makeIssueHistory(host, model) {
  const h = host.jsx;
  const { Button, Input } = host.ui;
  return function IssueHistory({ state, t }) {
    const [reason, setReason] = host.React.useState("");
    const d = state.issueDetail, issue = d?.issue;
    host.React.useEffect(() => { setReason(""); }, [issue?.id, issue?.status]);
    if (!issue && !state.issueLoading && !state.issueError) return null;
    return h("section", { className: "kandev-security-drawer-section", "aria-label": t("issueHistory") },
      h("h3", null, t("issueHistory")),
      state.issueLoading ? h("p", { role: "status" }, "Loading issue history…") : null,
      state.issueError ? h("p", { role: "alert" }, state.issueError) : null,
      issue ? h(host.React.Fragment, null,
        h("p", null, `${t("issueStatus")}: ${t(issue.status)}`),
        issue.status_reason ? h("p", { className: "kandev-security-detail-text" }, `${t("reviewReason")}: ${issue.status_reason}`) : null,
        h("p", { className: "kandev-security-detail-text" }, issue.identity_reason),
        h("dl", { className: "kandev-security-drawer-metadata" },
          h("div", null, h("dt", null, t("identityMethod")), h("dd", null, `${issue.identity_method} · v${issue.identity_version}`)),
          h("div", null, h("dt", null, t("identityScope")), h("dd", null, issue.identity_scope)),
          h("div", null, h("dt", null, t("firstSeen")), h("dd", null, new Date(issue.first_seen_at).toLocaleString())),
          h("div", null, h("dt", null, t("lastSeen")), h("dd", null, new Date(issue.last_seen_at).toLocaleString()))),
        h("p", null, t(d.total === 1 ? "occurrenceCountOne" : "occurrencesCount", { count: d.total })),
        h("ul", null, ...d.occurrences.map((o) => h("li", { key: `${o.report_id}:${o.ordinal}` },
          o.purged_at ? h("span", { className: "kandev-security-detail-text" }, `${o.report_name} · #${o.ordinal + 1} · ${t("sourcePurged")} · ${new Date(o.purged_at).toLocaleString()} · ${o.purge_reason}`)
            : h(Button, { variant: "link", onClick: () => model.openFinding(o) }, `${o.report_name} · #${o.ordinal + 1} · ${new Date(o.updated_at).toLocaleString()}${o.archived_at ? ` · ${t("archived")}` : ""}`)))),
        d.next_offset ? h(Button, { variant: "outline", disabled: state.issueLoading, onClick: () => model.loadIssue(issue.id, d.next_offset) }, t("moreOccurrences")) : null,
        h("p", null, t("manualStatusHelp")),
        h("form", { onSubmit: (event) => { event.preventDefault(); if (reason.trim()) model.setIssueStatus(issue.status === "open" ? "closed" : "open", reason); } },
          h(Input, { "aria-label": t("statusReason"), placeholder: t("statusReason"), value: reason, maxLength: 500, required: true, disabled: state.issueBusy, onChange: (event) => setReason(event.target.value) }),
          h(Button, { type: "submit", variant: "outline", disabled: state.issueBusy || !reason.trim() }, t(issue.status === "open" ? "closeIssue" : "reopenIssue"))),
        d.history.length ? h(host.React.Fragment, null, h("h4", null, t("statusHistory")), h("ul", null, ...d.history.map((change) => h("li", { key: change.id, className: "kandev-security-detail-text" }, `${t(change.kind === "reason_updated" ? "reasonUpdated" : change.new_status)} · ${change.actor} · ${new Date(change.created_at).toLocaleString()} · ${change.reason}`, change.task_id ? h("p", { className: "kandev-security-detail-text" }, t("agentReviewSource", { task: change.task_id, session: change.session_id })) : null)))) : null,
        d.history_next_offset ? h(Button, { variant: "outline", disabled: state.issueLoading, onClick: () => model.loadIssue(issue.id, 0, d.history_next_offset) }, t("moreStatusHistory")) : null) : null);
  };
}

function makeFindingDrawer(host, model, tasks) {
  const StartTaskMenu = makeStartTaskMenu(host, tasks);
  const h = host.jsx;
  const IssueHistory = makeIssueHistory(host, model);
  const { Sheet, SheetContent, SheetTitle, SheetDescription, Button } = host.ui;
  return function FindingDrawer({ state, t }) {
    const trigger = host.React.useRef(null);
    const detail = state.findingDetail;
    const finding = detail?.finding || state.selectedFinding;
    const urls = [...new Set([detail?.finding.help_uri, ...(detail?.references || []).map((ref) => ref.uri), ...(detail?.classifications || []).map((item) => item.help_uri), ...(detail?.guidance?.match(/https?:\/\/[^\s<>"\]\)]+/g) || [])]
      .map(safeAdvisoryURL).filter(Boolean))].slice(0, 8);
    const section = (title, text, markup) => text || markup?.length ? h("section", { className: "kandev-security-drawer-section" }, h("h3", null, title), markup?.length ? renderMarkdownDocument(host, markup) : h("p", { className: "kandev-security-detail-text" }, text)) : null;
    const meta = (label, value) => value ? h("div", { key: label }, h("dt", null, label), h("dd", null, value)) : null;
    return h(Sheet, { open: Boolean(state.selectedFinding), onOpenChange: (open) => { if (!open) model.closeFinding(); } },
      h(SheetContent, { side: "right", showCloseButton: false, className: "kandev-security-finding-drawer",
        onOpenAutoFocus: () => { trigger.current = document.activeElement; },
        onCloseAutoFocus: (event) => { event.preventDefault(); if (trigger.current?.isConnected) trigger.current.focus(); else [...document.querySelectorAll("button")].find((button) => button.getAttribute("aria-label") === t("viewMenu"))?.focus(); } },
        h("header", { className: "kandev-security-drawer-header" },
          h("div", null, h(SheetTitle, null, finding?.rule_id || t("findingDetails")),
            h(SheetDescription, null, finding ? `${finding.tool} · ${detail?.report.filename || finding.report_name || ""}` : t("findingDetails"))),
          h(Button, { variant: "ghost", size: "icon", "aria-label": t("closeFinding"), onClick: () => model.closeFinding() }, icon(host, "close"))),
        h("div", { className: "kandev-security-drawer-body", "aria-busy": state.findingLoading },
          finding ? h(host.React.Fragment, null,
            h("span", { className: "kandev-security-severity", "data-severity": finding.severity }, t(finding.severity)),
            h("p", { className: "kandev-security-detail-text kandev-security-drawer-message" }, finding.message)) : null,
          state.findingLoading ? h("p", { role: "status" }, t("loadingFinding")) : null,
          state.findingError ? h("div", null, h("p", { role: "alert" }, state.findingError), h(Button, { variant: "outline", onClick: () => model.openFinding(state.selectedFinding) }, t("retry"))) : null,
          finding ? h(StartTaskMenu, { finding: { ...finding, report_id: detail?.report.id || state.selectedFinding?.report_id }, t, drawer: true }) : null,
          h(IssueHistory, { state, t }),
          detail ? h(host.React.Fragment, null,
            detail.report.archived_at ? h("p", { role: "note" }, t("archiveNotice")) : null,
            detail.title ? h("h2", { className: "kandev-security-drawer-rule-title" }, detail.title) : null,
            h("dl", { className: "kandev-security-drawer-metadata" },
              meta(t("location"), finding.uri ? `${finding.uri}${finding.line ? `:${finding.line}${finding.column ? `:${finding.column}` : ""}` : ""}` : t("noLocation")),
              meta(t("scanner"), `${finding.tool} ${detail.run.version || ""}`),
              meta(t("securitySeverity"), finding.security_severity > 0 ? String(finding.security_severity) : null),
              meta(t("confidence"), finding.confidence ? t(finding.confidence) : null),
              meta(t("severitySource"), finding.severity_source ? t(({ "sarif.default": "severityDefault", "result.level": "severityResultLevel", "rule.defaultConfiguration.level": "severityRuleLevel", "rule.properties.security-severity": "severityRuleScore", "agent.severity": "severityAgent" })[finding.severity_source] || "unknown") : null),
              meta(t("resultKind"), finding.kind),
              meta(t("priorityRank"), finding.rank != null ? String(finding.rank) : null),
              meta(t("level"), t(finding.level)), meta(t("language"), finding.language === "Unknown" ? null : finding.language),
              meta(t("repository"), detail.run.repository), meta(t("revision"), detail.run.revision),
              meta(t("imported"), new Date(detail.report.created_at).toLocaleString()), meta(t("updated"), new Date(detail.report.updated_at).toLocaleString())),
            finding.origin === "llm" ? h("p", { className: "text-sm text-muted-foreground" }, t("llmNotice")) : null,
            section(t("description"), detail.description, detail.markup?.description),
            renderCommonFindingDetails(host, detail, t),
            !detail.evidence?.length ? section(t("evidence"), detail.agent_finding?.finding.evidence) : null,
            section(t("guidance"), detail.guidance || (!detail.fixes.length ? t("noGuidance") : ""), detail.markup?.guidance),
            detail.fixes.length ? h("section", { className: "kandev-security-drawer-section" }, h("h3", null, t("suggestedFixes")),
              h("ul", null, ...detail.fixes.map((text, index) => h("li", { key: index }, detail.markup?.fixes?.[index]?.length ? renderMarkdownDocument(host, detail.markup.fixes[index]) : h("span", { className: "kandev-security-detail-text" }, text))))) : null,
            urls.length ? h("section", { className: "kandev-security-drawer-section" }, h("h3", null, t("advisoryLinks")),
              h("ul", null, ...urls.map((url) => h("li", { key: url }, h("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, url))))) : null,
            detail.run.agent_audit ? renderAgentAudit(host, detail.run.agent_audit, t, true) : null,
            detail.truncated ? h("p", null, t("truncatedDetail")) : null,
            h(Button, { variant: "outline", onClick: () => model.open(detail.report.id) }, t("openReport", { filename: detail.report.filename }))) : null)));
  };
}

function renderCommonFindingDetails(host, detail, t) {
  const h = host.jsx, context = detail.context || {};
  const section = (label, children) => h("section", { className: "kandev-security-drawer-section" }, h("h3", null, label), children);
  const text = (value) => h("p", { className: "kandev-security-detail-text" }, value);
  const code = (value) => value ? h("pre", { className: "kandev-security-evidence-code" }, value) : null;
  const locationText = (location) => `${location.resolved_uri || location.uri || t("noLocation")}${location.line ? `:${location.line}${location.column ? `:${location.column}` : ""}` : ""}`;
  const locations = (label, items) => items?.length ? section(label, h("ul", null, ...items.map((location, index) => h("li", { key: index },
    text(locationText(location)), location.message ? text(location.message) : null,
    location.logical_names?.length ? text(location.logical_names.join(" · ")) : null, code(location.snippet))))) : null;
  const http = (label, value, response = false) => value ? h("details", null, h("summary", null, label),
    text(response ? `${value.status_code || ""} ${value.reason || ""}${value.no_response_received ? ` · ${t("noHTTPResponse")}` : ""}`.trim() : `${value.method || ""} ${value.target || ""}`.trim()),
    value.headers ? code(Object.entries(value.headers).map(([key, content]) => `${key}: ${content}`).join("\n")) : null, code(value.body)) : null;
  return h(host.React.Fragment, null,
    context.analysis_target || context.automation_id || context.first_detected_at || context.last_detected_at || context.baseline_state || context.repositories?.length || context.invocations?.length
      ? section(t("analysisContext"), h(host.React.Fragment, null,
        context.analysis_target ? text(`${t("analysisTarget")}: ${locationText(context.analysis_target)}`) : null,
        context.automation_id ? text(`${t("automationID")}: ${context.automation_id}`) : null,
        context.first_detected_at ? text(`${t("firstDetected")}: ${context.first_detected_at}`) : null,
        context.last_detected_at ? text(`${t("lastDetected")}: ${context.last_detected_at}`) : null,
        context.baseline_state ? text(`${t("reportedBaseline")}: ${context.baseline_state}`) : null,
        ...(context.repositories || []).map((repo, index) => h("p", { key: `repo-${index}`, className: "kandev-security-detail-text" }, [repo.uri, repo.revision, repo.branch].filter(Boolean).join(" · "))),
        ...(context.invocations || []).map((invocation, index) => h("p", { key: `scan-${index}`, className: "kandev-security-detail-text" },
          `${t("scanInvocation")}: ${invocation.started_at || t("unknown")} → ${invocation.ended_at || t("unknown")}${invocation.execution_successful != null ? ` · ${t(invocation.execution_successful ? "scannerSucceeded" : "scannerFailed")}` : ""}`)))) : null,
    locations(t("sourceLocations"), detail.locations), locations(t("relatedLocations"), detail.related_locations),
    detail.evidence?.length ? section(t("evidence"), h("ul", null, ...detail.evidence.map((item, index) => h("li", { key: index }, item.artifact ? text(locationText(item.artifact)) : null, item.text ? text(item.text) : null)))) : null,
    detail.http ? section(t("httpEvidence"), h(host.React.Fragment, null, http(t("httpRequest"), detail.http.request), http(t("httpResponse"), detail.http.response, true))) : null,
    detail.classifications?.length ? section(t("classifications"), h("ul", null, ...detail.classifications.map((item, index) => h("li", { key: index },
      text([item.taxonomy, item.id, item.name].filter(Boolean).join(" · ")), item.description ? text(item.description) : null)))) : null,
    detail.normalization_notes?.length ? section(t("importNotes"), h("ul", null, ...detail.normalization_notes.map((note, index) => h("li", { key: index }, note)))) : null);
}

// Report provenance and coverage are text; agent-supplied HTML is never inserted.
export function renderAgentAudit(host, audit, t, compact = false) {
  const h = host.jsx;
  const section = (label, text) => text ? h("section", null, h("h4", null, label), h("p", { className: "kandev-security-detail-text" }, text)) : null;
  return h("section", { className: "kandev-security-drawer-section", "aria-label": t("agentReport") },
    h("h3", null, t("agentReport")),
    !compact ? h("p", null, t("llmNotice")) : null,
    !compact ? section(t("auditTitle"), audit.spec.title) : null,
    !compact ? section(t("auditTask"), audit.task_id) : null,
    !compact ? section(t("agentLabel"), audit.spec.agent_label) : null,
    !compact ? section(t("auditInstructions"), audit.spec.instructions) : null,
    !compact ? h("section", null, h("h4", null, t("declaredScope")), h("ul", null, ...audit.spec.scope.map((scope, index) => h("li", { key: index }, scope)))) : null,
    section(t("auditSummary"), audit.completion.summary),
    section(t("reportedCoverage"), audit.completion.coverage),
    h("section", null, h("h4", null, t("auditLimitations")), audit.completion.limitations.length
      ? h("ul", null, ...audit.completion.limitations.map((limitation, index) => h("li", { key: index }, limitation)))
      : h("p", null, t("noLimitationsDeclared"))));
}

function renderAggregateRow(host, model, finding, t, StartTaskMenu) {
  const h = host.jsx;
  return h("li", { key: `${finding.report_id}:${finding.ordinal}`, className: "kandev-security-result-row kandev-security-compact-row" },
    h("button", { type: "button", className: "kandev-security-finding-link", "aria-label": t("viewFinding", { rule: finding.rule_id || t("unknown") }), onClick: () => model.openFinding(finding) },
      h("span", { className: "kandev-security-result-meta" },
        h("span", { className: "kandev-security-severity", "data-severity": finding.severity }, t(finding.severity)),
        h("span", { className: "font-mono" }, finding.rule_id), h("span", null, finding.tool),
        finding.origin === "llm" ? h("span", null, t("agentReported")) : null,
        finding.language !== "Unknown" ? h("span", null, finding.language) : null),
      h("span", { className: "kandev-security-compact-message" }, finding.title && finding.title !== finding.rule_id ? finding.title : finding.message),
      h("span", { className: "kandev-security-result-meta" },
        h("span", { className: "kandev-security-compact-path", title: finding.uri }, finding.uri ? `${compactLocation(finding.uri)}${finding.line ? `:${finding.line}` : ""}` : t("noLocation")),
        h("span", { className: "kandev-security-compact-source" }, finding.occurrence_count ? `${t(finding.occurrence_count === 1 ? "occurrenceCountOne" : "occurrencesCount", { count: finding.occurrence_count })} · ${t(finding.issue.status)}` : finding.report_name))),
    h(StartTaskMenu, { finding, t }));
}

function makeTokensView(host, model) {
  const h = host.jsx;
  const { useState } = host.React;
  const { Button, Input } = host.ui;
  return function TokensView({ state, t }) {
    const [name, setName] = useState("");
    const [confirmId, setConfirmId] = useState(null);
    const created = state.createdToken;
    return h("section", { className: "kandev-security-content space-y-4", "aria-label": t("tokens") },
      h("h2", { className: "text-lg font-medium" }, t("tokens")),
      h("p", { className: "text-sm text-muted-foreground" }, t("tokenHelp")),
      h("form", { className: "flex flex-col gap-2 sm:flex-row", onSubmit: (event) => { event.preventDefault(); model.createToken(name); } },
        h(Input, { "aria-label": t("tokenName"), placeholder: t("tokenName"), maxLength: 80, value: name,
          className: "min-h-11 min-w-0 flex-1", onChange: (event) => setName(event.target.value) }),
        h(Button, { type: "submit", className: "min-h-11", disabled: state.tokenBusy || !name.trim() }, t("createToken"))),
      created ? h("div", { className: "space-y-3 rounded border p-4", role: "group", "aria-label": t("newToken") },
        h("p", { role: "status" }, t("tokenOnce")),
        h(Input, { "aria-label": t("newToken"), readOnly: true, value: created.secret, autoComplete: "off", spellCheck: false,
          className: "min-h-11 w-full font-mono", onFocus: (event) => event.target.select() }),
        h(Button, { variant: "outline", className: "min-h-11", onClick: () => model.dismissToken() }, t("savedToken"))) : null,
      h(Button, { variant: "outline", className: "min-h-11", disabled: state.tokenLoading, onClick: () => model.listTokens() }, t("refresh")),
      state.tokenLoading ? h("p", { role: "status" }, t("loadingTokens")) : null,
      !state.tokenLoading && state.tokens.length === 0 ? h("p", null, t("noTokens")) : null,
      h("ul", { className: "space-y-3" }, ...state.tokens.map((token) => h("li", { key: token.id, className: "space-y-2 rounded-lg border p-4" },
        h("p", { className: "break-words font-medium" }, token.name),
        h("p", { className: "text-sm text-muted-foreground" }, token.revoked_at ? t("revoked") : t("active")),
        h("p", { className: "break-words text-sm" }, `${t("tokenIssuer")}: ${token.actor_id}`),
        h("p", { className: "text-sm" }, `${t("lastUsed")}: ${token.last_used_at ? new Date(token.last_used_at).toLocaleString() : t("never")}`),
        !token.revoked_at && confirmId !== token.id ? h(Button, { variant: "destructive", className: "min-h-11", disabled: state.tokenBusy,
          onClick: () => setConfirmId(token.id) }, t("revokeToken")) : null,
        confirmId === token.id && !token.revoked_at ? h("div", { className: "space-y-2" },
          h("p", null, t("revokeQuestion")),
          h(Button, { variant: "destructive", className: "min-h-11", disabled: state.tokenBusy, onClick: async () => { await model.revokeToken(token.id); setConfirmId(null); } }, t("confirmRevoke")),
          h(Button, { variant: "outline", className: "min-h-11", disabled: state.tokenBusy, onClick: () => setConfirmId(null) }, t("cancel"))) : null))),
      h("nav", { "aria-label": t("tokens"), className: "flex gap-2" },
        h(Button, { variant: "outline", className: "min-h-11", disabled: state.tokenLoading || !state.tokenOffset, onClick: () => model.listTokens(Math.max(0, state.tokenOffset - 25)) }, t("previous")),
        h(Button, { variant: "outline", className: "min-h-11", disabled: state.tokenLoading || !state.tokensNextOffset, onClick: () => model.listTokens(state.tokensNextOffset) }, t("next"))));
  };
}

function makeChatToolbarAction(host) {
  const h = host.jsx;
  return function ChatToolbarAction({ slotProps } = {}) {
    const label = host.i18n?.useTranslation().t("openSecurityPage", { defaultValue: english.openSecurityPage }) || english.openSecurityPage;
    const context = slotProps?.taskTitle || slotProps?.taskId;
    const tooltip = context ? `${label} (task: ${context})` : label;
    if (typeof host.ui.Action === "function") return h(host.ui.Action, { id: "security-chat-action", label,
      tooltip, icon: h("span", { "aria-hidden": true }, "◇"), onClick: () => host.navigate("/security") });
    return h(host.ui.Tooltip, null, h(host.ui.TooltipTrigger, { asChild: true }, h(host.ui.Button,
      { id: "security-chat-action", variant: "ghost", size: "icon", "aria-label": tooltip, onClick: () => host.navigate("/security") }, "◇")), h(host.ui.TooltipContent, null, tooltip));
  };
}

let model;
let taskModel;
let unsubscribe;
if (typeof window !== "undefined" && window.registerKandevPlugin) window.registerKandevPlugin("kandev-security", {
  initialize(registry, host) {
    registry.registerTranslations?.({ en: english });
    model = createReportsModel(host.api);
    taskModel = createTaskLaunchModel(host.api);
    const TaskPresetSettings = makeTaskPresetsSettings(host), RetentionSettings = makeRetentionSettings(host);
    registry.registerIntegrationSettings?.({ id: "kandev-security", label: "Kandev Security", description: "Workspace task presets and report retention", icon: makeSecurityIcon(host), Component: (props) => host.jsx(host.React.Fragment, null, host.jsx(TaskPresetSettings, props), host.jsx(RetentionSettings, props)) });
    registry.registerNavItem({ id: "security", label: "Security", path: "/security", icon: makeSecurityIcon(host), section: "main" });
    registry.registerRoute("/security", makePage(host, model, taskModel), { topbar: { title: "Kandev Security", subtitle: "Workspace security reports", actions: makeNavigationMenu(host, model) } });
    registry.registerRoute("/security/advisories", makePage(host, model, taskModel, true), { topbar: { title: "Kandev Security", subtitle: "Security advisories", actions: makeNavigationMenu(host, model) } });
    registry.registerComponent("chat-input-actions", makeChatToolbarAction(host));
    if (host.context) {
      unsubscribe = host.context.subscribeActiveWorkspace((workspaceId) => { model.setWorkspace(workspaceId); taskModel.setWorkspace(workspaceId); });
      model.setWorkspace(host.context.getActiveWorkspaceId());
      taskModel.setWorkspace(host.context.getActiveWorkspaceId());
    }
  },
  destroy() { unsubscribe?.(); unsubscribe = undefined; model?.destroy(); taskModel?.destroy(); model = undefined; taskModel = undefined; },
});
