// ══════════════════════════════════════════════════════════
// 🧭 报告 Agent 工作台
// ══════════════════════════════════════════════════════════
let agentProjects = [];
let agentCurrentProject = null;
let agentEvidence = [];
let agentEvidenceMeta = null;
let agentDrafts = [];
let agentSelectedEvidence = new Set();
let agentActiveDraft = null;
let agentNewspaper = null;
let agentLoading = false;
let agentMvpRunning = false;
let agentMvpPreflightState = null;
let agentMvpRunState = null;
const AGENT_LAST_PROJECT_KEY = 'agentLastProjectId';
const AGENT_MVP_MIN_SOURCES = 7;
const AGENT_VISIBLE_REPORT_TYPES = new Set(['institution_pack', 'strategic']);

function agentSetLoading(on, msg) {
  agentLoading = !!on;
  const preview = document.getElementById('agentPreview');
  if (preview) preview.setAttribute('aria-busy', agentLoading ? 'true' : 'false');
  if (preview && msg) {
    preview.innerHTML = `<div class="agent-loading"><div class="ai-spinner-sm"></div><span>${escHtml(msg)}</span></div>`;
  }
  agentSyncActionButtons();
}

function agentReportTypeLabel(t) {
  return ({
    institution_pack:'机构开源情报整编包（MVP）',
    strategic:'战略分析报告',
    daily:'每日简报',
    weekly:'周报汇编',
    short_topic:'专题短报'
  })[t] || t || '报告';
}

function agentDefaultCount(t) {
  return ({institution_pack:8, strategic:12, daily:5, weekly:8, short_topic:5})[t] || 12;
}

function agentIsVisibleReportType(reportType) {
  return AGENT_VISIBLE_REPORT_TYPES.has(reportType);
}

function agentMvpSourceGate(evidence) {
  const count = Array.isArray(evidence) ? evidence.length : Math.max(0, Number(evidence) || 0);
  return {
    ok: count >= AGENT_MVP_MIN_SOURCES,
    count,
    required: AGENT_MVP_MIN_SOURCES,
    gap: Math.max(0, AGENT_MVP_MIN_SOURCES - count),
  };
}

function agentMvpCollectionTarget(project) {
  const type = project?.report_type || 'strategic';
  const configured = Math.max(1, Number(project?.target_count) || agentDefaultCount(type));
  return type === 'institution_pack' ? Math.max(agentDefaultCount(type), configured) : configured;
}

function agentMvpCollectError(data) {
  if (String(data?.capture?.status || '').toLowerCase() !== 'failed') return '';
  return `自主采集失败：${data.capture.stop_reason || '未知原因'}`;
}

function agentResolveDraftContent(editorValue, draft) {
  return editorValue === undefined || editorValue === null
    ? String(draft?.content || '')
    : String(editorValue);
}

function agentBuildExportPayload(draftId, content, evidenceIds) {
  return {draft_id: draftId, content, evidence_ids: evidenceIds};
}

function agentNormalizePreflight(response) {
  const raw = response?.preflight || response || {};
  const checks = Array.isArray(raw.checks) ? raw.checks.map((check, index) => ({
    id: String(check?.id || check?.name || `check_${index + 1}`),
    ok: check?.ok === true,
    label: String(check?.label || check?.name || check?.id || `检查 ${index + 1}`),
    detail: String(check?.detail || check?.message || '未提供详情'),
  })) : [];
  const ok = raw.ok === true && checks.length > 0 && checks.every(check => check.ok);
  const declaredStatus = String(raw.status || (ok ? 'ready' : 'blocked'));
  const status = !ok && ['ready', 'passed', 'ok'].includes(declaredStatus.toLowerCase())
    ? 'blocked'
    : declaredStatus;
  const failures = checks.filter(check => !check.ok).map(check => `${check.label}：${check.detail}`);
  if (!checks.length) failures.push('预检响应：后端未返回检查项');
  return {
    ok,
    status,
    checks,
    failures,
  };
}

function agentCurrentReportType() {
  return agentCurrentProject?.report_type
    || document.getElementById('agentReportType')?.value
    || 'institution_pack';
}

function agentIsInstitutionPack() {
  return agentCurrentReportType() === 'institution_pack';
}

function agentSyncActionButtons() {
  const busy = agentLoading || agentMvpRunning;
  document.querySelectorAll?.('[data-agent-action], .agent-editor-panel .agent-actions button').forEach(button => {
    button.disabled = busy;
  });
  const runButton = document.getElementById('agentMvpRunBtn');
  if (!runButton) return;
  const enabledForType = agentIsInstitutionPack();
  runButton.hidden = !enabledForType;
  runButton.disabled = busy || !enabledForType;
  runButton.setAttribute('aria-busy', agentMvpRunning ? 'true' : 'false');
  runButton.textContent = agentMvpRunning ? 'MVP 闭环运行中…' : '⚡ 一键跑通 MVP';
}

function agentSyncReportTypeUi(reportType, {syncSelect = false} = {}) {
  const type = reportType || agentCurrentReportType();
  const select = document.getElementById('agentReportType');
  if (syncSelect && select && [...select.options].some(option => option.value === type)) {
    select.value = type;
  }
  const hint = document.getElementById('agentReportTypeHint');
  if (hint) hint.textContent = agentReportTypeLabel(type);
  const createButton = document.getElementById('agentCreateProjectBtn');
  if (createButton) createButton.textContent = `创建${agentReportTypeLabel(type)}`;
  const productionTitle = document.getElementById('agentProductionTitle');
  if (productionTitle) {
    productionTitle.textContent = `${agentReportTypeLabel(agentCurrentProject?.report_type || type)}生产台`;
  }
  agentRenderMvpPreflight();
  agentRenderReviewRadar();
  agentSyncActionButtons();
}

function agentInvalidateMvpPreflight(message = '') {
  agentMvpPreflightState = null;
  if (agentMvpRunning) {
    agentRenderMvpPreflight();
    return;
  }
  if (message && agentIsInstitutionPack()) {
    agentMvpRunState = {status: 'idle', message, steps: []};
  } else {
    agentMvpRunState = null;
  }
  agentRenderMvpPreflight();
}

function agentMvpSetStep(id, label, status, detail = '') {
  const run = agentMvpRunState || {status: 'running', message: '', steps: []};
  const steps = [...(run.steps || [])];
  const index = steps.findIndex(step => step.id === id);
  const next = {id, label, status, detail};
  if (index >= 0) steps[index] = next;
  else steps.push(next);
  agentMvpRunState = {...run, status: run.status === 'failed' ? 'failed' : 'running', steps};
  agentRenderMvpPreflight();
}

function agentMvpStepsHtml(steps) {
  return (steps || []).map(step => `<li class="${escHtml(step.status)}">
    <span aria-hidden="true">${step.status === 'done' ? '✓' : (step.status === 'failed' ? '!' : '…')}</span>
    <div><strong>${escHtml(step.label)}</strong>${step.detail ? `<small>${escHtml(step.detail)}</small>` : ''}</div>
  </li>`).join('');
}

function agentRenderMvpPreflight() {
  const box = document.getElementById('agentMvpPreflight');
  if (!box) return;
  const isMvp = agentIsInstitutionPack();
  box.hidden = !isMvp;
  if (!isMvp) return;
  box.classList.remove('ok', 'warn', 'running');

  if (agentMvpPreflightState) {
    const result = agentMvpPreflightState;
    box.classList.add(result.ok ? 'ok' : 'warn');
    const checks = result.checks.map(check => `<li class="${check.ok ? 'ok' : 'warn'}">
      <span aria-hidden="true">${check.ok ? '✓' : '!'}</span>
      <div><strong>${escHtml(check.label)}</strong><small>${escHtml(check.detail)}</small></div>
    </li>`).join('');
    const steps = agentMvpStepsHtml(agentMvpRunState?.steps);
    box.innerHTML = `<div class="agent-mvp-preflight-head">
        <div><span>后端真实预检</span><strong>${result.ok ? '可交付' : '已阻断'}</strong></div>
        <button type="button" class="agent-secondary-btn" data-agent-action onclick="agentRunPreflight()">重新预检</button>
      </div>
      <p>状态：${escHtml(result.status)}</p>
      <ul class="agent-mvp-checks">${checks || '<li class="warn"><span>!</span><div><strong>预检无检查项</strong><small>后端未返回 checks</small></div></li>'}</ul>
      ${steps ? `<div class="agent-mvp-step-title">闭环步骤</div><ul class="agent-mvp-steps">${steps}</ul>` : ''}`;
    return;
  }

  const run = agentMvpRunState;
  if (run?.status === 'running' || run?.status === 'failed') {
    box.classList.add(run.status === 'running' ? 'running' : 'warn');
    const steps = agentMvpStepsHtml(run.steps);
    box.innerHTML = `<div class="agent-mvp-preflight-head"><div><span>MVP 闭环</span><strong>${run.status === 'failed' ? '已停止' : '运行中'}</strong></div></div>
      ${run.message ? `<p>${escHtml(run.message)}</p>` : ''}
      <ul class="agent-mvp-steps">${steps}</ul>`;
    return;
  }

  box.innerHTML = `<div class="agent-mvp-preflight-head"><div><span>后端真实预检</span><strong>尚未运行</strong></div></div>
    <p>${escHtml(run?.message || '一键闭环完成草稿后将调用后端检查；机构包导出前也会强制复检。')}</p>`;
}

function agentExtractRequestedCount(text) {
  const s = String(text || '');
  const patterns = [
    /(?:搜集|收集|检索|抓取|找|列出)\s*(\d{1,6})\s*(?:份|条|个)?\s*(?:信息源|证据|资料|来源|智库|报告源|报告)?/,
    /(\d{1,6})\s*(?:份|条|个)\s*(?:信息源|证据|资料|来源|智库|报告源|报告)/
  ];
  for (const p of patterns) {
    const m = s.match(p);
    if (m) return Math.max(1, parseInt(m[1], 10));
  }
  return null;
}

function agentCurrentEvidenceIds() {
  const ids = [...agentSelectedEvidence];
  if (ids.length) return ids;
  return agentEvidence.map(e => e.evidence_id);
}

function agentEvidenceStats() {
  const target = parseInt(agentCurrentProject?.target_count || document.getElementById('agentTargetCount')?.value || '0', 10) || 0;
  const selectedRows = agentEvidence.filter(ev => agentSelectedEvidence.has(ev.evidence_id));
  const scores = agentEvidence.map(ev => Number(ev.quality_score || ev.score || 0)).filter(n => n > 0);
  const sourceSeeds = agentEvidenceMeta?.source_seeds ?? agentEvidence.filter(ev => {
    const type = ev.source_type || ev.payload?.source_type || '';
    return type.includes('智库') || type.includes('报告源') || type.includes('政策') || type.includes('条令');
  }).length;
  const sourceTypes = {};
  agentEvidence.forEach(ev => {
    const type = ev.source_type || ev.payload?.source_type || '公开信息';
    sourceTypes[type] = (sourceTypes[type] || 0) + 1;
  });
  return {
    target,
    total: agentEvidence.length,
    selected: selectedRows.length,
    sourceSeeds,
    rssCount: Math.max(0, agentEvidence.length - sourceSeeds),
    highQuality: agentEvidence.filter(ev => ['S', 'A'].includes(String(ev.quality_level || '').toUpperCase()) || Number(ev.quality_score || 0) >= 80).length,
    avgScore: scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0,
    gap: Math.max(0, target - agentEvidence.length),
    selectedGap: Math.max(0, Math.min(target || selectedRows.length, target || selectedRows.length) - selectedRows.length),
    sourceTypes,
  };
}

function agentRenderHandoffChecklist() {
  const box = document.getElementById('agentHandoffChecklist');
  if (!box) return;
  const stats = agentEvidenceStats();
  if (!agentCurrentProject) {
    box.innerHTML = `<div class="agent-handoff-empty">选择或创建项目后，这里显示资料完整度、来源类型和写作交接风险。</div>`;
    return;
  }
  const sourceTypePills = Object.entries(stats.sourceTypes).slice(0, 4)
    .map(([name, count]) => `<span>${escHtml(name)} ${count}</span>`).join('');
  const ready = stats.selected > 0 && stats.gap === 0;
  box.innerHTML = `<div class="agent-handoff-top">
      <strong>报告交接清单</strong>
      <span class="${ready ? 'ok' : 'warn'}">${ready ? '资料就绪' : '待补资料'}</span>
    </div>
    <div class="agent-handoff-metrics">
      <span><b>${stats.selected}/${stats.total}</b><em>已选/总证据</em></span>
      <span><b>${stats.sourceSeeds}</b><em>智库/报告源</em></span>
      <span><b>${stats.avgScore || '-'}</b><em>质量均分</em></span>
    </div>
    <div class="agent-handoff-pills">${sourceTypePills || '<span>暂无来源类型</span>'}</div>
    <div class="agent-handoff-lines">
      <p class="${stats.selected ? 'ok' : ''}">来源编号：${stats.selected ? '可用于生成' : '请先选择证据'}</p>
      <p class="${!stats.gap ? 'ok' : ''}">目标数量：${stats.total}/${stats.target || '-'}${stats.gap ? `，缺 ${stats.gap}` : ''}</p>
      <p class="${stats.highQuality ? 'ok' : ''}">高质量资料：${stats.highQuality} 条</p>
    </div>`;
}

function agentDraftStats() {
  const draftText = document.getElementById('agentDraftText')?.value || agentActiveDraft?.content || '';
  const outlineText = document.getElementById('agentOutlineText')?.value || '';
  const payload = agentActiveDraft?.payload || {};
  const compactText = String(draftText || '').replace(/\s/g, '');
  const roughWords = parseInt(payload.word_count || 0, 10) || compactText.length;
  const target = parseInt(payload.target_word_count || 0, 10) || 0;
  const citationHits = (String(draftText).match(/(\[\d+\]|S\d+|来源|http|《[^》]{2,80}》)/g) || []).length;
  const sections = (String(draftText || outlineText).split(/\n+/).filter(line => /^#{1,3}\s|^第[一二三四五六七八九十0-9]+[章节部分]|^[一二三四五六七八九十0-9]+、/.test(line.trim())).length);
  const selected = agentCurrentEvidenceIds().length;
  const wordOk = target ? !!payload.word_count_ok : roughWords > 0;
  return {
    roughWords,
    target,
    citationHits,
    sections,
    selected,
    hasDraft: !!String(draftText).trim(),
    wordOk,
    exportOk: !!agentCurrentProject && !!agentActiveDraft && !!String(draftText).trim() && wordOk && selected > 0,
  };
}

function agentRenderReviewRadar() {
  const box = document.getElementById('agentReviewRadar');
  if (!box) return;
  const stats = agentDraftStats();
  const mvp = agentIsInstitutionPack();
  const deliveryOk = mvp ? agentMvpPreflightState?.ok === true : stats.exportOk;
  const deliveryText = mvp
    ? (agentMvpPreflightState ? (deliveryOk ? '后端通过' : '后端阻断') : '未预检')
    : (deliveryOk ? '可导出' : '待完善');
  box.innerHTML = `<div class="agent-radar-card ${stats.hasDraft ? 'ok' : ''}">
      <strong>${stats.roughWords || 0}</strong><span>${stats.target ? `目标 ${stats.target}` : '当前字数'}</span>
    </div>
    <div class="agent-radar-card ${stats.citationHits ? 'ok' : 'warn'}">
      <strong>${stats.citationHits}</strong><span>引用线索</span>
    </div>
    <div class="agent-radar-card ${stats.sections >= 3 ? 'ok' : 'warn'}">
      <strong>${stats.sections}</strong><span>章节层级</span>
    </div>
    <div class="agent-radar-card ${deliveryOk ? 'ok' : 'warn'}">
      <strong>${deliveryText}</strong><span>${mvp ? '后端交付预检' : '交付预检'}</span>
    </div>`;
}

function agentRememberProject(projectId) {
  try {
    if (projectId) localStorage.setItem(AGENT_LAST_PROJECT_KEY, projectId);
    else localStorage.removeItem(AGENT_LAST_PROJECT_KEY);
  } catch(e) {}
}

function agentUpdateProjectCounts() {
  const total = agentProjects.length || 0;
  const header = document.getElementById('agentProjectCount');
  const sidebar = document.getElementById('agentProjectSidebarCount');
  if (header) header.textContent = total;
  if (sidebar) sidebar.textContent = `${total}个`;
}

function agentUpsertProjectSummary(project) {
  if (!project?.project_id || !agentIsVisibleReportType(project.report_type)) return;
  agentProjects = [project, ...agentProjects.filter(p => p.project_id !== project.project_id)];
  agentRenderProjects();
}

async function agentLoadProjects() {
  const list = document.getElementById('agentProjectList');
  if (list) list.innerHTML = '<div class="agent-empty">加载项目中…</div>';
  try {
    const resp = await apiFetch('/api/agent/projects', {}, {toast: false});
    const data = await resp.json();
    agentProjects = (data.projects || []).filter(project => agentIsVisibleReportType(project.report_type));
    const remembered = (() => {
      try { return localStorage.getItem(AGENT_LAST_PROJECT_KEY) || ''; } catch(e) { return ''; }
    })();
    if (agentCurrentProject && !agentIsVisibleReportType(agentCurrentProject.report_type)) {
      agentCurrentProject = null;
      agentEvidence = [];
      agentEvidenceMeta = null;
      agentDrafts = [];
      agentSelectedEvidence = new Set();
      agentActiveDraft = null;
    }
    agentUpdateProjectCounts();
    agentRenderProjects();
    const currentId = agentCurrentProject?.project_id || remembered;
    const nextProject = agentProjects.find(p => p.project_id === currentId) || agentProjects[0];
    if (nextProject) {
      await agentOpenProject(nextProject.project_id);
    } else {
      agentRenderEvidence();
      agentRenderDraft();
      agentSyncReportTypeUi('institution_pack', {syncSelect: true});
    }
  } catch(e) {
    if (list) list.innerHTML = `<div class="agent-empty">加载失败：${escHtml(e.message)}</div>`;
  }
}

function agentRenderProjects() {
  const list = document.getElementById('agentProjectList');
  if (!list) return;
  agentUpdateProjectCounts();
  if (!agentProjects.length) {
    list.innerHTML = '<div class="agent-empty">暂无项目</div>';
    return;
  }
  list.innerHTML = agentProjects.map(p => {
    const active = agentCurrentProject?.project_id === p.project_id ? ' active' : '';
    const topic = p.topic ? `<span>${escHtml(p.topic)}</span>` : '';
    const updated = fmtDate(p.updated_at || p.created_at);
    return `<button class="agent-project-item${active}" onclick="agentOpenProject('${escJsArg(p.project_id)}')">
      <span class="agent-project-status">${escHtml(p.status === 'active' ? '进行中' : (p.status || '项目'))}</span>
      <strong>${escHtml(p.title)}</strong>
      <small>${agentReportTypeLabel(p.report_type)} · 目标${p.target_count}条 · ${escHtml(updated)} ${topic}</small>
    </button>`;
  }).join('');
}

function agentNewProjectDraft() {
  agentCurrentProject = null;
  agentEvidence = [];
  agentEvidenceMeta = null;
  agentDrafts = [];
  agentSelectedEvidence = new Set();
  agentActiveDraft = null;
  agentMvpPreflightState = null;
  agentMvpRunState = null;
  agentRememberProject('');
  ['agentRequest', 'agentTopic', 'agentOutlineText', 'agentReviewInput', 'agentDraftText'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  const type = document.getElementById('agentReportType');
  if (type) type.value = 'institution_pack';
  const count = document.getElementById('agentTargetCount');
  if (count) count.value = agentDefaultCount('institution_pack');
  const req = document.getElementById('agentRequest');
  if (req) req.focus();
  agentRenderProjects();
  agentRenderEvidence();
  agentRenderDraft();
  agentSyncReportTypeUi('institution_pack', {syncSelect: true});
}

async function agentCreateProject({quiet = false} = {}) {
  const requestText = document.getElementById('agentRequest')?.value.trim() || '';
  const title = document.getElementById('agentTitle')?.value.trim() || '';
  const topic = document.getElementById('agentTopic')?.value.trim() || '';
  const reportType = document.getElementById('agentReportType')?.value || 'strategic';
  const targetCount = agentExtractRequestedCount(requestText)
    || parseInt(document.getElementById('agentTargetCount').value || agentDefaultCount(reportType), 10);
  if (!requestText && !title) {
    const error = new Error('请输入客户需求，例如：帮我做一个台海军力平衡报告');
    if (quiet) throw error;
    showToast(error.message);
    return null;
  }
  try {
    const resp = await apiFetch('/api/agent/projects', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({request: requestText, title, topic, report_type: reportType, target_count: targetCount})
    }, {toast: false});
    const data = await resp.json();
    agentCurrentProject = data.project;
    agentRememberProject(data.project?.project_id);
    agentUpsertProjectSummary(data.project);
    if (document.getElementById('agentTitle')) document.getElementById('agentTitle').value = '';
    if (document.getElementById('agentRequest')) document.getElementById('agentRequest').value = '';
    agentEvidence = [];
    agentEvidenceMeta = null;
    agentDrafts = [];
    agentSelectedEvidence = new Set();
    agentActiveDraft = null;
    agentMvpPreflightState = null;
    if (!agentMvpRunning) agentMvpRunState = null;
    agentRenderEvidence();
    agentRenderDraft();
    agentSyncReportTypeUi(data.project?.report_type || reportType, {syncSelect: true});
    agentUpdateProjectCounts();
    if (!quiet) showToast('已创建报告项目');
    return data;
  } catch(e) {
    if (quiet) throw e;
    showToast('创建失败：' + e.message);
    return null;
  }
}

async function agentOpenProject(projectId) {
  try {
    const resp = await apiFetch(`/api/agent/projects/${encodeURIComponent(projectId)}`, {}, {toast: false});
    const data = await resp.json();
    agentCurrentProject = data.project;
    agentUpsertProjectSummary(data.project);
    agentEvidence = data.evidence || [];
    agentEvidenceMeta = null;
    agentDrafts = data.drafts || [];
    agentSelectedEvidence = new Set(agentEvidence.map(e => e.evidence_id));
    agentActiveDraft = agentDrafts[0] || null;
    agentNewspaper = data.newspaper || null;
    agentMvpPreflightState = null;
    agentMvpRunState = null;
    agentRememberProject(projectId);
    const requestEl = document.getElementById('agentRequest');
    const topicEl = document.getElementById('agentTopic');
    const countEl = document.getElementById('agentTargetCount');
    const typeEl = document.getElementById('agentReportType');
    if (requestEl) requestEl.value = agentCurrentProject.client_request || '';
    if (topicEl) topicEl.value = agentCurrentProject.topic || '';
    if (countEl) countEl.value = agentCurrentProject.target_count || agentDefaultCount(agentCurrentProject.report_type);
    if (typeEl) typeEl.value = agentCurrentProject.report_type || 'strategic';
    agentRenderProjects();
    agentRenderEvidence();
    agentRenderDraft();
    agentSyncReportTypeUi(agentCurrentProject.report_type, {syncSelect: true});
  } catch(e) {
    showToast('打开项目失败：' + e.message);
  }
}

async function agentCollectEvidence() {
  if (!agentCurrentProject) { showToast('请先创建或选择项目'); return; }
  const minLevel = document.getElementById('agentMinLevel').value || 'A';
  agentSetLoading(true, 'Agent正在检索RSS信息、智库与报告源…');
  try {
    const resp = await apiFetch(`/api/agent/projects/${encodeURIComponent(agentCurrentProject.project_id)}/collect`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        min_level: minLevel,
        limit: agentCurrentProject.target_count || 12,
        source_limit: agentCurrentProject.target_count || 12,
        include_sources: true
      })
    }, {toast: false});
    const data = await resp.json();
    agentCurrentProject = data.project;
    agentEvidence = data.evidence || [];
    agentEvidenceMeta = data.meta || null;
    agentSelectedEvidence = new Set(agentEvidence.map(e => e.evidence_id));
    agentInvalidateMvpPreflight('证据池已更新，请重新运行预检。');
    agentRenderEvidence();
    agentRenderDraft();
    showToast(`已汇总 ${agentEvidence.length} 条信息源/证据`);
    return data;
  } catch(e) {
    showToast('收集失败：' + e.message);
    agentRenderDraft();
    return null;
  } finally {
    agentSetLoading(false);
  }
}

async function agentAutonomousCollect({quiet = false} = {}) {
  if (!agentCurrentProject) {
    const error = new Error('请先创建或选择项目');
    if (quiet) throw error;
    showToast(error.message);
    return null;
  }
  agentSetLoading(true, 'Agent正在自主联网检索并归档公开信源（可能耗时）…');
  try {
    const resp = await apiFetch(`/api/agent/projects/${encodeURIComponent(agentCurrentProject.project_id)}/autonomous_collect`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        target: agentMvpCollectionTarget(agentCurrentProject),
        max_rounds: 6
      })
    }, {toast: false});
    const data = await resp.json();
    agentCurrentProject = data.project || agentCurrentProject;
    agentEvidence = data.evidence || agentEvidence;
    agentSelectedEvidence = new Set(agentEvidence.map(e => e.evidence_id));
    agentInvalidateMvpPreflight('证据池已更新，请重新运行预检。');
    agentRenderEvidence();
    if (!quiet) {
      showToast(data.gap
        ? `自主扩池：新增 ${data.imported_count} 条；${data.gap_note}`
        : `自主扩池完成：新增 ${data.imported_count} 条，已达目标`);
    }
    return data;
  } catch(e) {
    if (quiet) throw e;
    showToast('自主扩池失败：' + e.message);
    return null;
  } finally {
    agentSetLoading(false);
  }
}

function agentToggleEvidence(evidenceId) {
  if (agentSelectedEvidence.has(evidenceId)) agentSelectedEvidence.delete(evidenceId);
  else agentSelectedEvidence.add(evidenceId);
  agentInvalidateMvpPreflight('证据选择已变化，请重新运行预检。');
  agentRenderEvidence();
}

// 5 维打分明细（与 quality.py score_quality_candidate 的 dims 上限对齐）
const AGENT_DIM_META = [
  ['source', '信源', 20],
  ['topic', '选题', 35],
  ['density', '密度', 20],
  ['novelty', '新颖', 15],
  ['writability', '可写', 10],
];

function agentDimsBar(dims) {
  if (!dims || !Object.keys(dims).length) return '';
  const segs = AGENT_DIM_META.map(([k, label, max]) => {
    const v = Number(dims[k] || 0);
    const pct = Math.max(0, Math.min(100, Math.round((v / max) * 100)));
    return `<span class="agent-dim" title="${escHtml(label)} ${v}/${max}">`
      + `<span class="agent-dim-label">${escHtml(label)}</span>`
      + `<span class="agent-dim-track"><span class="agent-dim-fill" style="width:${pct}%"></span></span>`
      + `<span class="agent-dim-val">${v}</span></span>`;
  }).join('');
  return `<div class="agent-dims" hidden>${segs}</div>`;
}

function agentToggleDims(el) {
  const body = el.closest('.agent-evidence-body');
  const dims = body && body.querySelector('.agent-dims');
  if (dims) dims.hidden = !dims.hidden;
}

function agentRenderEvidence() {
  const list = document.getElementById('agentEvidenceList');
  const count = document.getElementById('agentEvidenceCount');
  if (count) count.textContent = agentEvidence.length;
  agentRenderEvidenceMeta();
  agentRenderHandoffChecklist();
  if (!list) return;
  if (!agentCurrentProject) {
    list.innerHTML = '<div class="agent-empty">创建或选择项目后收集证据</div>';
    return;
  }
  if (!agentEvidence.length) {
    list.innerHTML = '<div class="agent-empty">证据池为空</div>';
    return;
  }
  list.innerHTML = agentEvidence.map(ev => {
    const checked = agentSelectedEvidence.has(ev.evidence_id);
    const reasons = (ev.quality_reasons || []).slice(0, 3).map(r => `<span>${escHtml(r)}</span>`).join('');
    const date = ev.date ? fmtDate(ev.date) : '—';
    const type = ev.source_type || ev.payload?.source_type || '公开信息';
    const hasDims = ev.dims && Object.keys(ev.dims).length;
    const corr = ev.corroboration_count || 0;
    const corrBadge = corr >= 2
      ? `<span class="agent-corrob agent-corrob-multi" title="${corr} 家独立信源报道同一事件（跨源印证越多越可信）">🔗 ${corr}源印证</span>`
      : (corr === 1 && type !== '智库/报告源')
        ? `<span class="agent-corrob agent-corrob-single" title="仅单一信源，建议交叉核实后再采信">⚠ 单源待核</span>`
        : '';
    const qscore = `<span class="agent-qscore${hasDims ? ' agent-qscore-expandable' : ''}"`
      + `${hasDims ? ` onclick="agentToggleDims(this)" title="点击展开5维打分明细"` : ''}>`
      + `Q ${ev.quality_score || 0}${hasDims ? ' ▾' : ''}</span>`;
    const verdict = ev.verdict_line
      ? `<div class="agent-ev-verdict">🧭 ${escHtml(ev.verdict_line)}<span class="agent-ev-verdict-tag">规则研判·供参考</span></div>`
      : '';
    return `<div class="agent-evidence-item${checked ? ' selected' : ''}">
      <button class="agent-check" onclick="agentToggleEvidence('${escHtml(ev.evidence_id)}')" title="选择证据">${checked ? '✓' : ''}</button>
      <div class="agent-evidence-body">
        <div class="agent-evidence-top">
          <span class="agent-source-type">${escHtml(type)}</span>
          <span class="agent-level level-${escHtml(ev.quality_level || 'B')}">${escHtml(ev.quality_level || '-')}</span>
          ${qscore}
          ${corrBadge}
          <span class="agent-source">${escHtml(ev.source_cn || ev.source || '公开来源')}</span>
          <span class="agent-date">${escHtml(date)}</span>
        </div>
        ${agentDimsBar(ev.dims)}
        <div class="agent-evidence-title">${escHtml(ev.title)}</div>
        ${verdict}
        <div class="agent-evidence-reasons">${reasons}</div>
        ${ev.link ? `<a class="agent-link" href="${escHtml(safeExternalUrl(ev.link))}" target="_blank" rel="noopener noreferrer">原文</a>` : ''}
      </div>
    </div>`;
  }).join('');
}

function agentRenderEvidenceMeta() {
  const metaBox = document.getElementById('agentEvidenceMeta');
  if (!metaBox) return;
  if (!agentCurrentProject) {
    metaBox.innerHTML = '<span>目标 -</span><span>已收集 0</span>';
    return;
  }
  const target = parseInt(agentCurrentProject.target_count || 0, 10) || 0;
  const sourceSeeds = agentEvidenceMeta?.source_seeds ?? agentEvidence.filter(ev => {
    const type = ev.source_type || ev.payload?.source_type || '';
    return type.includes('智库') || type.includes('报告源');
  }).length;
  const rssCount = Math.max(0, agentEvidence.length - sourceSeeds);
  const totalScored = agentEvidenceMeta?.total_scored ?? null;
  const gap = target && agentEvidence.length < target ? target - agentEvidence.length : 0;
  const parts = [
    `<span>目标 ${target || '-'}</span>`,
    `<span>已收集 ${agentEvidence.length}</span>`,
    `<span>智库/报告源 ${sourceSeeds}</span>`,
    `<span>RSS候选 ${rssCount}</span>`
  ];
  if (Number.isFinite(totalScored)) parts.push(`<span>已评分 ${totalScored}</span>`);
  if (gap) parts.push(`<span class="agent-meta-warn">可用源少 ${gap}</span>`);
  metaBox.innerHTML = parts.join('');
}

// 报纸式 front-matter 渲染（最小语义标记，样式后续可自由重设计）
function agentNewspaperHtml() {
  const np = agentNewspaper;
  if (!np) return '';
  const toc = (np.toc || []).map((t, i) =>
    `<li><span class="agent-np-idx">${String(i + 1).padStart(2, '0')}</span>${escHtml(t)}</li>`).join('');
  const cards = (np.cards || []).map(c => `<div class="agent-np-card">${escHtml(c)}</div>`).join('');
  return `<div class="agent-np${np.active ? ' agent-np-active' : ''}">
    <div class="agent-np-masthead">
      <span class="agent-np-issue">${escHtml(np.issue || '')}</span>
      <span class="agent-np-byline">${escHtml(np.byline || '')}</span>
      <span class="agent-np-meta">全文约 ${np.word_count || 0} 字 · 约 ${np.reading_minutes || 1} 分钟 · ${np.section_count || 0} 节</span>
    </div>
    ${cards ? `<div class="agent-np-cards"><div class="agent-np-h">核心判断卡</div>${cards}</div>` : ''}
    ${toc ? `<div class="agent-np-toc"><div class="agent-np-h">今日看点</div><ol>${toc}</ol></div>` : ''}
  </div>`;
}

function agentRenderDraft() {
  const area = document.getElementById('agentDraftText');
  const outlineArea = document.getElementById('agentOutlineText');
  const preview = document.getElementById('agentPreview');
  agentRenderDraftQuality();
  const content = agentActiveDraft?.content || '';
  if (agentActiveDraft?.kind === 'outline') {
    if (outlineArea) outlineArea.value = content;
    if (area) area.value = '';
  } else {
    if (area) area.value = content;
  }
  if (preview) {
    if (!content) preview.innerHTML = '<div class="agent-empty">暂无完整报告</div>';
    else if (agentActiveDraft?.kind === 'outline') preview.innerHTML = renderMarkdown(content);
    else preview.innerHTML = agentNewspaperHtml() + renderMarkdown(content);
  }
  agentRenderReviewRadar();
}

function agentRenderDraftQuality() {
  const box = document.getElementById('agentDraftQuality');
  if (!box) return;
  const payload = agentActiveDraft?.payload || {};
  const target = parseInt(payload.target_word_count || 0, 10) || 0;
  const count = parseInt(payload.word_count || 0, 10) || 0;
  const minRequired = parseInt(payload.min_required_word_count || 0, 10) || 0;
  box.classList.remove('ok', 'warn');
  if (!agentActiveDraft) {
    box.textContent = '字数校验：暂无完整报告';
    return;
  }
  if (!target) {
    box.textContent = count ? `字数校验：当前约 ${count} 字` : '字数校验：未设置目标字数';
    return;
  }
  const ok = !!payload.word_count_ok;
  box.classList.add(ok ? 'ok' : 'warn');
  box.textContent = ok
    ? `字数校验：目标 ${target} 字，当前约 ${count} 字，已达标`
    : `字数校验：目标 ${target} 字，当前约 ${count} 字，低于最低要求 ${minRequired} 字，导出将被阻断`;
}

function agentRefreshPreview() {
  const preview = document.getElementById('agentPreview');
  const area = document.getElementById('agentDraftText');
  if (preview && area) preview.innerHTML = area.value.trim() ? renderMarkdown(area.value) : '<div class="agent-empty">暂无完整报告</div>';
  agentRenderReviewRadar();
}

async function agentGenerateOutline({quiet = false} = {}) {
  if (!agentCurrentProject) {
    const error = new Error('请先选择项目');
    if (quiet) throw error;
    showToast(error.message);
    return null;
  }
  const ids = agentCurrentEvidenceIds();
  if (!ids.length) {
    const error = new Error('请先收集证据');
    if (quiet) throw error;
    showToast(error.message);
    return null;
  }
  agentSetLoading(true, '正在生成报告大纲…');
  try {
  const resp = await apiFetch(`/api/agent/projects/${encodeURIComponent(agentCurrentProject.project_id)}/outline`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({evidence_ids: ids, voice: 'strategic_analysis'})
    }, {toast: false});
    const data = await resp.json();
    if (!data.draft) throw new Error('生成未返回目录提纲');
    agentActiveDraft = data.draft;
    agentDrafts.unshift(data.draft);
    const outlineArea = document.getElementById('agentOutlineText');
    if (outlineArea) outlineArea.value = data.outline || data.draft?.content || '';
    agentInvalidateMvpPreflight();
    agentRenderDraft();
    if (!quiet) showToast('目录提纲已生成');
    return data;
  } catch(e) {
    if (quiet) throw e;
    showToast('生成失败：' + e.message);
    agentRenderDraft();
    return null;
  } finally {
    agentSetLoading(false);
  }
}

async function agentPollDraftJob(projectId, jobId, {intervalMs = 2500, maxAttempts = 240} = {}) {
  // 轮询后台草稿生成任务直到 done/failed；单次轮询失败不中止（网络抖动继续重试）。
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise(r => setTimeout(r, intervalMs));
    let data;
    try {
      const resp = await apiFetch(`/api/agent/projects/${encodeURIComponent(projectId)}/draft_jobs/${encodeURIComponent(jobId)}`, {}, {toast: false});
      data = await resp.json();
    } catch (e) {
      continue;
    }
    const status = data.job?.status;
    if (status === 'done' || status === 'failed') return data;
    const secs = Math.round((i + 1) * intervalMs / 1000);
    agentSetLoading(true, `报告生成中…（${status === 'running' ? '生成中' : '排队中'} ${secs}s）`);
  }
  throw new Error('生成超时，请稍后重新打开项目查看草稿');
}

async function agentGenerateDraft({quiet = false} = {}) {
  if (!agentCurrentProject) {
    const error = new Error('请先选择项目');
    if (quiet) throw error;
    showToast(error.message);
    return null;
  }
  const ids = agentCurrentEvidenceIds();
  if (!ids.length) {
    const error = new Error('请先收集证据');
    if (quiet) throw error;
    showToast(error.message);
    return null;
  }
  const outline = document.getElementById('agentOutlineText')?.value.trim() || '';
  const reviewNotes = document.getElementById('agentReviewInput')?.value.trim() || '';
  const projectId = agentCurrentProject.project_id;
  agentSetLoading(true, '正在提交报告生成任务…');
  try {
    const resp = await apiFetch(`/api/agent/projects/${encodeURIComponent(projectId)}/draft`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({evidence_ids: ids, outline, review_notes: reviewNotes, voice: 'strategic_analysis'})
    }, {toast: false});
    let data = await resp.json();
    // 阻塞式 AI 已移到后台 job：未完成则轮询到 done/failed，避免请求线程被长报告生成撑爆超时。
    if (data.job && data.job.status !== 'done' && data.job.status !== 'failed') {
      agentSetLoading(true, '报告生成中，请稍候…');
      data = await agentPollDraftJob(projectId, data.job.job_id);
    }
    if (data.job?.status === 'failed') {
      if (data.draft) {
        // 数据保护：扩写阶段失败，但首版草稿已落盘，照常展示 + 提示
        agentActiveDraft = data.draft;
        agentDrafts.unshift(data.draft);
        agentInvalidateMvpPreflight();
        agentRenderDraft();
        if (!quiet) showToast('扩写阶段失败，已保留首版草稿' + (data.job.error ? '：' + data.job.error : ''));
      } else {
        if (!quiet) showToast('生成失败：' + (data.job.error || '未知错误'));
        agentRenderDraft();
      }
      if (quiet) throw new Error(data.job.error || '草稿生成失败');
      return data;
    }
    if (!data.draft) {
      const error = new Error('生成未返回草稿');
      if (!quiet) showToast(error.message);
      agentRenderDraft();
      if (quiet) throw error;
      return null;
    }
    agentActiveDraft = data.draft;
    agentDrafts.unshift(data.draft);
    agentInvalidateMvpPreflight();
    agentRenderDraft();
    if (!quiet) showToast('完整报告已生成');
    return data;
  } catch(e) {
    if (quiet) throw e;
    showToast('生成失败：' + e.message);
    agentRenderDraft();
    return null;
  } finally {
    agentSetLoading(false);
  }
}

async function agentReviseDraft() {
  if (!agentCurrentProject || !agentActiveDraft) { showToast('暂无可修订草稿'); return; }
  const instruction = document.getElementById('agentReviewInput').value.trim();
  if (!instruction) { showToast('请输入审稿意见'); return; }
  const content = document.getElementById('agentDraftText').value;
  agentSetLoading(true, '正在按审稿意见修订…');
  try {
    const resp = await apiFetch(`/api/agent/projects/${encodeURIComponent(agentCurrentProject.project_id)}/revise`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({draft_id: agentActiveDraft.draft_id, instruction, content})
    }, {toast: false});
    const data = await resp.json();
    agentActiveDraft = data.draft;
    agentDrafts.unshift(data.draft);
    document.getElementById('agentReviewInput').value = '';
    agentInvalidateMvpPreflight('草稿已修订，请重新运行预检。');
    agentRenderDraft();
    showToast('修订已完成');
  } catch(e) {
    showToast('修订失败：' + e.message);
    agentRenderDraft();
  } finally {
    agentSetLoading(false);
  }
}

function agentPreflightFailureMessage(result) {
  return result?.failures?.length
    ? result.failures.join('；')
    : `后端预检状态：${result?.status || 'blocked'}`;
}

async function agentRunPreflight({quiet = false} = {}) {
  if (!agentCurrentProject || !agentActiveDraft) {
    const error = new Error('暂无可预检的完整草稿');
    if (quiet) throw error;
    showToast(error.message);
    return null;
  }
  if (agentCurrentProject.report_type !== 'institution_pack') {
    return {ok: true, status: 'not_required', checks: [], failures: []};
  }
  const draftArea = document.getElementById('agentDraftText');
  const content = agentResolveDraftContent(draftArea?.value, agentActiveDraft);
  agentSetLoading(true, '正在调用后端执行机构包交付预检…');
  try {
    const resp = await apiFetch(`/api/agent/projects/${encodeURIComponent(agentCurrentProject.project_id)}/preflight`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        draft_id: agentActiveDraft.draft_id,
        content,
        evidence_ids: agentCurrentEvidenceIds(),
      })
    }, {toast: false});
    const data = await resp.json();
    const result = agentNormalizePreflight(data);
    agentMvpPreflightState = result;
    agentRenderMvpPreflight();
    agentRenderReviewRadar();
    if (!quiet) {
      showToast(result.ok ? '后端交付预检通过' : `预检未通过：${agentPreflightFailureMessage(result)}`);
    }
    return result;
  } catch(e) {
    agentMvpPreflightState = null;
    agentMvpRunState = {
      status: 'failed',
      message: `预检调用失败：${e.message}`,
      steps: agentMvpRunState?.steps || [],
    };
    agentRenderMvpPreflight();
    agentRenderReviewRadar();
    if (quiet) throw e;
    showToast('预检调用失败：' + e.message);
    return null;
  } finally {
    agentSetLoading(false);
  }
}

async function agentRunMvp() {
  if (agentMvpRunning) return;
  const requestedType = agentCurrentProject?.report_type
    || document.getElementById('agentReportType')?.value
    || '';
  if (requestedType !== 'institution_pack') {
    showToast('“一键跑通 MVP”仅用于机构开源情报整编包');
    return;
  }

  agentMvpRunning = true;
  agentMvpPreflightState = null;
  agentMvpRunState = {status: 'running', message: '按顺序执行：建项 → 采集 → 提纲 → 草稿 → 后端预检', steps: []};
  agentSyncActionButtons();
  agentRenderMvpPreflight();
  let activeStep = null;

  try {
    if (!agentCurrentProject) {
      activeStep = {id: 'project', label: '创建机构包项目'};
      agentMvpSetStep(activeStep.id, activeStep.label, 'running');
      const created = await agentCreateProject({quiet: true});
      if (!created?.project) throw new Error('项目创建未返回有效结果');
      agentMvpSetStep(activeStep.id, activeStep.label, 'done', created.project.title || '项目已落盘');
    }

    activeStep = {id: 'collect', label: '自主采集公开来源'};
    agentMvpSetStep(activeStep.id, activeStep.label, 'running');
    const collected = await agentAutonomousCollect({quiet: true});
    const collectError = agentMvpCollectError(collected);
    if (collectError) throw new Error(collectError);
    const sourceGate = agentMvpSourceGate(agentEvidence);
    if (!sourceGate.ok) {
      throw new Error(`来源仅 ${sourceGate.count} 条，至少需要 ${sourceGate.required} 条，仍缺 ${sourceGate.gap} 条`);
    }
    agentMvpSetStep(activeStep.id, activeStep.label, 'done', `已归集 ${sourceGate.count} 条来源`);

    activeStep = {id: 'outline', label: '生成目录提纲'};
    agentMvpSetStep(activeStep.id, activeStep.label, 'running');
    await agentGenerateOutline({quiet: true});
    agentMvpSetStep(activeStep.id, activeStep.label, 'done', '提纲已保存');

    activeStep = {id: 'draft', label: '生成完整草稿'};
    agentMvpSetStep(activeStep.id, activeStep.label, 'running');
    await agentGenerateDraft({quiet: true});
    agentMvpSetStep(activeStep.id, activeStep.label, 'done', '草稿已保存');

    activeStep = {id: 'preflight', label: '后端交付预检'};
    agentMvpSetStep(activeStep.id, activeStep.label, 'running');
    const preflight = await agentRunPreflight({quiet: true});
    if (!preflight?.ok) throw new Error(agentPreflightFailureMessage(preflight));
    agentMvpSetStep(activeStep.id, activeStep.label, 'done', `状态 ${preflight.status}`);
    agentMvpRunState = {...agentMvpRunState, status: 'complete', message: 'MVP 闭环已跑通，可导出机构包。'};
    agentRenderMvpPreflight();
    showToast('MVP 闭环已跑通，可导出机构包');
  } catch(e) {
    if (activeStep) agentMvpSetStep(activeStep.id, activeStep.label, 'failed', e.message);
    agentMvpRunState = {...(agentMvpRunState || {}), status: 'failed', message: `闭环已停止：${e.message}`};
    agentRenderMvpPreflight();
    showToast('MVP 闭环已停止：' + e.message);
  } finally {
    agentMvpRunning = false;
    agentSetLoading(false);
    agentSyncActionButtons();
    agentRenderMvpPreflight();
  }
}

async function agentExportDocx() {
  if (!agentCurrentProject || !agentActiveDraft) { showToast('暂无可导出的草稿'); return; }
  const content = document.getElementById('agentDraftText').value;
  try {
    if (agentCurrentProject.report_type === 'institution_pack') {
      let preflight;
      try {
        preflight = await agentRunPreflight({quiet: true});
      } catch(e) {
        showToast('导出已阻断：预检调用失败：' + e.message);
        return;
      }
      if (!preflight?.ok) {
        showToast('导出已阻断：' + agentPreflightFailureMessage(preflight));
        return;
      }
    }
    const resp = await apiFetch(`/api/agent/projects/${encodeURIComponent(agentCurrentProject.project_id)}/export_docx`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(agentBuildExportPayload(
        agentActiveDraft.draft_id,
        content,
        agentCurrentEvidenceIds(),
      ))
    }, {toast: false});
    await downloadResponseBlob(resp, '防务报告.docx', '.docx');
    showToast('Word已下载');
  } catch(e) {
    showToast('导出失败：' + e.message);
  }
}

document.addEventListener('input', e => {
  if (e.target?.id === 'agentDraftText') {
    agentInvalidateMvpPreflight('正文已编辑，请重新运行预检。');
    agentRefreshPreview();
  } else if (e.target?.id === 'agentOutlineText') {
    agentInvalidateMvpPreflight('提纲已编辑，请重新运行预检。');
  }
});
document.addEventListener('change', e => {
  if (e.target?.id === 'agentReportType') {
    const count = document.getElementById('agentTargetCount');
    if (count) count.value = agentDefaultCount(e.target.value);
    agentSyncReportTypeUi(e.target.value);
  }
});

const _origShowTabAgent = window.showTab;
window.showTab = function(name, ...rest) {
  if (typeof _origShowTabAgent === 'function') _origShowTabAgent(name, ...rest);
  if (name === 'agent') {
    if (!agentProjects.length) agentLoadProjects();
    else agentSyncReportTypeUi(agentCurrentReportType(), {syncSelect: !!agentCurrentProject});
  }
};

