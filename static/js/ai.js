// ══════════════════════════════════════════════════════════
// 🤖 AI 分析系统
// ══════════════════════════════════════════════════════════
let aiEnabled = false;

// MVP providers are pinned to their official HTTPS endpoints.
const LLM_PROVIDERS = [
  {
    id: 'deepseek', name: 'DeepSeek', flag: 'CN', tier: 'MVP',
    desc: '官方 HTTPS · V4',
    base_url: 'https://api.deepseek.com',
    key_url: 'https://platform.deepseek.com/api_keys',
    models: [
      { id: 'deepseek-v4-flash', name: 'DeepSeek V4 Flash' },
      { id: 'deepseek-v4-pro', name: 'DeepSeek V4 Pro' },
    ],
  },
  {
    id: 'zhipu', name: '智谱 GLM', flag: 'CN', tier: 'MVP',
    desc: '官方 HTTPS · GLM 5',
    base_url: 'https://open.bigmodel.cn/api/paas/v4',
    key_url: 'https://bigmodel.cn/usercenter/apikeys',
    models: [
      { id: 'glm-5.2', name: 'GLM 5.2' },
      { id: 'glm-5-turbo', name: 'GLM 5 Turbo' },
    ],
  },
  {
    id: 'moonshot', name: 'Moonshot Kimi', flag: 'CN', tier: 'MVP',
    desc: '官方 HTTPS · Kimi',
    base_url: 'https://api.moonshot.cn/v1',
    key_url: 'https://platform.kimi.com/console/api-keys',
    models: [
      { id: 'kimi-k3', name: 'Kimi K3' },
      { id: 'kimi-k2.6', name: 'Kimi K2.6' },
    ],
  },
];

let currentProvider = 'deepseek';

function renderProviderPresets() {
  const grid = document.getElementById('aiPresetGrid');
  if (!grid) return;
  grid.innerHTML = LLM_PROVIDERS.map(p => `
    <button class="ai-preset-btn ${p.id===currentProvider?'active':''}" data-pid="${p.id}"
            onclick="selectProvider('${p.id}')" title="${p.desc}">
      <div class="ai-preset-top">
        <span class="ai-preset-flag">${p.flag}</span>
        <span class="ai-preset-tier ${p.tier==='旗舰'?'flagship':p.tier==='聚合'?'hub':'local'}">${p.tier}</span>
      </div>
      <div class="ai-preset-name">${p.name}</div>
      <div class="ai-preset-desc">${p.desc}</div>
    </button>
  `).join('');
}

function selectProvider(pid) {
  const p = LLM_PROVIDERS.find(x => x.id === pid);
  if (!p) return;
  currentProvider = pid;
  const baseUrlEl = document.getElementById('aiBaseUrl');
  const modelSel  = document.getElementById('aiModel');
  const keyHintEl = document.getElementById('aiKeyHint');
  const urlHintEl = document.getElementById('aiBaseUrlHint');
  const getKeyEl  = document.getElementById('aiGetKeyLink');
  if (baseUrlEl) baseUrlEl.value = p.base_url;
  if (modelSel)  modelSel.innerHTML = p.models.map(m =>
    `<option value="${m.id}">${m.name}</option>`).join('');
  if (urlHintEl) urlHintEl.textContent = `${p.flag} ${p.name} · ${p.desc}`;
  if (keyHintEl) keyHintEl.textContent = p.id==='ollama' ? '本地部署无需 API Key（随便填一个）' : '密钥仅保存在本机环境变量/内存中';
  if (getKeyEl)  { getKeyEl.href = p.key_url; getKeyEl.style.display = p.key_url ? '' : 'none'; }
  // 更新激活样式
  document.querySelectorAll('.ai-preset-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.pid === pid));
  // 记忆用户最近选择的提供商
  try { localStorage.setItem('ai_provider', pid); } catch(e) {}
}

// ── AI 配置 ───────────────────────────────────────────────
function currentCloudAiContext() {
  const context = globalThis.__V9_BUSINESS_CONTEXT__;
  if (
    context?.mode !== 'cloud'
    || context.unlocked !== true
    || !context.organizationId
  ) return null;
  return context;
}

async function ensureCloudAiCredentialActive(context) {
  let state = await apiFetch(
    `/api/v9/ai/credentials?organization_id=${encodeURIComponent(context.organizationId)}`,
    {},
    {toast: false},
  ).then(r => r.json());
  if (Array.isArray(state.active) && state.active.length) return state;
  const credentials = Array.isArray(state.credentials) ? state.credentials : [];
  const selected = credentials.find(item => item.provider === currentProvider)
    || credentials[0];
  if (!selected) return state;
  await apiFetch(`/api/v9/ai/credentials/${encodeURIComponent(selected.provider)}/activate`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({organization_id: context.organizationId}),
  }, {toast: false});
  state = {...state, active: [{
    provider: selected.provider,
    model_id: selected.model_id,
    active: true,
  }]};
  return state;
}

async function checkAiConfig() {
  try {
    const cloudContext = currentCloudAiContext();
    if (cloudContext) await ensureCloudAiCredentialActive(cloudContext);
    const data = await apiFetch('/api/ai/config').then(r => r.json());
    aiEnabled = data.enabled;
    if (data.provider && LLM_PROVIDERS.some(p => p.id === data.provider)) {
      selectProvider(data.provider);
      const model = document.getElementById('aiModel');
      if (model && data.model) model.value = data.model;
    }
    const el = document.getElementById('aiStatusText');
    if (el) {
      el.textContent = aiEnabled
        ? `✅ AI已就绪 · 模型: ${data.model} · 服务: ${data.base_url}`
        : data.source === 'cloud'
          ? '⚠️ 当前云端工作区尚未在本机激活 BYOK 凭据'
          : '⚠️ 未配置API Key，请点击右侧"⚙️ 配置AI"选择服务商';
      el.style.color = aiEnabled ? '#34d399' : '#f59e0b';
    }
  } catch(e) {
    aiEnabled = false;
    const el = document.getElementById('aiStatusText');
    if (el) {
      el.textContent = e?.status === 409
        ? '⚠️ 本机缺少该 BYOK 凭据的设备信封，请重新输入 API Key'
        : '⚠️ AI 配置状态读取失败';
      el.style.color = '#f59e0b';
    }
    console.error('AI config check error', e);
  }
}

function toggleAiSettings() {
  const panel = document.getElementById('aiSettingsPanel');
  panel.style.display = panel.style.display === 'none' ? '' : 'none';
  // 首次打开时渲染预设
  if (panel.style.display !== 'none' && !panel.dataset.initialized) {
    const saved = (()=>{ try { return localStorage.getItem('ai_provider'); } catch(e) { return null; } })();
    if (saved && LLM_PROVIDERS.find(p => p.id === saved)) currentProvider = saved;
    renderProviderPresets();
    selectProvider(currentProvider);
    panel.dataset.initialized = '1';
  }
}

async function saveAiConfig() {
  const keyInput = document.getElementById('aiApiKey');
  const payload = {
    api_key:  keyInput.value.trim(),
    provider: currentProvider,
    model:    document.getElementById('aiModel').value,
  };
  if (!payload.api_key) {
    showToast('❌ 请输入 API Key');
    return;
  }
  keyInput.value = '';
  try {
    const cloudContext = currentCloudAiContext();
    if (cloudContext) {
      const state = await apiFetch(
        `/api/v9/ai/credentials?organization_id=${encodeURIComponent(cloudContext.organizationId)}`,
        {},
        {toast: false},
      ).then(r => r.json());
      const existing = (state.credentials || []).find(
        item => item.provider === payload.provider,
      );
      const version = Number(existing?.credential_version || 0) + 1;
      const providerPath = encodeURIComponent(payload.provider);
      const stored = await apiFetch(`/api/v9/ai/credentials/${providerPath}`, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          organization_id: cloudContext.organizationId,
          model_id: payload.model,
          credential_version: version,
          api_key: payload.api_key,
        }),
      }, {toast: false}).then(r => r.json());
      if (stored.stored !== true) throw new Error('云端密文凭据未确认写入');
      await apiFetch(`/api/v9/ai/credentials/${providerPath}/activate`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({organization_id: cloudContext.organizationId}),
      }, {toast: false});
      showToast('✅ BYOK 凭据已加密同步并在本机激活 · 模型: ' + payload.model);
      await checkAiConfig();
      return;
    }
    const data = await apiFetch('/api/ai/config', {
      method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload)
    }, {toast: false}).then(r => r.json());
    if (data.ok) {
      showToast('✅ AI配置已保存 · 模型: ' + data.model);
      aiEnabled = data.enabled;
      await checkAiConfig();
    }
  } catch(e) { showToast('❌ 保存失败: ' + e.message); }
}

globalThis.addEventListener?.('v9:business-context', () => {
  checkAiConfig();
});

async function testAiConnection() {
  showToast('🔌 测试连接中…');
  // 先保存再测试
  await saveAiConfig();
  try {
    const data = await apiFetch('/api/ai/analyze', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ mode: 'freeqa', question: '请用一句话回复：连接测试成功' })
    }, {toast: false}).then(r => r.json());
    if (data.error) { showToast('❌ ' + data.error); }
    else { showToast('✅ 连接成功！AI回复: ' + (data.result || '').slice(0, 50)); }
  } catch(e) { showToast('❌ 连接失败: ' + e.message); }
}

// ── 防务报告源抓取 Agent ─────────────────────────────────
let consultCurrentSession = null;
let consultEvidence = [];
let consultSelectedEvidence = new Set();
let consultCurrentAnswer = null;
let consultBusy = false;
let consultSearchStatus = null;
let consultLastMeta = null;
let consultAssets = [];
let consultAssetFailures = [];
let consultArchivePath = '';
let consultCaptureJob = null;
let consultCapturePollTimer = null;
let consultCurrentPreview = null;
let consultSessions = [];
let consultEvidenceFilter = 'all';
const CONSULT_LAST_SESSION_KEY = 'consultLastSessionId';

function consultExtractRequestedCount(text) {
  const s = String(text || '');
  const m = s.match(/(?:搜集|收集|检索|抓取|找|列出)\s*(\d{1,6})\s*(?:份|条|个)?\s*(?:信息源|证据|资料|来源|文献|智库|报告源|报告)?/)
    || s.match(/(\d{1,6})\s*(?:份|条|个)\s*(?:信息源|证据|资料|来源|文献|智库|报告源|报告)/);
  return m ? Math.max(1, parseInt(m[1], 10)) : null;
}

function consultSetBusy(on, msg) {
  consultBusy = !!on;
  const body = document.getElementById('consultSourcePackBody');
  if (on && body && msg) {
    body.innerHTML = `<div class="consult-loading"><div class="ai-spinner-sm"></div><span>${escHtml(msg)}</span></div>`;
  }
  consultRenderOpsBoard();
}

function renderSearchStatus(status) {
  consultSearchStatus = status || consultSearchStatus;
  const statusText = document.getElementById('searchStatusText');
  const providersEl = document.getElementById('searchProviderStatus');
  if (!consultSearchStatus || !providersEl) return;
  const currentStatus = consultSearchStatus;
  if (statusText) {
    statusText.textContent = currentStatus.online_search_enabled ? '基础联网搜索可用' : '联网搜索不可用';
  }
  const providers = currentStatus.providers || {};
  const labels = [
    ['public_web', '基础联网搜索'],
    ['tavily', 'Tavily增强'],
    ['brave', 'Brave增强'],
    ['serpapi', 'SerpAPI增强'],
  ].map(([key, label]) => {
    const enabled = !!providers[key]?.enabled;
    const offText = key === 'public_web' ? '不可用' : '可选';
    return `<span class="consult-provider-chip ${enabled ? 'on' : 'off'}">${escHtml(label)}：${enabled ? '可用' : offText}</span>`;
  }).join('');
  const aux = `<span class="consult-provider-chip on">站点抓取：可用</span>
    <span class="consult-provider-chip ${currentStatus.rss_aux_enabled ? 'on' : 'off'}">RSS辅助：${currentStatus.rss_aux_enabled ? '可用' : '不可用'}</span>`;
  providersEl.innerHTML = labels + aux;
}

async function loadSearchStatus() {
  try {
    const resp = await apiFetch('/api/search/status', {}, {toast: false});
    const data = await resp.json();
    renderSearchStatus(data.status || {});
  } catch(e) {
    const statusText = document.getElementById('searchStatusText');
    if (statusText) statusText.textContent = '状态读取失败';
  }
}

async function saveSearchConfig() {
  try {
    const body = {
      tavily_api_key: document.getElementById('searchTavilyKey')?.value.trim() || '',
      brave_api_key: document.getElementById('searchBraveKey')?.value.trim() || '',
      serpapi_api_key: document.getElementById('searchSerpKey')?.value.trim() || '',
      default_providers: ['tavily', 'brave', 'serpapi', 'public_web'],
    };
    const resp = await apiFetch('/api/search/config', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body),
    }, {toast: false});
    const data = await resp.json();
    ['searchTavilyKey', 'searchBraveKey', 'searchSerpKey'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    renderSearchStatus(data.status || {});
    showToast('搜索配置已保存');
  } catch(e) {
    showToast('搜索配置保存失败：' + e.message);
  }
}

function consultRememberSession(sessionId) {
  try {
    if (sessionId) localStorage.setItem(CONSULT_LAST_SESSION_KEY, sessionId);
    else localStorage.removeItem(CONSULT_LAST_SESSION_KEY);
  } catch(e) {}
}

function consultUpdateProjectCount() {
  const countEl = document.getElementById('consultProjectCount');
  if (countEl) countEl.textContent = String(consultSessions.length || 0);
}

function consultRenderSessions() {
  const list = document.getElementById('consultProjectList');
  if (!list) return;
  consultUpdateProjectCount();
  if (!consultSessions.length) {
    list.innerHTML = `<div class="consult-empty">
      <strong>暂无资料项目</strong>
      <span>输入客户需求后点击一键搜集，项目会自动保存到本地资料库。</span>
    </div>`;
    return;
  }
  list.innerHTML = consultSessions.map(s => {
    const active = consultCurrentSession?.session_id === s.session_id ? ' active' : '';
    const title = s.topic || s.instruction || '未命名资料项目';
    const goal = s.report_goal || '防务资料包';
    const target = Number(s.target_source_count || 0);
    const time = fmtDate(s.updated_at || s.created_at);
    const status = s.status || 'active';
    return `<button class="consult-project-item${active}" type="button" onclick="consultOpenSession('${escJsArg(s.session_id)}')">
      <span class="consult-project-status">${escHtml(status === 'active' ? '进行中' : status)}</span>
      <strong>${escHtml(title)}</strong>
      <small>${escHtml(goal)} · 目标 ${target || '-'} 份 · ${escHtml(time)}</small>
    </button>`;
  }).join('');
}

async function consultLoadSessions(opts = {}) {
  const list = document.getElementById('consultProjectList');
  if (list && !opts.silent) list.innerHTML = '<div class="consult-empty">正在读取资料项目…</div>';
  try {
    const resp = await apiFetch('/api/consult/sessions?limit=80', {}, {toast: false});
    const data = await resp.json();
    consultSessions = data.sessions || [];
    consultRenderSessions();
    const remembered = (() => {
      try { return localStorage.getItem(CONSULT_LAST_SESSION_KEY) || ''; } catch(e) { return ''; }
    })();
    const shouldRestore = opts.restore && !consultCurrentSession && consultSessions.length;
    if (shouldRestore) {
      const next = consultSessions.find(s => s.session_id === remembered) || consultSessions[0];
      if (next?.session_id) await consultOpenSession(next.session_id, {silent: true});
    }
  } catch(e) {
    if (list) list.innerHTML = `<div class="consult-empty">资料项目读取失败：${escHtml(e.message)}</div>`;
  }
}

function consultApplySessionToForm(session) {
  const instructionEl = document.getElementById('consultInstruction');
  const targetEl = document.getElementById('consultTargetCount');
  const searchEl = document.getElementById('consultSearchWeb');
  if (instructionEl) instructionEl.value = session?.instruction || '';
  if (targetEl) targetEl.value = Number(session?.target_source_count || 20);
  if (searchEl) searchEl.checked = session?.search_web !== false && session?.search_web !== 0;
}

async function consultOpenSession(sessionId, opts = {}) {
  if (!sessionId) return;
  if (consultCapturePollTimer) {
    clearTimeout(consultCapturePollTimer);
    consultCapturePollTimer = null;
  }
  if (!opts.silent) consultSetBusy(true, '正在恢复资料项目现场…');
  try {
    const detailResp = await apiFetch(`/api/consult/sessions/${encodeURIComponent(sessionId)}`, {}, {toast: false});
    const detail = await detailResp.json();
    consultCurrentSession = detail.session || null;
    consultEvidence = detail.evidence || [];
    consultCurrentAnswer = Array.isArray(detail.answers) && detail.answers.length ? detail.answers[0] : null;
    consultCaptureJob = null;
    consultCurrentPreview = null;
    consultEvidenceFilter = 'all';
    consultSetCapability(detail);
    consultApplySessionToForm(consultCurrentSession);

    const assetResp = await apiFetch(`/api/consult/sessions/${encodeURIComponent(sessionId)}/assets`, {}, {toast: false});
    const assetData = await assetResp.json();
    consultAssets = assetData.assets || [];
    consultArchivePath = assetData.source_archive_path || '';
    consultAssetFailures = consultAssets.filter(a => a.status === 'failed');
    consultLastMeta = {
      archived_count: assetData.archived_count || 0,
      partial_count: assetData.partial_count || 0,
      failed_count: assetData.failed_count || 0,
      needs_user_input_count: assetData.needs_user_input_count || 0,
      previewable_count: assetData.previewable_count || 0,
      failure_breakdown: assetData.failure_breakdown || {},
      diagnosis_cards: assetData.diagnosis_cards || [],
      archive_shortfall: assetData.archive_shortfall || 0,
      target_source_count: consultCurrentSession?.target_source_count,
      source_archive_path: assetData.source_archive_path || '',
    };
    const ready = consultEvidence.filter(consultIsHandoffReady);
    const extractable = consultEvidence.filter(consultCanExtract);
    consultSelectedEvidence = new Set((ready.length ? ready : extractable).map(ev => ev.evidence_id));
    consultRememberSession(sessionId);
    consultRenderSessions();
    consultRenderPlan();
    consultRenderEvidence(consultLastMeta);
    consultRenderReport(consultCurrentAnswer);
    consultCloseAssetPreview();
  } catch(e) {
    showToast('打开资料项目失败：' + e.message);
  } finally {
    consultBusy = false;
    consultRenderOpsBoard();
  }
}

function consultNewSessionDraft() {
  if (consultCapturePollTimer) {
    clearTimeout(consultCapturePollTimer);
    consultCapturePollTimer = null;
  }
  consultCurrentSession = null;
  consultEvidence = [];
  consultSelectedEvidence = new Set();
  consultCurrentAnswer = null;
  consultLastMeta = null;
  consultAssets = [];
  consultAssetFailures = [];
  consultArchivePath = '';
  consultCaptureJob = null;
  consultCurrentPreview = null;
  consultEvidenceFilter = 'all';
  consultRememberSession('');
  const instructionEl = document.getElementById('consultInstruction');
  if (instructionEl) {
    instructionEl.value = '';
    instructionEl.focus();
  }
  const targetEl = document.getElementById('consultTargetCount');
  if (targetEl) targetEl.value = 20;
  const searchEl = document.getElementById('consultSearchWeb');
  if (searchEl) searchEl.checked = true;
  consultRenderSessions();
  consultRenderPlan();
  consultRenderEvidence();
  consultRenderReport();
  consultCloseAssetPreview();
}

function consultSetCapability(payload) {
  const box = document.getElementById('consultCapabilityNotice');
  if (!box) return;
  const cap = payload?.capabilities || {};
  const model = payload?.model || {};
  const notice = payload?.capability_notice || '实际功能：抓取公开报告、智库分析、研究论文、防务媒体深度分析和用户导入素材；智库目录只作为检索入口。';
  const web = cap.message || (cap.web_search_enabled ? '实时网页搜索已启用' : '实时网页搜索状态未知');
  const modelText = model.model ? `${model.model}${model.base_url ? ' · ' + model.base_url : ''}` : '未读取';
  if (Object.keys(cap).length) renderSearchStatus(cap);
  box.innerHTML = `<strong>Agent 实际功能</strong>
    <span>${escHtml(notice)}</span>
    <span>搜索状态：${escHtml(web)}；当前模型：${escHtml(modelText)}</span>`;
}

function consultEvidenceStats() {
  const rows = consultEvidence || [];
  const target = parseInt(consultCurrentSession?.target_source_count || document.getElementById('consultTargetCount')?.value || '0', 10) || 0;
  const concrete = rows.filter(ev => ev.channel !== 'thinktank_target');
  const targets = rows.filter(ev => ev.channel === 'thinktank_target');
  const archivedRows = rows.filter(ev => consultIsHandoffReady(ev));
  const archivedAssets = (consultAssets || []).filter(a => a.status === 'archived');
  const partialAssets = (consultAssets || []).filter(a => a.status === 'partial');
  const failedAssets = (consultAssets || []).filter(a => a.status === 'failed');
  const needsInputAssets = (consultAssets || []).filter(a => a.status === 'needs_user_input');
  const archivedCount = Math.max(
    archivedRows.length,
    archivedAssets.length,
    consultLastMeta?.archived_count || 0,
    consultCaptureJob?.archived_count || 0
  );
  const selectedRows = rows.filter(ev => consultSelectedEvidence.has(ev.evidence_id));
  const readySelected = selectedRows.filter(consultIsHandoffReady);
  const extractableSelected = selectedRows.filter(ev => {
    const payload = ev.payload || {};
    const status = consultAssetForEvidence(ev.evidence_id)?.status || payload.asset_status || '';
    return consultCanExtract(ev) && !consultIsHandoffReady(ev) && !['failed', 'needs_user_input', 'partial'].includes(status);
  });
  const scores = concrete.map(ev => Number(ev.score || 0)).filter(n => n > 0);
  const avgScore = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
  const docTypes = {};
  const providers = {};
  concrete.forEach(ev => {
    const payload = ev.payload || {};
    const type = String(payload.document_type || ev.document_type || 'html').toUpperCase();
    const provider = payload.provider || ev.provider || ev.source || '公开来源';
    docTypes[type] = (docTypes[type] || 0) + 1;
    providers[provider] = (providers[provider] || 0) + 1;
  });
  const failureBreakdown = consultCaptureJob?.failure_breakdown || consultLastMeta?.failure_breakdown || {};
  const diagnosisCards = consultCaptureJob?.diagnosis_cards || consultLastMeta?.diagnosis_cards || [];
  const previewable = Math.max(consultCaptureJob?.previewable_count || 0, consultLastMeta?.previewable_count || 0, archivedAssets.length + partialAssets.length);
  const relaxedFallback = consultCaptureJob?.relaxed_fallback_count || consultLastMeta?.relaxed_fallback_count || consultLastMeta?.web?.relaxed_fallback_count || 0;
  return {
    total: rows.length,
    target,
    concrete: concrete.length,
    targets: targets.length,
    fetched: archivedCount,
    archived: archivedCount,
    partial: Math.max(partialAssets.length, consultCaptureJob?.partial_count || 0),
    failed: Math.max(failedAssets.length, consultLastMeta?.failed_count || 0, consultAssetFailures.length, consultCaptureJob?.failed_count || 0),
    needsInput: Math.max(needsInputAssets.length, consultCaptureJob?.needs_user_input_count || 0),
    selected: selectedRows.length,
    readySelected: readySelected.length,
    extractableSelected: extractableSelected.length,
    avgScore,
    highScore: concrete.filter(ev => Number(ev.score || 0) >= 85).length,
    shortfall: Math.max(0, target - archivedCount),
    searchShortfall: Math.max(0, target - concrete.length),
    previewable,
    relaxedFallback,
    failureBreakdown,
    diagnosisCards,
    archivedRate: consultCaptureJob?.archived_per_minute || 0,
    elapsedSeconds: consultCaptureJob?.elapsed_seconds || 0,
    totalResults: consultCaptureJob?.total_result_count || 0,
    currentPhase: consultCaptureJob?.current_phase || '',
    stopReasonLabel: consultCaptureJob?.stop_reason_label || '',
    docTypes,
    providers,
    hasSession: !!consultCurrentSession,
    hasPack: !!consultCurrentAnswer,
    captureJob: consultCaptureJob,
  };
}

function consultOpsState(stats) {
  if (consultBusy) return {text: '执行中', cls: 'warn'};
  if (!stats.hasSession) return {text: '待输入需求', cls: 'idle'};
  if (!stats.concrete && !stats.targets) return {text: '待检索', cls: 'idle'};
  if (stats.shortfall > 0) return {text: `归档缺口 ${stats.shortfall}`, cls: 'warn'};
  if (stats.concrete && !stats.archived) return {text: '待归档原文', cls: 'warn'};
  if (!stats.hasPack) return {text: '待整理', cls: 'warn'};
  return {text: '可交付', cls: ''};
}

function consultOpsProgress(stats) {
  let value = stats.hasSession ? 14 : 0;
  if (stats.target) value += Math.min(30, Math.round((stats.concrete / stats.target) * 30));
  else if (stats.concrete) value += 30;
  if (stats.concrete || stats.target) value += Math.round((stats.archived / Math.max(1, stats.target || stats.concrete)) * 24);
  if (stats.selected) value += 8;
  if (stats.hasPack) value += 24;
  return Math.max(0, Math.min(100, value));
}

function consultAssetForEvidence(evidenceId) {
  return (consultAssets || []).find(asset => asset.evidence_id === evidenceId) || null;
}

function consultEvidenceStatus(ev) {
  if (!ev) return 'other';
  const payload = ev.payload || {};
  const asset = consultAssetForEvidence(ev.evidence_id);
  const status = asset?.status || payload.asset_status || '';
  if (ev.channel === 'thinktank_target') return 'target';
  if (consultIsHandoffReady(ev)) return 'archived';
  if (status === 'partial') return 'partial';
  if (status === 'needs_user_input') return 'needs_user_input';
  if (status === 'failed') return 'failed';
  if (consultCanExtract(ev)) return 'ready';
  return 'other';
}

function consultFilteredEvidenceRows() {
  const rows = consultEvidence || [];
  if (consultEvidenceFilter === 'all') return rows;
  return rows.filter(ev => consultEvidenceStatus(ev) === consultEvidenceFilter);
}

function consultEvidenceFilterCounts() {
  const counts = {
    all: (consultEvidence || []).length,
    archived: 0,
    ready: 0,
    partial: 0,
    needs_user_input: 0,
    failed: 0,
    target: 0,
  };
  (consultEvidence || []).forEach(ev => {
    const status = consultEvidenceStatus(ev);
    counts[status] = (counts[status] || 0) + 1;
  });
  return counts;
}

function consultSetEvidenceFilter(filter) {
  const allowed = new Set(['all', 'archived', 'ready', 'partial', 'needs_user_input', 'failed', 'target']);
  consultEvidenceFilter = allowed.has(filter) ? filter : 'all';
  consultRenderEvidence();
}

function consultRenderEvidenceFilters() {
  const el = document.getElementById('consultEvidenceFilters');
  if (!el) return;
  const counts = consultEvidenceFilterCounts();
  const filters = [
    ['all', '全部'],
    ['archived', '已归档'],
    ['ready', '待归档'],
    ['partial', '待复核'],
    ['needs_user_input', '需补充'],
    ['failed', '失败'],
    ['target', '机构入口'],
  ];
  el.innerHTML = filters.map(([key, label]) => {
    const active = consultEvidenceFilter === key ? ' active' : '';
    const disabled = !counts[key] && key !== 'all' ? ' disabled' : '';
    return `<button class="consult-filter-btn${active}${disabled}" type="button" onclick="consultSetEvidenceFilter('${key}')">
      <span>${label}</span><b>${counts[key] || 0}</b>
    </button>`;
  }).join('');
}

function consultAssetDisplayTitle(asset) {
  return asset?.title || asset?.url || asset?.local_path || '未命名资料';
}

function consultRenderReadingQueue() {
  const box = document.getElementById('consultReadingQueue');
  if (!box) return;
  const assets = [...(consultAssets || [])].sort((a, b) => {
    const rank = {archived: 0, partial: 1, needs_user_input: 2, failed: 3};
    return (rank[a.status] ?? 9) - (rank[b.status] ?? 9);
  });
  if (!assets.length) {
    box.innerHTML = `<div class="consult-mini-head">
        <h4>资料阅读队列</h4><span>0</span>
      </div>
      <div class="consult-mini-empty">归档后会在这里列出 PDF / DOCX / HTML，可直接预览或打开原始来源。</div>`;
    return;
  }
  const statusLabel = {
    archived: '已归档',
    partial: '待复核',
    failed: '失败',
    needs_user_input: '需补充',
  };
  const rows = assets.slice(0, 7).map(asset => {
    const title = consultAssetDisplayTitle(asset);
    const status = asset.status || 'unknown';
    const type = String(asset.document_type || asset.content_type || 'DOC').toUpperCase();
    const words = asset.word_count ? `${asset.word_count}字` : '-';
    const preview = asset.asset_id
      ? `<button type="button" onclick="consultPreviewAsset('${escJsArg(asset.asset_id)}')">预览</button>`
      : '';
    const open = asset.url ? `<a href="${escHtml(safeExternalUrl(asset.url))}" target="_blank" rel="noopener noreferrer">来源</a>` : '';
    return `<div class="consult-queue-item ${escHtml(status)}">
      <div>
        <strong>${escHtml(title).slice(0, 92)}</strong>
        <small>${escHtml(asset.source || asset.provider || '本地资料')} · ${escHtml(type)} · ${escHtml(words)}</small>
      </div>
      <span>${escHtml(statusLabel[status] || status)}</span>
      <div class="consult-queue-actions">${preview}${open}</div>
    </div>`;
  }).join('');
  box.innerHTML = `<div class="consult-mini-head">
      <h4>资料阅读队列</h4>
      <span>${assets.length} 项</span>
    </div>
    <div class="consult-queue-list">${rows}</div>
    ${assets.length > 7 ? `<div class="consult-mini-note">另有 ${assets.length - 7} 项资料在本地资料库中。</div>` : ''}`;
}

function consultPlanQueries() {
  const plan = consultCurrentSession?.plan || {};
  return [
    ...(consultCaptureJob?.next_queries || []),
    ...(consultLastMeta?.next_queries || []),
    ...(consultLastMeta?.topic_plan?.queries || []),
    ...(plan.queries || []),
    ...(plan.keywords || []),
  ].filter(Boolean);
}

function consultTopicText() {
  return String(consultCurrentSession?.topic || consultCurrentSession?.instruction || document.getElementById('consultInstruction')?.value || '').trim();
}

async function consultCopyText(text, label = '内容') {
  const clean = String(text || '').trim();
  if (!clean) return;
  try {
    if (navigator.clipboard) await navigator.clipboard.writeText(clean);
    showToast(`${label}已复制`);
  } catch(e) {
    showToast(`${label}复制失败：${e.message}`);
  }
}

function consultPreferredSourceCatalog() {
  return [
    {name: 'RAND', domain: 'rand.org', label: '战略研究'},
    {name: 'CSIS', domain: 'csis.org', label: '力量评估'},
    {name: 'IISS', domain: 'iiss.org', label: '军力平衡'},
    {name: 'CRS', domain: 'crsreports.congress.gov', label: '国会研究'},
    {name: 'NIDS', domain: 'nids.mod.go.jp', label: '日本防研'},
    {name: 'DoD/DIA', domain: 'defense.gov dia.mil media.defense.gov', label: '官方评估'},
    {name: 'GAO', domain: 'gao.gov', label: '审计报告'},
    {name: 'RUSI', domain: 'rusi.org', label: '作战研究'},
    {name: 'SIPRI', domain: 'sipri.org', label: '军备数据'},
    {name: 'CNAS', domain: 'cnas.org', label: '印太安全'},
  ];
}

function consultEvidenceHaystack(ev) {
  const payload = ev?.payload || {};
  return [
    ev?.title, ev?.source, ev?.url, ev?.snippet, ev?.reason, ev?.provider,
    payload.title, payload.source, payload.domain, payload.provider, payload.url, payload.snippet,
  ].filter(Boolean).join(' ').toLowerCase();
}

function consultSourceStatus(entry) {
  const domains = String(entry.domain || '').toLowerCase().split(/\s+/).filter(Boolean);
  const hits = (consultEvidence || []).filter(ev => {
    const hay = consultEvidenceHaystack(ev);
    return domains.some(domain => hay.includes(domain)) || hay.includes(entry.name.toLowerCase());
  });
  const hitIds = new Set(hits.map(ev => ev.evidence_id));
  const assets = (consultAssets || []).filter(asset => hitIds.has(asset.evidence_id));
  const archived = assets.filter(asset => asset.status === 'archived').length;
  const restricted = assets.filter(asset => ['needs_user_input', 'failed'].includes(asset.status)).length;
  const partial = assets.filter(asset => asset.status === 'partial').length;
  const score = hits.length
    ? Math.round(hits.reduce((sum, ev) => sum + Number(ev.score || 0), 0) / hits.length)
    : 0;
  let state = '建议补抓';
  let cls = 'todo';
  if (restricted) { state = `受限 ${restricted}`; cls = 'need'; }
  else if (archived) { state = `已归档 ${archived}`; cls = 'done'; }
  else if (partial) { state = `待复核 ${partial}`; cls = 'partial'; }
  else if (hits.length) { state = `已命中 ${hits.length}`; cls = 'hit'; }
  return {hits, archived, restricted, partial, score, state, cls};
}

function consultRestrictedAssets() {
  const rows = [];
  (consultAssets || []).forEach(asset => {
    if (['needs_user_input', 'failed', 'partial'].includes(asset.status)) rows.push({asset});
  });
  if (!rows.length) {
    (consultEvidence || []).forEach(ev => {
      const status = consultEvidenceStatus(ev);
      if (['needs_user_input', 'failed', 'partial'].includes(status)) {
        rows.push({asset: consultAssetForEvidence(ev.evidence_id), evidence: ev});
      }
    });
  }
  return rows;
}

function consultRenderCaptureCockpit(stats = consultEvidenceStats()) {
  const box = document.getElementById('consultCaptureCockpit');
  if (!box) return;
  const topic = consultTopicText();
  const activeQuery = consultCaptureJob?.current_query || '';
  const queries = [...new Set([activeQuery, ...consultPlanQueries()].filter(Boolean).map(String))]
    .slice(0, 4);
  const queueHtml = queries.length ? queries.map((q, idx) => {
    const active = q === activeQuery && consultCaptureJobActive(consultCaptureJob);
    return `<div class="consult-cockpit-query ${active ? 'active' : ''}">
      <span>${idx + 1}</span>
      <b>${escHtml(q).slice(0, 108)}</b>
      <button type="button" onclick="consultCopyText('${escJsArg(q)}','搜索式')">复制</button>
    </div>`;
  }).join('') : `<div class="consult-cockpit-empty">创建任务后显示下一轮中英文/PDF/站内搜索式。</div>`;

  const sources = consultPreferredSourceCatalog().map(entry => ({entry, status: consultSourceStatus(entry)}))
    .sort((a, b) => {
      const rank = {need: 0, todo: 1, partial: 2, hit: 3, done: 4};
      return (rank[a.status.cls] ?? 9) - (rank[b.status.cls] ?? 9);
    })
    .slice(0, 4);
  const sourceHtml = sources.map(({entry, status}) => {
    const query = `site:${entry.domain.split(/\s+/)[0]} ${topic || 'defense report'} PDF report analysis`;
    return `<div class="consult-source-target ${status.cls}">
      <div><strong>${escHtml(entry.name)}</strong><small>${escHtml(entry.label)} · ${status.score ? `Q${status.score}` : entry.domain.split(/\s+/)[0]}</small></div>
      <span>${escHtml(status.state)}</span>
      <button type="button" onclick="consultCopyText('${escJsArg(query)}','站内补抓式')">站内式</button>
    </div>`;
  }).join('');

  const restricted = consultRestrictedAssets().slice(0, 3);
  const restrictedHtml = restricted.length ? restricted.map(({asset, evidence}) => {
    const src = asset || {};
    const ev = evidence || consultEvidence.find(item => item.evidence_id === src.evidence_id) || {};
    const title = src.title || src.payload?.title || ev.title || src.url || ev.url || '受限资料';
    const reason = src.failure_reason || src.payload?.diagnosis?.label || ev.payload?.diagnosis?.label || src.status || '需要复核';
    const preview = src.asset_id ? `<button type="button" onclick="consultPreviewAsset('${escJsArg(src.asset_id)}')">诊断</button>` : '';
    const open = (src.url || ev.url) ? `<a href="${escHtml(safeExternalUrl(src.url || ev.url))}" target="_blank" rel="noopener noreferrer">网页</a>` : '';
    return `<div class="consult-restricted-item ${escHtml(src.status || consultEvidenceStatus(ev))}">
      <div><strong>${escHtml(title).slice(0, 72)}</strong><small>${escHtml(reason).slice(0, 94)}</small></div>
      <div>${preview}${open}</div>
    </div>`;
  }).join('') : `<div class="consult-cockpit-empty">暂无受限资料；若出现 403、验证码、正文过短，会集中到这里处理。</div>`;

  const ruleText = [
    '只按已归档可引用资产计入完成',
    '目录入口不计入目标',
    '优先 PDF / 官方 / 智库报告',
  ].map(item => `<span>${escHtml(item)}</span>`).join('');
  box.innerHTML = `<div class="consult-cockpit-head">
      <strong>采集驾驶舱</strong>
      <span>${stats.shortfall ? `缺 ${stats.shortfall}` : '就绪'}</span>
    </div>
    <div class="consult-cockpit-module">
      <div class="consult-cockpit-title"><b>下一轮搜索队列</b><em>${queries.length || 0}</em></div>
      <div class="consult-cockpit-query-list">${queueHtml}</div>
    </div>
    <div class="consult-cockpit-module">
      <div class="consult-cockpit-title"><b>优先补抓机构</b><em>${sources.filter(x => x.status.cls !== 'done').length}</em></div>
      <div class="consult-source-target-list">${sourceHtml}</div>
    </div>
    <div class="consult-cockpit-module">
      <div class="consult-cockpit-title"><b>受限资料处理箱</b><em>${restricted.length}</em></div>
      <div class="consult-restricted-list">${restrictedHtml}</div>
    </div>
    <div class="consult-cockpit-rules">${ruleText}</div>`;
}

function consultRenderGapAdvisor(stats) {
  const box = document.getElementById('consultGapAdvisor');
  if (!box) return;
  const queries = [...new Set(consultPlanQueries().map(String))].slice(0, 4);
  const failureRows = Object.entries(stats.failureBreakdown || {}).slice(0, 3)
    .map(([code, count]) => `<span class="consult-gap-pill danger">${escHtml(consultFailureCodeLabel(code))} ${count}</span>`)
    .join('');
  const queryRows = queries.map(q => `<span class="consult-gap-query">${escHtml(q).slice(0, 96)}</span>`).join('');
  const shortfallText = stats.target ? `${stats.shortfall}/${stats.target}` : '-';
  box.innerHTML = `<div class="consult-mini-head">
      <h4>缺口补抓建议</h4>
      <span>缺 ${shortfallText}</span>
    </div>
    <div class="consult-gap-summary">
      <b>${stats.archived}/${stats.target || '-'}</b>
      <span>已归档可引用资产；候选 ${stats.concrete}，需补充 ${stats.needsInput}，失败 ${stats.failed}</span>
    </div>
    <div class="consult-gap-queries">${queryRows || '<span class="consult-mini-empty">创建任务后生成下一轮查询式</span>'}</div>
    ${failureRows ? `<div class="consult-gap-failures">${failureRows}</div>` : ''}
    <div class="consult-advisor-actions">
      <button type="button" onclick="consultContinueToTarget()">继续补抓</button>
      <button type="button" onclick="consultDeepRetryToTarget()">深度补抓</button>
    </div>`;
}

function consultRenderHandoffChecklist(stats) {
  const box = document.getElementById('consultHandoffChecklist');
  if (!box) return;
  const ready = consultEvidence.filter(ev => consultSelectedEvidence.has(ev.evidence_id) && consultIsHandoffReady(ev)).length;
  const waiting = consultEvidence.filter(ev => consultSelectedEvidence.has(ev.evidence_id) && consultCanExtract(ev) && !consultIsHandoffReady(ev)).length;
  const selectedText = `${stats.selected || 0}/${stats.total || 0}`;
  box.innerHTML = `<div class="consult-mini-head">
      <h4>报告 Agent 交接清单</h4>
      <span>${selectedText}</span>
    </div>
    <div class="consult-handoff-grid">
      <span><b>${ready}</b><em>可转入</em></span>
      <span><b>${waiting}</b><em>待归档</em></span>
      <span><b>${stats.avgScore || '-'}</b><em>质量均分</em></span>
    </div>
    <div class="consult-handoff-checks">
      <p class="${ready ? 'ok' : ''}">来源编号：${ready ? '已具备' : '待归档后生成'}</p>
      <p class="${stats.hasPack ? 'ok' : ''}">资料包：${stats.hasPack ? '已整理' : '可先整理再导出'}</p>
      <p class="${stats.shortfall <= 0 && stats.target ? 'ok' : ''}">目标数量：${stats.target ? `${stats.archived}/${stats.target}` : '待设定'}</p>
    </div>
    <div class="consult-advisor-actions">
      <button type="button" onclick="consultArchiveSources()">归档选中</button>
      <button type="button" onclick="consultHandoffToReportAgent()">转入报告</button>
    </div>`;
}

function consultRenderWorkflowModules(stats = consultEvidenceStats()) {
  consultRenderEvidenceFilters();
  consultRenderCaptureCockpit(stats);
  consultRenderReadingQueue();
  consultRenderGapAdvisor(stats);
  consultRenderHandoffChecklist(stats);
}

function consultCaptureJobActive(job) {
  return !!job && !['completed', 'failed', 'cancelled'].includes(job.status);
}

function consultStatusPill(ok, waitText = '待处理') {
  return `<span class="consult-check-status ${ok ? 'ok' : 'wait'}">${ok ? '完成' : escHtml(waitText)}</span>`;
}

function consultFailureCodeLabel(code) {
  return ({
    not_found: '链接失效',
    blocked: '访问受限',
    needs_user_input: '需用户补充',
    timeout: '站点超时',
    too_large: '文件过大',
    unsupported: '解析不支持',
    too_short: '正文过短',
    unknown: '待复核',
  })[code] || code || '待复核';
}

function consultFormatDuration(seconds) {
  const n = Math.max(0, Number(seconds || 0));
  if (!n) return '-';
  const m = Math.floor(n / 60);
  const s = Math.round(n % 60);
  return m ? `${m}分${s}秒` : `${s}秒`;
}

function consultNextSteps(stats) {
  if (consultCaptureJobActive(stats.captureJob)) {
    return [
      `采集任务正在执行：第 ${stats.captureJob.round_no || 0}/${stats.captureJob.max_rounds || '-'} 轮。`,
      stats.captureJob.current_query ? `当前搜索式：${stats.captureJob.current_query}` : '正在准备下一轮搜索式与抓取队列。',
      '系统会把成功正文归档为可引用资产，受限页面会标为需用户上传/授权。',
    ];
  }
  if (!stats.hasSession) {
    return [
      '输入客户一句话需求，例如“搜集30份美以冲突导弹攻防战问题研究”。',
      '点击一键搜集并归档至目标，Agent 会自动搜索、抓取、归档。',
      '检索完成后抓取正文/PDF，再整理 DOCX/PDF 资料包。',
    ];
  }
  if (!stats.concrete && !stats.targets) {
    return [
      '点击一键搜集并归档至目标，先拿到具体网页、PDF、论文和报告入口。',
      '若客户指定数量较大，系统会按目标数量继续扩展检索。',
      '检索结果会自动区分具体来源和仅能继续站内查找的机构入口。',
    ];
  }
  if (!stats.extractableSelected && stats.shortfall > 0 && (stats.failed || stats.needsInput || stats.partial)) {
    return [
      `本轮未达到目标：已归档 ${stats.archived}/${stats.target || '-'}，仍缺 ${stats.shortfall} 份可引用资产。`,
      `失败 ${stats.failed}、需用户补充 ${stats.needsInput}、正文待复核 ${stats.partial}；这些不会被算作完成。`,
      '可继续归档至目标，或上传/粘贴客户已有 PDF、网页正文、授权可访问材料后再整理资料包。',
    ];
  }
  if (stats.extractableSelected) {
    return [
      `当前有 ${stats.extractableSelected} 条已选来源可归档原文，建议先执行归档。`,
      '抓取完成后再转入报告 Agent，避免把目录入口当作正式证据。',
      stats.shortfall ? `仍缺 ${stats.shortfall} 份已归档来源，可点击继续补抓至目标数量。` : '已归档数量达到客户目标，可进入整理。',
    ];
  }
  if (!stats.hasPack) {
    return [
      '来源池已具备基础资料，点击整理报告源包生成可审阅资料清单。',
      '资料包会保留已抓具体来源、站内检索目标、缺口和下一步建议。',
      stats.readySelected ? `已有 ${stats.readySelected} 条可转入报告 Agent 的本地归档证据。` : '如需写正式报告，先归档原文再转入报告 Agent。',
    ];
  }
  return [
    '资料包已整理，可直接导出 ZIP，内含 DOCX、PDF、manifest 和 sources 原文。',
    stats.readySelected ? `可转入报告 Agent 的已选证据：${stats.readySelected} 条。` : '如需转入报告 Agent，请选择已抓取原文的来源。',
    '后续正式报告写作只基于这些可核验来源展开。',
  ];
}

function consultCaptureStatusHtml(job) {
  if (!job) return '';
  const statusMap = {queued: '排队中', running: '采集中', completed: '已完成', failed: '失败'};
  const current = job.current_query ? `<div class="consult-capture-query">当前搜索式：${escHtml(job.current_query)}</div>` : '';
  const stopText = job.stop_reason_label || job.stop_reason || '';
  const stop = stopText ? `<div class="consult-capture-stop">停止原因：${escHtml(stopText)}</div>` : '';
  const breakdown = Object.entries(job.failure_breakdown || {})
    .map(([code, count]) => `<span class="consult-source-pill danger">${escHtml(consultFailureCodeLabel(code))} ${count}</span>`)
    .join('');
  const attempts = (job.attempts || []).slice(-4).reverse().map(a => `
    <div class="consult-attempt-row">
      <span>第${Number(a.round_no || 0)}轮</span>
      <b>${Number(a.result_count || 0)} 命中</b>
      <em>归档 ${Number(a.archived_delta || 0)} / 失败 ${Number(a.failed_delta || 0)} / 补充 ${Number(a.needs_user_input_delta || 0)}</em>
    </div>
  `).join('');
  const diagnosis = (job.diagnosis_cards || []).slice(0, 3).map(card => {
    const d = card.diagnosis || {};
    return `<div class="consult-diagnosis-card">
      <b>${escHtml(d.label || consultFailureCodeLabel(d.code))}</b>
      <span>${escHtml((card.title || card.url || '来源').slice(0, 80))}</span>
      <em>${escHtml(d.advice || card.reason || '可继续补抓或上传原文')}</em>
    </div>`;
  }).join('');
  return `<div class="consult-capture-status">
    <div class="consult-capture-top">
      <strong>一键采集任务 · ${escHtml(job.current_phase || '任务状态')}</strong>
      <span>${escHtml(statusMap[job.status] || job.status || '未知')}</span>
    </div>
    <div class="consult-capture-grid">
      <b>${job.archived_count || 0}<em>已归档</em></b>
      <b>${job.partial_count || 0}<em>待复核</em></b>
      <b>${job.needs_user_input_count || 0}<em>需补充</em></b>
      <b>${job.failed_count || 0}<em>失败</em></b>
    </div>
    <div class="consult-capture-microgrid">
      <span><b>${escHtml(consultFormatDuration(job.elapsed_seconds))}</b><em>任务耗时</em></span>
      <span><b>${Number(job.archived_per_minute || 0)}</b><em>份/分钟</em></span>
      <span><b>${Number(job.total_result_count || 0)}</b><em>搜索命中</em></span>
      <span><b>${Number(job.previewable_count || 0)}</b><em>可预览</em></span>
    </div>
    ${current}${stop}
    ${breakdown ? `<div class="consult-source-strip compact">${breakdown}</div>` : ''}
    ${attempts ? `<div class="consult-attempts">${attempts}</div>` : ''}
    ${diagnosis ? `<div class="consult-diagnosis-grid">${diagnosis}</div>` : ''}
  </div>`;
}

function consultRenderOpsBoard() {
  const board = document.getElementById('consultOpsBoard');
  if (!board) return;
  const stats = consultEvidenceStats();
  const state = consultOpsState(stats);
  const progress = consultOpsProgress(stats);
  const providerPills = Object.entries(stats.providers).slice(0, 4)
    .map(([name, count]) => `<span class="consult-source-pill">${escHtml(name)} ${count}</span>`).join('');
  const typePills = Object.entries(stats.docTypes)
    .map(([name, count]) => `<span class="consult-source-pill">${escHtml(name)} ${count}</span>`).join('');
  const strips = [
    providerPills,
    typePills,
    stats.targets ? `<span class="consult-source-pill">机构入口 ${stats.targets}</span>` : '',
    stats.partial ? `<span class="consult-source-pill">待复核 ${stats.partial}</span>` : '',
    stats.needsInput ? `<span class="consult-source-pill warn">需补充 ${stats.needsInput}</span>` : '',
    stats.failed ? `<span class="consult-source-pill danger">失败 ${stats.failed}</span>` : '',
    stats.highScore ? `<span class="consult-source-pill">高质量 ${stats.highScore}</span>` : '',
    stats.previewable ? `<span class="consult-source-pill">可预览 ${stats.previewable}</span>` : '',
    stats.relaxedFallback ? `<span class="consult-source-pill warn">低置信候选 ${stats.relaxedFallback}</span>` : '',
  ].filter(Boolean).join('');
  const next = consultNextSteps(stats).map((item, idx) => `
    <div class="consult-next-item"><span class="consult-next-num">${idx + 1}</span><span>${escHtml(item)}</span></div>
  `).join('');
  board.innerHTML = `
    <div class="consult-ops-head">
      <div>
        <div class="consult-ops-kicker">Source Pack Control</div>
        <div class="consult-ops-title">${escHtml(consultCurrentSession?.topic || '等待客户需求')}</div>
        <div class="consult-ops-sub">${escHtml(consultCurrentSession?.instruction || '这里显示检索完成度、证据质量和交付预检，不再留空。')}</div>
      </div>
      <span class="consult-ops-state ${state.cls}">${escHtml(state.text)}</span>
    </div>
    <div class="consult-ops-progress"><span style="width:${progress}%"></span></div>
    <div class="consult-ops-grid">
      <div class="consult-metric"><b>${stats.archived}/${stats.target || '-'}</b><span>已归档 / 客户目标</span></div>
      <div class="consult-metric"><b>${stats.concrete}</b><span>候选具体来源</span></div>
      <div class="consult-metric"><b>${stats.previewable || 0}</b><span>可预览资料</span></div>
      <div class="consult-metric"><b>${stats.archivedRate || stats.avgScore || '-'}</b><span>${stats.archivedRate ? '归档速度/分钟' : '来源质量均分'}</span></div>
    </div>
    <div class="consult-ops-lower">
      <div class="consult-checklist">
        <div class="consult-ops-section-title">交付预检</div>
        <div class="consult-check-row"><span>客户需求已拆解</span>${consultStatusPill(stats.hasSession)}</div>
        <div class="consult-check-row"><span>具体来源已检索</span>${consultStatusPill(stats.concrete > 0)}</div>
        <div class="consult-check-row"><span>原文已归档可引用</span>${consultStatusPill(stats.archived > 0, '待归档')}</div>
        <div class="consult-check-row"><span>资料包已整理</span>${consultStatusPill(stats.hasPack, '待整理')}</div>
      </div>
      <div class="consult-nextbox">
        <div class="consult-ops-section-title">下一步动作</div>
        ${next}
      </div>
    </div>
    <div class="consult-source-strip">${strips || '<span class="consult-source-pill">等待检索结果</span>'}</div>
    ${consultCaptureStatusHtml(consultCaptureJob)}
    ${consultArchivePath ? `<div class="consult-archive-path">本地资料库：${escHtml(consultArchivePath)}</div>` : ''}`;
  consultRenderWorkflowModules(stats);
}

function consultRenderPlan() {
  const el = document.getElementById('consultPlan');
  const badge = document.getElementById('consultSessionBadge');
  if (!el) return;
  if (!consultCurrentSession) {
    if (badge) badge.textContent = '未创建任务';
    el.innerHTML = '<div class="consult-empty">输入客户指令后，Agent 会生成报告源抓取计划、搜索式和证据目标。</div>';
    consultRenderOpsBoard();
    return;
  }
  const s = consultCurrentSession;
  const plan = s.plan || {};
  if (badge) badge.textContent = `目标 ${s.target_source_count || 0} 份来源`;
  const channels = (plan.channels || []).map(x => `<span class="consult-chip">${escHtml(x)}</span>`).join('');
  const keywords = (plan.keywords || []).slice(0, 8).map(x => `<span class="consult-chip">${escHtml(x)}</span>`).join('');
  el.innerHTML = `
    <div class="consult-plan-row"><strong>主题</strong><span>${escHtml(s.topic || '-')}</span></div>
    <div class="consult-plan-row"><strong>交付</strong><span>${escHtml(s.report_goal || '报告源抓取包')}</span></div>
    <div class="consult-plan-row"><strong>渠道</strong><span class="consult-chip-line">${channels || '<span class="consult-chip">未设置</span>'}</span></div>
    <div class="consult-plan-row"><strong>关键词</strong><span class="consult-chip-line">${keywords || '<span class="consult-chip">待生成</span>'}</span></div>`;
  consultRenderOpsBoard();
}

function consultRenderEvidence(meta) {
  const list = document.getElementById('consultEvidenceList');
  const metaEl = document.getElementById('consultSearchMeta');
  if (meta) consultLastMeta = meta;
  if (!list) return;
  if (metaEl) {
    if (meta) {
      const found = meta.archived_count ?? consultEvidence.filter(consultIsHandoffReady).length;
      const targetSeeds = meta.target_seed_count ?? 0;
      const shortfall = (meta.archive_shortfall ?? meta.shortfall) ? `，归档缺口 ${meta.archive_shortfall ?? meta.shortfall}` : '';
      metaEl.textContent = `已归档 ${found} / 目标 ${meta.target_source_count || consultEvidence.length}，待定位入口 ${targetSeeds}${shortfall}`;
    } else {
      metaEl.textContent = consultEvidence.length ? `已加载 ${consultEvidence.length} 份` : '尚未检索';
    }
  }
  consultRenderEvidenceFilters();
  if (!consultEvidence.length) {
    const rejected = meta?.web?.rejected_low_relevance || meta?.rejected_low_relevance || 0;
    const gap = meta?.archive_shortfall ?? meta?.shortfall ?? consultCurrentSession?.target_source_count ?? 0;
    const suggestions = (meta?.next_queries || meta?.topic_plan?.queries || []).slice(0, 3)
      .map(q => `<span class="consult-chip">${escHtml(q)}</span>`).join('');
    list.innerHTML = meta
      ? `<div class="consult-empty consult-empty-strong">
          <b>未找到足够相关的具体来源</b>
          <span>已完成本轮联网检索，但没有来源同时满足主题与能力关键词；已过滤低相关结果 ${rejected} 条，仍缺 ${gap} 份可归档资产。</span>
          ${suggestions ? `<div class="consult-chip-line">${suggestions}</div>` : ''}
          <span>可点击“继续补抓至目标”，或把需求写得更具体，例如加入机构、国家、装备或文件类型。</span>
        </div>`
      : '<div class="consult-empty">检索后将在这里列出已抓取的具体报告/分析，以及仍需站内检索的智库目标。</div>';
    consultRenderOpsBoard();
    return;
  }
  const visibleRows = consultFilteredEvidenceRows();
  if (!visibleRows.length) {
    list.innerHTML = `<div class="consult-empty consult-empty-strong">
      <b>当前视图暂无来源</b>
      <span>可切回“全部”，或继续补抓/归档来形成该状态的资料。</span>
    </div>`;
    consultRenderOpsBoard();
    return;
  }
  list.innerHTML = visibleRows.map(ev => {
    const selected = consultSelectedEvidence.has(ev.evidence_id);
    const payload = ev.payload || {};
    const asset = consultAssetForEvidence(ev.evidence_id);
    const provider = payload.provider || ev.provider || '';
    const docType = payload.document_type || ev.document_type || 'html';
    const fetched = consultIsHandoffReady(ev);
    const isTarget = ev.channel === 'thinktank_target';
    const status = asset?.status || payload.asset_status || '';
    const assetPayload = asset?.payload || {};
    const radar = assetPayload.quality_radar || payload.quality_radar || {};
    const diagnosis = assetPayload.diagnosis || payload.diagnosis || {};
    const relaxed = !!(payload.relaxed_fallback || ev.relaxed_fallback);
    const fetchState = isTarget ? '待站内定位'
      : (status === 'archived' || fetched ? '已归档原文'
        : status === 'partial' ? '正文待复核'
        : status === 'needs_user_input' ? '需用户补充'
        : status === 'failed' ? '抓取失败'
        : '待归档原文');
    const stateCls = status === 'archived' || fetched ? 'done'
      : status === 'failed' ? 'fail'
      : status === 'needs_user_input' ? 'need'
      : status === 'partial' ? 'partial'
      : 'todo';
    const query = payload.query || ev.query || '';
    const previewAction = asset?.asset_id
      ? `<button class="consult-evidence-action" onclick="consultPreviewAsset('${escHtml(asset.asset_id)}')" type="button">预览资料</button>`
      : (!isTarget && consultCanExtract(ev)
        ? `<button class="consult-evidence-action" onclick="consultArchiveThenPreview('${escHtml(ev.evidence_id)}')" type="button">抓取预览</button>`
        : '');
    const link = ev.url ? `<a class="consult-evidence-link" href="${escHtml(safeExternalUrl(ev.url))}" target="_blank" rel="noopener noreferrer">打开来源</a>` : '';
    const actions = (previewAction || link) ? `<div class="consult-evidence-links">${previewAction}${link}</div>` : '';
    const failure = asset?.failure_reason ? `<div class="consult-evidence-failure">${escHtml(asset.failure_reason).slice(0, 180)}</div>` : '';
    return `<article class="consult-evidence-card${selected ? ' selected' : ''}">
      <input class="consult-evidence-check" type="checkbox" ${selected ? 'checked' : ''}
        onchange="consultToggleEvidence('${escHtml(ev.evidence_id)}', this.checked)">
      <div>
        <div class="consult-evidence-top">
          <span class="consult-channel">${escHtml(ev.channel || 'source')}</span>
          ${provider ? `<span class="consult-provider">${escHtml(provider)}</span>` : ''}
          <span class="consult-doc-type">${escHtml(String(docType).toUpperCase())}</span>
          <span class="consult-fetch-state ${stateCls}">${fetchState}</span>
          ${relaxed ? '<span class="consult-fetch-state partial">低置信候选</span>' : ''}
          ${radar.overall ? `<span class="consult-quality-radar">Q ${Number(radar.overall)}</span>` : ''}
          <span class="consult-score">${Number(ev.score || 0)}分</span>
          <span class="consult-source">${escHtml(ev.source || '公开来源')}</span>
          <span class="consult-date">${escHtml((ev.published_at || '').slice(0, 10))}</span>
        </div>
        <div class="consult-evidence-title">${escHtml(ev.title || '未命名来源')}</div>
        <div class="consult-evidence-snippet">${escHtml((ev.snippet || ev.reason || '').slice(0, 220))}</div>
        ${failure}
        ${diagnosis.label ? `<div class="consult-evidence-diagnosis"><b>${escHtml(diagnosis.label)}</b><span>${escHtml(diagnosis.advice || '可继续补抓或上传原文')}</span></div>` : ''}
        ${query ? `<div class="consult-evidence-query">${escHtml(query).slice(0, 180)}</div>` : ''}
        ${actions}
      </div>
    </article>`;
  }).join('');
  consultRenderOpsBoard();
}

function consultCanExtract(ev) {
  return !!(ev && ev.url);
}

function consultIsHandoffReady(ev) {
  const payload = ev?.payload || {};
  const asset = consultAssetForEvidence(ev?.evidence_id);
  return !!(ev && (ev.channel === 'imported'
    || (ev.channel !== 'thinktank_target' && ((payload.asset_status === 'archived' && payload.asset_id) || asset?.status === 'archived'))));
}

function consultPreviewTextHtml(text) {
  const clean = String(text || '').trim();
  if (!clean) return '<div class="consult-asset-empty"><strong>暂无可预览正文</strong><span>该来源可能只有原件、正文过短，或需要人工上传/授权后再抽取。</span></div>';
  return clean
    .split(/\n{2,}/)
    .slice(0, 120)
    .map(block => `<p>${escHtml(block).replace(/\n/g, '<br>')}</p>`)
    .join('');
}

function consultCloseAssetPreview() {
  consultCurrentPreview = null;
  const box = document.getElementById('consultAssetPreview');
  if (!box) return;
  box.className = 'consult-asset-preview is-empty';
  box.innerHTML = `<div class="consult-asset-empty">
    <strong>资料阅读窗</strong>
    <span>在来源池点击“预览”，PDF 会在这里直接打开；DOCX/网页会以文档页方式显示已抽取正文。</span>
  </div>`;
}

function consultRenderAssetPreview(data) {
  const box = document.getElementById('consultAssetPreview');
  if (!box) return;
  const asset = data?.asset || {};
  const title = asset.title || '未命名资料';
  const source = asset.source || asset.url || '本地归档资料';
  const type = String(asset.document_type || 'document').toUpperCase();
  const status = asset.status || '-';
  const wordCount = asset.word_count ? `${asset.word_count} 字` : '字数未知';
  const fileUrl = data?.file_url || '';
  const downloadUrl = data?.download_url || fileUrl;
  const isBlockedReader = data?.reader_mode === 'blocked' || ['needs_user_input', 'failed'].includes(String(status));
  const radar = asset.quality_radar || {};
  const diagnosis = asset.diagnosis || {};
  const outline = (data?.outline || []).slice(0, 10);
  const radarHtml = radar.overall ? `<div class="consult-reader-radar">
    <span><b>${Number(radar.overall)}</b><em>综合</em></span>
    <span><b>${Number(radar.authority || 0)}</b><em>机构</em></span>
    <span><b>${Number(radar.topic || 0)}</b><em>主题</em></span>
    <span><b>${Number(radar.extractability || 0)}</b><em>正文</em></span>
  </div>` : '';
  const outlineHtml = outline.length ? `<aside class="consult-reader-outline">
    <strong>文档目录线索</strong>
    ${outline.map(item => `<span>${escHtml(item)}</span>`).join('')}
  </aside>` : '';
  const diagnosisHtml = diagnosis.label ? `<div class="consult-reader-diagnosis">
    <b>${escHtml(diagnosis.label)}</b><span>${escHtml(diagnosis.advice || asset.failure_reason || '')}</span>
  </div>` : '';
  const blockedBody = `<div class="consult-blocked-source">
      <div class="consult-blocked-icon">!</div>
      <div>
        <h4>${escHtml(diagnosis.label || '来源暂不可直接预览')}</h4>
        <p>${escHtml(diagnosis.advice || asset.failure_reason || '该来源没有形成可直接浏览的本地原文。')}</p>
        ${asset.failure_reason ? `<code>${escHtml(asset.failure_reason)}</code>` : ''}
      </div>
    </div>`;
  const body = isBlockedReader
    ? blockedBody
    : data?.preview_mode === 'pdf' && fileUrl
    ? `<iframe class="consult-asset-frame" src="${escHtml(fileUrl)}#view=FitH"></iframe>`
    : `<div class="consult-reader-layout">${outlineHtml}<div class="consult-document-paper">${consultPreviewTextHtml(data?.text || '')}</div></div>`;
  const openLink = asset.url ? `<a class="consult-preview-link" href="${escHtml(safeExternalUrl(asset.url))}" target="_blank" rel="noopener noreferrer">打开网页</a>` : '';
  const downloadLink = downloadUrl ? `<a class="consult-preview-link" href="${escHtml(safeUrl(downloadUrl))}" target="_blank" rel="noopener">下载原件</a>` : '';
  box.className = 'consult-asset-preview';
  box.innerHTML = `<div class="consult-asset-head">
      <div>
        <div class="consult-asset-kicker">SOURCE READER</div>
        <h4>${escHtml(title)}</h4>
        <p>${escHtml(source)}</p>
      </div>
      <div class="consult-asset-actions">
        <span>${escHtml(type)}</span>
        <span>${escHtml(isBlockedReader ? '受限诊断' : String(data?.reader_mode || 'document').toUpperCase())}</span>
        <span>${escHtml(status)}</span>
        <span>${escHtml(wordCount)}</span>
        ${openLink}
        ${downloadLink}
        <button type="button" onclick="consultCloseAssetPreview()">关闭</button>
      </div>
    </div>
    ${radarHtml}${diagnosisHtml}
    <div class="consult-asset-body">${body}</div>`;
}

async function consultPreviewAsset(assetId) {
  if (!consultCurrentSession?.session_id || !assetId) return;
  const box = document.getElementById('consultAssetPreview');
  if (box) {
    box.className = 'consult-asset-preview';
    box.innerHTML = '<div class="consult-loading"><div class="ai-spinner-sm"></div><span>正在打开本地归档资料…</span></div>';
  }
  try {
    const resp = await apiFetch(`/api/consult/sessions/${encodeURIComponent(consultCurrentSession.session_id)}/assets/${encodeURIComponent(assetId)}/preview`, {}, {toast: false});
    const data = await resp.json();
    consultCurrentPreview = data;
    consultRenderAssetPreview(data);
  } catch(e) {
    if (box) {
      box.innerHTML = `<div class="ai-error">资料预览失败<br><small>${escHtml(e.message)}</small>
        <div style="margin-top:10px;color:#93c5fd;font-size:12px">已保留来源卡片，可点击“打开来源”或重新抓取预览。</div></div>`;
    }
    consultRefreshSessionBundle(false).catch(() => {});
  }
}

async function consultArchiveThenPreview(evidenceId) {
  if (!evidenceId) return;
  const data = await consultExtractEvidenceIds([evidenceId], {silent: true});
  const asset = consultAssetForEvidence(evidenceId) || (data?.assets || []).find(a => a.evidence_id === evidenceId);
  if (asset?.asset_id) {
    await consultPreviewAsset(asset.asset_id);
  } else {
    showToast('该来源暂未形成可预览资料');
  }
}

function consultDefaultEvidenceSelection(rows) {
  const concrete = (rows || []).filter(consultCanExtract);
  return new Set((concrete.length ? concrete : rows || []).map(ev => ev.evidence_id));
}

function consultRenderReport(answer) {
  const body = document.getElementById('consultSourcePackBody');
  if (!body) return;
  const content = answer?.content || '';
  body.innerHTML = content ? renderMarkdown(content) : '<div class="consult-empty">上方交付预检会实时显示来源数量、正文抓取、选中状态与下一步动作。整理报告源包后，这里显示可导出的正文预览。</div>';
  consultRenderOpsBoard();
}

async function consultCreateSession() {
  const instruction = document.getElementById('consultInstruction')?.value.trim() || '';
  if (!instruction) { showToast('请输入客户指令'); return null; }
  const parsedCount = consultExtractRequestedCount(instruction);
  const countEl = document.getElementById('consultTargetCount');
  const target = parsedCount || parseInt(countEl?.value || '20', 10) || 20;
  if (countEl) countEl.value = target;
  try {
    const resp = await apiFetch('/api/consult/sessions', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        instruction,
        target_source_count: target,
        search_web: document.getElementById('consultSearchWeb')?.checked !== false,
      }),
    }, {toast: false});
    const data = await resp.json();
    consultCurrentSession = data.session;
    consultEvidence = [];
    consultSelectedEvidence = new Set();
    consultCurrentAnswer = null;
    consultLastMeta = null;
    consultAssets = [];
    consultAssetFailures = [];
    consultArchivePath = '';
    consultCaptureJob = null;
    consultCurrentPreview = null;
    consultEvidenceFilter = 'all';
    consultCloseAssetPreview();
    if (consultCapturePollTimer) {
      clearTimeout(consultCapturePollTimer);
      consultCapturePollTimer = null;
    }
    consultRememberSession(data.session?.session_id);
    consultSessions = [data.session, ...consultSessions.filter(s => s.session_id !== data.session?.session_id)];
    consultRenderSessions();
    consultSetCapability(data);
    consultRenderPlan();
    consultRenderEvidence();
    consultRenderReport();
    showToast('已拆解咨询任务');
    return consultCurrentSession;
  } catch(e) {
    showToast('任务创建失败：' + e.message);
    return null;
  }
}

async function consultSearchSources() {
  if (consultBusy) return;
  if (!consultCurrentSession) {
    const created = await consultCreateSession();
    if (!created) return;
  }
  const count = parseInt(document.getElementById('consultTargetCount')?.value || consultCurrentSession.target_source_count || 20, 10);
  consultSetBusy(true, '正在调用联网搜索服务抓取报告/分析来源…');
  try {
    const resp = await apiFetch(`/api/consult/sessions/${encodeURIComponent(consultCurrentSession.session_id)}/search`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        target_count: count,
        search_web: document.getElementById('consultSearchWeb')?.checked !== false,
        include_pdf: true,
        include_news: true,
        include_doctrine: true,
      }),
    }, {toast: false});
    const data = await resp.json();
    consultCurrentSession = data.session || consultCurrentSession;
    consultEvidence = data.evidence || [];
    consultSelectedEvidence = consultDefaultEvidenceSelection(consultEvidence);
    consultCurrentAnswer = null;
    consultAssets = data.meta?.assets || consultAssets;
    consultArchivePath = data.meta?.source_archive_path || consultArchivePath;
    consultSetCapability(data);
    consultRenderPlan();
    consultRenderEvidence(data.meta || {});
    consultRenderReport();
    consultLoadSessions({silent: true}).catch(() => {});
    const gap = data.meta?.archive_shortfall ?? data.meta?.shortfall;
    const shortfall = gap ? `，归档缺口 ${gap}` : '';
    showToast(`联网搜索完成：候选${data.meta?.found_count ?? consultEvidence.length}份，已归档${data.meta?.archived_count ?? 0}份${shortfall}`);
  } catch(e) {
    consultRenderReport();
    showToast('检索失败：' + e.message);
  } finally {
    consultBusy = false;
    consultRenderOpsBoard();
  }
}

async function consultRefreshSessionBundle(render = true) {
  if (!consultCurrentSession?.session_id) return null;
  const detailResp = await apiFetch(`/api/consult/sessions/${encodeURIComponent(consultCurrentSession.session_id)}`, {}, {toast: false});
  const detail = await detailResp.json();
  consultCurrentSession = detail.session || consultCurrentSession;
  consultEvidence = detail.evidence || consultEvidence;
  if (!consultCurrentAnswer && Array.isArray(detail.answers) && detail.answers.length) {
    consultCurrentAnswer = detail.answers[0];
  }
  consultSetCapability(detail);
  const assetResp = await apiFetch(`/api/consult/sessions/${encodeURIComponent(consultCurrentSession.session_id)}/assets`, {}, {toast: false});
  const assetData = await assetResp.json();
  consultAssets = assetData.assets || consultAssets;
  consultArchivePath = assetData.source_archive_path || consultArchivePath;
  consultLastMeta = {
    ...(consultLastMeta || {}),
    archived_count: assetData.archived_count || 0,
    partial_count: assetData.partial_count || 0,
    failed_count: assetData.failed_count || 0,
    needs_user_input_count: assetData.needs_user_input_count || 0,
    previewable_count: assetData.previewable_count || 0,
    failure_breakdown: assetData.failure_breakdown || {},
    diagnosis_cards: assetData.diagnosis_cards || [],
    archive_shortfall: assetData.archive_shortfall || 0,
    target_source_count: consultCurrentSession.target_source_count,
    source_archive_path: assetData.source_archive_path || '',
  };
  const ready = consultEvidence.filter(consultIsHandoffReady);
  consultSelectedEvidence = new Set((ready.length ? ready : consultEvidence.filter(consultCanExtract)).map(ev => ev.evidence_id));
  if (render) {
    consultRenderPlan();
    consultRenderEvidence(consultLastMeta);
    consultRenderReport(consultCurrentAnswer);
  }
  return {detail, assetData};
}

async function consultPollCaptureJob(jobId) {
  if (!consultCurrentSession?.session_id || !jobId) return;
  try {
    const resp = await apiFetch(`/api/consult/sessions/${encodeURIComponent(consultCurrentSession.session_id)}/capture_jobs/${encodeURIComponent(jobId)}`, {}, {toast: false});
    const data = await resp.json();
    consultCaptureJob = data.job || consultCaptureJob;
    await consultRefreshSessionBundle(true);
    if (consultCaptureJobActive(consultCaptureJob)) {
      consultCapturePollTimer = setTimeout(() => consultPollCaptureJob(jobId), 1000);
      return;
    }
    consultBusy = false;
    consultRenderOpsBoard();
    consultLoadSessions({silent: true}).catch(() => {});
    const archived = consultCaptureJob?.archived_count || 0;
    const target = consultCaptureJob?.target_count || consultCurrentSession?.target_source_count || 0;
    if (consultCaptureJob?.status === 'failed') {
      showToast(`采集任务失败：${consultCaptureJob.stop_reason || '未知错误'}`);
    } else if (archived >= target) {
      showToast(`采集完成：已归档 ${archived}/${target} 份可引用来源`);
    } else {
      showToast(`采集完成：已归档 ${archived}/${target} 份，缺口原因已记录`);
    }
  } catch(e) {
    consultBusy = false;
    consultRenderOpsBoard();
    showToast('采集进度读取失败：' + e.message);
  }
}

async function consultCaptureToTarget(opts = {}) {
  if (consultBusy) return;
  if (opts.reset) {
    consultCurrentSession = null;
    consultEvidence = [];
    consultSelectedEvidence = new Set();
    consultCurrentAnswer = null;
    consultAssets = [];
    consultLastMeta = null;
    consultCaptureJob = null;
  }
  if (!consultCurrentSession) {
    const created = await consultCreateSession();
    if (!created) return;
  }
  const target = parseInt(document.getElementById('consultTargetCount')?.value || consultCurrentSession.target_source_count || '20', 10) || 20;
  const deep = opts.deep === true;
  consultSetBusy(true, deep ? '正在深度补抓：联网搜索、直接抓取与浏览器渲染兜底并行处理…' : '正在一键联网搜索、站内定位、抓取正文/PDF并归档到本地资料库…');
  try {
    const resp = await apiFetch(`/api/consult/sessions/${encodeURIComponent(consultCurrentSession.session_id)}/capture_to_target`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        target_count: target,
        batch_size: deep ? 8 : 14,
        max_rounds: deep ? 10 : 8,
        crawl_mode: deep ? 'deep' : 'fast',
        allow_browser_render: deep,
      }),
    }, {toast: false});
    const data = await resp.json();
    consultCaptureJob = data;
    consultRenderOpsBoard();
    await consultRefreshSessionBundle(true);
    if (consultCaptureJobActive(consultCaptureJob)) {
      consultCapturePollTimer = setTimeout(() => consultPollCaptureJob(data.job_id), 700);
    } else {
      consultBusy = false;
      consultRenderOpsBoard();
      consultLoadSessions({silent: true}).catch(() => {});
      showToast(`采集完成：已归档 ${data.archived_count || 0}/${data.target_count || target} 份`);
    }
  } catch(e) {
    consultBusy = false;
    consultRenderReport();
    showToast('一键采集失败：' + e.message);
  }
}

async function consultRunSourceAgent() {
  if (consultBusy) return;
  await consultCaptureToTarget({reset: true});
}

function consultMergeEvidence(rows) {
  const byId = new Map(consultEvidence.map(ev => [ev.evidence_id, ev]));
  (rows || []).forEach(ev => byId.set(ev.evidence_id, ev));
  consultEvidence = [...byId.values()];
}

function consultToggleEvidence(id, checked) {
  if (checked) consultSelectedEvidence.add(id);
  else consultSelectedEvidence.delete(id);
  consultRenderEvidence();
}

function consultSelectAllEvidence() {
  if (!consultEvidence.length) return;
  const visibleRows = consultFilteredEvidenceRows();
  const scope = visibleRows.length ? visibleRows : consultEvidence;
  const allSelected = scope.every(ev => consultSelectedEvidence.has(ev.evidence_id));
  const next = new Set(consultSelectedEvidence);
  scope.forEach(ev => {
    if (allSelected) next.delete(ev.evidence_id);
    else next.add(ev.evidence_id);
  });
  consultSelectedEvidence = next;
  consultRenderEvidence();
}

async function consultBuildSourcePack() {
  if (consultBusy) return;
  if (!consultCurrentSession) { showToast('请先拆解任务'); return; }
  if (!consultEvidence.length) { showToast('请先检索报告源'); return; }
  const ids = consultSelectedEvidence.size ? [...consultSelectedEvidence] : consultEvidence.map(ev => ev.evidence_id);
  consultSetBusy(true, '正在整理报告源抓取包…');
  try {
    const resp = await apiFetch(`/api/consult/sessions/${encodeURIComponent(consultCurrentSession.session_id)}/source_pack`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        evidence_ids: ids,
        note: document.getElementById('consultWritingReq')?.value.trim() || '',
      }),
    }, {toast: false});
    const data = await resp.json();
    consultCurrentAnswer = data.answer;
    consultRenderReport(consultCurrentAnswer);
    consultLoadSessions({silent: true}).catch(() => {});
    showToast('报告源包已整理');
  } catch(e) {
    document.getElementById('consultSourcePackBody').innerHTML = `<div class="ai-error">整理失败<br><small>${escHtml(e.message)}</small></div>`;
  } finally {
    consultBusy = false;
    consultRenderOpsBoard();
  }
}

async function consultExportSourcePack() {
  if (consultBusy) return;
  if (!consultCurrentSession) { showToast('请先搜集资料'); return; }
  if (!consultCurrentAnswer && consultEvidence.length) {
    await consultBuildSourcePack();
  }
  const ids = consultSelectedEvidence.size ? [...consultSelectedEvidence] : consultEvidence.map(ev => ev.evidence_id);
  try {
    const resp = await apiFetch(`/api/consult/sessions/${encodeURIComponent(consultCurrentSession.session_id)}/export_source_pack`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        answer_id: consultCurrentAnswer?.answer_id || '',
        evidence_ids: ids,
      }),
    }, {toast: false});
    await downloadResponseBlob(resp, '报告源资料包.zip', '.zip');
    showToast('资料包已导出（DOCX + PDF + manifest + sources）');
  } catch(e) {
    showToast('导出失败：' + e.message);
  }
}

async function consultExtractEvidenceIds(ids, opts = {}) {
  if (!consultCurrentSession) { showToast('请先拆解任务'); return; }
  if (!consultEvidence.length) { showToast('请先联网搜索报告源'); return; }
  if (!ids.length) { showToast('没有可归档的来源'); return null; }
  consultSetBusy(true, '正在站内定位并归档网页正文/PDF原文…');
  try {
    const resp = await apiFetch(`/api/consult/sessions/${encodeURIComponent(consultCurrentSession.session_id)}/extract`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({evidence_ids: ids, allow_browser_render: opts.deep === true}),
    }, {toast: false});
    const data = await resp.json();
    consultMergeEvidence(data.resolved_evidence || []);
    consultMergeEvidence(data.evidence || []);
    consultAssets = data.all_assets || data.assets || consultAssets;
    consultAssetFailures = data.failures || [];
    consultArchivePath = data.meta?.source_archive_path || consultArchivePath;
    const focusRows = [...(data.evidence || []), ...(data.resolved_evidence || [])];
    consultSelectedEvidence = new Set((focusRows.length ? focusRows : consultEvidence).map(ev => ev.evidence_id));
    consultRenderEvidence({
      ...(data.meta || {}),
      found_count: consultEvidence.filter(ev => ev.channel !== 'thinktank_target').length,
      target_source_count: consultCurrentSession.target_source_count,
      archived_count: data.meta?.archived_count ?? data.archived_count,
      failed_count: data.meta?.failed_count ?? (data.failures || []).length,
    });
    consultRenderReport();
    consultLoadSessions({silent: true}).catch(() => {});
    const failed = (data.failures || []).length ? `，失败 ${data.failures.length} 条` : '';
    if (!opts.silent) showToast(`原文归档完成：${data.archived_count || 0} 条${failed}`);
    return data;
  } catch(e) {
    consultRenderReport();
    showToast('原文归档失败：' + e.message);
    return null;
  } finally {
    consultBusy = false;
    consultRenderOpsBoard();
  }
}

async function consultExtractSources() {
  if (consultBusy) return;
  const visibleRows = consultFilteredEvidenceRows();
  const scope = visibleRows.length ? visibleRows : consultEvidence;
  const ids = consultSelectedEvidence.size ? [...consultSelectedEvidence] : scope.filter(consultCanExtract).map(ev => ev.evidence_id);
  return consultExtractEvidenceIds(ids);
}

async function consultArchiveSources() {
  return consultExtractSources();
}

async function consultContinueToTarget() {
  if (consultBusy) return;
  if (!consultCurrentSession) { showToast('请先输入客户需求'); return; }
  const stats = consultEvidenceStats();
  if (stats.shortfall <= 0) { showToast('已达到客户目标归档数量'); return; }
  await consultCaptureToTarget();
}

async function consultDeepRetryToTarget() {
  if (consultBusy) return;
  if (!consultCurrentSession) { showToast('请先输入客户需求'); return; }
  await consultCaptureToTarget({deep: true});
}

async function consultOpenLocalArchive() {
  if (!consultCurrentSession) { showToast('请先搜集资料'); return; }
  try {
    const resp = await apiFetch(`/api/consult/sessions/${encodeURIComponent(consultCurrentSession.session_id)}/assets`, {}, {toast: false});
    const data = await resp.json();
    consultAssets = data.assets || [];
    consultArchivePath = data.source_archive_path || consultArchivePath;
    consultRenderOpsBoard();
    const text = consultArchivePath || '暂无本地资料库路径';
    if (navigator.clipboard && text) await navigator.clipboard.writeText(text);
    showToast(`本地资料库路径已复制：${text}`);
  } catch(e) {
    showToast('读取本地资料库失败：' + e.message);
  }
}

async function consultHandoffToReportAgent() {
  if (consultBusy) return;
  if (!consultCurrentSession) { showToast('请先拆解任务'); return; }
  if (!consultEvidence.length) { showToast('请先联网搜索并抓取原文'); return; }
  let ready = consultEvidence.filter(ev => consultSelectedEvidence.has(ev.evidence_id) && consultIsHandoffReady(ev));
  const selectedRows = consultEvidence.filter(ev => consultSelectedEvidence.has(ev.evidence_id));
  const extractable = selectedRows.filter(ev => consultCanExtract(ev) && !consultIsHandoffReady(ev));
  if (!ready.length && extractable.length) {
    showToast('先归档正文/PDF，再转入报告Agent');
    const extracted = await consultExtractEvidenceIds(extractable.map(ev => ev.evidence_id), {silent: true});
    if (extracted) {
      showToast(`原文归档完成：${extracted.archived_count || 0} 条，准备转入`);
      ready = consultEvidence.filter(ev => consultSelectedEvidence.has(ev.evidence_id) && consultIsHandoffReady(ev));
    }
  }
  if (!ready.length) { showToast('请选择已归档原文的来源再转入报告Agent'); return; }
  try {
    const resp = await apiFetch(`/api/consult/sessions/${encodeURIComponent(consultCurrentSession.session_id)}/handoff_to_report_agent`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({evidence_ids: ready.map(ev => ev.evidence_id)}),
    }, {toast: false});
    const data = await resp.json();
    if (typeof agentCurrentProject !== 'undefined') agentCurrentProject = data.project;
    showToast(`已转入报告Agent：${data.imported_count || 0} 条证据`);
    if (typeof showTab === 'function') showTab('agent');
    if (typeof agentLoadProjects === 'function') agentLoadProjects();
  } catch(e) {
    showToast('转入报告Agent失败：' + e.message);
  }
}

async function consultSynthesize() {
  return consultBuildSourcePack();
}

async function consultRevise() {
  if (consultBusy) return;
  if (!consultCurrentSession || !consultCurrentAnswer) { showToast('暂无可整理资料包'); return; }
  const instruction = document.getElementById('consultRevisionInput')?.value.trim() || '';
  if (!instruction) { showToast('请输入资料包备注'); return; }
  consultSetBusy(true, '正在按备注整理资料包…');
  try {
    const resp = await apiFetch(`/api/consult/sessions/${encodeURIComponent(consultCurrentSession.session_id)}/revise`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({answer_id: consultCurrentAnswer.answer_id, instruction}),
    }, {toast: false});
    const data = await resp.json();
    consultCurrentAnswer = data.answer;
    const input = document.getElementById('consultRevisionInput');
    if (input) input.value = '';
    consultRenderReport(consultCurrentAnswer);
    consultLoadSessions({silent: true}).catch(() => {});
    showToast('资料包已整理');
  } catch(e) {
    document.getElementById('consultSourcePackBody').innerHTML = `<div class="ai-error">整理失败<br><small>${escHtml(e.message)}</small></div>`;
  } finally {
    consultBusy = false;
  }
}

function consultCopySourcePack() {
  const body = document.getElementById('consultSourcePackBody');
  const text = body?.innerText || body?.textContent || '';
  if (!text.trim()) return;
  navigator.clipboard.writeText(text).then(() => showToast('报告源包已复制'));
}

function consultCopyReport() {
  return consultCopySourcePack();
}

function consultInit() {
  loadSearchStatus();
  consultRenderPlan();
  consultRenderEvidence();
  consultRenderReport();
  consultCloseAssetPreview();
  consultLoadSessions({restore: true}).catch(() => {});
}

// ── AI 流式请求 ───────────────────────────────────────────
async function aiStreamRequest(payload) {
  const body = document.getElementById('aiResultBody');
  body.innerHTML = '';
  let fullText = '';

  try {
    const resp = await apiFetch('/api/ai/stream', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload),
    }, {toast: false});

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const chunk = line.slice(6).trim();
        if (chunk === '[DONE]') break;
        try {
          const obj = JSON.parse(chunk);
          if (obj.error) throw new Error(obj.error);
          if (obj.text) {
            fullText += obj.text;
            body.innerHTML = renderMarkdown(fullText);
            body.scrollTop = body.scrollHeight;
          }
        } catch(e) {
          if (e.message && !e.message.includes('JSON')) throw e;
        }
      }
    }

    // 流式完成后的最终渲染
    if (fullText) {
      body.innerHTML = renderMarkdown(fullText);
      document.getElementById('aiModelBadge').textContent = payload.mode;
      showToast('✅ AI分析完成');
    } else {
      // 如果流式没有内容，尝试非流式fallback
      const data = await apiFetch('/api/ai/analyze', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload),
      }, {toast: false}).then(r => r.json());
      if (data.error) throw new Error(data.error);
      fullText = data.result || '';
      body.innerHTML = renderMarkdown(fullText);
      document.getElementById('aiModelBadge').textContent = data.model || '';
      showToast('✅ AI分析完成');
    }
  } catch(e) {
    // 流式失败，尝试非流式
    try {
      const data = await apiFetch('/api/ai/analyze', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload),
      }, {toast: false}).then(r => r.json());
      if (data.error) throw new Error(data.error);
      fullText = data.result || '';
      body.innerHTML = renderMarkdown(fullText);
      document.getElementById('aiModelBadge').textContent = data.model || '';
      showToast('✅ AI分析完成');
    } catch(e2) {
      setAiResultError(e2.message || e.message);
    }
  }
}

function renderMarkdown(text) {
  if (typeof marked !== 'undefined') {
    try {
      const html = marked.parse(text);
      if (typeof DOMPurify !== 'undefined') {
        return DOMPurify.sanitize(html, {USE_PROFILES: {html: true}});
      }
    } catch(e) {}
  }
  return '<pre>' + escHtml(text) + '</pre>';
}

// ── AI 结果面板控制 ──────────────────────────────────────
function showAiResult(icon, label) {
  const panel = document.getElementById('aiResultPanel');
  panel.style.display = '';
  document.getElementById('aiResultIcon').textContent = icon;
  document.getElementById('aiResultLabel').textContent = label;
  document.getElementById('aiModelBadge').textContent = '';
  document.getElementById('aiResultBody').innerHTML =
    '<div class="ai-loading"><div class="ai-spinner"></div><p>AI 正在分析中，请稍候…</p></div>';
  panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function setAiResultError(msg) {
  document.getElementById('aiResultBody').innerHTML =
    `<div class="ai-error">❌ 分析失败<br><small>${escHtml(msg)}</small></div>`;
}

function aiCloseResult() {
  document.getElementById('aiResultPanel').style.display = 'none';
}

function aiCopyResult() {
  const body = document.getElementById('aiResultBody');
  const text = body.innerText || body.textContent;
  navigator.clipboard.writeText(text).then(() => showToast('已复制到剪贴板'));
}

// 右键菜单
document.addEventListener('contextmenu', e => {
  const card = e.target.closest('.news-card');
  if (!card) { hideCtxMenu(); return; }
  e.preventDefault();
  ctxTarget = card;
  const menu = document.getElementById('ctxMenu');
  menu.style.display = 'block';
  // 定位
  const x = Math.min(e.clientX, window.innerWidth - 200);
  const y = Math.min(e.clientY, window.innerHeight - 250);
  menu.style.left = x + 'px';
  menu.style.top = y + 'px';
});

document.addEventListener('click', e => {
  if (!e.target.closest('.ctx-menu')) hideCtxMenu();
});

function hideCtxMenu() {
  document.getElementById('ctxMenu').style.display = 'none';
}

function getCtxArticle() {
  if (!ctxTarget) return null;
  const link = ctxTarget.dataset.link;
  return allNews.find(a => a.link === link) || window._currentNews?.find(a => a.link === link);
}

function ctxAiAnalyze() {
  hideCtxMenu();
  const article = getCtxArticle();
  if (!article) return;
  if (!aiEnabled) { showToast('请先配置AI'); return; }
  showTab('ai');
  setTimeout(() => {
    showAiResult('🔍', '深度分析中…');
    aiStreamRequest({ mode: 'analyze', articles: [article] });
  }, 300);
}

function ctxAiCompare() {
  hideCtxMenu();
  const article = getCtxArticle();
  if (!article) return;
  const exists = newsMultiSelect.has(article.link);
  if (exists) {
    newsMultiSelect.delete(article.link);
    ctxTarget.classList.remove('multi-selected');
  } else {
    newsMultiSelect.add(article.link);
    ctxTarget.classList.add('multi-selected');
  }
  updateFab();
}

function ctxTranslate() {
  hideCtxMenu();
  const btn = ctxTarget?.querySelector('.translate-btn');
  if (btn) btn.click();
}

function ctxBookmark() {
  hideCtxMenu();
  const btn = ctxTarget?.querySelector('.bookmark-btn');
  if (btn) btn.click();
}

function ctxCopyLink() {
  hideCtxMenu();
  const article = getCtxArticle();
  if (article) navigator.clipboard.writeText(article.link).then(() => showToast('链接已复制'));
}

function ctxOpenNew() {
  hideCtxMenu();
  const article = getCtxArticle();
  const url = article ? safeExternalUrl(article.link) : '#';
  if (url !== '#') window.open(url, '_blank', 'noopener,noreferrer');
}

// AI 浮动按钮
function updateFab() {
  const fab = document.getElementById('aiFab');
  const count = document.getElementById('aiFabCount');
  if (newsMultiSelect.size > 0) {
    fab.style.display = 'flex';
    count.textContent = newsMultiSelect.size;
  } else {
    fab.style.display = 'none';
  }
}

function aiAnalyzeSelected() {
  if (!aiEnabled) { showToast('⚠️ 请先配置AI'); return; }
  const articles = allNews.filter(a => newsMultiSelect.has(a.link));
  if (articles.length < 1) return;
  newsMultiSelect.clear();
  updateFab();
  document.querySelectorAll('.news-card.multi-selected').forEach(c => c.classList.remove('multi-selected'));
  showTab('ai');
  setTimeout(() => {
    const mode = articles.length >= 2 ? 'compare' : 'analyze';
    showAiResult(mode === 'compare' ? 'CP' : 'AN', mode === 'compare' ? '对比分析中…' : '深度分析中…');
    aiStreamRequest({ mode, articles });
  }, 300);
}

// ── 标签页增加AI ─────────────────────────────────────────
const TAB_KEYS_V7 = { '1':'news','2':'china','3':'thinktanks','4':'ai','5':'agent','6':'brief' };

// 覆盖原来的键盘快捷键
document.removeEventListener('keydown', null); // 无法移除匿名函数，所以重新注册
document.addEventListener('keydown', e => {
  const tag = document.activeElement?.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA') {
    if (e.key === 'Escape') { document.activeElement.blur(); clearSearch(); }
    return;
  }
  if (e.key === '/') { e.preventDefault(); document.getElementById('newsSearch')?.focus(); }
  if (TAB_KEYS_V7[e.key]) showTab(TAB_KEYS_V7[e.key]);
  if (e.key === 'Escape') { clearSearch(); hideCtxMenu(); }
  if (e.key === 'r' || e.key === 'R') { fetchAll(); showToast('正在刷新…'); }
}, true);

// 初始化AI兼容功能与咨询工作台
window.addEventListener('DOMContentLoaded', () => { consultInit(); });

// ══════════════════════════════════════════════════════════
// 🤖 AI 内嵌快速分析（新闻卡片内）
// ══════════════════════════════════════════════════════════
async function aiQuickAnalyze(idx) {
  const item = window._currentNews[idx];
  if (!item) return;
  if (!aiEnabled) { showToast('请先在AI分析标签页配置API'); return; }
  const el = document.getElementById('ai-' + idx);
  if (!el) return;
  if (el.style.display !== 'none') { el.style.display = 'none'; return; }
  el.style.display = 'block';
  el.innerHTML = '<div class="ai-inline-loading"><div class="ai-spinner-sm"></div> AI分析中…</div>';

  try {
    const data = await apiFetch('/api/ai/analyze', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ mode: 'analyze', articles: [item] })
    }, {toast: false}).then(r => r.json());
    if (data.error) {
      el.innerHTML = `<div class="ai-inline-err">${escHtml(data.error)}</div>`;
    } else {
      el.innerHTML = `<div class="ai-inline-content">${renderMarkdown(data.result)}</div>`;
    }
  } catch(e) {
    el.innerHTML = `<div class="ai-inline-err">${escHtml(e.message)}</div>`;
  }
}

// 加入对比列表
function addToCompare(idx) {
  const item = window._currentNews[idx];
  if (!item) return;
  if (newsMultiSelect.has(item.link)) {
    newsMultiSelect.delete(item.link);
    showToast('已移出对比列表');
  } else {
    if (newsMultiSelect.size >= 6) { showToast('最多选择6篇'); return; }
    newsMultiSelect.add(item.link);
    showToast(`已加入对比（${newsMultiSelect.size}篇）`);
  }
  // 更新卡片样式
  document.querySelectorAll('.news-card').forEach(card => {
    card.classList.toggle('multi-selected', newsMultiSelect.has(card.dataset.link));
  });
  updateFab();
}
