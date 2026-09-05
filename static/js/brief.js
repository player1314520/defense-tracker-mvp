// ══════════════════════════════════════════════════════════
// ✍️  要讯自动写作模块 (Auto-Brief Writing)
// ══════════════════════════════════════════════════════════
let briefCandidates = [];
let briefResults = [];   // 已生成要讯 { id, brief, article, timestamp }
let briefAutoTimer = null;
let briefAutoInterval = 5 * 60 * 1000;  // 5分钟
let briefBatchRunning = false;

const QUALITY_FEEDBACK_REASONS = {
  accepted: ['value_high', 'fit_brief'],
  skipped: ['low_priority'],
  rejected: ['not_defense', 'topic_weak'],
  discarded: ['generated_discarded'],
};

// 从localStorage加载历史要讯
try {
  const saved = localStorage.getItem('briefResults');
  if (saved) {
    const parsed = JSON.parse(saved);
    briefResults = Array.isArray(parsed) ? parsed.map(_briefCleanItem) : [];
  }
} catch(e) { briefResults = []; }

const BRIEF_PENDING_DELETE_KEY = 'briefPendingDeletes';
const BRIEF_PENDING_UPSERT_KEY = 'briefPendingUpserts';
let _briefSyncTail = Promise.resolve();
let _briefPendingDeletes = new Set();
let _briefPendingUpserts = new Map();
try {
  const pending = JSON.parse(localStorage.getItem(BRIEF_PENDING_DELETE_KEY) || '[]');
  if (Array.isArray(pending)) {
    _briefPendingDeletes = new Set(pending.filter(id => typeof id === 'string' && id));
  }
} catch (e) { _briefPendingDeletes = new Set(); }
try {
  const pending = JSON.parse(localStorage.getItem(BRIEF_PENDING_UPSERT_KEY) || '[]');
  if (Array.isArray(pending)) {
    _briefPendingUpserts = new Map(
      pending.filter(item => item && typeof item.id === 'string' && item.id)
        .map(item => [item.id, item])
    );
  }
} catch (e) { _briefPendingUpserts = new Map(); }
// 若上次退出发生在删除队列落盘之间，删除意图优先，避免旧 upsert 复活条目。
for (const id of _briefPendingDeletes) _briefPendingUpserts.delete(id);

function _briefCleanItem(item) {
  const {_editing, _editBuffer, sourceEvidence, ...rest} = item || {};
  const evidenceOrigin = sourceEvidence?.payload?.origin || 'unknown';
  const clean = {...rest};
  // 用户导入的原文及其证据只保留在当前页面内存，不写浏览器或用户状态库。
  if (rest.article && typeof rest.article === 'object') {
    clean.article = {...rest.article};
    if (evidenceOrigin !== 'rss_cache') clean.article.summary = '';
  }
  if (evidenceOrigin === 'rss_cache') clean.sourceEvidence = sourceEvidence;
  return clean;
}

function _briefNeedsCleanup(item) {
  return JSON.stringify(_briefCleanItem(item)) !== JSON.stringify(item);
}

function _briefArticleRef(article) {
  return {
    aid: article?.aid || '',
    article_id: article?.article_id || '',
    link: article?.link || '',
  };
}

function briefWasSaved(data) {
  return Boolean(data && (data.saved === true || data.saved_to));
}

function _briefPersistLocal() {
  const clean = briefResults.slice(0, 50).map(_briefCleanItem);
  try {
    localStorage.setItem('briefResults', JSON.stringify(clean));
  } catch (e) {
    console.warn('要讯历史未能写入浏览器存储', e);
    if (typeof showToast === 'function') showToast('浏览器存储空间不足；本次要讯仍保留在当前页面', 7000);
  }
  return clean;
}

function _briefPersistPendingDeletes() {
  try {
    localStorage.setItem(BRIEF_PENDING_DELETE_KEY, JSON.stringify([..._briefPendingDeletes]));
  } catch (e) {
    console.warn('待同步删除项未能写入浏览器存储', e);
  }
}

function _briefPersistPendingUpserts() {
  try {
    localStorage.setItem(BRIEF_PENDING_UPSERT_KEY, JSON.stringify([..._briefPendingUpserts.values()]));
  } catch (e) {
    console.warn('待同步要讯未能写入浏览器存储', e);
  }
}

function _briefApplyStateMeta(state) {
  if (typeof userdataApplyMeta === 'function') {
    userdataApplyMeta(state);
    return;
  }
  const revision = Number(state && state.revision);
  if (Number.isInteger(revision) && revision >= 0) window.__USERDATA_REVISION__ = revision;
}

function _briefMergeServerState(serverItems, additionallySuppressed = []) {
  const suppressed = new Set([..._briefPendingDeletes, ...additionallySuppressed]);
  const localById = new Map(
    briefResults.filter(item => item && item.id && !suppressed.has(item.id))
      .map(item => [item.id, item])
  );
  const merged = [];
  const seen = new Set();
  for (const serverItem of (Array.isArray(serverItems) ? serverItems : [])) {
    if (!serverItem || !serverItem.id || suppressed.has(serverItem.id) || seen.has(serverItem.id)) continue;
    merged.push(localById.get(serverItem.id) || serverItem);
    seen.add(serverItem.id);
  }
  for (const localItem of localById.values()) {
    if (!seen.has(localItem.id)) merged.push(localItem);
  }
  merged.sort((a, b) => String(b.timestamp || '').localeCompare(String(a.timestamp || '')));
  briefResults = merged.slice(0, 50);
  _briefPersistLocal();
  if (typeof briefRenderResults === 'function') briefRenderResults();
}

async function _briefRefreshState(suppressedIds = []) {
  const response = await fetch('/api/userdata/brief-results', {credentials: 'same-origin'});
  if (!response.ok) throw new Error(`刷新用户状态失败（HTTP ${response.status}）`);
  const state = await response.json();
  _briefApplyStateMeta(state);
  _briefMergeServerState(state.brief_results, suppressedIds);
  return state;
}

async function _briefMutate(method, path, body, suppressedIds = []) {
  for (let attempt = 0; attempt < 3; attempt++) {
    if (!Number.isInteger(window.__USERDATA_REVISION__)) {
      await _briefRefreshState(suppressedIds);
    }
    const revision = window.__USERDATA_REVISION__;
    const response = await fetch(path, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'If-Match': `"${revision}"`,
      },
      credentials: 'same-origin',
      body: JSON.stringify(body || {}),
    });
    let payload = {};
    try { payload = await response.json(); } catch (e) { payload = {}; }
    if (response.status === 409 && payload.code === 'REVISION_CONFLICT') {
      await _briefRefreshState(suppressedIds);
      continue;
    }
    if (!response.ok) {
      throw new Error(payload.error || `用户状态同步失败（HTTP ${response.status}）`);
    }
    _briefApplyStateMeta(payload);
    _briefMergeServerState(payload.brief_results, suppressedIds);
    return payload;
  }
  throw new Error('用户状态持续发生并发冲突，请稍后重试');
}

function _briefEnqueue(task) {
  const run = _briefSyncTail.then(task, task);
  _briefSyncTail = run.catch(() => {});
  return run;
}

function _briefQueueUpserts(items) {
  const cleanItems = (Array.isArray(items) ? items : [items])
    .filter(item => item && item.id)
    .map(_briefCleanItem);
  const unique = [...new Map(cleanItems.map(item => [item.id, item])).values()];
  for (const item of unique) {
    _briefPendingDeletes.delete(item.id);
    _briefPersistPendingDeletes();
    _briefPendingUpserts.set(item.id, item);
    _briefPersistPendingUpserts();
    _briefEnqueue(() => _briefMutate(
      'PUT',
      '/api/userdata/brief-results/' + encodeURIComponent(item.id),
      {item},
    )).then(() => {
      const current = _briefPendingUpserts.get(item.id);
      if (current && JSON.stringify(current) === JSON.stringify(item)) {
        _briefPendingUpserts.delete(item.id);
        _briefPersistPendingUpserts();
      }
    }).catch(error => console.warn('[brief sync upsert]', item.id, error.message));
  }
}

function _briefQueueDelete(itemIds) {
  const ids = [...new Set((Array.isArray(itemIds) ? itemIds : [itemIds]).filter(Boolean))];
  if (!ids.length) return;
  ids.forEach(id => _briefPendingDeletes.add(id));
  ids.forEach(id => _briefPendingUpserts.delete(id));
  _briefPersistPendingDeletes();
  _briefPersistPendingUpserts();
  const one = ids.length === 1;
  const path = one
    ? '/api/userdata/brief-results/' + encodeURIComponent(ids[0])
    : '/api/userdata/brief-results';
  const body = one ? {} : {item_ids: ids};
  _briefEnqueue(() => _briefMutate('DELETE', path, body, ids))
    .then(() => {
      ids.forEach(id => _briefPendingDeletes.delete(id));
      _briefPersistPendingDeletes();
    })
    .catch(error => console.warn('[brief sync delete]', error.message));
}

function briefSave(changedItems = []) {
  try {
    _briefPersistLocal();
    const items = Array.isArray(changedItems) ? changedItems : [changedItems];
    if (items.length) _briefQueueUpserts(items);
  } catch(e) {
    console.warn('[brief local save]', e.message);
  }
}

// ☁ 启动合并：服务端优先；仅把服务端缺少的本地条目逐条 upsert。
window.addEventListener('userdata-ready', (e) => {
  const detail = (e && e.detail) || {};
  _briefApplyStateMeta(detail);
  const rawServer = Array.isArray(detail.brief_results) ? detail.brief_results : [];
  const cleanupUpserts = rawServer
    .filter(item => item && item.id && !_briefPendingDeletes.has(item.id))
    .filter(_briefNeedsCleanup)
    .map(_briefCleanItem);
  const server = rawServer.map(_briefCleanItem);
  const localMap = new Map(
    briefResults.filter(item => item && item.id && !_briefPendingDeletes.has(item.id))
      .map(item => [item.id, item])
  );
  for (const item of _briefPendingUpserts.values()) {
    if (!_briefPendingDeletes.has(item.id)) localMap.set(item.id, item);
  }
  const local = [...localMap.values()];
  const serverIds = new Set(server.map(item => item && item.id).filter(Boolean));
  const localOnly = local.filter(item => !serverIds.has(item.id));
  const localById = new Map(local.map(item => [item.id, item]));
  const merged = server
    .filter(item => item && item.id && !_briefPendingDeletes.has(item.id))
    .map(item => _briefPendingUpserts.get(item.id) || item);
  const seen = new Set(merged.map(item => item.id));
  for (const item of localById.values()) {
    if (!seen.has(item.id)) merged.push(item);
  }
  merged.sort((a, b) => String(b.timestamp || '').localeCompare(String(a.timestamp || '')));
  briefResults = merged.slice(0, 50);
  _briefPersistLocal();
  if (typeof briefRenderResults === 'function') briefRenderResults();
  const pendingUpserts = [...new Map(
    [...cleanupUpserts, ...localOnly, ..._briefPendingUpserts.values()].map(item => [item.id, item])
  ).values()];
  if (pendingUpserts.length) _briefQueueUpserts(pendingUpserts);
  if (_briefPendingDeletes.size) _briefQueueDelete([..._briefPendingDeletes]);
});

// 加载候选文章
async function briefLoadCandidates() {
  const listEl = document.getElementById('briefCandList');
  if (!listEl) return;
  listEl.innerHTML = '<div class="brief-empty"><div class="ai-spinner-sm" style="margin:0 auto"></div><br>正在筛选精品候选…</div>';
  try {
    const r = await apiFetch('/api/quality/candidates?min_level=A&limit=10', {}, {toast: false});
    const data = await r.json();
    briefCandidates = data.candidates || [];
    document.getElementById('briefCandCount').textContent = briefCandidates.length;
    briefRenderCandidates();
  } catch(e) {
    listEl.innerHTML = `<div class="brief-empty">❌ 加载失败: ${escHtml(e.message)}</div>`;
  }
}

function briefRenderCandidates() {
  const listEl = document.getElementById('briefCandList');
  if (!listEl) return;
  if (!briefCandidates.length) {
    listEl.innerHTML = '<div class="brief-empty">暂无符合要讯标准的候选文章，请刷新RSS或稍后重试</div>';
    return;
  }
  listEl.innerHTML = briefCandidates.map((a, i) => {
    const hits = (a.brief_hits || []).map(h => `<span class="brief-hit-tag">${escHtml(h)}</span>`).join('');
    const quality = a.quality || {};
    const dims = quality.dims || {};
    const reasons = (quality.reasons || a.quality_reasons || []).map(h => `<span class="brief-quality-reason">${escHtml(h)}</span>`).join('');
    const penalties = (quality.penalties || a.quality_penalties || []).map(h => `<span class="brief-quality-penalty">${escHtml(h)}</span>`).join('');
    const level = a.quality_level || quality.level || 'A';
    const qScore = a.quality_score || quality.total || 0;
    const date = a.date ? new Date(a.date).toLocaleDateString('zh-CN', {month:'2-digit',day:'2-digit'}) : '';
    return `<div class="brief-cand-item" data-idx="${i}">
      <div class="brief-cand-head">
        <span class="brief-quality-level level-${escHtml(level)}">${escHtml(level)}级</span>
        <span class="brief-score">Q ${qScore}</span>
        <span class="brief-score muted">⭐ ${a.brief_score}</span>
        <span class="brief-src" style="color:${a.color||'#60a5fa'}">${escHtml(a.source_cn||a.source)}</span>
        <span class="brief-date">${date}</span>
      </div>
      <div class="brief-cand-title">${escHtml(a.title)}</div>
      <div class="brief-quality-dims">
        <span>源 ${dims.source ?? '-'}</span>
        <span>题 ${dims.topic ?? '-'}</span>
        <span>密 ${dims.density ?? '-'}</span>
        <span>新 ${dims.novelty ?? '-'}</span>
        <span>写 ${dims.writability ?? '-'}</span>
      </div>
      <div class="brief-cand-hits">${reasons || hits}${penalties}</div>
      <div class="brief-cand-actions">
        <button class="brief-single-btn" onclick="briefGenerateSingle(${i})">生成要讯</button>
        <button class="brief-feedback-btn ok" onclick="briefFeedback(${i}, 'accepted')" title="标记为高价值样本">采纳</button>
        <button class="brief-feedback-btn" onclick="briefFeedback(${i}, 'skipped')" title="暂不采用但保留样本">跳过</button>
        <button class="brief-feedback-btn bad" onclick="briefFeedback(${i}, 'rejected')" title="标记为不符合要求">不符合</button>
        <a class="brief-link-btn" href="${escHtml(safeExternalUrl(a.link))}" target="_blank" rel="noopener noreferrer">原文</a>
      </div>
    </div>`;
  }).join('');
}

async function briefFeedback(idx, label) {
  const article = briefCandidates[idx];
  if (!article) return;
  try {
    await apiFetch('/api/quality/feedback', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        article_id: article.article_id,
        article,
        label,
        reason_codes: QUALITY_FEEDBACK_REASONS[label] || [],
      })
    }, {toast: false});
    const map = {accepted: '已采纳为高价值样本', skipped: '已记录跳过', rejected: '已记录不符合'};
    showToast('✅ ' + (map[label] || '反馈已记录'));
    briefLoadCandidates();
  } catch(e) {
    showToast('❌ 反馈失败: ' + e.message);
  }
}

// 选题查重：近7天写过相似选题则弹确认（防连续两天写同一题）
async function briefTopicGuard(title) {
  try {
    const r = await apiFetch('/api/brief/check_topic', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ title })
    }, {toast: false});
    const data = await r.json();
    const hit = (data.similar || [])[0];
    if (hit) {
      const when = (hit.created_at || '').slice(5, 10);
      return confirm('近7天已写过相似选题（' + Math.round(hit.similarity * 100) + '%相似，' + when + '）：\n《' + hit.title.slice(0, 60) + '》\n\n仍要生成吗？');
    }
  } catch (e) { /* 查重失败不拦路 */ }
  return true;
}

// 单篇生成
async function briefGenerateSingle(idx) {
  const article = briefCandidates[idx];
  if (!article) return;
  if (!await briefTopicGuard(article.title)) return;
  const btn = event?.target;
  if (btn) { btn.disabled = true; btn.textContent = '⏳ 生成中…'; }
  try {
    const r = await apiFetch('/api/brief/generate', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ article: _briefArticleRef(article) })
    }, {toast: false});
    const data = await r.json();
    if (data.error) { showToast('❌ ' + data.error); return; }
    if (data.article_id) article.article_id = data.article_id;
    briefAddResult(data.brief, {...article, ...(data.source_article || {})}, data.source_evidence);
    showToast(briefWasSaved(data) ? '✅ 已生成1篇要讯 · 已安全存档' : '✅ 已生成1篇要讯');
  } catch(e) {
    showToast('❌ 生成失败: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '生成要讯'; }
  }
}

// 新闻卡「一键要讯」：主旅程最短路径（新闻流看中一条 -> 直接成稿，
// 不必祈祷它进候选池 Top10、也不必复制 URL 绕道导入面板）
async function oneClickBrief(idx, btn) {
  const item = window._currentNews && window._currentNews[idx];
  if (!item) { showToast('文章索引失效，请刷新'); return; }
  if (!await briefTopicGuard(item.title)) return;
  if (btn) { btn.disabled = true; btn.textContent = '生成中…'; }
  showToast('要讯生成中（约半分钟）…');
  try {
    const r = await apiFetch('/api/brief/generate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ article: _briefArticleRef(item) })
    }, {toast: false});
    const data = await r.json();
    if (data.error) { showToast('生成失败：' + data.error); return; }
    briefAddResult(data.brief, {...item, ...(data.source_article || {})}, data.source_evidence);
    showTab('brief');
    showToast(briefWasSaved(data) ? '要讯已生成并安全存档' : '要讯已生成');
  } catch(e) {
    showToast('生成失败: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '要讯'; }
  }
}

// 批量生成（SSE流式）
async function briefBatchGenerate() {
  if (briefBatchRunning) { showToast('正在生成中，请稍候…'); return; }
  const count = parseInt(document.getElementById('briefBatchCount').value || '8');
  const btn = document.getElementById('briefBatchBtn');
  const bar = document.getElementById('briefProgressBar');
  const fill = document.getElementById('briefProgressFill');
  const txt = document.getElementById('briefProgressText');
  briefBatchRunning = true;
  btn.disabled = true;
  btn.innerHTML = '⏳ 生成中…';
  bar.style.display = 'flex';
  fill.style.width = '0%';
  txt.textContent = `准备生成 ${count} 篇要讯…`;

  try {
    const r = await apiFetch('/api/brief/batch', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ count })
    }, {toast: false});
    const reader = r.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    let total = count;
    let done = 0;
    while (true) {
      const { value, done: rdone } = await reader.read();
      if (rdone) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split('\n\n');
      buf = lines.pop() || '';
      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const chunk = line.slice(6).trim();
        if (!chunk) continue;
        try {
          const obj = JSON.parse(chunk);
          if (obj.type === 'start') {
            total = obj.total;
            txt.textContent = `准备生成 ${total} 篇要讯…`;
          } else if (obj.type === 'brief') {
            done = obj.index;
            if (obj.article_id && obj.article) obj.article.article_id = obj.article_id;
            briefAddResult(obj.brief, obj.article, obj.source_evidence);
            const pct = (done / total * 100).toFixed(0);
            fill.style.width = pct + '%';
            txt.textContent = `已完成 ${done} / ${total} 篇 (${pct}%)`;
          } else if (obj.type === 'error') {
            done = obj.index;
            const pct = (done / total * 100).toFixed(0);
            fill.style.width = pct + '%';
            txt.textContent = `${done}/${total} · 第${obj.index}篇失败: ${obj.error}`;
          } else if (obj.type === 'done') {
            txt.textContent = `✅ 生成完成：${obj.total}篇`;
            fill.style.width = '100%';
          }
        } catch(e) { /* ignore */ }
      }
    }
    showToast(`✅ 已生成 ${done} 篇要讯 · 已存档到 素材库/每日新闻/`);
  } catch(e) {
    txt.textContent = '❌ 生成失败: ' + e.message;
    showToast('❌ ' + e.message);
  } finally {
    briefBatchRunning = false;
    btn.disabled = false;
    btn.innerHTML = '一键生成今日要讯';
    setTimeout(() => { bar.style.display = 'none'; }, 3000);
  }
}

function briefAddResult(brief, article, sourceEvidence) {
  const id = 'br_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
  briefResults.unshift({
    id,
    brief,
    sourceEvidence,
    article: {
      title: article.title,
      source: article.source_cn || article.source,
      source_en: article.source,
      region: article.region,
      link: safeExternalUrl(article.link),
      date: article.date,
      summary: article.summary,
      publication_date_verified: article.publication_date_verified !== false,
      article_id: article.article_id,
      quality_level: article.quality_level,
      quality_score: article.quality_score,
    },
    timestamp: new Date().toISOString(),
  });
  briefResults = briefResults.slice(0, 50);
  briefSave(briefResults[0]);
  briefRenderResults();
}

function briefRenderResults() {
  const listEl = document.getElementById('briefResultList');
  const doneEl = document.getElementById('briefDoneCount');
  if (!listEl) return;
  if (doneEl) doneEl.textContent = briefResults.length;
  if (!briefResults.length) {
    listEl.innerHTML = `<div class="brief-empty">
      <div style="font-size:28px;margin-bottom:12px">暂无内容</div>
      <div style="font-weight:600;margin-bottom:6px">暂无要讯</div>
      <div style="font-size:13px;opacity:.7">点击"一键生成今日要讯"或从左侧选择单篇生成</div>
    </div>`;
    return;
  }
  listEl.innerHTML = briefResults.map((r, i) => {
    const ts = new Date(r.timestamp);
    const tsStr = ts.toLocaleString('zh-CN', {month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'});
    const editing = !!r._editing;
    const v = briefClientValidate(r.brief);
    const bodyHtml = editing
      ? `<div class="brief-edit-wrap">
          <textarea class="brief-edit-area" oninput="briefOnEditInput('${r.id}', this.value)" data-id="${r.id}">${escHtml(r.brief)}</textarea>
          <div class="brief-edit-toolbar">
            <span class="brief-valid-badge ${v.bodyOk?'ok':'warn'}" title="正文字数">正文 ${v.bodyCount} 字 ${v.bodyOk?'✓':'⚠'}</span>
            <span class="brief-valid-badge ${v.titleOk?'ok':'warn'}" title="标题字数">标题 ${v.titleCount} 字 ${v.titleOk?'✓':'⚠'}</span>
            <span class="brief-valid-badge ${v.suggestOk?'ok':'warn'}" title="建议范式">建议 ${v.suggestOk?'✓':'⚠'}</span>
            <span class="brief-valid-badge ${v.structOk?'ok':'warn'}" title="(1)(2)(3)结构">结构 ${v.structOk?'✓':'⚠'}</span>
            <span class="brief-valid-badge ${v.mdOk?'ok':'warn'}" title="Markdown符号">Markdown ${v.mdOk?'✓':'⚠'}</span>
            ${v.issues.length?`<span class="brief-valid-issues" title="${escHtml(v.issues.join(' · '))}">⚠ ${v.issues.length} 项问题</span>`:''}
            <button class="brief-edit-save" onclick="briefEditSave('${r.id}')">保存</button>
            <button class="brief-edit-cancel" onclick="briefEditCancel('${r.id}')">✕ 取消</button>
          </div>
        </div>`
      : `<pre class="brief-result-body">${escHtml(r.brief)}</pre>
         <div class="brief-valid-row">
           <span class="brief-valid-badge ${v.bodyOk?'ok':'warn'}">正文 ${v.bodyCount}字</span>
           <span class="brief-valid-badge ${v.titleOk?'ok':'warn'}">标题 ${v.titleCount}字</span>
           <span class="brief-valid-badge ${v.suggestOk?'ok':'warn'}">建议范式 ${v.suggestOk?'✓':'⚠'}</span>
           <span class="brief-valid-badge ${v.structOk?'ok':'warn'}">结构 ${v.structOk?'✓':'⚠'}</span>
           ${!v.mdOk?`<span class="brief-valid-badge warn">⚠ Markdown</span>`:''}
         </div>`;
    return `<div class="brief-result-item${editing?' editing':''}" data-id="${r.id}">
      <div class="brief-result-head">
        <span class="brief-result-num">#${i+1}</span>
        <span class="brief-result-ts">${tsStr}</span>
        <div class="brief-result-actions">
          <button class="brief-copy-btn" onclick="briefCopyOne('${r.id}')" title="复制">复制</button>
          <button class="brief-docx-btn" onclick="briefDownloadDocx('${r.id}')" title="下载Word">Word</button>
          ${editing?'':`<button class="brief-edit-btn" onclick="briefEditToggle('${r.id}')" title="编辑">编辑</button>`}
          <button class="brief-regen-btn" onclick="briefRegenerate('${r.id}')" title="重新生成">重写</button>
          <button class="brief-discard-btn" onclick="briefDiscardResult('${r.id}')" title="标记为生成后废弃">废弃</button>
          <button class="brief-del-btn" onclick="briefDeleteOne('${r.id}')" title="删除">✕</button>
        </div>
      </div>
      ${bodyHtml}
      <div class="brief-result-foot">
        <a href="${escHtml(safeExternalUrl(r.article.link))}" target="_blank" rel="noopener noreferrer" class="brief-result-link">原文</a>
        <span class="brief-result-src">${escHtml(r.article.source)} · ${escHtml(r.article.region||'')}</span>
      </div>
    </div>`;
  }).join('');
}

// ── 客户端要讯校验（轻量版，与后端 _parse_brief_text / _validate_brief 规则一致）──
function briefClientValidate(text) {
  const out = {
    bodyCount: 0, bodyOk: false,
    titleCount: 0, titleOk: false,
    eventOk: false, valueOk: false, hatOk: false, sourceOk: false,
    suggestOk: false, structOk: false, mdOk: true, valid: false,
    issues: []
  };
  if (!text || typeof text !== 'string') { out.issues.push('空内容'); return out; }
  const rawLines = text.replace(/\r/g, '').split('\n').map(s => s.replace(/\s+$/, ''));
  let state = 'meta';
  const titleLines = [], bodyLines = [];
  let eventTime = '', valuePoint = '', sourceLine = '', reporter = '';
  const unexpected = [];
  for (const raw of rawLines) {
    const s = raw.trim();
    if (!s) {
      if (state === 'meta') state = 'title';
      else if (state === 'title' && titleLines.length) state = 'body';
      continue;
    }
    if (/^事件时间[：:]/.test(s)) {
      if (eventTime) unexpected.push(s);
      eventTime = s.replace(/^事件时间[：:]\s*/, '');
      state = 'meta'; continue;
    }
    if (/^价\s*值\s*点[：:]/.test(s)) {
      if (valuePoint) unexpected.push(s);
      valuePoint = s.replace(/^价\s*值\s*点[：:]\s*/, '');
      state = 'meta'; continue;
    }
    if (s.startsWith('（信息来源') || s.startsWith('(信息来源')) {
      if (sourceLine) unexpected.push(s);
      sourceLine = s; state = 'done'; continue;
    }
    if (s.startsWith('报送人')) {
      if (reporter) unexpected.push(s);
      reporter = s; state = 'done'; continue;
    }
    if (state === 'done') { unexpected.push(s); continue; }
    if (state === 'title') { titleLines.push(s); }
    else if (state === 'body' || state === 'meta') {
      if (state === 'meta') state = 'body';
      bodyLines.push(s);
    }
  }
  const title = titleLines.join('');
  const body = bodyLines.join('');
  const countCn = (s) => (s || '').replace(/\s/g, '').length;
  const compact = (s) => (s || '').replace(/[\s，,。；;：:！？!?（）()《》“”"'、]/g, '');
  out.bodyCount = countCn(body);
  out.titleCount = title.length;
  out.bodyOk = out.bodyCount >= 250 && out.bodyCount <= 350;
  out.titleOk = out.titleCount >= 8 && out.titleCount <= 15
    && !/[，,]/.test(title) && /(?:值得关注|值得警惕)$/.test(title);
  if (!out.bodyOk) out.issues.push(`正文${out.bodyCount}字（应250-350）`);
  if (!out.titleOk) out.issues.push('标题应为8-15字、无逗号并以“值得关注/值得警惕”收尾');

  const eventMatch = /^(\d{4})年(\d{1,2})月(\d{1,2})日$/.exec(eventTime);
  if (eventMatch && !/(近期|近日|日前|最近)/.test(eventTime)) {
    const y = Number(eventMatch[1]), m = Number(eventMatch[2]), d = Number(eventMatch[3]);
    const dt = new Date(Date.UTC(y, m - 1, d));
    out.eventOk = dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
  }
  if (!out.eventOk) out.issues.push('事件时间必须是有效的YYYY年M月D日，不能写近期');

  const titleCore = compact(title).replace(/(?:值得关注|值得警惕)$/, '');
  const valueCompact = compact(valuePoint);
  out.valueOk = Boolean(valueCompact && titleCore
    && valueCompact !== titleCore
    && !(valueCompact.startsWith(titleCore) && valueCompact.length - titleCore.length < 8));
  if (!out.valueOk) out.issues.push('价值点不得复制标题');

  out.suggestOk = /建议持续跟踪[^。]*?针对性加强[^。]*?能力建设/.test(body);
  if (!out.suggestOk) out.issues.push('建议未采用"持续跟踪X+针对性加强Y能力建设"范式');

  const normalizedBody = body.replace(/\(1\)/g, '（1）').replace(/\(2\)/g, '（2）').replace(/\(3\)/g, '（3）');
  const hasNumbered = ['（1）','（2）','（3）'].every(mark => normalizedBody.includes(mark));
  let hat = '';
  if (hasNumbered) {
    hat = normalizedBody.slice(0, normalizedBody.indexOf('（1）')).trim();
    out.structOk = normalizedBody.includes('。（2）') && normalizedBody.includes('。（3）');
  } else {
    const suggestion = normalizedBody.lastIndexOf('。建议');
    const beforeSuggestion = suggestion >= 0 ? normalizedBody.slice(0, suggestion) : '';
    const semicolons = [...beforeSuggestion.matchAll(/；/g)].map(match => match.index);
    const firstLayerSep = semicolons.length >= 2 ? semicolons[semicolons.length - 2] : -1;
    const hatEnd = firstLayerSep >= 0 ? beforeSuggestion.lastIndexOf('。', firstLayerSep) : -1;
    hat = hatEnd >= 0 ? normalizedBody.slice(0, hatEnd + 1).trim() : '';
    const layers = hatEnd >= 0 ? beforeSuggestion.slice(hatEnd + 1).split('；').map(s => s.trim()) : [];
    out.structOk = layers.length >= 3 && layers.every(Boolean) && !beforeSuggestion.includes(';');
  }
  if (!out.structOk) out.issues.push('编号层意须用句号，无编号层意须用中文分号');
  out.hatOk = countCn(hat) >= 80 && countCn(hat) <= 120;
  if (eventMatch) out.hatOk = out.hatOk && hat.includes(`${Number(eventMatch[2])}月${Number(eventMatch[3])}日`);
  if (!out.hatOk) out.issues.push('帽段应为80-120字并写明与事件时间一致的月日');

  const sourceMatch = /^[（(]信息来源[：:]([\s\S]+)[）)]$/.exec(sourceLine);
  const sourceItems = sourceMatch ? sourceMatch[1].split('；').map(s => s.trim()).filter(Boolean) : [];
  const sourceEntry = /^(.{1,100}?)\s*(\d{1,2})月(\d{1,2})日发文《([^》]+)》$/;
  const parsedSources = sourceItems.map(item => sourceEntry.exec(item));
  const lead = /^据([^，,。；;]{1,80}?)报道[，,]/.exec(body);
  out.sourceOk = Boolean(sourceItems.length && parsedSources.every(Boolean) && !sourceLine.includes(';')
    && lead && parsedSources[0][1].trim() === lead[1].trim() && !/\d{1,2}月\d{1,2}日/.test(lead[1]));
  if (!out.sourceOk) out.issues.push('据XX报道须与首条来源一致，来源须逐条按规定格式用中文分号列全');
  if (!/^报送人：\s+电话：\s*$/.test(reporter)) out.issues.push('报送人和电话必须留空');
  if (unexpected.length) out.issues.push('六部分之外不得附加内容');

  if (/(^|\s)(#{1,6}\s|\*\*|__|```|~~~|^\s*[-*+]\s)/m.test(text)) {
    out.mdOk = false; out.issues.push('含Markdown符号');
  }
  out.valid = out.issues.length === 0;
  return out;
}

function briefEditToggle(id) {
  const r = briefResults.find(x => x.id === id);
  if (!r) return;
  r._editing = true;
  r._editBuffer = r.brief;
  briefRenderResults();
  // 聚焦到textarea
  setTimeout(() => {
    const ta = document.querySelector(`textarea.brief-edit-area[data-id="${id}"]`);
    if (ta) { ta.focus(); ta.setSelectionRange(ta.value.length, ta.value.length); }
  }, 50);
}

function briefOnEditInput(id, val) {
  const r = briefResults.find(x => x.id === id);
  if (!r) return;
  r._editBuffer = val;
  // 只更新工具栏的实时指标，避免重渲染整个 textarea 导致光标跳走
  const item = document.querySelector(`.brief-result-item[data-id="${id}"]`);
  if (!item) return;
  const toolbar = item.querySelector('.brief-edit-toolbar');
  if (!toolbar) return;
  const v = briefClientValidate(val);
  toolbar.innerHTML = `
    <span class="brief-valid-badge ${v.bodyOk?'ok':'warn'}" title="正文字数">正文 ${v.bodyCount} 字 ${v.bodyOk?'✓':'⚠'}</span>
    <span class="brief-valid-badge ${v.titleOk?'ok':'warn'}" title="标题字数">标题 ${v.titleCount} 字 ${v.titleOk?'✓':'⚠'}</span>
    <span class="brief-valid-badge ${v.suggestOk?'ok':'warn'}" title="建议范式">建议 ${v.suggestOk?'✓':'⚠'}</span>
    <span class="brief-valid-badge ${v.structOk?'ok':'warn'}" title="(1)(2)(3)结构">结构 ${v.structOk?'✓':'⚠'}</span>
    <span class="brief-valid-badge ${v.mdOk?'ok':'warn'}" title="Markdown符号">Markdown ${v.mdOk?'✓':'⚠'}</span>
    ${v.issues.length?`<span class="brief-valid-issues" title="${escHtml(v.issues.join(' · '))}">⚠ ${v.issues.length} 项问题</span>`:''}
    <button class="brief-edit-save" onclick="briefEditSave('${id}')">保存</button>
    <button class="brief-edit-cancel" onclick="briefEditCancel('${id}')">✕ 取消</button>`;
}

async function briefEditSave(id) {
  const r = briefResults.find(x => x.id === id);
  if (!r) return;
  const newText = (r._editBuffer != null) ? r._editBuffer : r.brief;
  if (!await _briefValidateForRelease(r, newText)) return;
  if (briefResults.find(x => x.id === id) !== r) {
    showToast('校验期间该要讯已删除或替换，未保存', 5000);
    return;
  }
  const currentText = (r._editBuffer != null) ? r._editBuffer : r.brief;
  if (currentText !== newText) {
    showToast('校验期间内容已变化，请再次保存', 5000);
    return;
  }
  r.brief = newText;
  r._editing = false;
  delete r._editBuffer;
  briefSave(r);
  briefRenderResults();
  showToast('已保存修改');
}

function briefEditCancel(id) {
  const r = briefResults.find(x => x.id === id);
  if (!r) return;
  r._editing = false;
  delete r._editBuffer;
  briefRenderResults();
  showToast('已取消编辑');
}

// 编辑态下未保存就导出/复制时，自动 commit _editBuffer → r.brief，避免拿到旧值
function _briefFlushEdit(r) {
  if (r && r._editing && r._editBuffer != null && r._editBuffer !== r.brief) {
    r.brief = r._editBuffer;
    r._editing = false;
    delete r._editBuffer;
    return true;
  }
  return false;
}

function _briefFlushAllEdits() {
  const changed = [];
  briefResults.forEach(item => { if (_briefFlushEdit(item)) changed.push(item); });
  return changed;
}

function _briefReleaseReady(r, text) {
  const validation = briefClientValidate(text);
  if (!validation.valid) {
    showToast('要讯未通过写作门禁：' + validation.issues.slice(0, 3).join('；'), 7000);
    return false;
  }
  if (!r?.sourceEvidence) {
    showToast('缺少服务器签发的原始素材证据，请从原文重新生成', 7000);
    return false;
  }
  return true;
}

async function _briefValidateForRelease(r, text) {
  if (!_briefReleaseReady(r, text)) return false;
  try {
    await apiFetch('/api/brief/validate', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({brief: text, source_evidence: r.sourceEvidence}),
    }, {toast: false});
    return true;
  } catch (e) {
    showToast('要讯未通过来源门禁：' + e.message, 7000);
    return false;
  }
}

async function briefCopyOne(id) {
  const r = briefResults.find(x => x.id === id);
  if (!r) return;
  const candidate = (r._editing && r._editBuffer != null) ? r._editBuffer : r.brief;
  if (!await _briefValidateForRelease(r, candidate)) return;
  if (briefResults.find(x => x.id === id) !== r) {
    showToast('校验期间该要讯已删除或替换，未复制', 5000);
    return;
  }
  const current = (r._editing && r._editBuffer != null) ? r._editBuffer : r.brief;
  if (current !== candidate) {
    showToast('校验期间内容已变化，请重新复制', 5000);
    return;
  }
  if (r._editing) {
    r.brief = candidate;
    r._editing = false;
    delete r._editBuffer;
    briefSave(r);
    briefRenderResults();
  }
  navigator.clipboard.writeText(candidate).then(() => showToast('已复制要讯'));
}

async function briefDownloadDocx(id) {
  const r = briefResults.find(x => x.id === id);
  if (!r) return;
  const candidate = (r._editing && r._editBuffer != null) ? r._editBuffer : r.brief;
  if (!_briefReleaseReady(r, candidate)) return;
  if (_briefFlushEdit(r)) { briefSave(r); briefRenderResults(); }
  showToast('生成Word文件…');
  try {
    const resp = await apiFetch('/api/brief/export_docx', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ brief: r.brief, source_evidence: r.sourceEvidence })
    }, {toast: false});
    await downloadResponseBlob(resp, '要讯.docx', '.docx');
    showToast('Word已下载');
  } catch(e) {
    showToast('失败: ' + e.message);
  }
}

async function briefDownloadCompiledDocx() {
  if (!briefResults.length) { showToast('暂无要讯可汇编'); return; }
  const invalid = briefResults.find(r => !_briefReleaseReady(
    r, (r._editing && r._editBuffer != null) ? r._editBuffer : r.brief
  ));
  if (invalid) return;
  // 把所有编辑态未保存的修改 flush 到 r.brief
  const flushed = _briefFlushAllEdits();
  if (flushed.length) { briefSave(flushed); briefRenderResults(); }
  showToast(`汇编 ${briefResults.length} 篇要讯…`);
  try {
    const resp = await apiFetch('/api/brief/export_docx_compiled', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        briefs: briefResults.map(r => ({brief: r.brief, source_evidence: r.sourceEvidence})),
      })
    }, {toast: false});
    await downloadResponseBlob(resp, '要讯汇编.docx', '.docx');
    showToast(`汇编Word已下载（${briefResults.length}篇）`);
  } catch(e) {
    showToast('失败: ' + e.message);
  }
}

async function briefDownloadAllDocx() {
  if (!briefResults.length) { showToast('暂无要讯可导出'); return; }
  const invalid = briefResults.find(r => !_briefReleaseReady(
    r, (r._editing && r._editBuffer != null) ? r._editBuffer : r.brief
  ));
  if (invalid) return;
  const flushed = _briefFlushAllEdits();
  if (flushed.length) { briefSave(flushed); briefRenderResults(); }
  showToast(`批量生成 ${briefResults.length} 个Word文件…`);
  for (const r of briefResults) {
    try {
      const resp = await apiFetch('/api/brief/export_docx', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ brief: r.brief, source_evidence: r.sourceEvidence })
      }, {toast: false});
      await downloadResponseBlob(resp, '要讯_' + r.id + '.docx', '.docx');
      await new Promise(r => setTimeout(r, 400));
    } catch(e) { console.error(e); }
  }
  showToast(`已导出 ${briefResults.length} 个Word`);
}

function briefDeleteOne(id) {
  briefResults = briefResults.filter(x => x.id !== id);
  _briefPersistLocal();
  _briefQueueDelete(id);
  briefRenderResults();
  showToast('已删除');
}

async function briefDiscardResult(id) {
  const r = briefResults.find(x => x.id === id);
  if (!r) return;
  if (r.article?.region === '导入') {
    briefResults = briefResults.filter(x => x.id !== id);
    _briefPersistLocal();
    _briefQueueDelete(id);
    briefRenderResults();
    showToast('已废弃并删除；导入内容未写入质量样本库');
    return;
  }
  try {
    await apiFetch('/api/quality/feedback', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        article_id: r.article.article_id,
        article: {
          article_id: r.article.article_id,
          title: r.article.title,
          source: r.article.source_en || r.article.source,
          source_cn: r.article.source,
          region: r.article.region,
          link: r.article.link,
          date: r.article.date,
          summary: r.brief.slice(0, 800),
        },
        label: 'discarded',
        reason_codes: QUALITY_FEEDBACK_REASONS.discarded,
      })
    }, {toast: false});
    showToast('已记录为废弃样本');
  } catch(e) {
    showToast('反馈失败: ' + e.message);
    return;
  }
  briefDeleteOne(id);
}

async function briefRegenerate(id) {
  const r = briefResults.find(x => x.id === id);
  if (!r) { showToast('未找到该要讯记录'); return; }
  // 从候选列表找到原文章（优先完整数据，兜底用存储的article）
  const art = briefCandidates.find(c => c.link === r.article.link) || r.article;
  // ── UI: 标记加载态 ──
  const card = document.querySelector(`.brief-result-item[data-id="${id}"]`);
  const btn = card?.querySelector('.brief-regen-btn');
  if (btn) { btn.disabled = true; btn.innerHTML = '处理中'; btn.classList.add('loading'); }
  if (card) card.classList.add('brief-loading');
  showToast('正在调用AI重新生成，请稍候…', 8000);
  try {
    let resp;
    // 导入素材要讯走 import_text 接口（无RSS原文结构），RSS要讯走 generate 接口
    if (r.article.region === '导入') {
      if (!r.article.summary) {
        showToast('原始导入素材已缺失，不能用成稿反向自证；请重新导入原文', 7000);
        return;
      }
      resp = await apiFetch('/api/brief/import_text', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({
          text: r.article.summary,
          title: r.article.title,
          source: r.article.source,
          pub_date: r.article.date,
        })
      }, {toast: false});
    } else {
      resp = await apiFetch('/api/brief/generate', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ article: _briefArticleRef(art) })
      }, {toast: false});
    }
    const data = await resp.json();
    if (data.error) { showToast(data.error, 5000); return; }
    r.brief = data.brief;
    r.sourceEvidence = data.source_evidence;
    if (data.source_article) r.article = {...r.article, ...data.source_article};
    if (data.source_info) {
      r.article = {
        ...r.article,
        title: data.source_info.title || r.article.title,
        source: data.source_info.source || r.article.source,
        source_cn: data.source_info.source || r.article.source_cn,
        date: data.source_info.pub_date || r.article.date,
        summary: data.source_info.material_text || r.article.summary,
        publication_date_verified: Boolean(data.source_info.pub_date),
      };
    }
    r.timestamp = new Date().toISOString();
    if (data.validation) r.validation = data.validation;
    briefSave(r);
    briefRenderResults();
    showToast(briefWasSaved(data) ? '已重新生成并安全存档' : '已重新生成');
  } catch(e) {
    showToast('重写失败: ' + e.message, 5000);
  } finally {
    // 恢复按钮（若DOM还在）
    const btn2 = document.querySelector(`.brief-result-item[data-id="${id}"] .brief-regen-btn`);
    if (btn2) { btn2.disabled = false; btn2.innerHTML = '重写'; btn2.classList.remove('loading'); }
    const card2 = document.querySelector(`.brief-result-item[data-id="${id}"]`);
    if (card2) card2.classList.remove('brief-loading');
  }
}

function briefClearResults() {
  if (!briefResults.length) return;
  if (!confirm(`确定清空全部 ${briefResults.length} 篇已生成要讯吗？`)) return;
  const clearedIds = briefResults.map(item => item.id).filter(Boolean);
  briefResults = [];
  _briefPersistLocal();
  _briefQueueDelete(clearedIds);
  briefRenderResults();
  showToast('已清空');
}

async function briefExportAll() {
  if (!briefResults.length) { showToast('暂无要讯可导出'); return; }
  const snapshots = briefResults.map(r => ({
    result: r,
    text: (r._editing && r._editBuffer != null) ? r._editBuffer : r.brief,
  }));
  for (const item of snapshots) {
    if (!await _briefValidateForRelease(item.result, item.text)) return;
  }
  if (
    briefResults.length !== snapshots.length
    || snapshots.some((item, index) => briefResults[index] !== item.result)
    || snapshots.some(item => {
    const r = item.result;
    const current = (r._editing && r._editBuffer != null) ? r._editBuffer : r.brief;
    return current !== item.text;
    })
  ) {
    showToast('校验期间要讯集合或内容已变化，请重新导出', 5000);
    return;
  }
  const changed = [];
  let closedEditor = false;
  snapshots.forEach(item => {
    const r = item.result;
    if (r._editing) {
      if (r.brief !== item.text) changed.push(r);
      r.brief = item.text;
      r._editing = false;
      delete r._editBuffer;
      closedEditor = true;
    }
  });
  if (changed.length) briefSave(changed);
  if (closedEditor) briefRenderResults();
  const today = new Date().toISOString().slice(0, 10);
  const content = snapshots.map((item, i) => {
    const r = item.result;
    return `════════════════════════════════════════\n要讯 #${i+1}  · 生成时间 ${new Date(r.timestamp).toLocaleString('zh-CN')}\n════════════════════════════════════════\n${item.text}\n\n【原文链接】${r.article.link}\n【原始来源】${r.article.source} · ${r.article.region||''}\n`;
  }).join('\n\n');
  const header = `防务要讯汇编 · ${today}\n共 ${snapshots.length} 篇\n基于《写作要点》选题 · 符合《命令》规范\n\n\n`;
  const blob = new Blob([header + content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `防务要讯汇编_${today}.txt`;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`已导出 ${snapshots.length} 篇`);
}

function briefToggleAuto() {
  const stateEl = document.getElementById('briefAutoState');
  const btn = document.getElementById('briefAutoBtn');
  if (briefAutoTimer) {
    clearInterval(briefAutoTimer);
    briefAutoTimer = null;
    stateEl.textContent = '关';
    btn.classList.remove('active');
    showToast('自动刷新已关闭');
  } else {
    briefAutoTimer = setInterval(() => {
      briefLoadCandidates();
      showToast('候选列表已自动刷新');
    }, briefAutoInterval);
    stateEl.textContent = '开 (5分钟)';
    btn.classList.add('active');
    showToast('自动刷新已开启');
    briefLoadCandidates();
  }
}


// ── 今日产出：落盘 DOCX 应用内可见（此前 22:00 自动包只能翻文件夹）──
async function briefLoadTodayFiles() {
  const el = document.getElementById('briefTodayList');
  if (!el) return;
  try {
    const r = await apiFetch('/api/brief/today_files', {}, {toast: false});
    const data = await r.json();
    const files = data.files || [];
    document.getElementById('briefTodayCount').textContent = files.length;
    if (!files.length) {
      el.innerHTML = '<div class="brief-empty" style="padding:14px 0">今日暂无落盘要讯。生成后自动出现在这里。</div>';
      return;
    }
    el.innerHTML = files.map(f => {
      const kb = Math.max(1, Math.round(f.size / 1024));
      const tag = f.kind === 'auto' ? '自动' : '手动';
      const url = '/api/brief/download_file?kind=' + f.kind + '&f=' + encodeURIComponent(f.name);
      return '<a class="brief-today-row" href="' + url + '" title="下载">' +
        '<span class="brief-today-tag ' + f.kind + '">' + tag + '</span>' +
        '<span class="brief-today-name">' + escHtml(f.name) + '</span>' +
        '<span class="brief-today-meta">' + f.mtime + ' · ' + kb + 'KB</span></a>';
    }).join('');
  } catch (e) {
    el.innerHTML = '<div class="brief-empty">加载失败</div>';
  }
}

// 切换到要讯标签时，自动加载候选
const _origShowTab = window.showTab || showTab;
window.showTab = function(name, ...rest) {
  _origShowTab.call(this, name, ...rest);
  if (name === 'brief' && !briefCandidates.length) {
    setTimeout(briefLoadCandidates, 200);
  }
  if (name === 'brief') {
    briefRenderResults();
    briefLoadTodayFiles();
  }
};

// ══════════════════════════════════════════════════════════════
// 导入素材生成要讯
// ══════════════════════════════════════════════════════════════

function toggleImportPanel() {
  const body = document.getElementById('importPanelBody');
  const toggle = document.getElementById('importToggle');
  if (body.style.display === 'none') {
    body.style.display = '';
    toggle.textContent = '▲';
  } else {
    body.style.display = 'none';
    toggle.textContent = '▼';
  }
}

function switchImportTab(tab) {
  document.querySelectorAll('.import-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.import-content').forEach(c => c.style.display = 'none');
  document.getElementById('importTab' + tab.charAt(0).toUpperCase() + tab.slice(1)).classList.add('active');
  document.getElementById('importContent' + tab.charAt(0).toUpperCase() + tab.slice(1)).style.display = '';
  document.getElementById('importStatus').style.display = 'none';
}

function _importShowStatus(icon, text) {
  const s = document.getElementById('importStatus');
  s.style.display = 'flex';
  document.getElementById('importStatusIcon').textContent = icon;
  document.getElementById('importStatusText').textContent = text;
}

function _importHideStatus() {
  document.getElementById('importStatus').style.display = 'none';
}

function _importDisableBtn(btnId, disabled) {
  const btn = document.getElementById(btnId);
  btn.disabled = disabled;
  btn.style.opacity = disabled ? '.5' : '1';
}

function _importAddResult(data) {
  // 和RSS生成的要讯使用同一个结果列表
  const result = {
    id: 'br_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8),
    brief: data.brief,
    sourceEvidence: data.source_evidence,
    validation: data.validation,
    article: {
      title: data.source_info.title || '导入素材',
      source: data.source_info.source || '用户导入',
      source_cn: data.source_info.source || '用户导入',
      region: '导入',
      link: data.source_info.url || '',
      date: data.source_info.pub_date || data.generated_at,
      publication_date_verified: Boolean(data.source_info.pub_date),
      summary: data.source_info.material_text || '',
      brief_score: 0,
      brief_hits: ['imported'],
    },
    timestamp: data.generated_at,
    model: data.model,
  };
  briefResults.unshift(result);
  briefSave(result);
  briefRenderResults();
  document.getElementById('briefDoneCount').textContent = briefResults.length;
  showToast('要讯已生成（导入素材）');
}

async function importFromUrl() {
  const urlInput = document.getElementById('importUrlInput');
  const url = urlInput.value.trim();
  if (!url) { showToast('请输入URL地址'); urlInput.focus(); return; }
  if (!/^https?:\/\/.+/.test(url)) { showToast('请输入有效的网址（http/https开头）'); return; }
  _importDisableBtn('importUrlBtn', true);
  _importShowStatus('⏳', '正在抓取网页内容…');
  try {
    const resp = await apiFetch('/api/brief/import_url', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url}),
    }, {toast: false});
    const data = await resp.json();
    _importShowStatus('✅', `生成成功！提取 ${data.source_info.body_length} 字 · 来源: ${data.source_info.source}${briefWasSaved(data) ? ' · 已安全存档' : ''}`);
    _importAddResult(data);
    urlInput.value = '';
  } catch (e) {
    _importShowStatus('❌', '失败: ' + e.message);
  } finally {
    _importDisableBtn('importUrlBtn', false);
  }
}

function importFileSelected(input) {
  const btn = document.getElementById('importFileBtn');
  const text = document.getElementById('importFileText');
  if (input.files.length) {
    text.textContent = input.files[0].name;
    btn.disabled = false;
    btn.style.opacity = '1';
  } else {
    text.textContent = '点击选择文件或拖拽至此';
    btn.disabled = true;
    btn.style.opacity = '.5';
  }
}

async function importFromFile() {
  const input = document.getElementById('importFileInput');
  if (!input.files.length) { showToast('请先选择文件'); return; }
  const file = input.files[0];
  const source = document.getElementById('importFileSource').value.trim();
  const pubDate = document.getElementById('importFilePubDate').value;
  if (!source) { showToast('请填写文件素材的原始信息来源'); return; }
  if (!pubDate) { showToast('请选择文件素材的来源发文日期'); return; }
  const maxSize = 10 * 1024 * 1024; // 10MB
  if (file.size > maxSize) { showToast('文件过大（最大10MB）'); return; }
  _importDisableBtn('importFileBtn', true);
  _importShowStatus('⏳', `正在解析文件: ${file.name}…`);
  try {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('source', source);
    formData.append('pub_date', pubDate);
    const resp = await apiFetch('/api/brief/import_file', {method: 'POST', body: formData}, {toast: false});
    const data = await resp.json();
    _importShowStatus('✅', `生成成功！提取 ${data.source_info.body_length} 字 · 文件: ${data.source_info.source}${briefWasSaved(data) ? ' · 已安全存档' : ''}`);
    _importAddResult(data);
    input.value = '';
    document.getElementById('importFileText').textContent = '点击选择文件或拖拽至此';
    document.getElementById('importFileSource').value = '';
    document.getElementById('importFilePubDate').value = '';
    document.getElementById('importFileBtn').disabled = true;
  } catch (e) {
    _importShowStatus('❌', '失败: ' + e.message);
  } finally {
    _importDisableBtn('importFileBtn', false);
  }
}

async function importFromText() {
  const textArea = document.getElementById('importTextArea');
  const text = textArea.value.trim();
  if (!text || text.length < 30) { showToast('文本内容过短（至少30字）'); textArea.focus(); return; }
  const title = document.getElementById('importTextTitle').value.trim();
  const source = document.getElementById('importTextSource').value.trim();
  const pubDate = document.getElementById('importTextPubDate').value;
  if (!source) { showToast('请填写文本素材的原始信息来源'); return; }
  if (!pubDate) { showToast('请选择文本素材的来源发文日期'); return; }
  _importDisableBtn('importTextBtn', true);
  _importShowStatus('⏳', '正在生成要讯…');
  try {
    const resp = await apiFetch('/api/brief/import_text', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({text, title, source, pub_date: pubDate}),
    }, {toast: false});
    const data = await resp.json();
    _importShowStatus('✅', `生成成功！来源: ${data.source_info.source}${briefWasSaved(data) ? ' · 已安全存档' : ''}`);
    _importAddResult(data);
    textArea.value = '';
    document.getElementById('importTextTitle').value = '';
    document.getElementById('importTextSource').value = '';
    document.getElementById('importTextPubDate').value = '';
  } catch (e) {
    _importShowStatus('❌', '失败: ' + e.message);
  } finally {
    _importDisableBtn('importTextBtn', false);
  }
}

// URL输入框回车触发
document.addEventListener('DOMContentLoaded', () => {
  const urlInput = document.getElementById('importUrlInput');
  if (urlInput) {
    urlInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') importFromUrl();
    });
  }
  // 文件拖拽支持
  const fileLabel = document.querySelector('.import-file-label');
  if (fileLabel) {
    fileLabel.addEventListener('dragover', e => { e.preventDefault(); fileLabel.classList.add('dragover'); });
    fileLabel.addEventListener('dragleave', () => fileLabel.classList.remove('dragover'));
    fileLabel.addEventListener('drop', e => {
      e.preventDefault();
      fileLabel.classList.remove('dragover');
      const input = document.getElementById('importFileInput');
      if (e.dataTransfer.files.length) {
        input.files = e.dataTransfer.files;
        importFileSelected(input);
      }
    });
  }
});

// 初始加载
window.addEventListener('DOMContentLoaded', () => {
  briefRenderResults();
});
