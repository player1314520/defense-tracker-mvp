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
  if (saved) briefResults = JSON.parse(saved) || [];
} catch(e) { briefResults = []; }

function briefSave() {
  try {
    // 持久化时剥离编辑态临时字段
    const clean = briefResults.slice(0, 50).map(r => {
      const {_editing, _editBuffer, ...rest} = r;
      return rest;
    });
    localStorage.setItem('briefResults', JSON.stringify(clean));
    // ☁ write-through：同步到服务端（udSync 来自 news.js，先加载；不可达仅 warn）
    if (typeof udSync === 'function') {
      udSync('/api/userdata/kv/briefResults', { _method: 'PUT', value: clean });
    }
  } catch(e) {}
}

// ☁ 启动合并：服务端要讯历史与本地按 id 并集（服务端优先），合并后回推
window.addEventListener('userdata-ready', (e) => {
  const server = e.detail && e.detail.brief_results;
  if (Array.isArray(server) && server.length) {
    const seen = new Set(server.map(r => r.id));
    const merged = server.concat(briefResults.filter(r => !seen.has(r.id)));
    merged.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
    briefResults = merged.slice(0, 50);
    briefSave();
    if (typeof briefRenderResults === 'function') briefRenderResults();
  } else if (briefResults.length) {
    briefSave();  // 服务端为空、本地有存量 → 首次推上去
  }
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
        <a class="brief-link-btn" href="${escHtml(a.link)}" target="_blank" rel="noopener">原文</a>
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
      body: JSON.stringify({ article })
    }, {toast: false});
    const data = await r.json();
    if (data.error) { showToast('❌ ' + data.error); return; }
    if (data.article_id) article.article_id = data.article_id;
    briefAddResult(data.brief, article);
    showToast(data.saved_to ? '✅ 已生成1篇要讯 · 已存档到 素材库/每日新闻/' : '✅ 已生成1篇要讯');
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
      body: JSON.stringify({ article: item })
    }, {toast: false});
    const data = await r.json();
    if (data.error) { showToast('生成失败：' + data.error); return; }
    briefAddResult(data.brief, item);
    showTab('brief');
    showToast(data.saved_to ? '要讯已生成并存档到 素材库/每日新闻/' : '要讯已生成');
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
            briefAddResult(obj.brief, obj.article);
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

function briefAddResult(brief, article) {
  const id = 'br_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
  briefResults.unshift({
    id,
    brief,
    article: {
      title: article.title,
      source: article.source_cn || article.source,
      source_en: article.source,
      region: article.region,
      link: article.link,
      date: article.date,
      article_id: article.article_id,
      quality_level: article.quality_level,
      quality_score: article.quality_score,
    },
    timestamp: new Date().toISOString(),
  });
  briefResults = briefResults.slice(0, 50);
  briefSave();
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
        <a href="${escHtml(r.article.link)}" target="_blank" rel="noopener" class="brief-result-link">原文</a>
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
    suggestOk: false, structOk: false, mdOk: true,
    issues: []
  };
  if (!text || typeof text !== 'string') { out.issues.push('空内容'); return out; }
  // 解析：与后端一致 — 空行驱动 meta→title→body 状态切换
  const rawLines = text.replace(/\r/g, '').split('\n').map(s => s.replace(/\s+$/, ''));
  let state = 'meta';
  const titleLines = [], bodyLines = [];
  for (const raw of rawLines) {
    const s = raw.trim();
    if (!s) {
      if (state === 'meta') state = 'title';
      else if (state === 'title' && titleLines.length) state = 'body';
      continue;
    }
    if (s.startsWith('事件时间') || s.startsWith('价 值 点') || s.startsWith('价值点')) {
      state = 'meta'; continue;
    }
    if (s.startsWith('（信息来源') || s.startsWith('(信息来源')) { state = 'done'; continue; }
    if (s.startsWith('报送人')) continue;
    if (state === 'title') { titleLines.push(s); }
    else if (state === 'body' || state === 'meta') {
      if (state === 'meta') state = 'body';
      bodyLines.push(s);
    }
  }
  const title = titleLines.join('');
  const body = bodyLines.join('');
  // 去除中文标点后计字符数（与后端 _count_cn 一致）
  const countCn = (s) => (s || '').replace(/[，。、；：""''（）《》〈〉「」『』【】—…,.\s]/g, '').length;
  out.bodyCount = countCn(body);
  out.titleCount = countCn(title);
  out.bodyOk = out.bodyCount >= 250 && out.bodyCount <= 350;
  out.titleOk = out.titleCount >= 8 && out.titleCount <= 30;
  if (!out.bodyOk) out.issues.push(`正文${out.bodyCount}字（应250-350）`);
  if (!out.titleOk) out.issues.push(`标题${out.titleCount}字（应8-30）`);
  // 建议范式：持续跟踪...针对性加强...能力建设
  out.suggestOk = /建议持续跟踪[^。]*?针对性加强[^。]*?能力建设/.test(body);
  if (!out.suggestOk) out.issues.push('建议未采用"持续跟踪X+针对性加强Y能力建设"范式');
  // (1)(2)(3) 结构
  const hasStruct = (/（一）|\(1\)|一、/.test(body)) && (/（二）|\(2\)|二、/.test(body)) && (/（三）|\(3\)|三、/.test(body));
  out.structOk = hasStruct;
  if (!hasStruct) out.issues.push('缺少（一）（二）（三）三段结构');
  // Markdown 检查
  if (/(^|\s)(#{1,6}\s|\*\*|__|```|~~~|^\s*[-*+]\s)/m.test(text)) {
    out.mdOk = false; out.issues.push('含Markdown符号');
  }
  // 警示词检查
  const warnWords = ['值得警惕','值得关注','值得重视','威胁','压力','引发关注','引发热议'];
  const hitWarn = warnWords.filter(w => title.includes(w));
  if (hitWarn.length) out.issues.push(`标题含警示词：${hitWarn.join('、')}`);
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

function briefEditSave(id) {
  const r = briefResults.find(x => x.id === id);
  if (!r) return;
  const newText = (r._editBuffer != null) ? r._editBuffer : r.brief;
  r.brief = newText;
  r._editing = false;
  delete r._editBuffer;
  briefSave();
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

function briefCopyOne(id) {
  const r = briefResults.find(x => x.id === id);
  if (!r) return;
  if (_briefFlushEdit(r)) { briefSave(); briefRenderResults(); }
  navigator.clipboard.writeText(r.brief).then(() => showToast('已复制要讯'));
}

async function briefDownloadDocx(id) {
  const r = briefResults.find(x => x.id === id);
  if (!r) return;
  if (_briefFlushEdit(r)) { briefSave(); briefRenderResults(); }
  showToast('生成Word文件…');
  try {
    const resp = await apiFetch('/api/brief/export_docx', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ brief: r.brief })
    }, {toast: false});
    await downloadResponseBlob(resp, '要讯.docx', '.docx');
    showToast('Word已下载');
  } catch(e) {
    showToast('失败: ' + e.message);
  }
}

async function briefDownloadCompiledDocx() {
  if (!briefResults.length) { showToast('暂无要讯可汇编'); return; }
  // 把所有编辑态未保存的修改 flush 到 r.brief
  let _flushed = 0;
  briefResults.forEach(r => { if (_briefFlushEdit(r)) _flushed++; });
  if (_flushed) { briefSave(); briefRenderResults(); }
  showToast(`汇编 ${briefResults.length} 篇要讯…`);
  try {
    const resp = await apiFetch('/api/brief/export_docx_compiled', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ briefs: briefResults.map(r => r.brief) })
    }, {toast: false});
    await downloadResponseBlob(resp, '要讯汇编.docx', '.docx');
    showToast(`汇编Word已下载（${briefResults.length}篇）`);
  } catch(e) {
    showToast('失败: ' + e.message);
  }
}

async function briefDownloadAllDocx() {
  if (!briefResults.length) { showToast('暂无要讯可导出'); return; }
  let _flushed = 0;
  briefResults.forEach(r => { if (_briefFlushEdit(r)) _flushed++; });
  if (_flushed) { briefSave(); briefRenderResults(); }
  showToast(`批量生成 ${briefResults.length} 个Word文件…`);
  for (const r of briefResults) {
    try {
      const resp = await apiFetch('/api/brief/export_docx', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ brief: r.brief })
      }, {toast: false});
      await downloadResponseBlob(resp, '要讯_' + r.id + '.docx', '.docx');
      await new Promise(r => setTimeout(r, 400));
    } catch(e) { console.error(e); }
  }
  showToast(`已导出 ${briefResults.length} 个Word`);
}

function briefDeleteOne(id) {
  briefResults = briefResults.filter(x => x.id !== id);
  briefSave();
  briefRenderResults();
  showToast('已删除');
}

async function briefDiscardResult(id) {
  const r = briefResults.find(x => x.id === id);
  if (!r) return;
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
      resp = await apiFetch('/api/brief/import_text', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ text: r.brief, title: r.article.title, source: r.article.source })
      }, {toast: false});
    } else {
      resp = await apiFetch('/api/brief/generate', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ article: art })
      }, {toast: false});
    }
    const data = await resp.json();
    if (data.error) { showToast(data.error, 5000); return; }
    r.brief = data.brief;
    r.timestamp = new Date().toISOString();
    if (data.validation) r.validation = data.validation;
    briefSave();
    briefRenderResults();
    showToast(data.saved_to ? '已重新生成 · 已存档到 素材库/每日新闻/' : '已重新生成');
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
  briefResults = [];
  briefSave();
  briefRenderResults();
  showToast('已清空');
}

function briefExportAll() {
  if (!briefResults.length) { showToast('暂无要讯可导出'); return; }
  let _flushed = 0;
  briefResults.forEach(r => { if (_briefFlushEdit(r)) _flushed++; });
  if (_flushed) { briefSave(); briefRenderResults(); }
  const today = new Date().toISOString().slice(0, 10);
  const content = briefResults.map((r, i) => {
    return `════════════════════════════════════════\n要讯 #${i+1}  · 生成时间 ${new Date(r.timestamp).toLocaleString('zh-CN')}\n════════════════════════════════════════\n${r.brief}\n\n【原文链接】${r.article.link}\n【原始来源】${r.article.source} · ${r.article.region||''}\n`;
  }).join('\n\n');
  const header = `防务要讯汇编 · ${today}\n共 ${briefResults.length} 篇\n基于《写作要点》选题 · 符合《命令》规范\n\n\n`;
  const blob = new Blob([header + content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `防务要讯汇编_${today}.txt`;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`已导出 ${briefResults.length} 篇`);
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
    validation: data.validation,
    article: {
      title: data.source_info.title || '导入素材',
      source: data.source_info.source || '用户导入',
      source_cn: data.source_info.source || '用户导入',
      region: '导入',
      link: data.source_info.url || '',
      date: data.generated_at,
      brief_score: 0,
      brief_hits: ['imported'],
    },
    timestamp: data.generated_at,
    model: data.model,
  };
  briefResults.unshift(result);
  briefSave();
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
    _importShowStatus('✅', `生成成功！提取 ${data.source_info.body_length} 字 · 来源: ${data.source_info.source}${data.saved_to ? ' · 已存档到 素材库/每日新闻/' : ''}`);
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
  const maxSize = 10 * 1024 * 1024; // 10MB
  if (file.size > maxSize) { showToast('文件过大（最大10MB）'); return; }
  _importDisableBtn('importFileBtn', true);
  _importShowStatus('⏳', `正在解析文件: ${file.name}…`);
  try {
    const formData = new FormData();
    formData.append('file', file);
    const resp = await apiFetch('/api/brief/import_file', {method: 'POST', body: formData}, {toast: false});
    const data = await resp.json();
    _importShowStatus('✅', `生成成功！提取 ${data.source_info.body_length} 字 · 文件: ${data.source_info.source}${data.saved_to ? ' · 已存档到 素材库/每日新闻/' : ''}`);
    _importAddResult(data);
    input.value = '';
    document.getElementById('importFileText').textContent = '点击选择文件或拖拽至此';
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
  _importDisableBtn('importTextBtn', true);
  _importShowStatus('⏳', '正在生成要讯…');
  try {
    const resp = await apiFetch('/api/brief/import_text', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({text, title, source}),
    }, {toast: false});
    const data = await resp.json();
    _importShowStatus('✅', `生成成功！来源: ${data.source_info.source}${data.saved_to ? ' · 已存档到 素材库/每日新闻/' : ''}`);
    _importAddResult(data);
    textArea.value = '';
    document.getElementById('importTextTitle').value = '';
    document.getElementById('importTextSource').value = '';
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
