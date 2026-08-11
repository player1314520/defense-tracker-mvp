/* ═══════════════════════════════════════════════════════════
   我的追踪（Watchlist）· Supabase 持久化
   前端只调用本地 /api/tracking/*（同源，fetch 覆写自动带 CSRF）。
   动态列表用事件委托，绝不把 RSS 来源文本拼进 onclick，杜绝 XSS。
   ═══════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  // 本地转义（不依赖 util.js 内部实现细节）
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function safeHref(u) {
    u = String(u || '');
    return /^https?:\/\//i.test(u) ? u : '#';
  }

  // topicId -> 该 topic 的命中文章数组（供 star 委托按 article_id 回查）
  const _matchCache = Object.create(null);
  let _topics = [];  // 最近一次渲染的追踪项（供 tab 角标 + 同步预警读取）

  function hint(msg, isErr) {
    const el = document.getElementById('trkHint');
    if (!el) return;
    el.textContent = msg || '';
    el.className = 'trk-hint' + (isErr ? ' trk-hint-err' : '');
  }

  async function api(path, opts) {
    const r = await fetch(path, Object.assign({ credentials: 'same-origin' }, opts || {}));
    let data = null;
    try { data = await r.json(); } catch (e) { /* 无 body */ }
    return { ok: r.ok, status: r.status, data: data || {} };
  }

  // ── 加载：先看云端状态，再拉列表 ──────────────────────────
  async function trackingLoad() {
    const list = document.getElementById('trkList');
    const statusText = document.getElementById('trkStatusText');
    if (list) list.innerHTML = '<div class="trk-empty">加载中…</div>';
    hint('');

    const st = await api('/api/tracking/status');
    if (st.ok && st.data.configured === false) {
      if (statusText) statusText.textContent = '⚠ 云端未配置：在 .supabase_config.json 填 url+key（或设 SUPABASE_URL / SUPABASE_ANON_KEY）后刷新';
      if (list) list.innerHTML = '<div class="trk-empty">云端追踪未配置，无法保存追踪项。</div>';
      return;
    }
    if (st.ok && st.data.reachable === false) {
      if (list) list.innerHTML = '<div class="trk-empty">云端(Supabase)暂不可达，请检查网络后刷新。</div>';
      return;
    }

    const res = await api('/api/tracking/topics');
    if (!res.ok) {
      if (list) list.innerHTML = '<div class="trk-empty">' + esc(res.data.error || ('加载失败 (' + res.status + ')')) + '</div>';
      return;
    }
    renderTopics(res.data.topics || [], res.data.news_total || 0);
  }

  function renderTopics(topics, newsTotal) {
    _topics = topics || [];
    updateTabBadge(_topics);
    const list = document.getElementById('trkList');
    const countEl = document.getElementById('trkTopicCount');
    const statusText = document.getElementById('trkStatusText');
    if (countEl) countEl.textContent = topics.length;
    if (statusText) statusText.textContent = '添加关键词/主题 → 从 ' + newsTotal + ' 条实时新闻里匹配追踪 · 云端持久化(Supabase)';
    if (!list) return;
    if (!topics.length) {
      list.innerHTML = '<div class="trk-empty">还没有追踪项。上方输入名称+关键词，点「添加追踪」。</div>';
      return;
    }
    list.innerHTML = topics.map(function (t) {
      const kws = (t.keywords || []).map(esc).join(' · ');
      const kwsCsv = (t.keywords || []).join(',');
      const mode = t.match_mode === 'all' ? '全部命中' : '任一命中';
      const off = t.enabled === false;
      return '' +
        '<div class="trk-item' + (off ? ' trk-item-off' : '') + '" data-id="' + esc(t.id) + '">' +
          '<div class="trk-item-head">' +
            '<div class="trk-item-main">' +
              '<span class="trk-item-label">' + esc(t.label) + '</span>' +
              '<span class="trk-item-kw">' + (kws || '<i>无关键词</i>') + '</span>' +
              '<span class="trk-item-mode">' + mode + '</span>' +
              (off ? '<span class="trk-item-offtag">已暂停</span>' : '') +
            '</div>' +
            '<div class="trk-item-actions">' +
              '<span class="trk-badge" title="当前实时新闻中的命中数">命中 ' + (t.match_count || 0) + '</span>' +
              '<button class="trk-btn" data-act="view">查看命中</button>' +
              '<button class="trk-btn" data-act="edit">编辑</button>' +
              '<button class="trk-btn trk-btn-danger" data-act="del">删除</button>' +
            '</div>' +
          '</div>' +
          // 内联编辑表单（默认隐藏，值预填自当前 topic）
          '<div class="trk-edit" hidden>' +
            '<input class="trk-input trk-edit-label" type="text" maxlength="120" value="' + esc(t.label) + '" placeholder="名称">' +
            '<input class="trk-input trk-edit-kw" type="text" value="' + esc(kwsCsv) + '" placeholder="关键词,逗号分隔">' +
            '<select class="trk-select trk-edit-mode">' +
              '<option value="any"' + (t.match_mode !== 'all' ? ' selected' : '') + '>任一命中</option>' +
              '<option value="all"' + (t.match_mode === 'all' ? ' selected' : '') + '>全部命中</option>' +
            '</select>' +
            '<label class="trk-edit-en"><input type="checkbox" class="trk-edit-enabled"' + (off ? '' : ' checked') + '> 启用</label>' +
            '<button class="trk-add-btn" data-act="save-edit">保存</button>' +
            '<button class="trk-btn" data-act="cancel-edit">取消</button>' +
          '</div>' +
          '<div class="trk-matches" hidden></div>' +
        '</div>';
    }).join('');
  }

  // ── 添加追踪项 ────────────────────────────────────────────
  async function trackingAdd() {
    const labelEl = document.getElementById('trkLabel');
    const kwEl = document.getElementById('trkKeywords');
    const modeEl = document.getElementById('trkMode');
    const btn = document.getElementById('trkAddBtn');
    const label = (labelEl.value || '').trim();
    if (!label) { hint('请填写追踪项名称', true); labelEl.focus(); return; }
    const keywords = (kwEl.value || '').replace(/，/g, ',').split(',')
      .map(function (s) { return s.trim(); }).filter(Boolean);
    if (!keywords.length) { hint('至少填一个关键词', true); kwEl.focus(); return; }

    btn.disabled = true;
    const res = await api('/api/tracking/topics', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label: label, keywords: keywords, match_mode: modeEl.value })
    });
    btn.disabled = false;
    if (!res.ok) { hint(res.data.error || ('添加失败 (' + res.status + ')'), true); return; }
    labelEl.value = ''; kwEl.value = '';
    hint('已添加：' + label);
    trackingLoad();
  }

  // ── 事件委托：查看命中 / 删除 / 收藏 ──────────────────────
  async function onListClick(e) {
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    const item = e.target.closest('.trk-item');
    if (!item) return;
    const tid = item.getAttribute('data-id');
    const act = btn.getAttribute('data-act');

    if (act === 'del') {
      if (!window.confirm('删除该追踪项？其收藏记录也会一并删除。')) return;
      const res = await api('/api/tracking/topics/' + encodeURIComponent(tid), { method: 'DELETE' });
      if (!res.ok) { hint(res.data.error || '删除失败', true); return; }
      trackingLoad();
      return;
    }

    if (act === 'view') {
      const box = item.querySelector('.trk-matches');
      if (!box.hidden) { box.hidden = true; btn.textContent = '查看命中'; return; }
      box.hidden = false; btn.textContent = '收起';
      box.innerHTML = '<div class="trk-empty">匹配中…</div>';
      const res = await api('/api/tracking/topics/' + encodeURIComponent(tid) + '/matches');
      if (!res.ok) { box.innerHTML = '<div class="trk-empty">' + esc(res.data.error || '加载失败') + '</div>'; return; }
      _matchCache[tid] = res.data.matches || [];
      renderMatches(box, tid, _matchCache[tid], (res.data.topic || {}).keywords || []);
      return;
    }

    if (act === 'edit') {
      const box = item.querySelector('.trk-edit');
      box.hidden = !box.hidden;
      btn.textContent = box.hidden ? '编辑' : '取消编辑';
      return;
    }

    if (act === 'cancel-edit') {
      item.querySelector('.trk-edit').hidden = true;
      const eb = item.querySelector('[data-act="edit"]');
      if (eb) eb.textContent = '编辑';
      return;
    }

    if (act === 'save-edit') {
      const box = item.querySelector('.trk-edit');
      const label = (box.querySelector('.trk-edit-label').value || '').trim();
      if (!label) { hint('名称不能为空', true); return; }
      const keywords = (box.querySelector('.trk-edit-kw').value || '').replace(/，/g, ',')
        .split(',').map(function (s) { return s.trim(); }).filter(Boolean);
      if (!keywords.length) { hint('至少填一个关键词', true); return; }
      btn.disabled = true;
      const res = await api('/api/tracking/topics/' + encodeURIComponent(tid), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          label: label,
          keywords: keywords,
          match_mode: box.querySelector('.trk-edit-mode').value,
          enabled: box.querySelector('.trk-edit-enabled').checked
        })
      });
      btn.disabled = false;
      if (!res.ok) { hint(res.data.error || '保存失败', true); return; }
      hint('已保存：' + label);
      trackingLoad();
      return;
    }

    if (act === 'star') {
      const aid = btn.getAttribute('data-aid');
      const arr = _matchCache[tid] || [];
      const art = arr.find(function (a) { return a.article_id === aid; });
      if (!art) return;
      const nowStar = !(btn.getAttribute('data-on') === '1');
      btn.disabled = true;
      const res = await api('/api/tracking/topics/' + encodeURIComponent(tid) + '/star', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ starred: nowStar, article: art })
      });
      btn.disabled = false;
      if (!res.ok) { hint(res.data.error || '收藏失败', true); return; }
      art.starred = nowStar;
      btn.setAttribute('data-on', nowStar ? '1' : '0');
      btn.textContent = nowStar ? '★' : '☆';
      btn.classList.toggle('on', nowStar);
    }
  }

  // 高亮：先转义标题，再把匹配到的关键词包 <mark>（$1 取自已转义串，无 XSS）
  function highlight(text, keywords) {
    let safe = esc(text);
    (keywords || []).forEach(function (kw) {
      kw = String(kw || '').trim();
      if (!kw) return;
      const re = new RegExp('(' + kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
      safe = safe.replace(re, '<mark class="trk-mark">$1</mark>');
    });
    return safe;
  }

  function renderMatches(box, tid, matches, keywords) {
    if (!matches.length) {
      box.innerHTML = '<div class="trk-empty">当前实时新闻里暂无命中。</div>';
      return;
    }
    box.innerHTML = matches.map(function (m) {
      const on = m.starred ? '1' : '0';
      const meta = [m.source_cn || m.source, m.date].filter(Boolean).map(esc).join(' · ');
      const score = m.score ? '<span class="trk-hit-score" title="相关度（标题命中权重更高）">相关 ' + esc(m.score) + '</span>' : '';
      return '' +
        '<div class="trk-hit">' +
          '<button class="trk-star' + (m.starred ? ' on' : '') + '" data-act="star" data-on="' + on +
                 '" data-aid="' + esc(m.article_id) + '" title="收藏/取消">' + (m.starred ? '★' : '☆') + '</button>' +
          '<a class="trk-hit-title" href="' + esc(safeHref(m.link)) + '" target="_blank" rel="noopener noreferrer">' + highlight(m.title, keywords) + '</a>' +
          score +
          '<span class="trk-hit-meta">' + meta + '</span>' +
        '</div>';
    }).join('');
  }

  // ── tab 角标：所有启用追踪项的命中总数 ──────────────────────
  function updateTabBadge(topics) {
    const badge = document.getElementById('trkTabBadge');
    if (!badge) return;
    const total = (topics || []).reduce(function (s, t) {
      return s + (t.enabled === false ? 0 : (t.match_count || 0));
    }, 0);
    if (total > 0) { badge.textContent = total; badge.hidden = false; }
    else { badge.textContent = ''; badge.hidden = true; }
  }

  // ── 同步追踪关键词到实时新闻「预警词」（复用 news.js 全局变量/函数） ──
  function trackingSyncAlerts() {
    const kws = [];
    _topics.forEach(function (t) {
      if (t.enabled === false) return;
      (t.keywords || []).forEach(function (k) { if (k && kws.indexOf(k) < 0) kws.push(k); });
    });
    if (!kws.length) { hint('没有可同步的关键词', true); return; }
    if (typeof alertKeywords !== 'undefined' && alertKeywords instanceof Set) {
      kws.forEach(function (k) { alertKeywords.add(k); });
      if (typeof saveAlerts === 'function') saveAlerts();
      if (typeof renderAlertTags === 'function') renderAlertTags();
      if (typeof showToast === 'function') showToast('已同步 ' + kws.length + ' 个关键词到预警词');
      hint('已同步 ' + kws.length + ' 个关键词到「预警词」（实时新闻 Tab 生效）');
    } else {
      hint('预警词模块未就绪，无法同步', true);
    }
  }

  // ── 收藏夹：跨追踪项看全部已 star 的文章 ──────────────────
  async function trackingToggleFav() {
    const panel = document.getElementById('trkFav');
    const btn = document.getElementById('trkFavBtn');
    if (!panel) return;
    if (!panel.hidden) { panel.hidden = true; if (btn) btn.classList.remove('on'); return; }
    panel.hidden = false; if (btn) btn.classList.add('on');
    panel.innerHTML = '<div class="trk-empty">加载收藏…</div>';
    const res = await api('/api/tracking/starred');
    if (!res.ok) { panel.innerHTML = '<div class="trk-empty">' + esc(res.data.error || '加载失败') + '</div>'; return; }
    renderStarred(panel, res.data.starred || []);
  }

  function renderStarred(panel, rows) {
    if (!rows.length) {
      panel.innerHTML = '<div class="trk-empty">还没有收藏。展开某个追踪项，点 ☆ 收藏文章。</div>';
      return;
    }
    panel.innerHTML = '<div class="trk-fav-head">⭐ 我的收藏（' + rows.length + '）</div>' + rows.map(function (r) {
      const label = (r.topic || {}).label || '';
      const meta = [label, r.source, String(r.published_at || '').slice(0, 10)].filter(Boolean).map(esc).join(' · ');
      return '<div class="trk-hit">' +
        '<button class="trk-star on" data-act="fav-unstar" data-tid="' + esc(r.topic_id) + '" data-aid="' + esc(r.article_id) + '" title="取消收藏">★</button>' +
        '<a class="trk-hit-title" href="' + esc(safeHref(r.link)) + '" target="_blank" rel="noopener noreferrer">' + esc(r.title || r.article_id) + '</a>' +
        '<span class="trk-hit-meta">' + meta + '</span>' +
        '</div>';
    }).join('');
  }

  async function onFavClick(e) {
    const btn = e.target.closest('[data-act="fav-unstar"]');
    if (!btn) return;
    const tid = btn.getAttribute('data-tid');
    const aid = btn.getAttribute('data-aid');
    btn.disabled = true;
    const res = await api('/api/tracking/topics/' + encodeURIComponent(tid) + '/star', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ starred: false, article: { article_id: aid } })
    });
    btn.disabled = false;
    if (!res.ok) { hint(res.data.error || '取消失败', true); return; }
    const hit = btn.closest('.trk-hit'); if (hit) hit.remove();
    const panel = document.getElementById('trkFav');
    const remain = panel.querySelectorAll('.trk-hit').length;
    if (!remain) {
      renderStarred(panel, []);                    // 空态
    } else {
      const head = panel.querySelector('.trk-fav-head');
      if (head) head.textContent = '⭐ 我的收藏（' + remain + '）';
    }
  }

  // ── 挂载 ──────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', function () {
    const list = document.getElementById('trkList');
    if (list) list.addEventListener('click', onListClick);
    const fav = document.getElementById('trkFav');
    if (fav) fav.addEventListener('click', onFavClick);
    const kw = document.getElementById('trkKeywords');
    if (kw) kw.addEventListener('keydown', function (e) { if (e.key === 'Enter') trackingAdd(); });
  });

  // showTab 链式 override：首次进入「我的追踪」自动加载（唯一变量名，遵项目约定）
  const _origShowTabTracking = window.showTab;
  let _trkLoadedOnce = false;
  window.showTab = function (name) {
    if (typeof _origShowTabTracking === 'function') _origShowTabTracking.apply(this, arguments);
    if (name === 'tracking' && !_trkLoadedOnce) { _trkLoadedOnce = true; trackingLoad(); }
  };

  // 暴露给内联 onclick（刷新/添加/收藏夹/同步预警按钮）
  window.trackingLoad = trackingLoad;
  window.trackingAdd = trackingAdd;
  window.trackingToggleFav = trackingToggleFav;
  window.trackingSyncAlerts = trackingSyncAlerts;
})();
