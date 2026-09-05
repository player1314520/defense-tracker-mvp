// ══════════════════════════════════════════════════════════
// 价值标签颜色映射
// ══════════════════════════════════════════════════════════
const VALUE_LABELS_CN = {
  china_intel: '对华情报', nuclear: '核战略',
  equipment:   '装备动态', cyber_intel: '网络情报',
  strategy:    '战略分析', think_tank: '智库报告',
  budget:      '军工财经', breaking: '突发军情',
  pla_research:'PLA研究',
};
const VALUE_LABELS_EN = {
  china_intel: 'China Intel', nuclear: 'Nuclear',
  equipment:   'Equipment',   cyber_intel: 'Cyber Intel',
  strategy:    'Strategy',    think_tank: 'Think Tank',
  budget:      'Defense Budget', breaking: 'Breaking',
  pla_research:'PLA Research',
};

// ══════════════════════════════════════════════════════════
// ☁ 用户状态云同步（write-through：localStorage 离线缓存 + 服务端 SQLite 真相）
// ══════════════════════════════════════════════════════════
function udSync(path, body) {
  // fire-and-forget：服务端不可达只 warn，不打断本地操作
  try {
    fetch(path, {
      method: body && body._method === 'PUT' ? 'PUT' : 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(body),
    }).catch(e => console.warn('[udSync]', path, e.message));
  } catch (e) { /* noop */ }
}

// briefResults 使用乐观并发；bootstrap 是 revision/schema 的唯一启动来源。
window.__USERDATA_REVISION__ = Number.isInteger(window.__USERDATA_REVISION__)
  ? window.__USERDATA_REVISION__ : null;
window.__USERDATA_SCHEMA_VERSION__ = Number.isInteger(window.__USERDATA_SCHEMA_VERSION__)
  ? window.__USERDATA_SCHEMA_VERSION__ : 0;

function userdataApplyMeta(state) {
  if (!state || typeof state !== 'object') return;
  const revision = Number(state.revision);
  const schemaVersion = Number(state.schema_version);
  if (Number.isInteger(revision) && revision >= 0) window.__USERDATA_REVISION__ = revision;
  if (Number.isInteger(schemaVersion) && schemaVersion >= 0) {
    window.__USERDATA_SCHEMA_VERSION__ = schemaVersion;
  }
}

// ══════════════════════════════════════════════════════════
// 🔖 书签系统（localStorage 缓存 + 服务端同步）
// ══════════════════════════════════════════════════════════
const bookmarks = new Set(JSON.parse(localStorage.getItem('defense_bookmarks') || '[]'));

function toggleBookmark(link, btn) {
  const on = !bookmarks.has(link);
  if (on) {
    bookmarks.add(link);
    if (btn) { btn.textContent = '★'; btn.title = '已收藏'; btn.classList.add('bookmarked'); }
  } else {
    bookmarks.delete(link);
    if (btn) { btn.textContent = '☆'; btn.title = '收藏'; btn.classList.remove('bookmarked'); }
  }
  localStorage.setItem('defense_bookmarks', JSON.stringify([...bookmarks]));
  updateBookmarkStat();
  const art = (typeof allNews !== 'undefined' && allNews.find(a => a.link === link)) || { link };
  udSync('/api/userdata/bookmark', {
    on,
    article: { link, title: art.title || '', source: art.source_cn || art.source || '', date: art.date || '' },
  });
}

function updateBookmarkStat() {
  const el = document.getElementById('statBookmarks');
  if (el) el.textContent = bookmarks.size;
}

// ══════════════════════════════════════════════════════════
// 🔍 新闻搜索
// ══════════════════════════════════════════════════════════
let searchQuery = '';

function handleSearch(val) {
  searchQuery = val.trim().toLowerCase();
  const clearBtn = document.getElementById('searchClearBtn');
  if (clearBtn) clearBtn.style.display = searchQuery ? 'flex' : 'none';
  renderNews();
}

function clearSearch() {
  searchQuery = '';
  const input = document.getElementById('newsSearch');
  if (input) input.value = '';
  const clearBtn = document.getElementById('searchClearBtn');
  if (clearBtn) clearBtn.style.display = 'none';
  renderNews();
}

// ══════════════════════════════════════════════════════════
// 中文翻译：本地 LLM 端点优先（军事术语准确），MyMemory 免费 API 降级
// ══════════════════════════════════════════════════════════
const translateCache = {};
async function translateText(text) {
  if (!text || text.length < 3) return text;
  if (translateCache[text]) return translateCache[text];
  // ① 首选 /api/translate（走已配置的 LLM，带军事术语表）
  try {
    const r = await fetch('/api/translate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ text: text.slice(0, 600) }),
    });
    if (r.ok) {
      const data = await r.json();
      if (data.translation) { translateCache[text] = data.translation; return data.translation; }
    }
  } catch { /* 降级 */ }
  // ② 降级：MyMemory（AI 未配置/超预算/异常时兜底）
  try {
    const url = `https://api.mymemory.translated.net/get?q=${encodeURIComponent(text.slice(0,400))}&langpair=en|zh-CN`;
    const data = await fetch(url).then(r => r.json());
    const result = data?.responseData?.translatedText || text;
    translateCache[text] = result;
    return result;
  } catch { return text; }
}

// ══════════════════════════════════════════════════════════
// 🔔 预警关键词
// ══════════════════════════════════════════════════════════
let alertKeywords = new Set(JSON.parse(localStorage.getItem('defense_alerts') || '[]'));
let alertBarOpen = true;

function saveAlerts() { localStorage.setItem('defense_alerts', JSON.stringify([...alertKeywords])); }

function handleAlertKey(e) {
  if (e.key !== 'Enter') return;
  const val = e.target.value.trim().toLowerCase();
  if (!val) return;
  alertKeywords.add(val);
  saveAlerts();
  udSync('/api/userdata/alert', { term: val, on: true });
  e.target.value = '';
  renderAlertTags();
  renderNews();
  showToast(`预警词 "${val}" 已添加`);
}

function removeAlert(kw) {
  alertKeywords.delete(kw);
  saveAlerts();
  udSync('/api/userdata/alert', { term: kw, on: false });
  renderAlertTags();
  renderNews();
}

function renderAlertTags() {
  const el = document.getElementById('alertTagsDisplay');
  if (!el) return;
  el.innerHTML = [...alertKeywords].map(kw =>
    `<span class="alert-tag">${escHtml(kw)}<button onclick="removeAlert('${escAttrJs(kw)}')" title="移除">×</button></span>`
  ).join('');
}

function toggleAlertBar() {
  alertBarOpen = !alertBarOpen;
  const input = document.getElementById('alertInput');
  const btn   = document.getElementById('alertToggleBtn');
  if (input) input.style.display = alertBarOpen ? '' : 'none';
  if (btn)   btn.textContent = alertBarOpen ? '▲' : '▼';
}

// ══════════════════════════════════════════════════════════
// 📖 已读状态
// ══════════════════════════════════════════════════════════
const readSet = new Set(JSON.parse(localStorage.getItem('defense_read') || '[]'));
function markRead(link) {
  if (readSet.has(link)) return;
  readSet.add(link);
  localStorage.setItem('defense_read', JSON.stringify([...readSet]));
  udSync('/api/userdata/read', { links: [link] });
  updateUnreadBadge();
}
function markAllRead() {
  const newlyRead = allNews.filter(a => !readSet.has(a.link)).map(a => a.link);
  allNews.forEach(a => readSet.add(a.link));
  localStorage.setItem('defense_read', JSON.stringify([...readSet]));
  if (newlyRead.length) udSync('/api/userdata/read', { links: newlyRead });
  updateUnreadBadge();
  renderNews();
}
function updateUnreadBadge() {
  const unread = allNews.filter(a => !readSet.has(a.link)).length;
  const badge  = document.getElementById('unreadBadge');
  const cnt    = document.getElementById('unreadCount');
  if (!badge) return;
  if (unread > 0) { badge.style.display = 'flex'; if (cnt) cnt.textContent = unread; }
  else             { badge.style.display = 'none'; }
}

// ══════════════════════════════════════════════════════════
// 🍞 Toast 通知
// ══════════════════════════════════════════════════════════
function showToast(msg, duration = 2800) {
  let wrap = document.getElementById('toastWrap');
  if (!wrap) {
    wrap = document.createElement('div');
    wrap.id = 'toastWrap';
    wrap.className = 'toast-wrap';
    document.body.appendChild(wrap);
  }
  const t = document.createElement('div');
  t.className = 'toast-item';
  t.textContent = msg;
  wrap.appendChild(t);
  requestAnimationFrame(() => t.classList.add('show'));
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 400); }, duration);
}

// ══════════════════════════════════════════════════════════
// ⌨️ 键盘快捷键
// ══════════════════════════════════════════════════════════
const TAB_KEYS = { '1':'news','2':'china','3':'thinktanks','4':'ai','5':'agent','6':'brief' };
document.addEventListener('keydown', e => {
  const tag = document.activeElement?.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA') {
    if (e.key === 'Escape') { document.activeElement.blur(); clearSearch(); }
    return;
  }
  if (e.key === '/') { e.preventDefault(); document.getElementById('newsSearch')?.focus(); }
  if (TAB_KEYS[e.key]) showTab(TAB_KEYS[e.key]);
  if (e.key === 'Escape') clearSearch();
  if (e.key === 'r' || e.key === 'R') { fetchAll(); showToast('正在刷新…'); }
});

// ══════════════════════════════════════════════════════════
// 新闻渲染（带价值标签 + 翻译按钮）
// ══════════════════════════════════════════════════════════
let allNews = [], currentFilter = 'all', currentSort = 'priority', activeTagFilter = null, minStarFilter = 0;

// ── ☁ 启动合并：bootstrap → 按服务端 schema 迁移 → 并集 → 刷 UI ──
async function userdataBoot() {
  let d = null;
  try {
    const r = await fetch('/api/userdata/bootstrap', { credentials: 'same-origin' });
    if (!r.ok) return;
    d = await r.json();
    userdataApplyMeta(d);
  } catch (e) { return; }  // 服务端不可达：保持纯 localStorage 模式

  // 迁移标记跟随服务器 schema；只有迁移请求成功才推进，失败时下次启动重试。
  const markerKey = 'defense_ud_schema_version';
  const localSchemaVersion = Number.parseInt(localStorage.getItem(markerKey) || '0', 10) || 0;
  const serverSchemaVersion = window.__USERDATA_SCHEMA_VERSION__;
  if (localSchemaVersion < serverSchemaVersion) {
    try {
      const migration = await fetch('/api/userdata/migrate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({
          bookmarks: [...bookmarks].map(link => {
            const a = (typeof allNews !== 'undefined' && allNews.find(x => x.link === link)) || {};
            return { link, title: a.title || '', source: a.source_cn || a.source || '', date: a.date || '' };
          }),
          read: [...readSet],
          alerts: [...alertKeywords],
        }),
      });
      if (migration.ok) localStorage.setItem(markerKey, String(serverSchemaVersion));
    } catch (e) {
      console.warn('[userdata migrate]', e.message);
    }
  }

  // 并集合并（跨设备各自的增量都保留）
  (d.bookmarks || []).forEach(b => { if (b.link) bookmarks.add(b.link); });
  (d.read_links || []).forEach(l => readSet.add(l));
  (d.alerts || []).forEach(t => alertKeywords.add(t));
  localStorage.setItem('defense_bookmarks', JSON.stringify([...bookmarks]));
  localStorage.setItem('defense_read', JSON.stringify([...readSet]));
  saveAlerts();

  updateBookmarkStat();
  renderAlertTags();
  updateUnreadBadge();
  if (typeof allNews !== 'undefined' && allNews.length) renderNews();
  // 通知 brief.js 等模块（要讯历史合并）
  window.dispatchEvent(new CustomEvent('userdata-ready', { detail: d }));
}

// 初始化时渲染已保存的预警词 + 拉云端用户状态
window.addEventListener('DOMContentLoaded', () => { renderAlertTags(); updateUnreadBadge(); userdataBoot(); });

async function fetchNews() {
  try {
    const data = await apiFetch('/api/news').then(r => r.json());
    document.getElementById('statArticles').textContent = data.total;
    document.getElementById('statUpdate').textContent = data.last_update ? fmtDate(data.last_update) : '—';
    const prevCount = allNews.length;
    allNews = data.news || [];
    const overviewNews = document.getElementById('v9OverviewNewsText');
    if (overviewNews) overviewNews.textContent = data.total ? `实时新闻　${data.total} 条 · ${data.errors?.length || 0} 个源异常` : '当前暂无实时新闻';
    window.loadV9Situation?.(true);
    window.loadV9AlertRules?.();
    // 新文章通知
    if (prevCount > 0 && allNews.length > prevCount) {
      const diff = allNews.length - prevCount;
      showToast(`新增 ${diff} 条情报`);
    }
    // 预警词命中通知
    if (alertKeywords.size > 0) {
      const hits = allNews.filter(a => [...alertKeywords].some(kw => a.title.toLowerCase().includes(kw)));
      if (hits.length) showToast(`预警：${hits.length} 条命中监控词`, 4000);
    }
    renderNews();
    renderChinaPage();
    renderFeedStatus(data.stats || {}, data.errors || []);
    renderValueStats();
    setStatus(true, lang==='cn' ? `在线 · ${data.total}条（3天）` : `Online · ${data.total} (3d)`);
  } catch(e) {
    setStatus(false, lang==='cn' ? '连接失败' : 'Offline');
    document.getElementById('newsList').innerHTML =
      `<div class="error-state">⚠️ 无法连接到后端<br><small>${e.message}</small></div>`;
  }
}

// ── 星级渲染 ─────────────────────────────────────────────
function renderStars(stars) {
  const full = Math.min(10, Math.max(0, stars));
  let html = '';
  for (let i = 0; i < 10; i++) html += i < full ? '★' : '☆';
  return html;
}
function starColorClass(stars) {
  if (stars >= 8) return 'star-10';   // 红金
  if (stars >= 6) return 'star-8';    // 橙
  if (stars >= 4) return 'star-5';    // 蓝
  if (stars >= 2) return 'star-3';    // 灰蓝
  return 'star-1';                    // 暗
}

function newsCardHtml(item, idx) {
  const tags = item.value_tags || [];
  // 优先级星级
  const pri = item.priority || {};
  const stars = pri.stars || 0;
  const dim = pri.dim || {};

  // 价值标签 — 可点击过滤
  const tagsHtml = tags.map(t =>
    `<span class="vtag ${activeTagFilter===t.key?'vtag-active':''}"
           style="background:${t.color}22;border-color:${t.color}55;color:${t.color}"
           onclick="filterByTag('${t.key}')" title="按此标签过滤">
      ${lang==='cn' ? t.label : t.label_en}
    </span>`
  ).join('');

  const ageHours = (Date.now() - new Date(item.date)) / 3600000;
  const srcName = lang==='cn' ? (item.source_cn || item.source) : item.source;
  const isBookmarked = bookmarks.has(item.link);
  const isRead = readSet.has(item.link);

  // 预警词高亮检测
  const titleLow = item.title.toLowerCase();
  const isAlert = alertKeywords.size > 0 && [...alertKeywords].some(kw => titleLow.includes(kw));
  const alertClass = isAlert ? ' news-card-alert' : '';

  // 价值说明（基于最高价值标签给出一句话说明）
  const valueDesc = getValueDesc(item);

  // 摘要截断 + 展开
  const fullSum = item.summary || '';
  const shortSum = fullSum.slice(0, 160);
  const hasMore = fullSum.length > 160;
  const sumHtml = fullSum ? `
    <div class="news-summary">
      <span class="sum-short" id="sum-s-${idx}">${escHtml(shortSum)}${hasMore?'…':''}</span>
      ${hasMore ? `<span class="sum-full" id="sum-f-${idx}" style="display:none">${escHtml(fullSum)}</span>
        <button class="sum-toggle" onclick="toggleSum(${idx})">展开▼</button>` : ''}
    </div>` : '';

  // 编辑室卡片：56px 评分栏 │ 报头 meta + 衬线标题 + 摘要 + 判断块 + 标签/动作
  const isTop = item.tier <= 1 && stars >= 8;
  const metaBits = [];
  if (isTop) metaBits.push('<span class="ed-top">今日首选</span>');
  metaBits.push(`<span class="ed-src">${escHtml(srcName)}</span>`);
  metaBits.push(fmtDate(item.date));
  if (ageHours < 3) metaBits.push('<span class="ed-breaking">突发</span>');
  if (item.tier <= 1) metaBits.push('<span class="ed-toptier">顶尖源</span>');
  if (isAlert) metaBits.push('<span class="ed-alertb">预警</span>');
  if (isRead) metaBits.push('<span class="ed-readb">已读</span>');
  const metaHtml = metaBits.join('<span class="ed-dot">·</span>');

  return `
  <article class="news-card ed-card new${alertClass}${isRead?' read':''}${stars>=8?' card-hot':stars>=6?' card-warm':''}"
       style="animation-delay:${Math.min(idx,30)*.03}s"
       data-link="${escHtml(item.link)}" data-stars="${stars}">
    <div class="ed-score ${starColorClass(stars)}" title="${lang==='cn'
      ? `写作优先级 ${stars}★ · 信源${dim.source||0}/选题${dim.topic||0}/质量${dim.quality||0}`
      : `Priority ${stars}★ · S${dim.source||0}/T${dim.topic||0}/Q${dim.quality||0}`}">
      <div class="ed-score-num">${stars}</div>
      <div class="ed-score-lab">写作<br>优先</div>
    </div>
    <div class="ed-body">
      <div class="ed-meta">
        ${metaHtml}
        <button class="bookmark-btn ed-bm ${isBookmarked?'bookmarked':''}"
                onclick="toggleBookmark('${escAttrJs(item.link)}', this)"
                title="${isBookmarked?'已收藏':'收藏'}">${isBookmarked?'★':'☆'}</button>
      </div>
      <a class="news-title-link ed-title-link" href="${escHtml(safeExternalUrl(item.link))}" target="_blank" rel="noopener noreferrer"
         onclick="markRead('${escAttrJs(item.link)}')">
        <span class="news-title ed-title">${escHtml(item.title)}</span>
      </a>
      ${sumHtml}
      ${valueDesc ? `<div class="ed-judge"><span class="ed-judge-lab">判断</span><span class="ed-judge-txt">${escHtml(valueDesc)}</span></div>` : ''}
      <div class="ed-foot">
        <div class="ed-tags">${tagsHtml}</div>
        <div class="ed-actions news-footer-actions">
          <button class="ed-act evidence-archive-btn" onclick="event.stopPropagation();archiveNewsEvidence(${idx}, this)" title="加密归档到证据库">归档证据</button>
          <button class="brief-one-btn ed-act" onclick="event.stopPropagation();oneClickBrief(${idx}, this)" title="一键生成要讯（PLA 6节规范+自动校验+落盘）">要讯</button>
          <button class="translate-btn ed-act" onclick="translateCard(this, ${idx})" title="翻译标题">
            <span data-cn="翻译" data-en="Translate">翻译</span>
          </button>
          <button class="ai-inline-btn ed-act" onclick="event.stopPropagation();aiQuickAnalyze(${idx})" title="AI快速分析">
            <span data-cn="分析" data-en="AI">分析</span>
          </button>
          <button class="compare-add-btn ed-act" onclick="event.stopPropagation();addToCompare(${idx})" title="加入对比">对比</button>
        </div>
      </div>
      <div class="translation-result" id="tr-${idx}" style="display:none"></div>
      <div class="ai-inline-result" id="ai-${idx}" style="display:none"></div>
    </div>
  </article>`;
}

// 摘要展开/折叠
function toggleSum(idx) {
  const s = document.getElementById('sum-s-' + idx);
  const f = document.getElementById('sum-f-' + idx);
  const btn = s?.parentElement?.querySelector('.sum-toggle');
  if (!s || !f) return;
  const expanded = f.style.display !== 'none';
  s.style.display  = expanded ? '' : 'none';
  f.style.display  = expanded ? 'none' : '';
  if (btn) btn.textContent = expanded ? '展开▼' : '折叠▲';
}

// 根据价值标签生成价值说明
function getValueDesc(item) {
  const tags = item.value_tags || [];
  const title = item.title.toLowerCase();
  const src = (item.source || '').toLowerCase();
  if (tags.some(t => t.key === 'china_intel')) {
    if (/taiwan|strait/.test(title))   return '台海动态：涉及两岸军事博弈或解放军演习，高度关注';
    if (/nuclear|df-|icbm/.test(title)) return '中国核力量：弹道导弹/核战略动向，极高战略价值';
    if (/j-20|j-35|carrier/.test(title)) return 'PLA装备动态：战机/舰艇现代化进展，装备情报价值';
    return '对华情报：来自美欧信源的中国军事分析，参考价值高';
  }
  if (tags.some(t => t.key === 'nuclear'))   return '核战略动向：核威慑、核力量变化影响全球战略稳定';
  if (tags.some(t => t.key === 'think_tank')) return `顶尖智库分析：${src.includes('rand')?'兰德公司':src.includes('csis')?'CSIS':src.includes('cnas')?'CNAS':src.includes('atlantic')?'大西洋理事会':src.includes('aspi')?'ASPI':src.includes('chatham')?'皇家国际事务所':'美欧智库'}深度报告，政策参考价值极高`;
  if (tags.some(t => t.key === 'cyber_intel')) return '网络/情报领域：影响国家安全的网络战或情报行动';
  if (tags.some(t => t.key === 'equipment'))  return '武器装备：主战平台技术突破或部署动向，装备情报';
  if (tags.some(t => t.key === 'breaking'))   return '突发军情：实时战场或外交危机事件，即时关注';
  if (tags.some(t => t.key === 'strategy'))   return '战略分析：大国博弈格局与军事战略演变研判';
  if (tags.some(t => t.key === 'budget'))     return '军工财经：国防预算与采购动向反映战略优先级';
  return '';
}

// ── 过滤器 ──────────────────────────────────────────────
function setFilter(f, btn) {
  currentFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderNews();
}

// ── 排序 ────────────────────────────────────────────────
function setSort(s, btn) {
  currentSort = s;
  document.querySelectorAll('.sort-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  renderNews();
}

// ── 星级筛选 ──────────────────────────────────────────────
function setMinStars(n, btn) {
  minStarFilter = (minStarFilter === n) ? 0 : n;
  document.querySelectorAll('.star-filter-btn').forEach(b => b.classList.remove('active'));
  if (minStarFilter > 0 && btn) btn.classList.add('active');
  renderNews();
  if (minStarFilter > 0) showToast(`⭐ 仅显示 ${minStarFilter}★ 以上`);
}

// ── 价值标签点击过滤 ──────────────────────────────────
function filterByTag(key) {
  activeTagFilter = (activeTagFilter === key) ? null : key;
  renderNews();
  if (activeTagFilter) showToast(`🏷️ 过滤：${VALUE_LABELS_CN[key] || key}`);
}

window._currentNews = [];
function renderNews() {
  const list = document.getElementById('newsList');
  let news;

  // 地区/类型过滤
  if (currentFilter === 'all')        news = [...allNews];
  else if (currentFilter === 'tier1') news = allNews.filter(n => n.tier <= 1);
  else                                news = allNews.filter(n => n.region === currentFilter);

  // 价值标签过滤
  if (activeTagFilter) news = news.filter(n => (n.value_tags||[]).some(t => t.key === activeTagFilter));

  // 搜索过滤
  if (searchQuery) {
    news = news.filter(n =>
      n.title.toLowerCase().includes(searchQuery) ||
      (n.summary || '').toLowerCase().includes(searchQuery) ||
      n.source.toLowerCase().includes(searchQuery) ||
      (n.source_cn || '').includes(searchQuery)
    );
  }

  // 星级过滤
  if (minStarFilter > 0) {
    news = news.filter(n => (n.priority?.stars || 0) >= minStarFilter);
  }

  // 排序
  if (currentSort === 'priority') {
    // 写作优先：按星级降序，同星级按时间降序
    news.sort((a, b) => {
      const sa = a.priority?.stars || 0, sb = b.priority?.stars || 0;
      return sb - sa || new Date(b.date) - new Date(a.date);
    });
  } else if (currentSort === 'value') {
    news.sort((a, b) => (b.value_tags||[]).length - (a.value_tags||[]).length
      || new Date(b.date) - new Date(a.date));
  } else if (currentSort === 'unread') {
    news.sort((a, b) => {
      const ua = readSet.has(a.link) ? 1 : 0, ub = readSet.has(b.link) ? 1 : 0;
      return ua - ub || new Date(b.date) - new Date(a.date);
    });
  } else {
    news.sort((a, b) => new Date(b.date) - new Date(a.date));
  }

  window._currentNews = news;
  updateUnreadBadge();

  if (!news.length) {
    list.innerHTML = `<div class="loading-state"><p>${
      searchQuery ? `🔍 未找到 "${escHtml(searchQuery)}" 相关新闻`
      : activeTagFilter ? `暂无「${VALUE_LABELS_CN[activeTagFilter]||activeTagFilter}」类文章`
      : lang==='cn' ? '暂无新闻' : 'No articles'
    }</p></div>`;
    return;
  }

  const tips = [];
  if (searchQuery)    tips.push(`🔍 "${escHtml(searchQuery)}" · <strong>${news.length}</strong>条 <button onclick="clearSearch()" class="tip-clear">清除</button>`);
  if (activeTagFilter) tips.push(`🏷️ ${escHtml(VALUE_LABELS_CN[activeTagFilter]||activeTagFilter)} · <button onclick="filterByTag('${activeTagFilter}')" class="tip-clear">取消过滤</button>`);
  const tipHtml = tips.length ? `<div class="search-result-tip">${tips.join(' &nbsp;·&nbsp; ')}</div>` : '';

  // 分页：默认只渲染前 100 条，"加载更多"按需追加。
  // 之前一次性 innerHTML 564 个卡片 + 逐个 addEventListener 是 UI 卡顿主因，分页+事件委托后 DOM 节点降 5x。
  const PAGE_SIZE = 100;
  const limit = Math.min(window._newsRenderLimit || PAGE_SIZE, news.length);
  const moreHtml = (news.length > limit)
    ? `<button class="news-load-more" onclick="loadMoreNews()" style="display:block;width:100%;padding:12px;margin:16px 0;background:#1e293b;border:1px solid #334155;color:#94a3b8;border-radius:6px;cursor:pointer;font-size:13px;">加载更多（剩 ${news.length - limit} 条）</button>`
    : '';
  list.innerHTML = tipHtml + news.slice(0, limit).map((item, i) => newsCardHtml(item, i)).join('') + moreHtml;

  // 事件委托：一次 onclick 处理所有 card 点击，省 100-500 个 listener
  list.onclick = function(e) {
    const card = e.target.closest('.news-card');
    if (!card || card.classList.contains('read')) return;
    // 排除卡片内按钮（翻译/书签等）的点击冒泡
    if (e.target.closest('button, a, .news-card-actions')) return;
    markRead(card.dataset.link);
    card.classList.add('read');
  };
}

function loadMoreNews() {
  window._newsRenderLimit = (window._newsRenderLimit || 100) + 100;
  renderNews();
}

// 翻译某条新闻
async function translateCard(btn, idx) {
  const item = window._currentNews[idx];
  if (!item) return;
  const el = document.getElementById('tr-' + idx);
  if (!el) return;
  btn.disabled = true;
  btn.innerHTML = '⏳ 翻译中…';
  el.style.display = 'block';
  el.innerHTML = '<span style="color:#64748b;font-size:11px">翻译中，请稍候…</span>';
  const [titleTr, summaryTr] = await Promise.all([
    translateText(item.title),
    item.summary ? translateText(item.summary.slice(0, 200)) : Promise.resolve(''),
  ]);
  el.innerHTML = `
    <div class="tr-title">${escHtml(titleTr)}</div>
    ${summaryTr ? `<div class="tr-summary">${escHtml(summaryTr)}</div>` : ''}
  `;
  btn.innerHTML = '已翻译';
}

// 过滤按钮
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.filter || 'all';
    renderNews();
  });
});

// 新闻源状态
let feedHealthCache = null;

const FEED_ERROR_LABELS = Object.freeze({
  connection_error: '连接失败',
  fetch_error: '抓取失败',
  http_error: '上游 HTTP 错误',
  processing_error: '内容处理失败',
  timeout: '请求超时',
  too_many_redirects: '重定向过多',
  unsafe_url: '地址被安全策略拒绝',
});

function feedFailureText(health) {
  const code = String(health?.last_error_code || '');
  const label = Object.prototype.hasOwnProperty.call(FEED_ERROR_LABELS, code)
    ? FEED_ERROR_LABELS[code]
    : '';
  const status = health?.last_http_status;
  const http = Number.isInteger(status) && status >= 100 && status <= 599
    ? `HTTP ${status}`
    : '';
  return [label, http].filter(Boolean).join(' · ');
}

function appendFeedText(parent, className, text, tagName = 'span') {
  const node = document.createElement(tagName);
  node.className = className;
  node.textContent = String(text);
  parent.append(node);
  return node;
}

function renderFeedStatusView(el, entries, errors, healthPayload) {
  const errorNames = new Set(Array.isArray(errors) ? errors : []);
  const healthMap = Object.create(null);
  for (const health of healthPayload?.feeds || []) {
    if (health && typeof health.name === 'string') healthMap[health.name] = health;
  }
  const fallbackHealthy = entries.filter(([name]) => !errorNames.has(name)).length;
  const fallbackUnhealthy = errorNames.size;
  const safeCount = (value, fallback) => (
    Number.isInteger(value) && value >= 0 ? value : fallback
  );
  const healthyN = safeCount(healthPayload?.healthy, fallbackHealthy);
  const unhealthyN = safeCount(healthPayload?.unhealthy, fallbackUnhealthy);
  const deadN = safeCount(healthPayload?.dead, 0);
  const totalN = safeCount(healthPayload?.total, entries.length);

  const summary = document.createElement('div');
  summary.className = 'feed-summary';
  appendFeedText(summary, 'feed-summary-total', `${totalN} 源`);
  appendFeedText(summary, 'feed-summary-ok', `✓ ${healthyN}`);
  if (unhealthyN) appendFeedText(summary, 'feed-summary-warn', `⚠ ${unhealthyN}`);
  if (deadN) appendFeedText(summary, 'feed-summary-dead', `✕ ${deadN}`);
  const toggle = appendFeedText(summary, 'feed-summary-toggle', '展开', 'button');
  toggle.type = 'button';
  toggle.id = 'feedDetailsToggle';
  toggle.addEventListener('click', toggleFeedDetails);

  const details = document.createElement('div');
  details.className = 'feed-details';
  details.id = 'feedDetails';
  details.style.display = 'none';
  for (const [name, rawCount] of entries) {
    const health = healthMap[name] || {};
    const failure = feedFailureText(health);
    const streak = Number.isInteger(health.fail_streak) && health.fail_streak > 0
      ? health.fail_streak
      : 0;
    const row = document.createElement('div');
    row.className = 'feed-row';
    appendFeedText(row, `feed-dot ${errorNames.has(name) ? 'err' : 'ok'}`, '');
    const feedName = appendFeedText(row, 'feed-name', name);
    feedName.title = failure ? `${name} · ${failure}` : String(name);
    if (streak) {
      const badge = appendFeedText(row, 'feed-streak', `✕${streak}`);
      badge.title = failure
        ? `连续失败${streak}次：${failure}`
        : `连续失败${streak}次`;
    }
    const count = Number.isInteger(rawCount) && rawCount >= 0 ? rawCount : 0;
    appendFeedText(row, 'feed-count', count);
    details.append(row);
  }
  el.replaceChildren(summary, details);
}

async function renderFeedStatus(stats, errors) {
  const el = document.getElementById('feedStatus');
  if (!el) return;
  const entries = Object.entries(stats || {});
  if (!entries.length) {
    const loading = appendFeedText(el, 'feed-loading', '加载中…', 'div');
    loading.style.padding = '12px';
    loading.style.color = 'var(--text-3)';
    loading.style.fontSize = '12px';
    el.replaceChildren(loading);
    return;
  }
  // 尝试拉取健康档案（带连续失败数）
  try {
    const r = await apiFetch('/api/feeds/health');
    feedHealthCache = await r.json();
  } catch(e) { feedHealthCache = null; }
  renderFeedStatusView(el, entries, errors, feedHealthCache);
}
function toggleFeedDetails() {
  const det = document.getElementById('feedDetails');
  const btn = document.getElementById('feedDetailsToggle');
  if (!det || !btn) return;
  const show = det.style.display === 'none';
  det.style.display = show ? '' : 'none';
  btn.textContent = show ? '折叠' : '展开';
}

async function logoutWorkspace() {
  globalThis.__WORKSPACE_LOGGING_OUT__ = true;
  const csrf = getCookie('csrf_token');
  const headers = new Headers();
  if (csrf) headers.set('X-CSRF-Token', csrf);
  let response;
  try {
    response = await apiFetch('/logout', {
      method: 'POST',
      credentials: 'same-origin',
      headers,
    }, {toast: false});
  } catch (error) {
    globalThis.__WORKSPACE_LOGGING_OUT__ = false;
    throw error;
  }
  const target = new URL(response.url || '/login', window.location.href);
  const safeTarget = target.origin === window.location.origin
    && (target.pathname === '/login' || target.pathname === '/')
    ? target.href
    : new URL('/login', window.location.origin).href;
  window.location.assign(safeTarget);
}

function bindWorkspaceLogout(button) {
  if (!button) return false;
  button.addEventListener('click', async () => {
    try {
      await logoutWorkspace();
    } catch (_error) {
      if (typeof showToast === 'function') showToast('退出失败，请稍后重试');
    }
  });
  return true;
}

if (typeof window !== 'undefined') {
  window.logoutWorkspace = logoutWorkspace;
  bindWorkspaceLogout(document.getElementById('workspaceLogout'));
}

// 价值标签统计
function renderValueStats() {
  const el = document.getElementById('valueStats');
  if (!el || !allNews.length) return;
  const counts = {};
  allNews.forEach(a => (a.value_tags || []).forEach(t => {
    counts[t.key] = (counts[t.key] || {label: t.label, label_en: t.label_en, color: t.color, n: 0});
    counts[t.key].n++;
  }));
  const sorted = Object.values(counts).sort((a,b) => b.n - a.n);
  // 编辑室：单色条（首项锈红，其余暖灰），不用彩虹色
  el.innerHTML = sorted.map((v, i) => `
    <div class="vstats-row">
      <span class="vstats-tag" style="color:${i===0?'#d1442f':'#ece6da'}">${lang==='cn'?v.label:v.label_en}</span>
      <div class="vstats-bar-wrap">
        <div class="vstats-bar" style="width:${Math.min(v.n/allNews.length*400,100)}%;background:${i===0?'#d1442f':'#7d7566'}"></div>
      </div>
      <span class="vstats-count">${v.n}</span>
    </div>`).join('');
  renderPriorityStats();
}

// 写作优先级星级分布
function renderPriorityStats() {
  const el = document.getElementById('priorityStats');
  if (!el || !allNews.length) return;
  // 统计各星级文章数
  const dist = {};
  for (let i = 0; i <= 10; i++) dist[i] = 0;
  allNews.forEach(a => { const s = a.priority?.stars || 0; dist[s]++; });
  const max = Math.max(...Object.values(dist), 1);
  // 编辑室色阶：0-1 暗棕 · 2-3 灰褐 · 4-5 暖灰 · 6-7 赭石 · 8-10 锈红
  const colors = ['#544d42','#544d42','#7d7566','#7d7566','#ada491','#ada491','#b28a4d','#b28a4d','#d1442f','#d1442f','#d1442f'];
  el.innerHTML = `
    <div class="pstats-header">${lang==='cn'?'写作优先级分布':'Priority Distribution'}</div>
    <div class="pstats-bars">
      ${[10,9,8,7,6,5,4,3,2,1,0].map(s => `
        <div class="pstats-row" onclick="setMinStars(${s})" title="${s}★ 以上: ${Object.entries(dist).filter(([k])=>+k>=s).reduce((a,[,v])=>a+v,0)}条">
          <span class="pstats-label" style="color:${colors[s]}">${s}★</span>
          <div class="pstats-bar-bg"><div class="pstats-bar-fill" style="width:${dist[s]/max*100}%;background:${colors[s]}"></div></div>
          <span class="pstats-cnt">${dist[s]}</span>
        </div>`).join('')}
    </div>`;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    bindWorkspaceLogout,
    feedFailureText,
    renderFeedStatusView,
    logoutWorkspace,
  };
}
