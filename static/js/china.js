// ══════════════════════════════════════════════════════════
// 中国专区
// ══════════════════════════════════════════════════════════
function renderChinaPage() {
  renderChinaElite();
  renderChinaNews();
  if (thinktankData.length) renderChinaThinktanks();
  updateChinaStats();
}

function isChinaRelated(item) {
  const txt = (item.title + ' ' + (item.summary || '') + ' ' + item.source).toLowerCase();
  return item.region === '🇨🇳 中国' || item.region === '🌏 亚太' ||
    /china|pla|taiwan|beijing|xi jinping|south china sea|plaaf|plan|plarf|sinopec|byd|huawei/.test(txt);
}

function isEliteSource(item) {
  const elites = ['war on the rocks', 'rand research', 'csis analysis', 'lawfare',
                  'stimson center', 'the diplomat'];
  return elites.some(e => item.source.toLowerCase().includes(e));
}

const CHINA_TOPIC_RULES = [
  {key: 'taiwan', label: '台海', label_en: 'Taiwan Strait', rx: /taiwan|strait|台海|台湾|两岸/},
  {key: 'pla', label: 'PLA/战力', label_en: 'PLA Force', rx: /pla|plarf|plaaf|plan|j-20|j-35|carrier|navy|air force|rocket force|解放军|航母|火箭军/},
  {key: 'nuclear', label: '核力量', label_en: 'Nuclear', rx: /nuclear|icbm|missile silo|warhead|df-|核|洲际|弹头/},
  {key: 'maritime', label: '海空/南海', label_en: 'Maritime', rx: /south china sea|philippines|coast guard|maritime|naval|南海|海警|海军/},
  {key: 'tech', label: '军工科技', label_en: 'Defense Tech', rx: /drone|uav|ai|semiconductor|huawei|byd|shipbuilding|无人|芯片|军工|造船/},
  {key: 'strategy', label: '印太竞争', label_en: 'Indo-Pacific', rx: /indo-pacific|quad|aukus|japan|india|australia|印太|美日|澳英美|四方安全/},
];

function chinaRankRows(rows) {
  return [...(rows || [])].sort((a, b) =>
    (b.priority?.stars || 0) - (a.priority?.stars || 0)
    || new Date(b.date || 0) - new Date(a.date || 0)
  );
}

function chinaTopicFor(item) {
  const txt = `${item?.title || ''} ${item?.summary || ''} ${item?.source || ''}`.toLowerCase();
  return CHINA_TOPIC_RULES.find(rule => rule.rx.test(txt)) || {key: 'other', label: '综合', label_en: 'General'};
}

function chinaCompactCardHtml(item, idx) {
  const pri = item.priority || {};
  const stars = pri.stars || 0;
  const tags = (item.value_tags || []).slice(0, 3);
  const srcName = lang === 'cn' ? (item.source_cn || item.source) : item.source;
  const topic = chinaTopicFor(item);
  const summary = (item.summary || '').slice(0, 150);
  const isRead = readSet.has(item.link);
  const isBookmarked = bookmarks.has(item.link);
  const linkArg = escAttrJs(item.link || '');
  const tagsHtml = tags.map(t => `<span class="china-mini-tag" style="color:${t.color};border-color:${t.color}66">${escHtml(lang === 'cn' ? t.label : t.label_en)}</span>`).join('');
  return `<article class="china-intel-row${stars >= 8 ? ' hot' : ''}${isRead ? ' read' : ''}" data-link="${escHtml(item.link || '')}">
    <div class="china-intel-score"><b>${stars}</b><span>★</span></div>
    <div class="china-intel-body">
      <div class="china-intel-meta">
        <span class="china-source-chip">${escHtml(srcName || '公开来源')}</span>
        <span class="china-topic-chip">${escHtml(lang === 'cn' ? topic.label : topic.label_en)}</span>
        <span>${escHtml(fmtDate(item.date))}</span>
        ${isEliteSource(item) ? '<span class="china-elite-chip">顶尖源</span>' : ''}
      </div>
      <a class="china-intel-title" href="${escHtml(safeExternalUrl(item.link))}" target="_blank" rel="noopener noreferrer"
         onclick="markRead('${linkArg}')">${escHtml(item.title || '未命名情报')}</a>
      ${summary ? `<p>${escHtml(summary)}${(item.summary || '').length > 150 ? '…' : ''}</p>` : ''}
      <div class="china-intel-foot">
        <div class="china-mini-tags">${tagsHtml || '<span class="china-mini-tag">未标注</span>'}</div>
        <div class="china-row-actions">
          <button onclick="event.stopPropagation();toggleBookmark('${linkArg}', this)" class="${isBookmarked ? 'bookmarked' : ''}">${isBookmarked ? '已收藏' : '收藏'}</button>
          <button onclick="event.stopPropagation();chinaAddToCompare('${linkArg}')">对比</button>
        </div>
      </div>
    </div>
  </article>`;
}

function chinaAddToCompare(link) {
  const item = allNews.find(n => n.link === link);
  if (!item) return;
  if (newsMultiSelect.has(item.link)) {
    newsMultiSelect.delete(item.link);
    showToast('已移出对比列表');
  } else {
    if (newsMultiSelect.size >= 6) { showToast('最多选择6篇'); return; }
    newsMultiSelect.add(item.link);
    showToast(`已加入对比（${newsMultiSelect.size}篇）`);
  }
  updateFab();
}

function renderChinaPulse(chinaRows, eliteRows) {
  const pulse = document.getElementById('chinaPulseGrid');
  if (!pulse) return;
  const china = chinaRankRows(chinaRows);
  const topicCounts = {};
  china.forEach(item => {
    const topic = chinaTopicFor(item);
    topicCounts[topic.key] = (topicCounts[topic.key] || 0) + 1;
  });
  const high = china.filter(a => (a.priority?.stars || 0) >= 7).length;
  const unread = china.filter(a => !readSet.has(a.link)).length;
  const latest = [...chinaRows].sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0))[0];
  const cards = [
    {k: '重点来源', v: high, sub: '7★以上'},
    {k: '智库分析', v: eliteRows.length, sub: '顶尖源'},
    {k: '台海相关', v: topicCounts.taiwan || 0, sub: '专题热度'},
    {k: '未读线索', v: unread, sub: latest ? fmtDate(latest.date) : '暂无'},
  ];
  pulse.innerHTML = cards.map(c => `<div class="china-pulse-card"><b>${c.v}</b><span>${c.k}</span><small>${escHtml(c.sub)}</small></div>`).join('');
}

function renderChinaTopicMatrix(chinaRows) {
  const el = document.getElementById('chinaTopicMatrix');
  if (!el) return;
  const ranked = chinaRankRows(chinaRows);
  el.innerHTML = CHINA_TOPIC_RULES.map(rule => {
    const rows = ranked.filter(item => chinaTopicFor(item).key === rule.key);
    const top = rows[0];
    return `<div class="china-topic-cell${rows.length ? '' : ' muted'}">
      <div class="china-topic-top"><strong>${lang === 'cn' ? rule.label : rule.label_en}</strong><b>${rows.length}</b></div>
      <p>${top ? escHtml(top.title).slice(0, 54) : '暂无最近线索'}</p>
    </div>`;
  }).join('');
}

function renderChinaElite() {
  const el = document.getElementById('chinaEliteList');
  if (!el) return;
  const elite = chinaRankRows(allNews.filter(a => isChinaRelated(a) && isEliteSource(a)));
  const meta = document.getElementById('chinaEliteMeta');
  if (meta) meta.textContent = `${elite.length}篇 · 显示前8`;
  if (!elite.length) {
    el.innerHTML = `<div class="loading-state"><p style="color:#94a3b8;font-size:12px">
      暂无顶尖智库对华分析（3天内），可查看下方综合新闻
    </p></div>`;
    return;
  }
  el.innerHTML = elite.slice(0, 8).map((item, i) => chinaCompactCardHtml(item, 10000 + i)).join('');
}

function renderChinaNews() {
  const el = document.getElementById('chinaNewsList');
  if (!el) return;
  const china = chinaRankRows(allNews.filter(isChinaRelated));
  const meta = document.getElementById('chinaNewsMeta');
  if (meta) meta.textContent = `${china.length}条 · 优先级排序`;
  if (!china.length) {
    el.innerHTML = `<div class="loading-state"><p>暂无中国相关新闻</p></div>`;
    return;
  }
  const visible = china.slice(0, 24);
  const more = china.length > visible.length
    ? `<div class="china-more-note">已显示前 ${visible.length} 条高优先级线索；更多可在“实时新闻”中按中国标签继续筛选。</div>`
    : '';
  el.innerHTML = visible.map((item, i) => chinaCompactCardHtml(item, 20000 + i)).join('') + more;
}

function renderChinaThinktanks() {
  const el = document.getElementById('chinaThinktankGrid');
  if (!el) return;
  const cat = thinktankData.find(c => c.id === 'china_zone');
  if (!cat) return;
  el.innerHTML = cat.sites.slice(0, 14).map(site => `
    <a class="china-tt-link" href="${escHtml(safeExternalUrl(site.url))}" target="_blank" rel="noopener noreferrer">
      <strong>${escHtml(site.name_cn || site.name)}</strong>
      <span>${escHtml(site.url.replace(/^https?:\/\//,'').replace(/\/$/,''))}</span>
    </a>`).join('');
}

function updateChinaStats() {
  const el = document.getElementById('chinaStats');
  if (!el) return;
  const chinaRows = allNews.filter(isChinaRelated);
  const chinaNews  = chinaRows.length;
  const eliteRows  = chinaRows.filter(isEliteSource);
  const eliteNews  = eliteRows.length;
  const chinaSites = thinktankData.find(c => c.id === 'china_zone')?.sites.length || 0;
  const highNews = chinaRows.filter(a => (a.priority?.stars || 0) >= 7).length;
  el.innerHTML = [
    {n: chinaNews,  label: '条相关新闻', label_en: 'related news'},
    {n: eliteNews,  label: '篇顶尖分析', label_en: 'elite analyses'},
    {n: highNews,   label: '条高优先级', label_en: 'high priority'},
    {n: chinaSites, label: '个收录网站', label_en: 'sites'},
  ].map(s => `
    <div class="china-stat">
      <span class="china-stat-num">${s.n}</span>
      <span>${lang==='cn' ? s.label : s.label_en}</span>
    </div>`).join('');
  renderChinaPulse(chinaRows, eliteRows);
  renderChinaTopicMatrix(chinaRows);
}

