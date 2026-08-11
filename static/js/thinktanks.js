// ══════════════════════════════════════════════════════════
// 智库目录
// ══════════════════════════════════════════════════════════
let thinktankData = [];
async function fetchThinktanks() {
  try {
    const data = await apiFetch('/api/thinktanks').then(r => r.json());
    thinktankData = data.data || [];
    const total = thinktankData.reduce((s,c) => s + c.sites.length, 0);
    document.getElementById('statSites').textContent = total;
    renderThinktanks(thinktankData);
  } catch(e) { console.error('智库加载失败', e); }
}

function renderThinktanks(cats) {
  const el = document.getElementById('thinktankContent');
  if (!cats.length) { el.innerHTML = '<div class="loading-state"><p>无数据</p></div>'; return; }
  el.innerHTML = cats.map(cat => `
    <div class="tt-category ${cat.id==='china_zone'?'china-category':''} ${cat.id==='us_eu_china_analysis'?'elite-category':''}" id="cat-${cat.id}">
      <div class="tt-cat-header">
        <span class="tt-cat-icon">${cat.icon}</span>
        <div class="tt-cat-titles">
          <div class="tt-cat-name-cn">${lang==='cn' ? cat.category : cat.category_en}</div>
          <div class="tt-cat-name-en">${lang==='cn' ? cat.category_en : cat.category}</div>
          <div class="tt-cat-desc">${lang==='cn' ? cat.desc : cat.desc_en}</div>
        </div>
        <span class="tt-cat-count">${cat.sites.length} ${lang==='cn'?'个网站':'sites'}</span>
      </div>
      <div class="tt-sites-grid">
        ${cat.sites.map((site, i) => `
          <a class="tt-site-card ${cat.id==='china_zone'?'china-card':''} ${cat.id==='us_eu_china_analysis'?'elite-card':''}"
             href="${escHtml(site.url)}" target="_blank" rel="noopener"
             data-search="${[site.name,site.name_cn,site.desc_cn,site.desc_en].join(' ').toLowerCase()}"
             style="animation-delay:${i*0.04}s">
            <div class="tt-site-name">${escHtml(site.name)}</div>
            <div class="tt-site-name-cn">${escHtml(site.name_cn)}</div>
            <div class="tt-site-desc-cn">${escHtml(lang==='cn' ? site.desc_cn : site.desc_en)}</div>
            <div class="tt-site-desc-en">${escHtml(lang==='cn' ? site.desc_en : site.desc_cn)}</div>
            <span class="tt-site-url">${escHtml(site.url.replace(/^https?:\/\//,'').replace(/\/$/,''))}</span>
          </a>`).join('')}
      </div>
    </div>`).join('');
}

function filterThinktanks(q) {
  q = q.toLowerCase().trim();
  document.querySelectorAll('.tt-site-card').forEach(card => {
    card.classList.toggle('hidden', !!q && !card.dataset.search.includes(q));
  });
}

// ══════════════════════════════════════════════════════════
// 状态 & 初始化
// ══════════════════════════════════════════════════════════
async function fetchStatus() {
  try {
    const d = await apiFetch('/api/status').then(r => r.json());
    document.getElementById('statActive').textContent = `${d.active_feeds}/${d.feeds_configured}`;
    if (d.thinktank_sites) document.getElementById('statSites').textContent = d.thinktank_sites;
  } catch {}
}

// ══════════════════════════════════════════════════════════
// 回到顶部按钮
// ══════════════════════════════════════════════════════════
window.addEventListener('scroll', () => {
  const btn = document.getElementById('backToTop');
  if (btn) btn.classList.toggle('visible', window.scrollY > 400);
});

// ══════════════════════════════════════════════════════════
// 初始化
// ══════════════════════════════════════════════════════════
async function fetchAll() {
  setStatus(true, lang==='cn'?'抓取中…':'Fetching…');
  await Promise.all([fetchStatus(), fetchNews(), fetchThinktanks()]);
  updateBookmarkStat();
  checkAiConfig();
}

fetchAll();
setInterval(fetchNews, 10 * 60 * 1000);  // 10min；之前 3min 太频繁拖累 WebView2

