/* ═══════════════════════════════════════════════════════════
   DefenseTracker V9 · legacy scoring schema
   · 写作要点优先评分(0-10★) · 报告Agent · AI分析 · PLA追踪
   ═══════════════════════════════════════════════════════════ */

// ── 语言 ─────────────────────────────────────────────────
let lang = 'cn';
function toggleLang() {
  lang = lang === 'cn' ? 'en' : 'cn';
  document.getElementById('langLabel').textContent = lang === 'cn' ? 'EN' : '中';
  applyLang();
}
function applyLang() {
  document.querySelectorAll('[data-cn]').forEach(el => {
    el.textContent = lang === 'cn' ? el.dataset.cn : el.dataset.en;
  });
  renderNews(); renderChinaPage();
  if (thinktankData.length) renderThinktanks(thinktankData);
}

// ── 标签页 ────────────────────────────────────────────────
const TAB_NAMES = ['overview', 'news', 'china', 'thinktanks', 'ai', 'agent', 'brief', 'tracking', 'squad', 'scenario', 'delivery'];
const TAB_BUTTON_ALIAS = {};
function showTab(name, opts = {}) {
  const content = document.getElementById('tab-content-' + name);
  const tab = document.getElementById('tab-' + name)
           || document.getElementById(TAB_BUTTON_ALIAS[name] || '');
  if (!content || !tab) return;
  document.querySelectorAll('.tab-content').forEach(e => {
    e.classList.remove('active');
    e.hidden = true;
  });
  document.querySelectorAll('.tab-btn').forEach(e => { e.classList.remove('active'); e.setAttribute('aria-selected', 'false'); });
  content.hidden = false;
  content.classList.add('active');
  tab.classList.add('active');
  tab.setAttribute('aria-selected', 'true');
  if (!opts.silentHash && TAB_NAMES.includes(name) && location.hash !== '#' + name) {
    history.replaceState(null, '', '#' + name);
  }
  if (name === 'china')     renderChinaPage();
  if (name === 'overview')   window.loadV9Situation?.();
  if (name === 'ai')         window.loadV9Evidence?.();
  if (name === 'thinktanks') window.loadV9Graph?.();
  if (name === 'china')      window.loadV9Geo?.();
  if (name === 'tracking')   window.loadV9Alerts?.();
  if (name === 'agent')      window.loadV9Cases?.();
  if (name === 'squad')      window.loadV9Jobs?.();
  if (name === 'scenario')   window.loadV9Scenarios?.();
  if (name === 'brief')      window.loadV9Documents?.();
  if (name === 'delivery')   window.loadV9Publications?.();
}
window.addEventListener('DOMContentLoaded', () => {
  const initialTab = (location.hash || '').replace(/^#/, '');
  showTab(TAB_NAMES.includes(initialTab) ? initialTab : 'overview', {silentHash: true});
});

// ── 时钟 ──────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent = now.toLocaleTimeString('zh-CN',
    {hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});
  const dateEl = document.getElementById('v9Date');
  if (dateEl) {
    const weekday = ['周日','周一','周二','周三','周四','周五','周六'][now.getDay()];
    dateEl.textContent = `${weekday} · ${now.getMonth() + 1}月${now.getDate()}日 · 第${Math.ceil((now - new Date(now.getFullYear(), 0, 1)) / 86400000)}号`;
  }
}
setInterval(updateClock, 1000); updateClock();

// ── 工具函数 ──────────────────────────────────────────────
// fmtDate / escHtml / escJsArg / escAttrJs / safeUrl / getCookie / apiFetch /
// ensureFileExt / filenameFromContentDisposition 已抽到 static/js/util.js
// （经典 <script> 在本文件之前加载，函数仍为全局，供内联 onclick 调用）。

const nativeFetch = window.fetch.bind(window);
window.fetch = function(input, init = {}) {
  const opts = Object.assign({}, init);
  const method = (opts.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();
  const url = new URL(input instanceof Request ? input.url : String(input), window.location.href);
  const sameOrigin = url.origin === window.location.origin;
  if (sameOrigin && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const headers = new Headers(opts.headers || (input instanceof Request ? input.headers : undefined));
    const token = getCookie('csrf_token');
    if (token && !headers.has('X-CSRF-Token')) headers.set('X-CSRF-Token', token);
    opts.headers = headers;
    opts.credentials = opts.credentials || 'same-origin';
  }
  return nativeFetch(input, opts);
};

async function downloadResponseBlob(resp, fallbackName, ext = '.docx') {
  const blob = await resp.blob();
  const fname = filenameFromContentDisposition(resp.headers.get('Content-Disposition') || '', fallbackName, ext);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fname;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    URL.revokeObjectURL(url);
    a.remove();
  }, 1000);
  return fname;
}

function setStatus(ok, txt) {
  document.getElementById('statusText').textContent = txt;
  document.getElementById('statusPill').classList.toggle('error', !ok);
}

