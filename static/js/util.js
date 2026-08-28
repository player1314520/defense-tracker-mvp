/* ═══════════════════════════════════════════════════════════
   防务数据追踪系统 · 前端纯工具函数（util.js）
   纯搬运自 app.js（零行为变更）。必须在 app.js 之前以经典 <script> 加载，
   函数声明在共享全局作用域中可见，供 app.js 与内联 onclick 调用。
   依赖说明（均在调用时解析，加载顺序无碍）：
     · fmtDate 读取全局 lang（在 app.js 中声明）
     · apiFetch 使用被 app.js 改写的 window.fetch 与可选 showToast
     · filenameFromContentDisposition 调用本文件内 ensureFileExt
   ═══════════════════════════════════════════════════════════ */

// ── 工具函数 ──────────────────────────────────────────────
function fmtDate(iso) {
  try {
    const d = (Date.now() - new Date(iso)) / 1000;
    if (d < 60)    return lang==='cn' ? `${~~d}秒前`      : `${~~d}s ago`;
    if (d < 3600)  return lang==='cn' ? `${~~(d/60)}分钟前` : `${~~(d/60)}m ago`;
    if (d < 86400) return lang==='cn' ? `${~~(d/3600)}小时前`: `${~~(d/3600)}h ago`;
    return lang==='cn' ? `${~~(d/86400)}天前` : `${~~(d/86400)}d ago`;
  } catch { return '—'; }
}
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function escJsArg(s) {
  return String(s || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\r?\n/g, ' ');
}
// 值要进入「双引号 HTML 属性里的单引号 JS 字符串」(如 onclick="f('${x}')")：
// 必须先 JS 转义(escJsArg 的 \' 经 HTML 实体解码后仍是转义)，再属性转义。
// 注意：只给 escHtml 加 ' → &#39; 对内联事件处理器无效——实体会在 JS 执行前解码回 '。
function escAttrJs(s) {
  return escHtml(escJsArg(s));
}
// href 防 javascript:/data: 协议 XSS：仅放行 http(s)/mailto/相对地址，其余降级为 #
function safeUrl(u) {
  const s = String(u || '').trim();
  return /^(https?:|mailto:|\/|#|\.)/i.test(s) ? s : '#';
}
// RSS/搜索/证据“外部原文”不允许 mailto 或相对路径，仅放行绝对 HTTP(S)。
function safeExternalUrl(u) {
  const s = String(u || '').trim();
  try {
    const parsed = new URL(s);
    return ['http:', 'https:'].includes(parsed.protocol) && !parsed.username && !parsed.password
      ? parsed.href
      : '#';
  } catch (_) {
    return '#';
  }
}
function getCookie(name) {
  const prefix = encodeURIComponent(name) + '=';
  return document.cookie.split(';').map(v => v.trim()).find(v => v.startsWith(prefix))?.slice(prefix.length) || '';
}

function v9RequestPath(input) {
  const raw = typeof input === 'string'
    ? input
    : (input instanceof URL ? input.href : input?.url);
  if (!raw) return '';
  try {
    return new URL(raw, 'http://127.0.0.1').pathname;
  } catch (_) {
    return '';
  }
}

function v9ContextPolicy(input) {
  const path = v9RequestPath(input);
  if (!path.startsWith('/api/v9/')) return 'none';
  if (
    path.startsWith('/api/v9/auth/')
    || path === '/api/v9/business-context/personal'
    || path === '/api/v9/organizations'
    || path === '/api/v9/organizations/bootstrap'
    || path === '/api/v9/organizations/bootstrap/acknowledge'
    || path === '/api/v9/situation'
    || path === '/api/v9/pairing-sessions/claim'
  ) {
    return 'none';
  }
  if (
    path.startsWith('/api/v9/devices')
    || path.startsWith('/api/v9/members/')
    || path.startsWith('/api/v9/sync/status')
    || /^\/api\/v9\/organizations\/[^/]+\/(?:members|devices)(?:\/|$)/.test(path)
  ) {
    return 'control';
  }
  return 'business';
}

function isV9BusinessRequest(input) {
  return v9ContextPolicy(input) !== 'none';
}

function lockV9BusinessContextAfterAuthFailure(context) {
  if (!context || context.mode !== 'cloud') return;
  globalThis.__V9_BUSINESS_CONTEXT__ = Object.freeze({
    ...context,
    unlocked: false,
    reason: 'session_expired',
  });
  if (typeof globalThis.dispatchEvent === 'function'
      && typeof globalThis.CustomEvent === 'function') {
    globalThis.dispatchEvent(new globalThis.CustomEvent('v9:business-context-locked', {
      detail: {reason: 'session_expired'},
    }));
  }
}

async function v9BusinessRequestInit(input, init) {
  const policy = v9ContextPolicy(input);
  if (policy === 'none') return init;
  let context = globalThis.__V9_BUSINESS_CONTEXT__;
  if (
    policy !== 'control'
    &&
    context?.mode === 'cloud'
    && !context.unlocked
    && context.reason === 'initializing'
    && globalThis.__V9_BUSINESS_CONTEXT_READY__ instanceof Promise
  ) {
    await globalThis.__V9_BUSINESS_CONTEXT_READY__;
    context = globalThis.__V9_BUSINESS_CONTEXT__;
  }
  if (
    !context
    || !['personal', 'cloud'].includes(context.mode)
    || !context.organizationId
  ) {
    const error = new Error('业务上下文尚未就绪，已阻止业务请求');
    error.code = 'V9_BUSINESS_CONTEXT_UNAVAILABLE';
    throw error;
  }
  if (
    !context.unlocked
    && (policy !== 'control' || context.mode !== 'cloud')
  ) {
    const error = new Error(
      context.mode === 'cloud'
        ? '云组织尚未解锁，已阻止业务请求'
        : '业务上下文尚未就绪，已阻止业务请求',
    );
    error.code = context.mode === 'cloud'
      ? 'V9_CLOUD_CONTEXT_LOCKED'
      : 'V9_BUSINESS_CONTEXT_UNAVAILABLE';
    throw error;
  }
  const headers = new Headers(
    typeof Request !== 'undefined' && input instanceof Request
      ? input.headers
      : undefined,
  );
  new Headers(init.headers || {}).forEach((value, key) => {
    headers.set(key, value);
  });
  headers.set('X-V9-Context-Mode', context.mode);
  headers.set('X-V9-Organization-ID', context.organizationId);
  return {...init, headers};
}

async function apiFetch(input, init = {}, opts = {}) {
  const businessRequest = isV9BusinessRequest(input);
  const requestInit = await v9BusinessRequestInit(input, init);
  const resp = await fetch(input, requestInit);
  if (resp.ok) return resp;

  if (businessRequest && resp.status === 401) {
    lockV9BusinessContextAfterAuthFailure(
      globalThis.__V9_BUSINESS_CONTEXT__,
    );
  }
  let msg = `HTTP ${resp.status}`;
  try {
    const data = await resp.clone().json();
    msg = data.error || data.message || msg;
  } catch(e) {
    try {
      const text = await resp.clone().text();
      if (text) {
        const normalized = text.replace(/\s+/g, ' ').trim();
        if (/<!doctype html|<html/i.test(normalized) && resp.status === 404) {
          msg = '接口未找到：请刷新页面，或重启本地服务以加载最新后端路由';
        } else if (/<!doctype html|<html/i.test(normalized)) {
          msg = `服务返回HTML错误页（HTTP ${resp.status}），请查看后端日志`;
        } else {
          msg = normalized.slice(0, 180);
        }
      }
    } catch(_) {}
  }
  const err = new Error(msg);
  err.status = resp.status;
  err.response = resp;
  if (opts.toast !== false && typeof showToast === 'function') {
    showToast('❌ ' + msg);
    err.toastShown = true;
  }
  throw err;
}

function ensureFileExt(name, ext) {
  const wanted = ext.startsWith('.') ? ext : `.${ext}`;
  let clean = String(name || '').trim().replace(/[\\/:*?"<>|]+/g, '_');
  clean = clean.replace(/\s+/g, '_').replace(/^_+|_+$/g, '');
  if (!clean) clean = `download${wanted}`;
  if (!clean.toLowerCase().endsWith(wanted.toLowerCase())) clean += wanted;
  return clean;
}

function filenameFromContentDisposition(disposition, fallback, ext = '.docx') {
  const disp = String(disposition || '');
  let raw = '';
  const star = disp.match(/filename\*\s*=\s*(?:UTF-8''|utf-8'')?([^;]+)/i);
  const plain = disp.match(/filename\s*=\s*"?([^";]+)"?/i);
  raw = (star && star[1]) || (plain && plain[1]) || '';
  raw = raw.trim().replace(/^["']|["']$/g, '');
  if (raw) {
    try { raw = decodeURIComponent(raw); } catch(e) {}
  }
  return ensureFileExt(raw || fallback, ext);
}

// ── Node 测试桥 ───────────────────────────────────────────
// 浏览器经典脚本里 typeof module === 'undefined'，此块不执行 → 零行为变更。
// 仅在 Node（tests/js/util.test.cjs）通过 require() 加载时导出纯函数供单测。
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    fmtDate, escHtml, escJsArg, escAttrJs, safeUrl, safeExternalUrl,
    getCookie, apiFetch, ensureFileExt, filenameFromContentDisposition,
    isV9BusinessRequest, v9BusinessRequestInit,
  };
}
