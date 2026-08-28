/* 前端纯工具函数单测（static/js/util.js）
 * 运行：node --test tests/js/util.test.cjs
 * 无构建工具/无 npm 依赖，仅用 Node 内置 node:test + node:assert。
 * util.js 末尾的 module.exports 仅在 Node 下生效（浏览器经典脚本中 typeof module === 'undefined'）。
 */
const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const util = require(path.join(__dirname, '..', '..', 'static', 'js', 'util.js'));
const {
  fmtDate, escHtml, escJsArg, escAttrJs, safeUrl, safeExternalUrl,
  getCookie, apiFetch, ensureFileExt, filenameFromContentDisposition,
} = util;

// ── escHtml ───────────────────────────────────────────────
test('escHtml 转义 & < > "（不转义单引号，与原实现一致）', () => {
  assert.strictEqual(escHtml('<script>'), '&lt;script&gt;');
  assert.strictEqual(escHtml('a & b'), 'a &amp; b');
  assert.strictEqual(escHtml('say "hi"'), 'say &quot;hi&quot;');
  assert.strictEqual(escHtml("it's"), "it's"); // 单引号保留
  assert.strictEqual(escHtml('&<>'), '&amp;&lt;&gt;'); // & 先于其它替换，避免二次转义
  assert.strictEqual(escHtml(123), '123'); // 非字符串先 String() 强转
});

// ── escJsArg ──────────────────────────────────────────────
test('escJsArg 转义反斜杠、单引号，并把换行折叠成空格', () => {
  assert.strictEqual(escJsArg('a\\b'), 'a\\\\b'); // 反斜杠加倍
  assert.strictEqual(escJsArg("a'b"), "a\\'b");   // 单引号转义
  assert.strictEqual(escJsArg('a\nb'), 'a b');     // \n → 空格
  assert.strictEqual(escJsArg('a\r\nb'), 'a b');   // \r\n → 单个空格
  assert.strictEqual(escJsArg(null), '');          // null → ''
  assert.strictEqual(escJsArg(undefined), '');     // undefined → ''
});

// ── escAttrJs（XSS 关键：onclick="f('${escAttrJs(x)}')"）─────
test('escAttrJs 同时挡住 JS 字符串逃逸与 HTML 属性逃逸', () => {
  // 单引号被 JS 层转义（escJsArg），HTML 层不动单引号
  assert.strictEqual(escAttrJs("a'b"), "a\\'b");
  // 双引号被 HTML 层转义（escHtml），防止冲出双引号属性
  assert.strictEqual(escAttrJs('a"b'), 'a&quot;b');
  // 尖括号 HTML 转义
  assert.strictEqual(escAttrJs('a<b>'), 'a&lt;b&gt;');
  // 换行折叠
  assert.strictEqual(escAttrJs('a\nb'), 'a b');
  // 典型 XSS payload：试图闭合 JS 字符串后注入
  assert.strictEqual(escAttrJs("');alert(1);//"), "\\');alert(1);//");
  // 试图闭合 HTML 属性 + 标签：双引号与尖括号都被中和
  assert.strictEqual(
    escAttrJs('"><img src=x onerror=alert(1)>'),
    '&quot;&gt;&lt;img src=x onerror=alert(1)&gt;'
  );
});

// ── safeUrl（XSS 关键：阻断 javascript:/data:）─────────────
test('safeUrl 放行 http(s)/mailto/相对/锚点，拦截危险协议', () => {
  assert.strictEqual(safeUrl('https://example.com/a'), 'https://example.com/a');
  assert.strictEqual(safeUrl('http://example.com'), 'http://example.com');
  assert.strictEqual(safeUrl('//cdn.example.com/x'), '//cdn.example.com/x');
  assert.strictEqual(safeUrl('/relative/path'), '/relative/path');
  assert.strictEqual(safeUrl('./rel'), './rel');
  assert.strictEqual(safeUrl('../rel'), '../rel');
  assert.strictEqual(safeUrl('#anchor'), '#anchor');
  assert.strictEqual(safeUrl('mailto:user@example.com'), 'mailto:user@example.com');
  assert.strictEqual(safeUrl(' https://x.com '), 'https://x.com'); // 先 trim
});
test('safeUrl 拦截 javascript:/data:/vbscript: 等', () => {
  assert.strictEqual(safeUrl('javascript:alert(1)'), '#');
  assert.strictEqual(safeUrl('JavaScript:alert(1)'), '#'); // 大小写绕过
  assert.strictEqual(safeUrl('  javascript:alert(1)'), '#'); // 前导空格绕过
  assert.strictEqual(safeUrl('data:text/html,<script>alert(1)</script>'), '#');
  assert.strictEqual(safeUrl('vbscript:msgbox(1)'), '#');
  assert.strictEqual(safeUrl(null), '#');
  assert.strictEqual(safeUrl(''), '#');
});

test('safeExternalUrl 仅放行绝对 HTTP(S) 原文链接', () => {
  assert.strictEqual(safeExternalUrl('https://example.com/a'), 'https://example.com/a');
  assert.strictEqual(safeExternalUrl('http://example.com/a?q=1'), 'http://example.com/a?q=1');
  assert.strictEqual(safeExternalUrl('javascript:alert(1)'), '#');
  assert.strictEqual(safeExternalUrl('data:text/html,x'), '#');
  assert.strictEqual(safeExternalUrl('mailto:user@example.com'), '#');
  assert.strictEqual(safeExternalUrl('https://user:password@example.com/a'), '#');
  assert.strictEqual(safeExternalUrl('/relative'), '#');
  assert.strictEqual(safeExternalUrl(''), '#');
});

// ── ensureFileExt ─────────────────────────────────────────
test('ensureFileExt 补扩展名、清非法字符、空名回退', () => {
  assert.strictEqual(ensureFileExt('report', '.docx'), 'report.docx');
  assert.strictEqual(ensureFileExt('report.docx', '.docx'), 'report.docx'); // 已有扩展名不重复
  assert.strictEqual(ensureFileExt('name', 'docx'), 'name.docx'); // ext 不带点也可
  assert.strictEqual(ensureFileExt('a/b:c*?"<>|d', '.pdf'), 'a_b_c_d.pdf'); // 非法字符 → _
  assert.strictEqual(ensureFileExt('a   b', '.txt'), 'a_b.txt'); // 空白 → _
  assert.strictEqual(ensureFileExt('   ', '.docx'), 'download.docx'); // 空 → 回退
  assert.strictEqual(ensureFileExt('中国军力报告', '.docx'), '中国军力报告.docx'); // CJK 保留
  assert.strictEqual(ensureFileExt('Report.DOCX', '.docx'), 'Report.DOCX'); // 扩展名大小写不敏感
});

// ── filenameFromContentDisposition ────────────────────────
test('filenameFromContentDisposition 解析普通/RFC5987 文件名，缺失则回退', () => {
  assert.strictEqual(
    filenameFromContentDisposition('attachment; filename="report.docx"', 'fb'),
    'report.docx'
  );
  assert.strictEqual(
    filenameFromContentDisposition("attachment; filename*=UTF-8''%E6%8A%A5%E5%91%8A.docx", 'fb'),
    '报告.docx' // RFC5987 优先 + 百分号解码
  );
  assert.strictEqual(
    filenameFromContentDisposition('attachment; filename=plain.pdf', 'fb', '.pdf'),
    'plain.pdf'
  );
  assert.strictEqual(
    filenameFromContentDisposition('', 'fallback-name'),
    'fallback-name.docx' // 头缺失 → 回退 + 默认扩展名
  );
  assert.strictEqual(
    filenameFromContentDisposition(null, '回退报告', '.docx'),
    '回退报告.docx'
  );
});

// ── fmtDate（依赖全局 lang）────────────────────────────────
test('fmtDate 依据相对时间与全局 lang 输出', () => {
  global.lang = 'cn';
  assert.match(fmtDate(new Date(Date.now() - 30 * 1000).toISOString()), /秒前$/);
  assert.match(fmtDate(new Date(Date.now() - 30 * 60 * 1000).toISOString()), /分钟前$/);
  assert.match(fmtDate(new Date(Date.now() - 5 * 3600 * 1000).toISOString()), /小时前$/);
  assert.match(fmtDate(new Date(Date.now() - 3 * 86400 * 1000).toISOString()), /天前$/);
  global.lang = 'en';
  assert.match(fmtDate(new Date(Date.now() - 30 * 1000).toISOString()), /s ago$/);
  assert.match(fmtDate(new Date(Date.now() - 5 * 3600 * 1000).toISOString()), /h ago$/);
  delete global.lang;
});

// ── getCookie（依赖 document.cookie）───────────────────────
test('getCookie 按名取值，支持百分号编码名，缺失返回空串', () => {
  global.document = { cookie: 'csrf_token=abc123; other=xyz' };
  assert.strictEqual(getCookie('csrf_token'), 'abc123');
  assert.strictEqual(getCookie('other'), 'xyz');
  assert.strictEqual(getCookie('missing'), '');
  global.document = { cookie: 'a%20b=spaced' };
  assert.strictEqual(getCookie('a b'), 'spaced'); // 名按 encodeURIComponent 匹配
  delete global.document;
});

// ── apiFetch（依赖被改写的全局 fetch + 可选 showToast）──────
function fakeResp({ ok = true, status = 200, json, text, headers = {} }) {
  const make = () => ({
    json: async () => { if (json === undefined) throw new Error('no json'); return json; },
    text: async () => (text === undefined ? '' : text),
  });
  return {
    ok, status,
    clone: make,
    headers: { get: (k) => headers[k] || null },
  };
}

test('apiFetch 成功时原样返回响应', async () => {
  const resp = fakeResp({ ok: true, status: 200 });
  global.fetch = async () => resp;
  const out = await apiFetch('/api/x');
  assert.strictEqual(out, resp);
  delete global.fetch;
});

test('apiFetch 为已解锁云组织的 V9 业务请求附加显式上下文头', async () => {
  const organizationId = '00000000-0000-4000-8000-000000000021';
  global.__V9_BUSINESS_CONTEXT__ = Object.freeze({
    mode: 'cloud',
    organizationId,
    unlocked: true,
  });
  let captured;
  const resp = fakeResp({ ok: true, status: 200 });
  global.fetch = async (_input, init) => {
    captured = init;
    return resp;
  };

  await apiFetch('/api/v9/evidence', {
    headers: {'X-Existing': 'preserved'},
  });

  const headers = new Headers(captured.headers);
  assert.strictEqual(headers.get('X-V9-Context-Mode'), 'cloud');
  assert.strictEqual(
    headers.get('X-V9-Organization-ID'),
    organizationId,
  );
  assert.strictEqual(headers.get('X-Existing'), 'preserved');
  delete global.fetch;
  delete global.__V9_BUSINESS_CONTEXT__;
});

test('apiFetch 为个人工作区的 V9 业务请求附加显式上下文头', async () => {
  const organizationId = '00000000-0000-4000-8000-000000000011';
  global.__V9_BUSINESS_CONTEXT__ = Object.freeze({
    mode: 'personal',
    organizationId,
    unlocked: true,
  });
  let captured;
  const resp = fakeResp({ok: true, status: 200});
  global.fetch = async (_input, init) => {
    captured = init;
    return resp;
  };

  await apiFetch('/api/v9/evidence');

  const headers = new Headers(captured.headers);
  assert.strictEqual(headers.get('X-V9-Context-Mode'), 'personal');
  assert.strictEqual(
    headers.get('X-V9-Organization-ID'),
    organizationId,
  );
  delete global.fetch;
  delete global.__V9_BUSINESS_CONTEXT__;
});

test('apiFetch 在业务上下文尚未解析时阻断 V9 业务请求', async () => {
  delete global.__V9_BUSINESS_CONTEXT__;
  let fetchCalled = false;
  global.fetch = async () => {
    fetchCalled = true;
    return fakeResp({ok: true});
  };

  await assert.rejects(
    () => apiFetch('/api/v9/evidence', {}, {toast: false}),
    (error) => error.code === 'V9_BUSINESS_CONTEXT_UNAVAILABLE',
  );
  assert.strictEqual(fetchCalled, false);
  delete global.fetch;
});

test('apiFetch 在云组织待配对或锁定时阻断 V9 业务请求', async () => {
  global.__V9_BUSINESS_CONTEXT__ = Object.freeze({
    mode: 'cloud',
    organizationId: '00000000-0000-4000-8000-000000000021',
    unlocked: false,
    reason: 'pending_device',
  });
  let fetchCalled = false;
  global.fetch = async () => {
    fetchCalled = true;
    return fakeResp({ ok: true });
  };

  await assert.rejects(
    () => apiFetch('/api/v9/cases', {}, {toast: false}),
    (error) => error.code === 'V9_CLOUD_CONTEXT_LOCKED',
  );
  assert.strictEqual(fetchCalled, false);
  delete global.fetch;
  delete global.__V9_BUSINESS_CONTEXT__;
});

test('apiFetch 收到云会话 401 后锁定上下文，后续不回退个人模式', async () => {
  const organizationId = '00000000-0000-4000-8000-000000000021';
  global.__V9_BUSINESS_CONTEXT__ = Object.freeze({
    mode: 'cloud',
    organizationId,
    unlocked: true,
  });
  let calls = 0;
  global.fetch = async () => {
    calls += 1;
    return fakeResp({
      ok: false,
      status: 401,
      json: {error: 'session expired'},
    });
  };

  await assert.rejects(
    () => apiFetch('/api/v9/documents', {}, {toast: false}),
    (error) => error.status === 401,
  );
  assert.strictEqual(global.__V9_BUSINESS_CONTEXT__.unlocked, false);
  await assert.rejects(
    () => apiFetch('/api/v9/documents', {}, {toast: false}),
    (error) => error.code === 'V9_CLOUD_CONTEXT_LOCKED',
  );
  assert.strictEqual(calls, 1);
  delete global.fetch;
  delete global.__V9_BUSINESS_CONTEXT__;
});

test('apiFetch 不把云业务上下文注入身份与设备控制请求', async () => {
  global.__V9_BUSINESS_CONTEXT__ = Object.freeze({
    mode: 'cloud',
    organizationId: '00000000-0000-4000-8000-000000000021',
    unlocked: false,
  });
  let captured;
  global.fetch = async (_input, init) => {
    captured = init;
    return fakeResp({ok: true});
  };

  await apiFetch('/api/v9/auth/session');

  const headers = new Headers(captured.headers || {});
  assert.strictEqual(headers.get('X-V9-Context-Mode'), null);
  assert.strictEqual(headers.get('X-V9-Organization-ID'), null);
  delete global.fetch;
  delete global.__V9_BUSINESS_CONTEXT__;
});

test('apiFetch 为未解锁云组织的设备控制请求附加显式上下文', async () => {
  const organizationId = '00000000-0000-4000-8000-000000000021';
  global.__V9_BUSINESS_CONTEXT__ = Object.freeze({
    mode: 'cloud',
    organizationId,
    unlocked: false,
  });
  let captured;
  global.fetch = async (_input, init) => {
    captured = init;
    return fakeResp({ok: true});
  };

  await apiFetch(`/api/v9/devices?organization_id=${organizationId}`);

  const headers = new Headers(captured.headers || {});
  assert.strictEqual(headers.get('X-V9-Context-Mode'), 'cloud');
  assert.strictEqual(
    headers.get('X-V9-Organization-ID'),
    organizationId,
  );
  delete global.fetch;
  delete global.__V9_BUSINESS_CONTEXT__;
});

test('apiFetch 失败时抛出携带 status 的错误，并解析 JSON error 字段', async () => {
  global.fetch = async () => fakeResp({ ok: false, status: 400, json: { error: '参数错误' } });
  const toasts = [];
  global.showToast = (m) => toasts.push(m);
  await assert.rejects(
    () => apiFetch('/api/x'),
    (err) => {
      assert.strictEqual(err.message, '参数错误');
      assert.strictEqual(err.status, 400);
      assert.strictEqual(err.toastShown, true);
      return true;
    }
  );
  assert.deepStrictEqual(toasts, ['❌ 参数错误']);
  delete global.fetch;
  delete global.showToast;
});

test('apiFetch 在 opts.toast===false 时不弹 toast', async () => {
  global.fetch = async () => fakeResp({ ok: false, status: 500, json: { message: '服务器错误' } });
  let toasted = false;
  global.showToast = () => { toasted = true; };
  await assert.rejects(
    () => apiFetch('/api/x', {}, { toast: false }),
    (err) => err.message === '服务器错误' && err.status === 500 && !err.toastShown
  );
  assert.strictEqual(toasted, false);
  delete global.fetch;
  delete global.showToast;
});

test('apiFetch 对 404 HTML 错误页给出可读提示', async () => {
  global.fetch = async () => fakeResp({ ok: false, status: 404, text: '<!DOCTYPE html><html>not found</html>' });
  await assert.rejects(
    () => apiFetch('/api/missing', {}, { toast: false }),
    (err) => /接口未找到/.test(err.message) && err.status === 404
  );
  delete global.fetch;
});
