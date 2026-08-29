const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

class FakeElement {
  constructor(tagName) {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.className = '';
    this.id = '';
    this.style = {};
    this.title = '';
    this.textContent = '';
    this.listeners = {};
  }

  append(...children) {
    this.children.push(...children);
  }

  replaceChildren(...children) {
    this.children = [...children];
  }

  addEventListener(type, listener) {
    this.listeners[type] = listener;
  }

  set innerHTML(_value) {
    throw new Error('feed health renderer must not use innerHTML');
  }
}

function installBrowserStubs() {
  global.localStorage = {
    getItem: () => null,
    setItem: () => {},
  };
  global.window = {
    addEventListener: () => {},
    location: {
      origin: 'https://tracker.example',
      href: 'https://tracker.example/',
      assign: () => {},
    },
  };
  global.document = {
    cookie: '',
    addEventListener: () => {},
    querySelectorAll: () => [],
    getElementById: () => null,
    createElement: (tagName) => new FakeElement(tagName),
  };
}

installBrowserStubs();
global.getCookie = require(
  path.join(__dirname, '..', '..', 'static', 'js', 'util.js'),
).getCookie;
const {
  bindWorkspaceLogout,
  renderFeedStatusView,
  logoutWorkspace,
} = require(path.join(__dirname, '..', '..', 'static', 'js', 'news.js'));

function walk(node) {
  return [node, ...node.children.flatMap(walk)];
}

test('feed health renderer never parses upstream error text as HTML or handlers', () => {
  const payload = '\"><img src=x onerror=globalThis.__feedXss=1>';
  const root = new FakeElement('div');
  global.__feedXss = 0;

  renderFeedStatusView(
    root,
    [['Malicious feed', 0]],
    ['Malicious feed'],
    {
      total: 1,
      healthy: 0,
      unhealthy: 1,
      dead: 0,
      feeds: [{
        name: 'Malicious feed',
        fail_streak: 1,
        last_err: payload,
        last_error_code: payload,
        last_http_status: '502\" onmouseover=globalThis.__feedXss=2',
      }],
    },
  );

  const nodes = walk(root);
  const rendered = nodes.map((node) => `${node.textContent} ${node.title}`).join(' ');
  assert.doesNotMatch(rendered, /img|onerror|onmouseover|__feedXss/);
  assert.strictEqual(global.__feedXss, 0);
  assert.strictEqual(nodes.some((node) => node.tagName === 'IMG'), false);
  delete global.__feedXss;
});

test('workspace logout frontend uses POST with the existing CSRF token', async () => {
  global.document.cookie = 'csrf_token=csrf-test-token';
  globalThis.__WORKSPACE_LOGGING_OUT__ = false;
  let captured;
  global.apiFetch = async (input, init) => {
    assert.strictEqual(globalThis.__WORKSPACE_LOGGING_OUT__, true);
    captured = {input, init};
    return {url: 'https://tracker.example/login'};
  };
  let assigned = '';
  global.window.location.assign = (target) => { assigned = target; };

  await logoutWorkspace();

  assert.strictEqual(captured.input, '/logout');
  assert.strictEqual(captured.init.method, 'POST');
  assert.strictEqual(
    new Headers(captured.init.headers).get('X-CSRF-Token'),
    'csrf-test-token',
  );
  assert.strictEqual(assigned, 'https://tracker.example/login');
  assert.strictEqual(globalThis.__WORKSPACE_LOGGING_OUT__, true);
  delete global.apiFetch;
});

test('failed workspace logout releases the in-progress guard', async () => {
  globalThis.__WORKSPACE_LOGGING_OUT__ = false;
  global.apiFetch = async () => {
    assert.strictEqual(globalThis.__WORKSPACE_LOGGING_OUT__, true);
    throw new Error('synthetic logout failure');
  };

  await assert.rejects(logoutWorkspace, /synthetic logout failure/);

  assert.strictEqual(globalThis.__WORKSPACE_LOGGING_OUT__, false);
  delete global.apiFetch;
});

test('account panel exposes a separately bound local workspace logout', async () => {
  const button = new FakeElement('button');
  global.document.cookie = 'csrf_token=bound-logout-token';
  let captured;
  global.apiFetch = async (input, init) => {
    captured = {input, init};
    return {url: 'https://tracker.example/login'};
  };

  assert.strictEqual(bindWorkspaceLogout(button), true);
  assert.strictEqual(typeof button.listeners.click, 'function');
  await button.listeners.click();

  assert.strictEqual(captured.input, '/logout');
  assert.strictEqual(captured.init.method, 'POST');
  assert.strictEqual(
    new Headers(captured.init.headers).get('X-CSRF-Token'),
    'bound-logout-token',
  );
  delete global.apiFetch;
});

test('account panel keeps local logout outside the cloud-only workspace', () => {
  const root = path.join(__dirname, '..', '..');
  const html = fs.readFileSync(path.join(root, 'templates', 'index.html'), 'utf8');
  const panelIndex = html.indexOf('id="v9CloudPanel"');
  const localLogoutIndex = html.indexOf('id="workspaceLogout"');
  const cloudWorkspaceIndex = html.indexOf('id="v9CloudWorkspace"');

  assert.ok(panelIndex >= 0);
  assert.ok(localLogoutIndex > panelIndex);
  assert.ok(localLogoutIndex < cloudWorkspaceIndex);
  assert.match(html, /id="workspaceLogout"[^>]*>退出本地工作区<\/button>/);
});

test('mobile command hub releases the fixed desktop topbar width', () => {
  const css = fs.readFileSync(
    path.join(__dirname, '..', '..', 'static', 'css', 'command-hub-v9.css'),
    'utf8',
  );

  assert.match(
    css,
    /@media\s*\(max-width:\s*820px\)[\s\S]*?\.topbar-left\s*\{[^}]*min-width:\s*0[^}]*\}/,
  );
});

test('AI status checks stay silent while local logout is in progress', () => {
  const aiSource = fs.readFileSync(
    path.join(__dirname, '..', '..', 'static', 'js', 'ai.js'),
    'utf8',
  );

  assert.match(
    aiSource,
    /if\s*\(globalThis\.__WORKSPACE_LOGGING_OUT__\)\s*return;/,
  );
  assert.match(
    aiSource,
    /apiFetch\('\/api\/ai\/config',\s*\{\},\s*\{toast:\s*false\}\)/,
  );
});

test.after(() => {
  delete global.localStorage;
  delete global.window;
  delete global.document;
  delete global.getCookie;
  delete globalThis.__WORKSPACE_LOGGING_OUT__;
});
