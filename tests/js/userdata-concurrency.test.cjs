const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..', '..');
const news = fs.readFileSync(path.join(root, 'static', 'js', 'news.js'), 'utf8');
const brief = fs.readFileSync(path.join(root, 'static', 'js', 'brief.js'), 'utf8');

function syncContext(fetchImpl, initialStorage = {}) {
  const values = new Map(Object.entries(initialStorage));
  const listeners = new Map();
  const window = {
    showTab() {},
    __USERDATA_REVISION__: null,
    addEventListener(name, callback) { listeners.set(name, callback); },
  };
  const context = vm.createContext({
    window,
    fetch: fetchImpl,
    console,
    document: {addEventListener() {}, getElementById() { return null; }},
    localStorage: {
      getItem(key) { return values.has(key) ? values.get(key) : null; },
      setItem(key, value) { values.set(key, String(value)); },
    },
    encodeURIComponent,
  });
  vm.runInContext(brief, context, {filename: 'brief.js'});
  return {context, values, listeners, window};
}

function jsonResponse(status, payload) {
  return {ok: status >= 200 && status < 300, status, async json() { return payload; }};
}

test('userdata startup uses bootstrap and schema-version migration marker', () => {
  assert.match(news, /fetch\(['"]\/api\/userdata\/bootstrap['"]/);
  assert.match(news, /defense_ud_schema_version/);
  assert.doesNotMatch(news, /fetch\(['"]\/api\/userdata\/all['"]/);
  assert.doesNotMatch(news, /defense_ud_migrated/);
});

test('brief writes are item based and revision guarded', () => {
  assert.match(brief, /\/api\/userdata\/brief-results\/['"]?\s*\+\s*encodeURIComponent/);
  assert.match(brief, /['"]If-Match['"]/);
  assert.match(brief, /REVISION_CONFLICT/);
  assert.doesNotMatch(brief, /\/api\/userdata\/kv\/briefResults/);
});

test('delete and clear send only selected ids so concurrent additions survive', () => {
  assert.match(brief, /_briefMutate\(['"]DELETE['"]/);
  assert.match(brief, /item_ids/);
  assert.match(brief, /_briefPendingDeletes/);
});

test('stale upsert refreshes revision, retries, and merges the other window item', async () => {
  const calls = [];
  const responses = [
    jsonResponse(409, {code: 'REVISION_CONFLICT'}),
    jsonResponse(200, {schema_version: 2, revision: 1, brief_results: [{id: 'from-a'}]}),
    jsonResponse(200, {schema_version: 2, revision: 2, brief_results: [{id: 'from-b'}, {id: 'from-a'}]}),
  ];
  const runtime = syncContext(async (url, init = {}) => {
    calls.push({url, init});
    return responses.shift();
  });
  runtime.window.__USERDATA_REVISION__ = 0;

  await vm.runInContext(`
    briefResults = [{id: 'from-b', brief: 'local'}];
    briefSave(briefResults[0]);
    _briefSyncTail;
  `, runtime.context);

  const ids = vm.runInContext('briefResults.map(item => item.id).sort()', runtime.context);
  assert.deepEqual([...ids], ['from-a', 'from-b']);
  assert.equal(calls[0].init.headers['If-Match'], '"0"');
  assert.equal(calls[1].url, '/api/userdata/brief-results');
  assert.equal(calls[2].init.headers['If-Match'], '"1"');
});

test('snapshot clear retries without deleting a concurrent addition', async () => {
  const calls = [];
  const responses = [
    jsonResponse(409, {code: 'REVISION_CONFLICT'}),
    jsonResponse(200, {
      schema_version: 2,
      revision: 3,
      brief_results: [{id: 'old-a'}, {id: 'old-b'}, {id: 'new-window'}],
    }),
    jsonResponse(200, {
      schema_version: 2,
      revision: 4,
      brief_results: [{id: 'new-window'}],
    }),
  ];
  const runtime = syncContext(async (url, init = {}) => {
    calls.push({url, init});
    return responses.shift();
  });
  runtime.window.__USERDATA_REVISION__ = 2;

  await vm.runInContext(`
    briefResults = [];
    _briefQueueDelete(['old-a', 'old-b']);
    _briefSyncTail;
  `, runtime.context);

  const ids = vm.runInContext('briefResults.map(item => item.id)', runtime.context);
  assert.deepEqual([...ids], ['new-window']);
  assert.deepEqual(JSON.parse(calls[0].init.body).item_ids, ['old-a', 'old-b']);
  assert.deepEqual(JSON.parse(calls[2].init.body).item_ids, ['old-a', 'old-b']);
});

test('failed item write remains a durable pending upsert for next startup', async () => {
  const runtime = syncContext(async () => { throw new Error('offline'); });
  runtime.window.__USERDATA_REVISION__ = 0;

  await vm.runInContext(`
    briefResults = [{id: 'offline-edit', brief: 'new local value'}];
    briefSave(briefResults[0]);
    _briefSyncTail;
  `, runtime.context);

  const pending = JSON.parse(runtime.values.get('briefPendingUpserts') || '[]');
  assert.deepEqual(pending, [{id: 'offline-edit', brief: 'new local value'}]);
});

test('next startup retries a dirty existing item instead of accepting stale server data', async () => {
  const calls = [];
  const local = {id: 'same-id', brief: 'offline edit'};
  const runtime = syncContext(async (url, init = {}) => {
    calls.push({url, init});
    return jsonResponse(200, {
      schema_version: 2,
      revision: 2,
      brief_results: [local],
    });
  }, {
    briefResults: JSON.stringify([local]),
    briefPendingUpserts: JSON.stringify([local]),
  });

  runtime.listeners.get('userdata-ready')({
    detail: {
      schema_version: 2,
      revision: 1,
      brief_results: [{id: 'same-id', brief: 'stale server value'}],
    },
  });
  await vm.runInContext('_briefSyncTail', runtime.context);

  assert.equal(JSON.parse(calls[0].init.body).item.brief, 'offline edit');
  const current = vm.runInContext('briefResults[0].brief', runtime.context);
  assert.equal(current, 'offline edit');
  assert.deepEqual(JSON.parse(runtime.values.get('briefPendingUpserts')), []);
});
