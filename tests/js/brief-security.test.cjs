const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(
  path.resolve(__dirname, '../../static/js/brief.js'),
  'utf8',
);

let syncPayload = null;
let clipboardWrites = 0;
let downloadClicks = 0;
const context = {
  console,
  window: {addEventListener() {}, _currentNews: [], showTab() {}},
  document: {
    addEventListener() {},
    getElementById() { return null; },
    querySelector() { return null; },
    createElement() { return {click() { downloadClicks += 1; }}; },
  },
  localStorage: {
    getItem() { return null; },
    setItem() { throw Object.assign(new Error('quota'), {name: 'QuotaExceededError'}); },
  },
  navigator: {
    clipboard: {
      async writeText() { clipboardWrites += 1; },
    },
  },
  udSync(_path, payload) { syncPayload = payload; },
  showToast() {},
  apiFetch: async () => { throw new Error('server source gate blocked'); },
  confirm() { return true; },
  setInterval,
  clearInterval,
  setTimeout,
  clearTimeout,
  URL,
  Blob,
  TextDecoder,
};
vm.createContext(context);
vm.runInContext(source, context, {filename: 'brief.js'});

(async () => {
  vm.runInContext(`
    briefResults = [{
      id: 'imported',
      brief: 'draft',
      sourceEvidence: {payload: {origin: 'import_text', material_text: 'private source'}},
      article: {region: '导入', summary: 'private source'}
    }];
    briefSave();
  `, context);
  assert.ok(syncPayload, 'localStorage quota failure must not block server sync');
  assert.equal(syncPayload.value[0].sourceEvidence, undefined);
  assert.equal(syncPayload.value[0].article.summary, '');

  let importedFeedbackCalls = 0;
  context.apiFetch = async () => { importedFeedbackCalls += 1; return {}; };
  await vm.runInContext(`briefDiscardResult('imported')`, context);
  assert.equal(importedFeedbackCalls, 0, 'discarding an import must not write a quality sample');
  assert.equal(vm.runInContext(`briefResults.length`, context), 0);
  context.apiFetch = async () => { throw new Error('server source gate blocked'); };

  vm.runInContext(`
    _briefReleaseReady = () => true;
    briefResults = [{
      id: 'edited', brief: 'old', _editing: true, _editBuffer: 'forged edit',
      sourceEvidence: {payload: {origin: 'rss_cache'}}, article: {}
    }];
  `, context);

  await vm.runInContext(`briefEditSave('edited')`, context);
  assert.equal(
    vm.runInContext(`briefResults[0].brief`, context),
    'old',
    'server rejection must prevent saving an edited brief',
  );

  await vm.runInContext(`briefCopyOne('edited')`, context);
  assert.equal(clipboardWrites, 0, 'server rejection must prevent clipboard release');

  await vm.runInContext(`briefExportAll()`, context);
  assert.equal(downloadClicks, 0, 'server rejection must stop TXT release before export');

  let releaseValidation;
  context.apiFetch = () => new Promise((resolve) => { releaseValidation = resolve; });
  vm.runInContext(`
    briefResults = [{
      id: 'copy-race', brief: 'old', _editing: true, _editBuffer: 'validated snapshot',
      sourceEvidence: {payload: {origin: 'rss_cache'}}, article: {}
    }];
  `, context);
  const copyRace = vm.runInContext(`briefCopyOne('copy-race')`, context);
  await new Promise((resolve) => setImmediate(resolve));
  vm.runInContext(`briefResults[0]._editBuffer = 'changed while validating'`, context);
  releaseValidation({});
  await copyRace;
  assert.equal(clipboardWrites, 0, 'copy must reject text changed during validation');
  assert.equal(vm.runInContext(`briefResults[0].brief`, context), 'old');

  context.apiFetch = () => new Promise((resolve) => { releaseValidation = resolve; });
  vm.runInContext(`
    briefResults = [{
      id: 'export-race', brief: 'old', _editing: true, _editBuffer: 'validated snapshot',
      sourceEvidence: {payload: {origin: 'rss_cache'}}, article: {},
      timestamp: new Date().toISOString()
    }];
  `, context);
  const exportRace = vm.runInContext(`briefExportAll()`, context);
  await new Promise((resolve) => setImmediate(resolve));
  vm.runInContext(`briefResults[0]._editBuffer = 'changed while validating'`, context);
  releaseValidation({});
  await exportRace;
  assert.equal(downloadClicks, 0, 'TXT export must reject text changed during validation');

  context.apiFetch = () => new Promise((resolve) => { releaseValidation = resolve; });
  vm.runInContext(`
    briefResults = [{
      id: 'export-set-race', brief: 'validated snapshot',
      sourceEvidence: {payload: {origin: 'rss_cache'}}, article: {},
      timestamp: new Date().toISOString()
    }];
  `, context);
  const exportSetRace = vm.runInContext(`briefExportAll()`, context);
  await new Promise((resolve) => setImmediate(resolve));
  vm.runInContext(`briefResults.push({
    id: 'unvalidated-new-item', brief: 'unvalidated', article: {},
    timestamp: new Date().toISOString()
  })`, context);
  releaseValidation({});
  await exportSetRace;
  assert.equal(downloadClicks, 0, 'TXT export must reject a result-set change during validation');

  context.apiFetch = async () => ({});
  vm.runInContext(`
    briefResults = [{
      id: 'positive', brief: 'validated snapshot',
      sourceEvidence: {payload: {origin: 'rss_cache'}},
      article: {link: 'https://example.test/source', source: 'Test', region: 'US'},
      timestamp: new Date().toISOString()
    }];
  `, context);
  const clipboardBeforeSuccess = clipboardWrites;
  await vm.runInContext(`briefCopyOne('positive')`, context);
  assert.equal(clipboardWrites, clipboardBeforeSuccess + 1, 'validated copy should succeed');
  const downloadsBeforeSuccess = downloadClicks;
  await vm.runInContext(`briefExportAll()`, context);
  assert.equal(downloadClicks, downloadsBeforeSuccess + 1, 'validated TXT export should succeed');

  console.log('brief security tests passed');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
