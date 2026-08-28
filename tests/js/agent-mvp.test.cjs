const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(
  path.resolve(__dirname, '../../static/js/agent.js'),
  'utf8',
);
const markup = fs.readFileSync(
  path.resolve(__dirname, '../../templates/index.html'),
  'utf8',
);
const styles = fs.readFileSync(
  path.resolve(__dirname, '../../static/css/agent.css'),
  'utf8',
);

const context = {
  console,
  document: {
    addEventListener() {},
    getElementById() { return null; },
  },
  window: {},
  localStorage: {
    getItem() { return null; },
    setItem() {},
    removeItem() {},
  },
};
vm.createContext(context);
vm.runInContext(source, context, {filename: 'agent.js'});

assert.equal(
  context.agentReportTypeLabel('institution_pack'),
  '机构开源情报整编包（MVP）',
  '机构包应有明确的用户可见名称',
);
assert.equal(
  context.agentDefaultCount('institution_pack'),
  8,
  '机构包默认目标应为 8 条来源',
);
assert.equal(context.agentIsVisibleReportType('institution_pack'), true);
assert.equal(context.agentIsVisibleReportType('strategic'), true);
assert.equal(context.agentIsVisibleReportType('daily'), false);

assert.deepEqual(
  JSON.parse(JSON.stringify(context.agentMvpSourceGate(new Array(6).fill({})))),
  {ok: false, count: 6, required: 7, gap: 1},
  '不足 7 条来源时应停止闭环',
);
assert.deepEqual(
  JSON.parse(JSON.stringify(context.agentMvpSourceGate(new Array(7).fill({})))),
  {ok: true, count: 7, required: 7, gap: 0},
  '达到 7 条来源时才能继续生成',
);

const normalized = context.agentNormalizePreflight({
  ok: true,
  preflight: {
    ok: false,
    status: 'blocked',
    checks: [
      {id: 'sources', ok: true, label: '机构来源覆盖', detail: '7/7'},
      {id: 'citations', ok: false, label: '引注闭环'},
    ],
  },
});
assert.equal(normalized.ok, false);
assert.equal(normalized.status, 'blocked');
assert.equal(normalized.checks[0].detail, '7/7');
assert.equal(normalized.checks[1].detail, '未提供详情');
assert.deepEqual(
  JSON.parse(JSON.stringify(normalized.failures)),
  ['引注闭环：未提供详情'],
  '失败原因必须来自后端 checks，而不是前端关键词计数',
);
const malformedPreflight = context.agentNormalizePreflight({
  preflight: {ok: true, status: 'ready', checks: []},
});
assert.equal(malformedPreflight.ok, false, '后端未返回 checks 时必须 fail closed');
assert.equal(malformedPreflight.status, 'blocked');
assert.deepEqual(
  JSON.parse(JSON.stringify(malformedPreflight.failures)),
  ['预检响应：后端未返回检查项'],
);
assert.equal(
  context.agentMvpCollectionTarget({report_type: 'institution_pack', target_count: 3}),
  8,
  '机构包即使被手工调低目标，也应按 8 条采集',
);
assert.equal(
  context.agentMvpCollectionTarget({report_type: 'daily', target_count: 3}),
  3,
  '其它报告保留既有目标数量行为',
);
assert.equal(
  context.agentMvpCollectError({capture: {status: 'failed', stop_reason: 'provider_error'}}),
  '自主采集失败：provider_error',
);
assert.equal(context.agentMvpCollectError({capture: {status: 'completed'}}), '');
assert.equal(
  context.agentResolveDraftContent('', {content: '已保存正文'}),
  '',
  '用户清空正文时预检必须看到空正文，不能回退到旧草稿',
);
assert.equal(context.agentResolveDraftContent(undefined, {content: '已保存正文'}), '已保存正文');
assert.deepEqual(
  JSON.parse(JSON.stringify(context.agentBuildExportPayload('draft-1', '正文', ['ev-1', 'ev-2']))),
  {draft_id: 'draft-1', content: '正文', evidence_ids: ['ev-1', 'ev-2']},
  '导出与预检必须使用同一证据选择集',
);

assert.match(markup, /id="agentReportType"/);
assert.match(markup, /value="institution_pack"[^>]*selected/);
const reportTypeSelect = markup.match(/<select id="agentReportType"[\s\S]*?<\/select>/)?.[0] || '';
assert.match(reportTypeSelect, /value="strategic"/);
assert.doesNotMatch(reportTypeSelect, /value="(?:daily|weekly|short_topic)"/);
assert.match(markup, /id="agentMvpRunBtn"/);
assert.match(markup, /id="agentMvpPreflight"[^>]*aria-live="polite"/);
assert.match(styles, /@media\(max-width:1500px\)\{\.agent-grid\{grid-template-columns:1fr 1fr\}/);

console.log('agent MVP pure-function tests passed');
