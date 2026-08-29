const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const notice = require('../../static/js/credential-notice.js');


function fakeDocument() {
  const nodes = new Map();
  for (const id of [
    'credentialNotice',
    'credentialNoticeButton',
    'credentialNoticeDismiss',
    'credentialNoticeText',
  ]) {
    nodes.set(id, {
      hidden: true,
      textContent: '',
      focused: false,
      handlers: {},
      addEventListener(event, handler) { this.handlers[event] = handler; },
      focus() { this.focused = true; },
    });
  }
  return {
    nodes,
    getElementById(id) { return nodes.get(id) || null; },
  };
}


test('migration status renders only the fixed redacted security notice', async () => {
  const documentRef = fakeDocument();
  const attackerControlledText = 'do-not-render-this-credential-value';
  const required = await notice.loadCredentialNotice({
    documentRef,
    request: async () => ({
      json: async () => ({
        credential_rotation_required: true,
        credential_notice: attackerControlledText,
        app_secret: attackerControlledText,
      }),
    }),
  });

  assert.equal(required, true);
  assert.equal(documentRef.nodes.get('credentialNotice').hidden, false);
  assert.equal(documentRef.nodes.get('credentialNoticeButton').hidden, false);
  assert.equal(
    documentRef.nodes.get('credentialNoticeText').textContent,
    notice.FIXED_ROTATION_NOTICE,
  );
  assert.doesNotMatch(
    documentRef.nodes.get('credentialNoticeText').textContent,
    new RegExp(attackerControlledText),
  );
  assert.match(notice.FIXED_ROTATION_NOTICE, /无法自动核验/);
  assert.match(notice.FIXED_ROTATION_NOTICE, /确认.*撤销/);
});


test('notice is keyboard reachable, dismissible, and can be reopened', () => {
  const documentRef = fakeDocument();
  notice.applyCredentialNoticeState(
    {credential_rotation_required: true},
    documentRef,
  );

  assert.equal(notice.dismissCredentialNotice(documentRef), true);
  assert.equal(documentRef.nodes.get('credentialNotice').hidden, true);
  assert.equal(documentRef.nodes.get('credentialNoticeButton').hidden, false);
  assert.equal(documentRef.nodes.get('credentialNoticeButton').focused, true);
  assert.equal(notice.showCredentialNotice(documentRef), true);
  assert.equal(documentRef.nodes.get('credentialNotice').hidden, false);
  assert.equal(documentRef.nodes.get('credentialNotice').focused, true);
});


test('template wires an accessible persistent notice and status control', () => {
  const html = fs.readFileSync(
    path.join(__dirname, '../../templates/index.html'),
    'utf8',
  );

  assert.match(html, /id="credentialNotice"[^>]*role="alert"/);
  assert.match(html, /id="credentialNotice"[^>]*tabindex="-1"/);
  assert.match(html, /id="credentialNoticeDismiss"[^>]*type="button"/);
  assert.match(html, /id="credentialNoticeButton"[^>]*aria-controls="credentialNotice"/);
  assert.match(html, /\/static\/js\/credential-notice\.js/);
});
