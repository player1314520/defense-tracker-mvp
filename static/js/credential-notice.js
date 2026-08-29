/* Persistent, fixed-text security notice for migrated local Feishu secrets. */
(function credentialNoticeModule(global) {
  'use strict';

  const FIXED_ROTATION_NOTICE =
    '旧版明文飞书凭据已迁移到 Windows 当前用户保护存储。请在飞书开发者后台轮换 App Secret、Verification Token、Encrypt Key 和 Tenant Key，并确认旧凭据已撤销；本应用无法自动核验远程撤销状态，旧备份也可能仍保留明文。';

  function elements(documentRef) {
    return {
      banner: documentRef?.getElementById('credentialNotice'),
      button: documentRef?.getElementById('credentialNoticeButton'),
      dismiss: documentRef?.getElementById('credentialNoticeDismiss'),
      text: documentRef?.getElementById('credentialNoticeText'),
    };
  }

  function applyCredentialNoticeState(payload, documentRef) {
    const refs = elements(documentRef);
    if (!refs.banner || !refs.button || !refs.text) return false;
    const required = payload?.credential_rotation_required === true;
    refs.button.hidden = !required;
    refs.banner.hidden = !required;
    refs.text.textContent = required ? FIXED_ROTATION_NOTICE : '';
    return required;
  }

  function showCredentialNotice(documentRef = global.document) {
    const refs = elements(documentRef);
    if (!refs.banner || !refs.button || refs.button.hidden) return false;
    refs.banner.hidden = false;
    refs.banner.focus();
    return true;
  }

  function dismissCredentialNotice(documentRef = global.document) {
    const refs = elements(documentRef);
    if (!refs.banner || !refs.button || refs.button.hidden) return false;
    refs.banner.hidden = true;
    refs.button.focus();
    return true;
  }

  async function loadCredentialNotice({
    documentRef = global.document,
    request = global.apiFetch,
  } = {}) {
    if (typeof request !== 'function') return false;
    try {
      const response = await request('/api/feishu/config', {}, {toast: false});
      return applyCredentialNoticeState(await response.json(), documentRef);
    } catch (error) {
      if (error?.status !== 401 && global.console?.warn) {
        global.console.warn('飞书凭据安全状态暂不可用');
      }
      return false;
    }
  }

  function initializeCredentialNotice(documentRef = global.document) {
    const refs = elements(documentRef);
    refs.button?.addEventListener('click', () => showCredentialNotice(documentRef));
    refs.dismiss?.addEventListener('click', () => dismissCredentialNotice(documentRef));
    return loadCredentialNotice({documentRef});
  }

  global.showCredentialNotice = showCredentialNotice;
  global.dismissCredentialNotice = dismissCredentialNotice;
  if (global.document?.addEventListener) {
    global.document.addEventListener(
      'DOMContentLoaded',
      () => initializeCredentialNotice(global.document),
    );
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      FIXED_ROTATION_NOTICE,
      applyCredentialNoticeState,
      dismissCredentialNotice,
      initializeCredentialNotice,
      loadCredentialNotice,
      showCredentialNotice,
    };
  }
}(typeof globalThis !== 'undefined' ? globalThis : this));
