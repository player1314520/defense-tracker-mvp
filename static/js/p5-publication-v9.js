/* V9 P5 · evidence-bound writing, layout, approval and immutable release */
(function () {
  let documentCache = [];
  let publicationCache = [];
  let auditCache = [];
  let activeDocumentId = null;

  const boardLabels = {
    evidence_needed: '待补证',
    editing: '编辑中',
    pending_approval: '待签发',
    signed: '已签发',
    recalled: '已撤回'
  };
  const sourceLabels = {
    verified: '已验证事实',
    source_claim: '来源声明',
    inference: '分析推断',
    scenario_assumption: '情景假设'
  };
  const factLabels = {pending: '待核查', passed: '已通过', failed: '未通过'};

  function csv(value) {
    return String(value || '').split(/[,，\n]+/).map(item => item.trim()).filter(Boolean);
  }

  async function requestJson(url, init) {
    const response = await apiFetch(url, init);
    return response.json();
  }

  function sendJson(url, body, method) {
    return requestJson(url, {
      method: method || 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    });
  }

  function maybeShowRecovery(data) {
    if (data?.recovery_code) {
      window.prompt('个人工作区恢复码仅显示一次，请离线保存：', data.recovery_code);
    }
  }

  function emptyParagraph(value) {
    return Object.assign({
      paragraph_id: '',
      heading: '',
      text: '',
      evidence_ids: [],
      claim_ids: [],
      source_status: 'source_claim',
      fact_check: 'pending',
      fact_check_note: ''
    }, value || {});
  }

  function bindEvidenceDrop(input) {
    if (!input || input.dataset.dropBound) return;
    input.dataset.dropBound = '1';
    input.addEventListener('dragover', event => {
      event.preventDefault();
      event.dataTransfer.dropEffect = 'copy';
    });
    input.addEventListener('drop', event => {
      event.preventDefault();
      const recordId = event.dataTransfer.getData('application/x-defense-evidence');
      if (!recordId) return;
      const ids = csv(input.value);
      if (!ids.includes(recordId)) ids.push(recordId);
      input.value = ids.join(', ');
    });
  }

  function paragraphMarkup(paragraph, index) {
    const item = emptyParagraph(paragraph);
    return `<article class="v9-paragraph-card" data-paragraph-id="${escHtml(item.paragraph_id)}">
      <header><span>段落 ${String(index + 1).padStart(2, '0')}</span><button type="button" data-paragraph-remove aria-label="删除段落">删除</button></header>
      <label>小标题<input data-paragraph-field="heading" value="${escHtml(item.heading)}" placeholder="例如：核心判断"></label>
      <label>正文<textarea data-paragraph-field="text" placeholder="每项事实和判断均需关联证据">${escHtml(item.text)}</textarea></label>
      <div class="v9-paragraph-controls">
        <label>证据 ID<input class="v9-evidence-drop" data-paragraph-field="evidence" value="${escHtml((item.evidence_ids || []).join(', '))}" placeholder="从证据库拖入或粘贴 ID"></label>
        <label>主张 ID<input data-paragraph-field="claims" value="${escHtml((item.claim_ids || []).join(', '))}" placeholder="关联已建档主张 ID"></label>
        <label>来源状态<select data-paragraph-field="source_status">${Object.entries(sourceLabels).map(([value, label]) => `<option value="${value}" ${item.source_status === value ? 'selected' : ''}>${label}</option>`).join('')}</select></label>
        <label>事实核查<select data-paragraph-field="fact_check">${Object.entries(factLabels).map(([value, label]) => `<option value="${value}" ${item.fact_check === value ? 'selected' : ''}>${label}</option>`).join('')}</select></label>
      </div>
      <label>核查备注<input data-paragraph-field="fact_check_note" value="${escHtml(item.fact_check_note)}" placeholder="记录核查人、方法或待解决问题"></label>
    </article>`;
  }

  function renderParagraphs(paragraphs) {
    const list = document.getElementById('v9ParagraphList');
    if (!list) return;
    const values = paragraphs?.length ? paragraphs : [emptyParagraph()];
    list.innerHTML = values.map(paragraphMarkup).join('');
    list.querySelectorAll('.v9-evidence-drop').forEach(bindEvidenceDrop);
  }

  function collectParagraphs() {
    return [...document.querySelectorAll('#v9ParagraphList .v9-paragraph-card')].map(card => ({
      paragraph_id: card.dataset.paragraphId || undefined,
      heading: card.querySelector('[data-paragraph-field="heading"]').value,
      text: card.querySelector('[data-paragraph-field="text"]').value,
      evidence_ids: csv(card.querySelector('[data-paragraph-field="evidence"]').value),
      claim_ids: csv(card.querySelector('[data-paragraph-field="claims"]').value),
      source_status: card.querySelector('[data-paragraph-field="source_status"]').value,
      fact_check: card.querySelector('[data-paragraph-field="fact_check"]').value,
      fact_check_note: card.querySelector('[data-paragraph-field="fact_check_note"]').value
    }));
  }

  function renderValidation(validation, revision) {
    const target = document.getElementById('v9DocumentValidation');
    if (!target) return;
    if (!validation) {
      target.className = 'v9-document-validation';
      target.textContent = '保存后显示校验结果';
      return;
    }
    target.className = `v9-document-validation ${validation.ready ? 'ready' : 'blocked'}`;
    target.innerHTML = validation.ready
      ? `<strong>校验通过 · 可进入待签发</strong><span>V${revision} · ${validation.paragraph_count} 段 · ${validation.evidence_count} 条证据</span>`
      : `<strong>签发阻断 · ${validation.errors.length} 项</strong><ul>${validation.errors.map(error => `<li>${escHtml(error)}</li>`).join('')}</ul>`;
  }

  function renderDocumentList() {
    const list = document.getElementById('v9DocumentList');
    if (!list) return;
    if (!activeDocumentId && documentCache.length) activeDocumentId = documentCache[0].record_id;
    list.innerHTML = documentCache.map(item => {
      const content = item.content || {};
      const validation = content.validation || {};
      return `<button type="button" data-document-id="${escHtml(item.record_id)}" class="${item.record_id === activeDocumentId ? 'active' : ''}">
        <span>${content.kind === 'brief' ? '要讯' : '报告'} · V${item.version}</span>
        <strong>${escHtml(content.title || '未命名稿件')}</strong>
        <small>${escHtml(content.stage || 'outline')} · ${validation.ready ? '校验通过' : `${(validation.errors || []).length} 项待处理`}</small>
      </button>`;
    }).join('') || '<div class="v9-panel-loading">尚无 V9 稿件</div>';
  }

  function openDocument(recordId) {
    const selected = documentCache.find(item => item.record_id === recordId);
    const form = document.getElementById('v9DocumentForm');
    const empty = document.getElementById('v9DocumentEmpty');
    if (!selected || !form) return;
    activeDocumentId = selected.record_id;
    const content = selected.content || {};
    form.hidden = false;
    if (empty) empty.hidden = true;
    document.getElementById('v9DocumentId').value = selected.record_id;
    document.getElementById('v9DocumentVersion').value = selected.version;
    document.getElementById('v9DocumentTitle').value = content.title || '';
    document.getElementById('v9DocumentKind').value = content.kind || 'report';
    document.getElementById('v9DocumentStage').value = content.stage || 'outline';
    document.getElementById('v9DocumentOutline').value = content.outline || '';
    document.getElementById('v9RevisionNote').value = '';
    renderParagraphs(content.paragraphs || []);
    renderValidation(content.validation, content.revision);
    renderDocumentList();
  }

  function startNewDocument() {
    activeDocumentId = null;
    renderDocumentList();
    const form = document.getElementById('v9DocumentForm');
    const empty = document.getElementById('v9DocumentEmpty');
    form.hidden = false;
    if (empty) empty.hidden = true;
    form.reset();
    document.getElementById('v9DocumentId').value = '';
    document.getElementById('v9DocumentVersion').value = '';
    document.getElementById('v9DocumentKind').value = 'report';
    document.getElementById('v9DocumentStage').value = 'outline';
    renderParagraphs([emptyParagraph()]);
    renderValidation(null);
    document.getElementById('v9DocumentTitle').focus();
  }

  async function loadDocuments(selectId) {
    try {
      const data = await requestJson('/api/v9/documents');
      documentCache = data.documents || [];
      if (selectId) activeDocumentId = selectId;
      renderDocumentList();
      if (activeDocumentId) openDocument(activeDocumentId);
    } catch (error) {
      if (!error.toastShown) showToast(`稿件加载失败：${error.message}`);
    }
  }

  async function saveDocument(event) {
    event.preventDefault();
    const recordId = document.getElementById('v9DocumentId').value;
    const value = {
      title: document.getElementById('v9DocumentTitle').value,
      kind: document.getElementById('v9DocumentKind').value,
      stage: document.getElementById('v9DocumentStage').value,
      outline: document.getElementById('v9DocumentOutline').value,
      paragraphs: collectParagraphs()
    };
    try {
      let result;
      if (recordId) {
        result = await sendJson(`/api/v9/documents/${encodeURIComponent(recordId)}`, {
          version: Number(document.getElementById('v9DocumentVersion').value),
          changes: Object.assign(value, {
            revision_note: document.getElementById('v9RevisionNote').value
          })
        }, 'PATCH');
      } else {
        result = await sendJson('/api/v9/documents', value);
        maybeShowRecovery(result);
      }
      activeDocumentId = result.record_id || recordId;
      await loadDocuments(activeDocumentId);
      showToast('稿件已保存为密文修订版本');
    } catch (error) {
      if (!error.toastShown) showToast(`稿件保存失败：${error.message}`);
    }
  }

  async function sendToLayout() {
    const recordId = document.getElementById('v9DocumentId').value;
    if (!recordId) {
      showToast('请先保存稿件');
      return;
    }
    try {
      await sendJson('/api/v9/publications', {document_id: recordId});
      showToast('稿件已送入版面计划');
      showTab('delivery');
    } catch (error) {
      if (!error.toastShown) showToast(`送入版面失败：${error.message}`);
    }
  }

  async function exportCurrentDocument(format) {
    const recordId = document.getElementById('v9DocumentId').value;
    if (!recordId) return showToast('请先保存稿件');
    try {
      const response = await apiFetch(`/api/v9/documents/${encodeURIComponent(recordId)}/export.${format}`);
      await downloadResponseBlob(response, document.getElementById('v9DocumentTitle').value, `.${format}`);
      showToast(`已导出 ${format.toUpperCase()} 与来源索引`);
    } catch (error) {
      if (!error.toastShown) showToast(`导出失败：${error.message}`);
    }
  }

  function publicationCard(item) {
    const content = item.content || {};
    const validationText = content.status === 'signed'
      ? `不可变快照 · ${String(content.signed_snapshot?.receipt?.document_content_hash || '').slice(0, 12)}…`
      : `稿件 V${content.document_version || 1}`;
    let actions = '';
    if (content.status === 'evidence_needed') {
      actions = '<button data-publication-action="editing">退回编辑</button>';
    } else if (content.status === 'editing') {
      actions = '<button data-publication-action="pending_approval">提交终审</button>';
    } else if (content.status === 'pending_approval') {
      actions = '<button class="approve" data-publication-action="sign">核对来源并签发</button>';
    } else if (content.status === 'signed') {
      actions = '<button data-publication-export="docx">DOCX</button><button data-publication-export="pdf">PDF</button><button class="danger" data-publication-action="recall">撤回</button>';
    }
    return `<article class="v9-publication-card" data-publication-id="${escHtml(item.record_id)}" data-version="${item.version}">
      <span>${content.kind === 'brief' ? '要讯' : '报告'} · V${item.version}</span>
      <h3>${escHtml(content.title || '未命名稿件')}</h3>
      <p>${escHtml(validationText)}</p>
      <div>${actions}</div>
    </article>`;
  }

  function renderPublications() {
    const statuses = ['evidence_needed', 'editing', 'pending_approval', 'signed'];
    statuses.forEach(status => {
      const column = document.querySelector(`[data-publication-column="${status}"]`);
      if (!column) return;
      const items = publicationCache.filter(item => item.content?.status === status);
      column.querySelector('em').textContent = items.length;
      column.querySelector(':scope > div').innerHTML = items.map(publicationCard).join('') || '<p class="v9-board-empty">暂无稿件</p>';
    });
    const recalled = publicationCache.filter(item => item.content?.status === 'recalled');
    document.getElementById('v9RecalledList').innerHTML = recalled.map(item => {
      const content = item.content || {};
      return `<article><strong>${escHtml(content.title || '未命名')}</strong><span>${escHtml(content.recall_reason || '未记录原因')}</span><small>${escHtml(content.recalled_at || '')}</small></article>`;
    }).join('') || '暂无撤回记录';
    const counts = statuses.map(status => `${boardLabels[status]} ${publicationCache.filter(item => item.content?.status === status).length}`).join(' · ');
    document.getElementById('v9DeliverySummary').textContent = `${counts} · 已撤回 ${recalled.length}`;
  }

  function renderAudit() {
    const list = document.getElementById('v9AuditList');
    if (!list) return;
    list.innerHTML = auditCache.slice().reverse().map(item => {
      const content = item.content || {};
      return `<article><span>${escHtml(content.action || '')}</span><strong>${escHtml(content.target_id || '')}</strong><small>${escHtml(content.occurred_at || '')} · ${escHtml(content.actor_user_id || '')}</small></article>`;
    }).join('') || '暂无审计事件';
  }

  async function loadPublications() {
    try {
      const [publications, audits] = await Promise.all([
        requestJson('/api/v9/publications'),
        requestJson('/api/v9/audit-events')
      ]);
      publicationCache = publications.publications || [];
      auditCache = audits.events || [];
      renderPublications();
      renderAudit();
    } catch (error) {
      if (!error.toastShown) showToast(`版面加载失败：${error.message}`);
    }
  }

  async function publicationAction(card, action) {
    const recordId = card.dataset.publicationId;
    const version = Number(card.dataset.version);
    try {
      if (action === 'sign') {
        if (!window.confirm('确认已核对全部段落证据、来源状态和事实核查，并生成不可变签发版本？')) return;
        await sendJson(`/api/v9/publications/${encodeURIComponent(recordId)}/sign`, {version});
        showToast('签发完成：正文、来源索引与哈希已固化');
      } else if (action === 'recall') {
        const reason = window.prompt('撤回原因（将写入审计记录）：', '');
        if (!reason) return;
        await sendJson(`/api/v9/publications/${encodeURIComponent(recordId)}/recall`, {version, reason});
        showToast('签发版本已撤回；原不可变快照仍保留');
      } else {
        await sendJson(`/api/v9/publications/${encodeURIComponent(recordId)}`, {
          version,
          status: action
        }, 'PATCH');
        showToast(`版面已转入${boardLabels[action]}`);
      }
      await loadPublications();
    } catch (error) {
      if (!error.toastShown) showToast(`版面操作失败：${error.message}`);
    }
  }

  async function exportPublication(card, format) {
    try {
      const recordId = card.dataset.publicationId;
      const response = await apiFetch(`/api/v9/publications/${encodeURIComponent(recordId)}/export.${format}`);
      await downloadResponseBlob(response, card.querySelector('h3')?.textContent || '已签发稿件', `.${format}`);
      showToast(`已导出签发快照 ${format.toUpperCase()}`);
    } catch (error) {
      if (!error.toastShown) showToast(`签发导出失败：${error.message}`);
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('v9DocumentNew')?.addEventListener('click', startNewDocument);
    document.getElementById('v9DocumentRefresh')?.addEventListener('click', () => loadDocuments(activeDocumentId));
    document.getElementById('v9DocumentForm')?.addEventListener('submit', saveDocument);
    document.getElementById('v9ParagraphAdd')?.addEventListener('click', () => {
      const list = document.getElementById('v9ParagraphList');
      list.insertAdjacentHTML('beforeend', paragraphMarkup(emptyParagraph(), list.children.length));
      bindEvidenceDrop(list.lastElementChild.querySelector('.v9-evidence-drop'));
    });
    document.getElementById('v9ParagraphList')?.addEventListener('click', event => {
      if (!event.target.closest('[data-paragraph-remove]')) return;
      const card = event.target.closest('.v9-paragraph-card');
      if (document.querySelectorAll('.v9-paragraph-card').length === 1) {
        showToast('稿件至少保留一个段落');
        return;
      }
      card.remove();
    });
    document.getElementById('v9DocumentList')?.addEventListener('click', event => {
      const button = event.target.closest('[data-document-id]');
      if (button) openDocument(button.dataset.documentId);
    });
    document.getElementById('v9DocumentLayout')?.addEventListener('click', sendToLayout);
    document.querySelectorAll('[data-document-export]').forEach(button => {
      button.addEventListener('click', () => exportCurrentDocument(button.dataset.documentExport));
    });
    document.getElementById('v9PublicationRefresh')?.addEventListener('click', loadPublications);
    document.querySelector('.v9-p5-board')?.addEventListener('click', event => {
      const card = event.target.closest('.v9-publication-card');
      if (!card) return;
      const action = event.target.closest('[data-publication-action]')?.dataset.publicationAction;
      const format = event.target.closest('[data-publication-export]')?.dataset.publicationExport;
      if (action) publicationAction(card, action);
      if (format) exportPublication(card, format);
    });
  });

  window.loadV9Documents = loadDocuments;
  window.loadV9Publications = loadPublications;
})();
