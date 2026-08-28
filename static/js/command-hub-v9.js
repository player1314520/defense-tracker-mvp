/* Defense Command Hub · V9 shell interactions */
(function () {
  const ONBOARDING_KEY = 'defense_hub_v9_onboarded';
  let situationLoading = false;
  let evidenceCache = [];
  let alertRuleCache = [];

  function openOnboarding() {
    const el = document.getElementById('v9Onboarding');
    if (!el) return;
    el.hidden = false;
    document.body.classList.add('v9-modal-open');
    requestAnimationFrame(() => document.getElementById('v9StartBtn')?.focus({ preventScroll: true }));
  }

  function closeOnboarding(persist) {
    const el = document.getElementById('v9Onboarding');
    if (!el) return;
    el.hidden = true;
    document.body.classList.remove('v9-modal-open');
    if (persist) localStorage.setItem(ONBOARDING_KEY, '1');
  }

  function go(name) {
    if (typeof showTab === 'function') showTab(name);
    document.querySelector('.v9-stage')?.scrollIntoView({ block: 'start' });
  }

  function openSearch() {
    closeOnboarding(false);
    go('news');
    requestAnimationFrame(() => document.getElementById('newsSearch')?.focus());
  }

  function renderWire(items) {
    const track = document.getElementById('v9WireTrack');
    if (!track) return;
    if (!items?.length) {
      track.innerHTML = '<span>当前没有可追溯的高优先级新闻</span>';
      return;
    }
    track.innerHTML = items.map((item, index) => {
      const divider = index < items.length - 1 ? '<b>◆</b>' : '';
      const href = safeExternalUrl(item.url);
      return `<a href="${escHtml(href)}" target="_blank" rel="noopener noreferrer">` +
        `${escHtml(item.age_label)} · ${escHtml(item.title)}</a>${divider}`;
    }).join('');
  }

  function situationCard(region) {
    const ready = region.status === 'ready' && Number.isFinite(region.score);
    const score = ready ? String(region.score) : '—';
    const meter = ready ? Math.max(0, Math.min(100, region.score)) : 0;
    const evidenceLinks = (region.evidence || []).slice(0, 5).map(item => {
      const href = safeExternalUrl(item.url);
      return `<li><a href="${escHtml(href)}" target="_blank" rel="noopener noreferrer">` +
        `${escHtml(item.title)}</a><span>${escHtml(item.source)}</span></li>`;
    }).join('');
    const formula = region.formula || {};
    return `<article class="v9-risk-card ${escHtml(region.class_name || '')} ${ready ? '' : 'insufficient'}">
      <div class="v9-risk-title"><h2>${escHtml(region.name)}</h2><span>${escHtml(region.name_en)}</span></div>
      <div class="v9-risk-value"><strong>${score}</strong><small>${escHtml(region.label || '证据不足')}</small></div>
      <div class="v9-risk-meter"><i style="width:${meter}%"></i></div>
      <p>${escHtml(region.headline || '暂无可追溯信号')}</p>
      <div class="v9-risk-meta">${region.evidence_count || 0} 条证据 · ${region.source_count || 0} 个独立来源 · ${region.updated_at ? fmtDate(region.updated_at) : '未更新'}</div>
      <details class="v9-risk-trace">
        <summary>查看公式与证据链</summary>
        <div class="v9-formula">
          <span>${escHtml(formula.source_weight || '')}</span>
          <span>${escHtml(formula.time_decay || '')}</span>
          <span>${escHtml(formula.priority_factor || '')}</span>
          <span>${escHtml(formula.corroboration || '')}</span>
          <strong>${escHtml(formula.minimum_evidence || '')}</strong>
        </div>
        <ol>${evidenceLinks || '<li>暂无符合条件的证据</li>'}</ol>
      </details>
    </article>`;
  }

  async function loadSituation(force) {
    if (situationLoading) return;
    const grid = document.getElementById('v9RiskGrid');
    if (!grid) return;
    if (!force && grid.dataset.loaded === '1') return;
    situationLoading = true;
    try {
      const response = await apiFetch('/api/v9/situation');
      const data = await response.json();
      grid.innerHTML = (data.regions || []).map(situationCard).join('') ||
        '<div class="v9-panel-loading">当前没有可计算的区域信号。</div>';
      grid.dataset.loaded = '1';
      renderWire(data.wire || []);
    } catch (error) {
      grid.innerHTML = `<div class="v9-panel-loading error">态势计算失败：${escHtml(error.message)}</div>`;
    } finally {
      situationLoading = false;
    }
  }

  function renderEvidence(filterValue, focusIds) {
    const list = document.getElementById('v9EvidenceList');
    if (!list) return;
    const query = String(filterValue || '').trim().toLowerCase();
    const focused = new Set((focusIds || []).map(String));
    const filtered = evidenceCache.filter(item => {
      const content = item.content || {};
      if (focused.size) return focused.has(String(item.record_id));
      return !query || [content.title, content.source, content.summary]
        .some(value => String(value || '').toLowerCase().includes(query));
    });
    if (!filtered.length) {
      list.innerHTML = `<div class="v9-panel-loading">${query ? '没有匹配证据' : '尚未归档证据；可在实时新闻点击“归档证据”。'}</div>`;
      return;
    }
    list.innerHTML = filtered.map(item => {
      const content = item.content || {};
      const provenance = content.provenance || {};
      return `<article class="v9-evidence-card" draggable="true" data-evidence-id="${escHtml(item.record_id)}">
        <div class="v9-evidence-meta"><span>v${item.version}</span><span>${escHtml(content.citation_status || 'unreviewed')}</span><span>${item.updated_at ? fmtDate(item.updated_at) : ''}</span></div>
        <h2>${escHtml(content.title || '无标题证据')}</h2>
        <p>${escHtml(content.summary || '暂无摘要')}</p>
        <footer><span>${escHtml(content.source || provenance.source || '未知来源')}</span>
          <a href="${escHtml(safeExternalUrl(provenance.url))}" target="_blank" rel="noopener noreferrer">打开原文 ↗</a>
        </footer>
      </article>`;
    }).join('');
    list.querySelectorAll('[draggable="true"]').forEach(card => {
      card.addEventListener('dragstart', event => {
        event.dataTransfer.setData('application/x-defense-evidence', card.dataset.evidenceId);
        event.dataTransfer.effectAllowed = 'copy';
      });
    });
    if (focused.size) {
      list.querySelectorAll('.v9-evidence-card').forEach(card => {
        card.classList.add('focused');
      });
      list.querySelector('.v9-evidence-card')?.scrollIntoView({
        behavior: 'smooth',
        block: 'center'
      });
    }
  }

  async function loadEvidence() {
    const list = document.getElementById('v9EvidenceList');
    if (!list) return;
    try {
      const response = await apiFetch('/api/v9/evidence');
      const data = await response.json();
      evidenceCache = data.evidence || [];
      renderEvidence(document.getElementById('v9EvidenceSearch')?.value);
    } catch (error) {
      list.innerHTML = `<div class="v9-panel-loading error">证据库打开失败：${escHtml(error.message)}</div>`;
    }
  }

  async function focusEvidence(recordIds) {
    const ids = [...new Set((recordIds || []).map(String).filter(Boolean))];
    showTab('ai');
    const search = document.getElementById('v9EvidenceSearch');
    if (search) search.value = '';
    await loadEvidence();
    renderEvidence('', ids);
    if (!ids.length) showToast('该对象尚未关联证据');
  }

  async function archiveNewsEvidence(index, button) {
    const article = typeof allNews !== 'undefined' ? allNews[index] : null;
    if (!article || !button) return;
    const previous = button.textContent;
    button.disabled = true;
    button.textContent = '加密中…';
    try {
      const response = await apiFetch('/api/v9/evidence/archive-news', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({article})
      });
      const data = await response.json();
      button.textContent = data.created ? '已归档' : '已存在';
      button.classList.add('archived');
      if (data.recovery_code) {
        window.prompt('这是个人工作区恢复码，仅显示一次。请离线保存：', data.recovery_code);
      }
      evidenceCache = [];
      showToast(data.created ? '证据已加密归档' : '该证据已经归档');
    } catch (error) {
      button.textContent = previous;
      button.disabled = false;
      showToast(`归档失败：${error.message}`, 4000);
    }
  }

  function resetAlertRuleForm() {
    const form = document.getElementById('v9RuleForm');
    if (!form) return;
    form.reset();
    document.getElementById('v9RuleId').value = '';
    document.getElementById('v9RuleVersion').value = '';
    document.getElementById('v9RuleStars').value = '6';
    document.getElementById('v9RuleSeverity').value = 'medium';
    document.getElementById('v9RuleEnabled').checked = true;
  }

  function renderAlertRuleList() {
    const list = document.getElementById('v9RuleList');
    if (!list) return;
    if (!alertRuleCache.length) {
      list.innerHTML = '<div class="v9-panel-loading">尚未建立加密预警规则。</div>';
      return;
    }
    list.innerHTML = alertRuleCache.map(item => {
      const rule = item.content || {};
      return `<article class="v9-rule-row ${rule.enabled ? '' : 'off'}" data-rule-id="${escHtml(item.record_id)}">
        <h3>${escHtml(rule.name || '未命名规则')}</h3>
        <p>${(rule.keywords || []).map(escHtml).join(' · ')}${rule.sources?.length ? `　/　${rule.sources.map(escHtml).join(' · ')}` : ''}</p>
        <small>${escHtml(rule.severity || 'medium')} · ≥${Number(rule.min_stars || 0)}★ · v${item.version}</small>
        <div><button type="button" data-rule-action="toggle">${rule.enabled ? '停用' : '启用'}</button> <button type="button" data-rule-action="edit">编辑</button></div>
      </article>`;
    }).join('');
  }

  function renderAlertRhythm(data) {
    const rhythm = document.getElementById('v9RuleRhythm');
    const summary = document.getElementById('v9RuleSummary');
    if (!rhythm || !summary) return;
    const buckets = data.rhythm || [];
    const maxCount = Math.max(1, ...buckets.map(item => Number(item.count || 0)));
    rhythm.innerHTML = buckets.map(item => {
      const count = Number(item.count || 0);
      const height = count ? Math.max(14, Math.round(count / maxCount * 100)) : 4;
      const hour = new Date(item.hour).toLocaleTimeString('zh-CN', {hour: '2-digit', minute: '2-digit'});
      return `<i class="${count ? 'hot' : ''}" style="height:${height}%" title="${escHtml(hour)} · ${count} 次"></i>`;
    }).join('');
    const latest = (data.hits || [])[0];
    summary.textContent = `过去 24 小时 ${data.total_hits || 0} 次命中` +
      (latest ? ` · 最近：${latest.rule_name} / ${latest.title}` : ' · 暂无触发');
  }

  async function loadAlertRules() {
    const list = document.getElementById('v9RuleList');
    if (!list) return;
    try {
      const [rulesResponse, rhythmResponse] = await Promise.all([
        apiFetch('/api/v9/alert-rules'),
        apiFetch('/api/v9/alert-rules/evaluate')
      ]);
      const rulesData = await rulesResponse.json();
      alertRuleCache = rulesData.rules || [];
      renderAlertRuleList();
      renderAlertRhythm(await rhythmResponse.json());
    } catch (error) {
      list.innerHTML = `<div class="v9-panel-loading error">规则加载失败：${escHtml(error.message)}</div>`;
    }
  }

  function alertRulePayload(overrides) {
    return {
      record_id: document.getElementById('v9RuleId')?.value || undefined,
      version: Number(document.getElementById('v9RuleVersion')?.value || 0) || undefined,
      name: document.getElementById('v9RuleName')?.value || '',
      keywords: (document.getElementById('v9RuleKeywords')?.value || '').split(/[,，]/).map(value => value.trim()).filter(Boolean),
      min_stars: Number(document.getElementById('v9RuleStars')?.value || 0),
      severity: document.getElementById('v9RuleSeverity')?.value || 'medium',
      sources: (document.getElementById('v9RuleSources')?.value || '').split(/[,，]/).map(value => value.trim()).filter(Boolean),
      enabled: Boolean(document.getElementById('v9RuleEnabled')?.checked),
      ...(overrides || {})
    };
  }

  async function persistAlertRule(payload) {
    const response = await apiFetch('/api/v9/alert-rules', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    const result = await response.json();
    if (result.recovery_code) {
      window.prompt('这是个人工作区恢复码，仅显示一次。请离线保存：', result.recovery_code);
    }
    resetAlertRuleForm();
    await loadAlertRules();
    showToast(payload.record_id ? '预警规则已更新' : '预警规则已加密保存');
  }

  function editAlertRule(recordId) {
    const item = alertRuleCache.find(rule => rule.record_id === recordId);
    if (!item) return;
    const rule = item.content || {};
    document.getElementById('v9RuleId').value = item.record_id;
    document.getElementById('v9RuleVersion').value = item.version;
    document.getElementById('v9RuleName').value = rule.name || '';
    document.getElementById('v9RuleKeywords').value = (rule.keywords || []).join(', ');
    document.getElementById('v9RuleStars').value = Number(rule.min_stars || 0);
    document.getElementById('v9RuleSeverity').value = rule.severity || 'medium';
    document.getElementById('v9RuleSources').value = (rule.sources || []).join(', ');
    document.getElementById('v9RuleEnabled').checked = Boolean(rule.enabled);
    document.getElementById('v9RuleName').focus();
  }

  window.loadV9Situation = loadSituation;
  window.loadV9Evidence = loadEvidence;
  window.focusV9Evidence = focusEvidence;
  window.loadV9AlertRules = loadAlertRules;
  window.archiveNewsEvidence = archiveNewsEvidence;

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-v9-target]').forEach(function (button) {
      button.addEventListener('click', function () { go(button.dataset.v9Target); });
    });
    document.querySelectorAll('[data-v9-dismiss]').forEach(function (el) {
      el.addEventListener('click', function () { closeOnboarding(true); });
    });

    document.getElementById('v9HelpBtn')?.addEventListener('click', openOnboarding);
    document.getElementById('v9TourBtn')?.addEventListener('click', openOnboarding);
    document.getElementById('v9StartBtn')?.addEventListener('click', function () { closeOnboarding(true); });
    document.getElementById('v9FollowAlert')?.addEventListener('click', function () {
      closeOnboarding(true);
      go('tracking');
    });
    document.getElementById('v9SavedBtn')?.addEventListener('click', function () {
      go('tracking');
      setTimeout(function () {
        if (typeof trackingToggleFav === 'function') trackingToggleFav();
      }, 0);
    });
    document.getElementById('v9QueueBtn')?.addEventListener('click', function () { go('tracking'); });
    document.getElementById('v9SearchBtn')?.addEventListener('click', openSearch);
    document.getElementById('v9EvidenceSearch')?.addEventListener('input', function () {
      renderEvidence(this.value);
    });
    document.getElementById('v9RuleOpen')?.addEventListener('click', function () {
      document.getElementById('v9RuleEditor').hidden = false;
      loadAlertRules();
    });
    document.getElementById('v9RuleClose')?.addEventListener('click', function () {
      document.getElementById('v9RuleEditor').hidden = true;
    });
    document.getElementById('v9RuleReset')?.addEventListener('click', resetAlertRuleForm);
    document.getElementById('v9RuleForm')?.addEventListener('submit', async function (event) {
      event.preventDefault();
      try {
        await persistAlertRule(alertRulePayload());
      } catch (error) {
        if (!error.toastShown) showToast(`规则保存失败：${error.message}`, 4000);
      }
    });
    document.getElementById('v9RuleList')?.addEventListener('click', async function (event) {
      const button = event.target.closest('button[data-rule-action]');
      const row = button?.closest('[data-rule-id]');
      if (!button || !row) return;
      const item = alertRuleCache.find(rule => rule.record_id === row.dataset.ruleId);
      if (!item) return;
      if (button.dataset.ruleAction === 'edit') {
        editAlertRule(item.record_id);
        return;
      }
      try {
        await persistAlertRule({
          record_id: item.record_id,
          version: item.version,
          ...(item.content || {}),
          enabled: !item.content?.enabled
        });
      } catch (error) {
        if (!error.toastShown) showToast(`规则更新失败：${error.message}`, 4000);
      }
    });

    if (!localStorage.getItem(ONBOARDING_KEY)) openOnboarding();
    loadSituation(false);
  });

  document.addEventListener('keydown', function (event) {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      openSearch();
      return;
    }
    if (event.key === '?' && !/input|textarea|select/i.test(document.activeElement?.tagName || '')) {
      event.preventDefault();
      openOnboarding();
    }
    if (event.key === 'Escape' && !document.getElementById('v9Onboarding')?.hidden) {
      closeOnboarding(false);
    }
  });
})();
