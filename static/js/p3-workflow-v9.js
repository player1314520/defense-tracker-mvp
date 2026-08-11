/* V9 P3 · encrypted graph, offline geo, alert triage and case workspace */
(function () {
  let graphCache = {entities: [], relations: []};
  let alertCache = [];
  let caseCache = [];
  let activeCaseId = null;

  async function jsonRequest(url, init) {
    const response = await apiFetch(url, init);
    return response.json();
  }

  function csvIds(value) {
    return String(value || '').split(/[,，\s]+/).map(item => item.trim()).filter(Boolean);
  }

  function statusLabel(value) {
    return {fact: '已验证事实', source_claim: '来源声明', inference: '分析推断', scenario_assumption: '情景假设'}[value] || value || '未标注';
  }

  function maybeShowRecovery(data) {
    if (data?.recovery_code) {
      window.prompt('这是个人工作区恢复码，仅显示一次。请离线保存：', data.recovery_code);
    }
  }

  function focusEvidence(recordIds) {
    const ids = (recordIds || []).map(String).filter(Boolean);
    if (typeof window.focusV9Evidence === 'function') {
      window.focusV9Evidence(ids);
    } else {
      showTab('ai');
    }
  }

  function postJson(url, body, method) {
    return jsonRequest(url, {
      method: method || 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    });
  }

  function renderGraph() {
    const canvas = document.getElementById('v9GraphCanvas');
    const ledger = document.getElementById('v9GraphLedger');
    if (!canvas || !ledger) return;
    const entities = graphCache.entities || [];
    const hours = Number(document.getElementById('v9GraphHours')?.value || 120);
    const cutoff = Date.now() - hours * 3600000;
    const relations = (graphCache.relations || []).filter(item => {
      const occurred = Date.parse(item.content?.occurred_at || '');
      return !Number.isFinite(occurred) || occurred >= cutoff;
    });
    const positions = new Map();
    entities.forEach((item, index) => {
      const angle = (Math.PI * 2 * index / Math.max(entities.length, 1)) - Math.PI / 2;
      positions.set(item.record_id, {
        x: 450 + Math.cos(angle) * Math.min(310, 100 + entities.length * 24),
        y: 260 + Math.sin(angle) * Math.min(190, 80 + entities.length * 16)
      });
    });
    const lines = relations.map(item => {
      const relation = item.content || {};
      const from = positions.get(relation.subject_id);
      const to = positions.get(relation.object_id);
      if (!from || !to) return '';
      const css = relation.epistemic_status === 'source_claim' ? 'claim' : relation.epistemic_status;
      return `<g class="v9-graph-edge ${escHtml(css)}"><line x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}"></line><text x="${(from.x + to.x) / 2}" y="${(from.y + to.y) / 2}">${escHtml(relation.predicate)}</text></g>`;
    }).join('');
    const nodes = entities.map(item => {
      const entity = item.content || {};
      const pos = positions.get(item.record_id);
      const css = entity.epistemic_status === 'source_claim' ? 'claim' : entity.epistemic_status;
      return `<g class="v9-graph-node ${escHtml(css)}" tabindex="0" role="button" data-evidence-ids="${escHtml((entity.evidence_ids || []).join(','))}" data-entity-id="${escHtml(item.record_id)}"><circle cx="${pos.x}" cy="${pos.y}" r="34"></circle><text x="${pos.x}" y="${pos.y + 4}">${escHtml(entity.name)}</text><title>${escHtml(statusLabel(entity.epistemic_status))} · ${entity.evidence_ids?.length || 0} 条证据；点击回溯</title></g>`;
    }).join('');
    canvas.innerHTML = lines + nodes || '<text x="450" y="260" text-anchor="middle" class="v9-svg-empty">从证据创建第一个实体</text>';
    ledger.innerHTML = [
      ...entities.map(item => `<article tabindex="0" role="button" data-evidence-ids="${escHtml((item.content?.evidence_ids || []).join(','))}"><strong>${escHtml(item.content?.name || '实体')}</strong><span class="${escHtml(item.content?.epistemic_status || '')}">${escHtml(statusLabel(item.content?.epistemic_status))}</span><small>${item.content?.evidence_ids?.length || 0} 条证据 · v${item.version}</small></article>`),
      ...relations.map(item => `<article tabindex="0" role="button" data-evidence-ids="${escHtml((item.content?.evidence_ids || []).join(','))}"><strong>${escHtml(item.content?.predicate || '关系')}</strong><span class="${escHtml(item.content?.epistemic_status || '')}">${escHtml(statusLabel(item.content?.epistemic_status))}</span><small>${item.content?.evidence_ids?.length || 0} 条证据 · v${item.version}</small></article>`)
    ].join('') || '<div class="v9-panel-loading">尚无实体与关系</div>';
    const options = entities.map(item => `<option value="${escHtml(item.record_id)}">${escHtml(item.content?.name || item.record_id)}</option>`).join('');
    ['v9RelationFrom', 'v9RelationTo'].forEach(id => {
      const select = document.getElementById(id);
      if (select) select.innerHTML = options;
    });
  }

  async function loadGraph() {
    try {
      graphCache = await jsonRequest('/api/v9/graph');
      renderGraph();
    } catch (error) {
      const ledger = document.getElementById('v9GraphLedger');
      if (ledger) ledger.innerHTML = `<div class="v9-panel-loading error">${escHtml(error.message)}</div>`;
    }
  }

  async function saveEntity(event) {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      const result = await postJson('/api/v9/graph/entities', {
        name: document.getElementById('v9EntityName').value,
        kind: document.getElementById('v9EntityKind').value,
        epistemic_status: document.getElementById('v9EntityStatus').value,
        evidence_ids: csvIds(document.getElementById('v9EntityEvidence').value)
      });
      maybeShowRecovery(result);
      form.reset();
      form.hidden = true;
      await loadGraph();
      showToast('实体已加密保存');
    } catch (error) {
      if (!error.toastShown) showToast(`实体保存失败：${error.message}`);
    }
  }

  async function saveRelation(event) {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      const result = await postJson('/api/v9/graph/relations', {
        subject_id: document.getElementById('v9RelationFrom').value,
        object_id: document.getElementById('v9RelationTo').value,
        predicate: document.getElementById('v9RelationPredicate').value,
        epistemic_status: document.getElementById('v9RelationStatus').value,
        evidence_ids: csvIds(document.getElementById('v9RelationEvidence').value)
      });
      maybeShowRecovery(result);
      form.reset();
      form.hidden = true;
      await loadGraph();
      showToast('关系已加密保存');
    } catch (error) {
      if (!error.toastShown) showToast(`关系保存失败：${error.message}`);
    }
  }

  function renderGeo(events) {
    const markers = document.getElementById('v9GeoMarkers');
    const list = document.getElementById('v9GeoList');
    if (!markers || !list) return;
    markers.innerHTML = events.map(item => {
      const event = item.content || {};
      const left = (Number(event.longitude) + 180) / 360 * 100;
      const top = (90 - Number(event.latitude)) / 180 * 100;
      const css = event.epistemic_status === 'source_claim' ? 'claim' : event.epistemic_status;
      const layer = event.case_id ? 'case' : event.alert_id ? 'alert' : event.entity_ids?.length ? 'entity' : 'event';
      return `<button class="v9-map-marker ${escHtml(css)}" data-geo-layer="${layer}" data-evidence-ids="${escHtml((event.evidence_ids || []).join(','))}" data-case-id="${escHtml(event.case_id || '')}" style="left:${left}%;top:${top}%" title="${escHtml(event.title)} · ${escHtml(statusLabel(event.epistemic_status))}；点击打开证据或案件"></button>`;
    }).join('');
    list.innerHTML = events.map(item => {
      const event = item.content || {};
      const layer = event.case_id ? 'case' : event.alert_id ? 'alert' : event.entity_ids?.length ? 'entity' : 'event';
      return `<article data-geo-layer="${layer}"><strong>${escHtml(event.title)}</strong><span class="${escHtml(event.epistemic_status || '')}">${escHtml(statusLabel(event.epistemic_status))}</span><small>${Number(event.latitude).toFixed(2)}, ${Number(event.longitude).toFixed(2)} · ${event.evidence_ids?.length || 0} 条证据</small></article>`;
    }).join('') || '<div class="v9-panel-loading">当前时间窗没有地理事件</div>';
    applyGeoLayers();
  }

  function applyGeoLayers() {
    const enabled = new Set(
      [...document.querySelectorAll('.v9-layer-switch input:checked')]
        .map(input => input.value)
    );
    document.querySelectorAll('[data-geo-layer]').forEach(element => {
      element.hidden = !enabled.has(element.dataset.geoLayer);
    });
  }

  async function loadGeo() {
    const hours = Number(document.getElementById('v9GeoHours')?.value || 120);
    try {
      const data = await jsonRequest(`/api/v9/geo-events?hours=${hours}`);
      renderGeo(data.events || []);
    } catch (error) {
      const list = document.getElementById('v9GeoList');
      if (list) list.innerHTML = `<div class="v9-panel-loading error">${escHtml(error.message)}</div>`;
    }
  }

  async function saveGeo(event) {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      const result = await postJson('/api/v9/geo-events', {
        title: document.getElementById('v9GeoEventTitle').value,
        latitude: Number(document.getElementById('v9GeoLat').value),
        longitude: Number(document.getElementById('v9GeoLon').value),
        epistemic_status: document.getElementById('v9GeoStatus').value,
        evidence_ids: csvIds(document.getElementById('v9GeoEvidence').value),
        entity_ids: csvIds(document.getElementById('v9GeoEntities').value),
        alert_id: document.getElementById('v9GeoAlert').value.trim(),
        case_id: document.getElementById('v9GeoCase').value.trim()
      });
      maybeShowRecovery(result);
      form.reset();
      form.hidden = true;
      await loadGeo();
      showToast('地理事件已加密保存');
    } catch (error) {
      if (!error.toastShown) showToast(`事件保存失败：${error.message}`);
    }
  }

  function renderAlerts() {
    const list = document.getElementById('v9AlertList');
    if (!list) return;
    const active = alertCache.filter(item => !['closed', 'converted'].includes(item.content?.status));
    document.getElementById('v9AlertOpenCount').textContent = active.length;
    document.getElementById('v9AlertEscalatedCount').textContent = alertCache.filter(item => item.content?.status === 'escalated').length;
    document.getElementById('v9AlertCaseCount').textContent = alertCache.filter(item => item.content?.case_id).length;
    document.getElementById('v9AlertNavBadge').textContent = active.length;
    const overviewAlert = document.getElementById('v9OverviewAlertText');
    if (overviewAlert) overviewAlert.textContent = active.length ? `告警 ${active.length} 待处理` : '告警队列暂无待处理项';
    list.innerHTML = alertCache.map(item => {
      const alert = item.content || {};
      return `<article class="v9-alert-card severity-${escHtml(alert.severity || 'medium')}">
        <div><span>${escHtml(alert.severity || 'medium')}</span><span>${escHtml(alert.status || 'new')}</span><span>v${item.version}</span></div>
        <h2>${escHtml(alert.title || '未命名告警')}</h2>
        <p>${escHtml(alert.rule_name || '')} · ${escHtml(alert.source || '')} · ${alert.evidence_ids?.length || 0} 条证据</p>
        <footer data-alert-id="${escHtml(item.record_id)}"><button data-action="claim">认领</button><button data-action="snooze">静默</button><button data-action="escalate">升级</button><button data-action="convert_case">转案件</button><button data-action="close">关闭</button></footer>
      </article>`;
    }).join('') || '<div class="v9-panel-loading">尚无告警；运行规则扫描后显示。</div>';
  }

  async function loadAlerts() {
    try {
      const data = await jsonRequest('/api/v9/alerts');
      alertCache = data.alerts || [];
      renderAlerts();
    } catch (error) {
      const list = document.getElementById('v9AlertList');
      if (list) list.innerHTML = `<div class="v9-panel-loading error">${escHtml(error.message)}</div>`;
    }
  }

  async function materializeAlerts() {
    try {
      const data = await postJson('/api/v9/alerts/materialize', {});
      maybeShowRecovery(data);
      await loadAlerts();
      showToast(`规则扫描完成：新增 ${data.created || 0} 条告警`);
    } catch (error) {
      if (!error.toastShown) showToast(`规则扫描失败：${error.message}`);
    }
  }

  async function alertAction(recordId, action) {
    const item = alertCache.find(alert => alert.record_id === recordId);
    if (!item) return;
    const payload = {action, version: item.version};
    if (action === 'snooze') payload.until = new Date(Date.now() + 3600000).toISOString();
    if (action === 'close') payload.resolution = '人工关闭';
    try {
      const result = await postJson(`/api/v9/alerts/${encodeURIComponent(recordId)}/action`, payload);
      await loadAlerts();
      if (result.case_id) {
        activeCaseId = result.case_id;
        showToast('告警已转为案件，完整证据链已复制');
      } else {
        showToast('告警状态已更新');
      }
    } catch (error) {
      if (!error.toastShown) showToast(`分诊失败：${error.message}`);
    }
  }

  function renderCases() {
    const list = document.getElementById('v9CaseList');
    const detail = document.getElementById('v9CaseDetail');
    if (!list || !detail) return;
    list.innerHTML = caseCache.map(item => `<button type="button" data-case-id="${escHtml(item.record_id)}" class="${item.record_id === activeCaseId ? 'active' : ''}"><strong>${escHtml(item.content?.title || '未命名案件')}</strong><span>${escHtml(item.content?.status || 'open')} · v${item.version}</span></button>`).join('') || '<div class="v9-panel-loading">尚无案件；可从告警一键转入。</div>';
    const selected = caseCache.find(item => item.record_id === activeCaseId) || caseCache[0];
    if (!selected) {
      detail.innerHTML = '<div class="v9-panel-loading">选择一个案件查看证据时间线。</div>';
      document.getElementById('v9CaseConclusionForm').hidden = true;
      return;
    }
    activeCaseId = selected.record_id;
    const value = selected.content || {};
    const overviewCase = document.getElementById('v9OverviewCaseText');
    if (overviewCase) overviewCase.textContent = `案件更新　${value.title || '未命名案件'}`;
    detail.innerHTML = `<header><span>${escHtml(value.status || 'open')} · v${selected.version}</span><h2>${escHtml(value.title || '案件')}</h2></header>
      <div class="v9-case-metrics"><span>证据 <b>${value.evidence_ids?.length || 0}</b></span><span>假设 <b>${value.hypotheses?.length || 0}</b></span><span>任务 <b>${value.tasks?.length || 0}</b></span><span>矛盾证据 <b>${value.contradictory_evidence_ids?.length || 0}</b></span></div>
      <section><h3>证据链</h3><p>${(value.evidence_ids || []).map(escHtml).join('<br>') || '无'}</p></section>
      <section><h3>分析结论</h3>${(value.conclusions || []).map(item => `<article><p>${escHtml(item.text)}</p><small>${escHtml(statusLabel(item.epistemic_status))} · ${item.confidence_status === 'evidence_insufficient' ? '证据不足' : `置信度 ${Math.round(Number(item.confidence) * 100)}%`} · 引用 ${(item.evidence_ids || []).length} 条证据 · 反证 ${(item.counter_evidence_ids || []).length} 条</small></article>`).join('') || '<p>尚无结论；所有结论必须引用证据。</p>'}</section>`;
    const form = document.getElementById('v9CaseConclusionForm');
    form.hidden = value.status === 'issued';
    form.dataset.caseId = selected.record_id;
    form.dataset.version = selected.version;
  }

  async function loadCases() {
    try {
      const data = await jsonRequest('/api/v9/cases');
      caseCache = data.cases || [];
      renderCases();
    } catch (error) {
      const list = document.getElementById('v9CaseList');
      if (list) list.innerHTML = `<div class="v9-panel-loading error">${escHtml(error.message)}</div>`;
    }
  }

  async function saveCaseConclusion(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const selected = caseCache.find(item => item.record_id === form.dataset.caseId);
    if (!selected) return;
    const hypothesis = document.getElementById('v9CaseHypothesis').value.trim();
    const task = document.getElementById('v9CaseTask').value.trim();
    const counterEvidence = csvIds(document.getElementById('v9CaseContradiction').value);
    const conclusions = [...(selected.content?.conclusions || []), {
      text: document.getElementById('v9CaseConclusion').value,
      epistemic_status: document.getElementById('v9CaseConclusionStatus').value,
      evidence_ids: csvIds(document.getElementById('v9CaseConclusionEvidence').value),
      counter_evidence_ids: counterEvidence,
      confidence: Number(document.getElementById('v9CaseConfidence').value)
    }];
    const hypotheses = [...(selected.content?.hypotheses || [])];
    const tasks = [...(selected.content?.tasks || [])];
    if (hypothesis) hypotheses.push({text: hypothesis, state: 'open'});
    if (task) tasks.push({text: task, state: 'open'});
    const contradictory = [...new Set([
      ...(selected.content?.contradictory_evidence_ids || []),
      ...counterEvidence
    ])];
    const timeline = [...(selected.content?.timeline || []), {
      kind: 'analysis_updated',
      at: new Date().toISOString()
    }];
    try {
      await postJson(`/api/v9/cases/${encodeURIComponent(selected.record_id)}`, {
        version: selected.version,
        changes: {
          conclusions,
          hypotheses,
          tasks,
          contradictory_evidence_ids: contradictory,
          timeline
        }
      }, 'PATCH');
      form.reset();
      await loadCases();
      showToast('案件结论已保存为新版本');
    } catch (error) {
      if (!error.toastShown) showToast(`结论保存失败：${error.message}`);
    }
  }

  function bindEvidenceDrops() {
    document.querySelectorAll('.v9-evidence-drop').forEach(input => {
      input.addEventListener('dragover', event => {
        event.preventDefault();
        event.dataTransfer.dropEffect = 'copy';
      });
      input.addEventListener('drop', event => {
        event.preventDefault();
        const recordId = event.dataTransfer.getData('application/x-defense-evidence');
        if (!recordId) return;
        const ids = csvIds(input.value);
        if (!ids.includes(recordId)) ids.push(recordId);
        input.value = ids.join(', ');
      });
    });
  }

  function bindReplay(sliderId, labelId, loader) {
    const slider = document.getElementById(sliderId);
    const label = document.getElementById(labelId);
    slider?.addEventListener('input', () => {
      label.textContent = `${slider.value}h`;
      loader();
    });
  }

  function bindPlay(buttonId, sliderId, labelId, loader) {
    const button = document.getElementById(buttonId);
    const slider = document.getElementById(sliderId);
    const label = document.getElementById(labelId);
    let timer = null;
    button?.addEventListener('click', () => {
      if (timer) {
        clearInterval(timer);
        timer = null;
        button.textContent = '▶ 播放';
        return;
      }
      slider.value = 1;
      button.textContent = '■ 停止';
      timer = setInterval(() => {
        slider.value = Math.min(120, Number(slider.value) + 4);
        label.textContent = `${slider.value}h`;
        loader();
        if (Number(slider.value) >= 120) {
          clearInterval(timer);
          timer = null;
          button.textContent = '▶ 播放';
        }
      }, 180);
    });
  }

  window.loadV9Graph = loadGraph;
  window.loadV9Geo = loadGeo;
  window.loadV9Alerts = loadAlerts;
  window.loadV9Cases = loadCases;
  window.openV9Case = function (caseId) {
    activeCaseId = String(caseId || '');
    showTab('agent');
  };

  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('v9GraphEntityNew')?.addEventListener('click', () => { document.getElementById('v9EntityForm').hidden = false; });
    document.getElementById('v9GraphRelationNew')?.addEventListener('click', () => { document.getElementById('v9RelationForm').hidden = false; });
    document.getElementById('v9EntityForm')?.addEventListener('submit', saveEntity);
    document.getElementById('v9RelationForm')?.addEventListener('submit', saveRelation);
    const graphOpenEvidence = event => {
      const target = event.target.closest('[data-evidence-ids]');
      if (!target || (event.type === 'keydown' && !['Enter', ' '].includes(event.key))) return;
      event.preventDefault();
      focusEvidence(csvIds(target.dataset.evidenceIds));
    };
    document.getElementById('v9GraphCanvas')?.addEventListener('click', graphOpenEvidence);
    document.getElementById('v9GraphCanvas')?.addEventListener('keydown', graphOpenEvidence);
    document.getElementById('v9GraphLedger')?.addEventListener('click', graphOpenEvidence);
    document.getElementById('v9GraphLedger')?.addEventListener('keydown', graphOpenEvidence);
    document.getElementById('v9GeoNew')?.addEventListener('click', () => { document.getElementById('v9GeoForm').hidden = false; });
    document.getElementById('v9GeoForm')?.addEventListener('submit', saveGeo);
    document.getElementById('v9GeoMarkers')?.addEventListener('click', event => {
      const marker = event.target.closest('.v9-map-marker');
      if (!marker) return;
      if (marker.dataset.caseId) window.openV9Case(marker.dataset.caseId);
      else focusEvidence(csvIds(marker.dataset.evidenceIds));
    });
    document.getElementById('v9AlertMaterialize')?.addEventListener('click', materializeAlerts);
    document.getElementById('v9AlertList')?.addEventListener('click', event => {
      const button = event.target.closest('button[data-action]');
      const footer = button?.closest('[data-alert-id]');
      if (button && footer) alertAction(footer.dataset.alertId, button.dataset.action);
    });
    document.getElementById('v9CaseList')?.addEventListener('click', event => {
      const button = event.target.closest('[data-case-id]');
      if (!button) return;
      activeCaseId = button.dataset.caseId;
      renderCases();
    });
    document.getElementById('v9CaseConclusionForm')?.addEventListener('submit', saveCaseConclusion);
    bindEvidenceDrops();
    bindReplay('v9GraphHours', 'v9GraphHoursLabel', renderGraph);
    bindReplay('v9GeoHours', 'v9GeoHoursLabel', loadGeo);
    bindPlay('v9GraphPlay', 'v9GraphHours', 'v9GraphHoursLabel', renderGraph);
    bindPlay('v9GeoPlay', 'v9GeoHours', 'v9GeoHoursLabel', loadGeo);
    document.querySelectorAll('.v9-layer-switch input').forEach(input => {
      input.addEventListener('change', applyGeoLayers);
    });
  });
})();
