/* V9 P4 · local recoverable agent jobs and evidence-bound scenarios */
(function () {
  let jobCache = [];
  let scenarioCache = [];
  let activeJobId = null;
  let activeScenarioId = null;

  const phaseLabels = {
    collect: '搜集',
    close_read: '精读',
    outline: '构架',
    draft: '成稿',
    verify: '校验'
  };
  const stateLabels = {
    queued: '排队',
    running: '运行中',
    waiting_user: '等待人工',
    succeeded: '已完成',
    failed: '失败',
    cancelled: '已取消'
  };
  const branchLabels = {
    baseline: '基准',
    escalation: '升级',
    deescalation: '缓和'
  };
  const teamLabels = {red: '红队', blue: '蓝队', judge: '裁判'};

  function csv(value) {
    return String(value || '').split(/[,，\n]+/).map(item => item.trim()).filter(Boolean);
  }

  async function jsonRequest(url, init) {
    const response = await apiFetch(url, init);
    return response.json();
  }

  function sendJson(url, body, method) {
    return jsonRequest(url, {
      method: method || 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    });
  }

  function maybeShowRecovery(data) {
    if (data?.recovery_code) {
      window.prompt('这是个人工作区恢复码，仅显示一次。请离线保存：', data.recovery_code);
    }
  }

  function renderJobList() {
    const list = document.getElementById('v9JobList');
    if (!list) return;
    if (!activeJobId && jobCache.length) activeJobId = jobCache[0].record_id;
    list.innerHTML = jobCache.map(item => {
      const job = item.content || {};
      const progress = Math.max(0, Math.min(100, Number(job.progress || 0)));
      return `<button type="button" data-job-id="${escHtml(item.record_id)}" class="${item.record_id === activeJobId ? 'active' : ''}">
        <span>${escHtml(job.template_name || job.template || '任务')} · V${item.version}</span>
        <strong>${escHtml(job.title || '未命名任务')}</strong>
        <small>${escHtml(stateLabels[job.state] || job.state)} · ${escHtml(phaseLabels[job.phase] || job.phase)}</small>
        <i><b style="width:${progress}%"></b></i>
      </button>`;
    }).join('') || '<div class="v9-panel-loading">尚无本地智能体任务</div>';
  }

  function jobActions(job) {
    if (job.state === 'queued') {
      return '<button data-job-action="start">开始本地执行</button><button data-job-action="cancel">取消</button>';
    }
    if (job.state === 'running') {
      return '<button data-job-action="execute_phase">AI 执行本阶段</button><button data-job-action="advance">保存人工输出并推进</button><button data-job-action="fail">标记中断</button><button data-job-action="cancel">取消</button>';
    }
    if (job.state === 'waiting_user' && job.gate === 'outline') {
      return '<button data-job-action="approve_outline">批准大纲并成稿</button><button data-job-action="cancel">取消</button>';
    }
    if (job.state === 'waiting_user' && job.gate === 'release') {
      return '<button data-job-action="approve_release">人工确认完成</button><button data-job-action="cancel">取消</button>';
    }
    if (job.state === 'failed') {
      return '<button data-job-action="resume">从失败阶段恢复</button>';
    }
    return '';
  }

  function renderJobDetail() {
    const detail = document.getElementById('v9JobDetail');
    if (!detail) return;
    const selected = jobCache.find(item => item.record_id === activeJobId) || jobCache[0];
    if (!selected) {
      detail.innerHTML = '<div class="v9-panel-loading">选择任务查看阶段与人工闸门。</div>';
      return;
    }
    activeJobId = selected.record_id;
    const job = selected.content || {};
    const phases = ['collect', 'close_read', 'outline', 'draft', 'verify'];
    const currentIndex = phases.indexOf(job.phase);
    const error = job.error
      ? `<div class="v9-job-error"><strong>${escHtml(job.error.type)}</strong><p>${escHtml(job.error.message)}</p></div>`
      : '';
    detail.innerHTML = `<header><span>${escHtml(job.template_name || '')} · V${selected.version}</span><h2>${escHtml(job.title || '任务')}</h2><p>${escHtml(job.instructions || '未设置额外任务要求')}</p></header>
      <div class="v9-job-scope">LOCAL ONLY · 已解锁桌面执行 · 云端仅同步密文状态</div>
      <ol class="v9-job-phases">${phases.map((phase, index) => `<li class="${index < currentIndex ? 'done' : index === currentIndex ? 'active' : ''}"><b>${String(index + 1).padStart(2, '0')}</b><span>${escHtml(phaseLabels[phase])}</span></li>`).join('')}</ol>
      <div class="v9-job-gate ${job.state === 'waiting_user' ? 'waiting' : ''}"><span>状态</span><strong>${escHtml(stateLabels[job.state] || job.state)}</strong><small>${job.gate === 'outline' ? '大纲人工闸门：确认后才进入成稿' : job.gate === 'release' ? '签发前人工闸门：确认后才标记完成' : '任务可安全中断；失败阶段可恢复'}</small></div>
      ${error}
      ${job.state === 'running' ? '<label class="v9-stage-output">本阶段本地输出（可选）<textarea id="v9JobStageOutput" placeholder="保存在该阶段的加密输出"></textarea></label>' : ''}
      <footer class="v9-job-actions" data-job-id="${escHtml(selected.record_id)}">${jobActions(job)}</footer>`;
    if (job.state === 'running') {
      const output = job.stage_outputs?.[job.phase] || '';
      document.getElementById('v9JobStageOutput').value = output;
    }
  }

  function renderJobs() {
    renderJobList();
    renderJobDetail();
  }

  async function loadJobs() {
    try {
      const data = await jsonRequest('/api/v9/jobs');
      jobCache = data.jobs || [];
      renderJobs();
    } catch (error) {
      const list = document.getElementById('v9JobList');
      if (list) list.innerHTML = `<div class="v9-panel-loading error">${escHtml(error.message)}</div>`;
    }
  }

  async function createJob(event) {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      const data = await sendJson('/api/v9/jobs', {
        template: document.getElementById('v9JobTemplate').value,
        title: document.getElementById('v9JobTitle').value,
        instructions: document.getElementById('v9JobInstructions').value,
        evidence_ids: csv(document.getElementById('v9JobEvidence').value)
      });
      maybeShowRecovery(data);
      activeJobId = data.record_id;
      form.reset();
      form.hidden = true;
      await loadJobs();
      showToast('本地智能体任务已加密入队');
    } catch (error) {
      if (!error.toastShown) showToast(`任务创建失败：${error.message}`);
    }
  }

  async function controlJob(recordId, action) {
    const item = jobCache.find(job => job.record_id === recordId);
    if (!item) return;
    const body = {action, version: item.version};
    if (action === 'advance') {
      body.output = document.getElementById('v9JobStageOutput')?.value || '';
    }
    if (action === 'fail') {
      body.error_type = 'interrupted';
      body.message = '任务在本地阶段被人工标记为中断';
    }
    try {
      await sendJson(`/api/v9/jobs/${encodeURIComponent(recordId)}/action`, body);
      await loadJobs();
      showToast(action.startsWith('approve_') ? '人工闸门已确认' : '任务状态已更新');
    } catch (error) {
      await loadJobs();
      if (!error.toastShown) showToast(`任务操作失败：${error.message}`);
    }
  }

  function renderScenarioList() {
    const list = document.getElementById('v9ScenarioList');
    if (!list) return;
    if (!activeScenarioId && scenarioCache.length) activeScenarioId = scenarioCache[0].record_id;
    list.innerHTML = scenarioCache.map(item => `<button type="button" data-scenario-id="${escHtml(item.record_id)}" class="${item.record_id === activeScenarioId ? 'active' : ''}">
      <span>推演/推断 · V${item.version}</span><strong>${escHtml(item.content?.title || '未命名推演')}</strong><small>${item.content?.evidence_ids?.length || 0} 条基础证据</small>
    </button>`).join('') || '<div class="v9-panel-loading">尚无情景推演</div>';
  }

  function setBranchForm(branch, value) {
    const fieldset = document.querySelector(`#v9BranchEditors [data-branch="${branch}"]`);
    if (!fieldset) return;
    fieldset.querySelector('[data-field="summary"]').value = value.summary || '';
    fieldset.querySelector('[data-field="triggers"]').value = (value.triggers || []).join(', ');
    fieldset.querySelector('[data-field="indicators"]').value = (value.indicators || []).join(', ');
    fieldset.querySelector('[data-field="counter"]').value = (value.counter_evidence_ids || []).join(', ');
    fieldset.querySelector('[data-field="confidence"]').value = Number(value.confidence || 0);
  }

  function setTeamForm(team, value) {
    const fieldset = document.querySelector(`.v9-team-editor [data-team="${team}"]`);
    if (!fieldset) return;
    fieldset.querySelector('[data-field="text"]').value = value.text || '';
    fieldset.querySelector('[data-field="evidence"]').value = (value.evidence_ids || []).join(', ');
  }

  function renderScenarioDetail() {
    const detail = document.getElementById('v9ScenarioDetail');
    const form = document.getElementById('v9ScenarioEditForm');
    if (!detail || !form) return;
    const selected = scenarioCache.find(item => item.record_id === activeScenarioId) || scenarioCache[0];
    if (!selected) {
      detail.innerHTML = '<div class="v9-panel-loading">选择推演查看三分支。</div>';
      form.hidden = true;
      return;
    }
    activeScenarioId = selected.record_id;
    const value = selected.content || {};
    detail.innerHTML = `<header><span>SCENARIO / INFERENCE · V${selected.version}</span><h2>${escHtml(value.title || '推演')}</h2><p>${escHtml(value.question || '')}</p></header>
      <div class="v9-scenario-evidence">基础证据 ${(value.evidence_ids || []).map(escHtml).join(' · ')}</div>
      <div class="v9-scenario-branches">${['baseline', 'escalation', 'deescalation'].map(branch => {
        const item = value.branches?.[branch] || {};
        return `<article class="${branch}"><span>${escHtml(branchLabels[branch])} · 推演</span><strong>${escHtml(item.summary || '尚未形成分支摘要')}</strong><p>触发器：${escHtml((item.triggers || []).join('；') || '待补充')}</p><p>观察指标：${escHtml((item.indicators || []).join('；') || '待补充')}</p><small>置信度 ${Math.round(Number(item.confidence || 0) * 100)}% · 反证 ${(item.counter_evidence_ids || []).length} 条</small></article>`;
      }).join('')}</div>
      <div class="v9-team-outputs">${['red', 'blue', 'judge'].map(team => {
        const item = value.team_outputs?.[team] || {};
        return `<article><span>${escHtml(teamLabels[team])}输出 · 推演/推断</span><p>${escHtml(item.text || '尚无输出')}</p><small>引用 ${(item.evidence_ids || []).length} 条证据</small></article>`;
      }).join('')}</div>`;
    form.hidden = false;
    form.dataset.scenarioId = selected.record_id;
    form.dataset.version = selected.version;
    document.getElementById('v9ScenarioEditAssumptions').value = (value.assumptions || []).join(', ');
    document.getElementById('v9ScenarioObservables').value = (value.observables || []).join(', ');
    ['baseline', 'escalation', 'deescalation'].forEach(branch => setBranchForm(branch, value.branches?.[branch] || {}));
    ['red', 'blue', 'judge'].forEach(team => setTeamForm(team, value.team_outputs?.[team] || {}));
  }

  function renderScenarios() {
    renderScenarioList();
    renderScenarioDetail();
  }

  async function loadScenarios() {
    try {
      const data = await jsonRequest('/api/v9/scenarios');
      scenarioCache = data.scenarios || [];
      renderScenarios();
    } catch (error) {
      const list = document.getElementById('v9ScenarioList');
      if (list) list.innerHTML = `<div class="v9-panel-loading error">${escHtml(error.message)}</div>`;
    }
  }

  async function createScenario(event) {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      const data = await sendJson('/api/v9/scenarios', {
        title: document.getElementById('v9ScenarioTitle').value,
        question: document.getElementById('v9ScenarioQuestion').value,
        evidence_ids: csv(document.getElementById('v9ScenarioEvidence').value),
        assumptions: csv(document.getElementById('v9ScenarioAssumptions').value)
      });
      maybeShowRecovery(data);
      activeScenarioId = data.record_id;
      form.reset();
      form.hidden = true;
      await loadScenarios();
      showToast('三分支推演已加密创建');
    } catch (error) {
      if (!error.toastShown) showToast(`推演创建失败：${error.message}`);
    }
  }

  function branchPayload(branch) {
    const fieldset = document.querySelector(`#v9BranchEditors [data-branch="${branch}"]`);
    return {
      summary: fieldset.querySelector('[data-field="summary"]').value,
      triggers: csv(fieldset.querySelector('[data-field="triggers"]').value),
      indicators: csv(fieldset.querySelector('[data-field="indicators"]').value),
      counter_evidence_ids: csv(fieldset.querySelector('[data-field="counter"]').value),
      confidence: Number(fieldset.querySelector('[data-field="confidence"]').value)
    };
  }

  function teamPayload(team) {
    const fieldset = document.querySelector(`.v9-team-editor [data-team="${team}"]`);
    return {
      text: fieldset.querySelector('[data-field="text"]').value,
      evidence_ids: csv(fieldset.querySelector('[data-field="evidence"]').value)
    };
  }

  async function saveScenario(event) {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      await sendJson(`/api/v9/scenarios/${encodeURIComponent(form.dataset.scenarioId)}`, {
        version: Number(form.dataset.version),
        changes: {
          assumptions: csv(document.getElementById('v9ScenarioEditAssumptions').value),
          observables: csv(document.getElementById('v9ScenarioObservables').value),
          branches: {
            baseline: branchPayload('baseline'),
            escalation: branchPayload('escalation'),
            deescalation: branchPayload('deescalation')
          },
          team_outputs: {
            red: teamPayload('red'),
            blue: teamPayload('blue'),
            judge: teamPayload('judge')
          }
        }
      }, 'PATCH');
      await loadScenarios();
      showToast('推演已保存为新版本');
    } catch (error) {
      if (!error.toastShown) showToast(`推演保存失败：${error.message}`);
    }
  }

  window.loadV9Jobs = loadJobs;
  window.loadV9Scenarios = loadScenarios;

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-job-template]').forEach(button => {
      button.addEventListener('click', () => {
        document.getElementById('v9JobTemplate').value = button.dataset.jobTemplate;
        document.getElementById('v9JobTitle').value = button.querySelector('strong')?.textContent || '';
        document.getElementById('v9JobForm').hidden = false;
        document.getElementById('v9JobTitle').focus();
      });
    });
    document.getElementById('v9JobForm')?.addEventListener('submit', createJob);
    document.getElementById('v9JobRefresh')?.addEventListener('click', loadJobs);
    document.getElementById('v9JobList')?.addEventListener('click', event => {
      const button = event.target.closest('[data-job-id]');
      if (!button) return;
      activeJobId = button.dataset.jobId;
      renderJobs();
    });
    document.getElementById('v9JobDetail')?.addEventListener('click', event => {
      const button = event.target.closest('[data-job-action]');
      const item = jobCache.find(job => job.record_id === activeJobId);
      if (button && item) controlJob(item.record_id, button.dataset.jobAction);
    });
    document.getElementById('v9ScenarioNew')?.addEventListener('click', () => {
      document.getElementById('v9ScenarioCreateForm').hidden = false;
      document.getElementById('v9ScenarioTitle').focus();
    });
    document.getElementById('v9ScenarioCreateForm')?.addEventListener('submit', createScenario);
    document.getElementById('v9ScenarioList')?.addEventListener('click', event => {
      const button = event.target.closest('[data-scenario-id]');
      if (!button) return;
      activeScenarioId = button.dataset.scenarioId;
      renderScenarios();
    });
    document.getElementById('v9ScenarioEditForm')?.addEventListener('submit', saveScenario);
  });
})();
