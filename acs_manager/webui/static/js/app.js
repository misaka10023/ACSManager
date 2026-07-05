(() => {
  'use strict';

  const basePath = (document.body.getAttribute('data-base-path') || '').replace(/\/+$/, '');
  const page = document.body.getAttribute('data-page') || '';
  const DEFAULT_CONTAINER_NAME = 'default';

  const withBase = (path) => {
    const normalized = path.startsWith('/') ? path : `/${path}`;
    return `${basePath}${normalized}` || '/';
  };

  async function fetchJSON(url, options) {
    const res = await fetch(withBase(url), options);
    if (!res.ok) {
      let text;
      try {
        text = await res.text();
      } catch {
        text = res.statusText;
      }
      throw new Error(`${res.status} ${res.statusText}: ${text}`);
    }
    return res.json();
  }

  function showToast(message, tone = 'info') {
    const layer = document.getElementById('app-toast');
    const card = document.getElementById('app-toast-card');
    const msg = document.getElementById('app-toast-message');
    if (!layer || !card || !msg) return;
    msg.textContent = message;
    card.classList.remove('is-error');
    if (tone === 'error') card.classList.add('is-error');
    layer.classList.add('is-visible');
  }

  function hideToast() {
    const layer = document.getElementById('app-toast');
    if (layer) layer.classList.remove('is-visible');
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // ---------- Dashboard (multi-container) ----------
  let containersCache = [];
  let tasksCache = [];

  function populateTaskDatalist(list) {
    const datalist = document.getElementById('acs-task-options');
    if (!datalist) return;
    datalist.innerHTML = (list || [])
      .map((t) => {
        const name = escapeHtml(t.name);
        const meta = escapeHtml([t.service_type || t.task_type, t.status].filter(Boolean).join(' / '));
        return `<option value="${name}">${name}${meta ? ` (${meta})` : ''}</option>`;
      })
      .join('');
  }

  async function loadTasks() {
    try {
      const resp = await fetchJSON('/acs/tasks');
      tasksCache = resp.tasks || [];
      populateTaskDatalist(tasksCache);
    } catch (e) {
      tasksCache = [];
      populateTaskDatalist([]);
      console.error('Failed to load ACS tasks', e);
    }
  }

  function taskLabel(task) {
    const parts = [];
    if (task.trigger === 'auto_on_start') parts.push('自动');
    if (task.mode === 'ensure_running') parts.push('保活');
    parts.push(task.runner_type || task.runner?.type || 'nohup');
    return parts.join(' / ');
  }

  function renderTaskSummary(containerId, task) {
    const status = escapeHtml(task.last_status || 'idle');
    const message = escapeHtml(task.last_message || '');
    const meta = escapeHtml(taskLabel(task));
    const title = escapeHtml(task.title || task.id);
    const taskId = escapeHtml(task.id);
    const lastRunAt = escapeHtml(task.last_run_at || '');
    const logFile = escapeHtml(task.log_file || '');
    const cid = escapeHtml(containerId);
    return `
      <div class="rounded-2xl border border-slate-200/80 bg-slate-50/90 p-3 space-y-2">
        <div class="flex items-start justify-between gap-2">
          <div class="min-w-0">
            <div class="text-sm font-medium text-slate-900 truncate">${title}</div>
            <div class="text-[11px] text-slate-500 break-all">${taskId}</div>
          </div>
          <div class="text-[11px] text-slate-500 whitespace-nowrap">${meta}</div>
        </div>
        <div class="text-xs text-slate-600">状态: ${status}${task.last_run_at ? ` · ${lastRunAt}` : ''}</div>
        ${message ? `<div class="text-xs text-slate-500 break-words">${message}</div>` : ''}
        <div class="flex items-center justify-between gap-2">
          ${task.log_file ? `<div class="text-[11px] text-slate-400 truncate" title="${logFile}">${logFile}</div>` : '<div></div>'}
          <button class="btn btn-secondary btn-xxs" data-action="run-task" data-id="${cid}" data-task-id="${taskId}">执行任务</button>
        </div>
      </div>
    `;
  }

  function renderContainers(containers) {
    const listEl = document.getElementById('containers-list');
    if (!listEl) return;
    if (!containers || !containers.length) {
      listEl.innerHTML = '<div class="text-slate-500 text-sm">No containers configured.</div>';
      return;
    }
    const html = containers
      .map((c) => {
        const cidRaw = c.id || c.name || 'unknown';
        const cid = escapeHtml(cidRaw);
        const name = escapeHtml(c.name || cidRaw);
        const ip = escapeHtml(c.container_ip || 'unknown');
        const source = escapeHtml(c.ip_source || 'unknown');
        const status = escapeHtml(c.container_status || 'unknown');
        const serviceType = escapeHtml(c.service_type || 'container');
        const tunnel = escapeHtml(c.tunnel_status || 'stopped');
        const lastSeen = escapeHtml(c.last_seen || '');
        const remaining = escapeHtml(c.remaining_time_str || '');
        const configuredName = escapeHtml(c.configured_container_name || '');
        const taskList = Array.isArray(c.tasks) ? c.tasks : [];
        return `
          <div class="rounded-2xl border border-white/60 bg-white/80 shadow-sm shadow-slate-900/10 p-4 flex flex-col gap-2">
            <div class="flex items-center justify-between gap-2">
              <div class="font-semibold truncate text-slate-900" title="${name}">${name}</div>
              <div class="text-xs text-slate-500">Tunnel: ${tunnel}</div>
            </div>
            <div class="text-xs text-slate-600">Type: ${serviceType}</div>
            ${configuredName ? `<div class="text-xs text-slate-500 truncate">ACS name: <span class="font-mono">${configuredName}</span></div>` : ''}
            <div class="text-xs text-slate-600">Status: ${status}</div>
            <div class="text-xs text-slate-600 truncate">IP: <span class="font-mono">${ip}</span> <span class="text-slate-400">(${source})</span></div>
            ${remaining ? `<div class="text-xs text-slate-600">剩余时间: ${remaining}</div>` : ''}
            ${lastSeen ? `<div class="text-xs text-slate-500">Last seen: ${lastSeen}</div>` : ''}
            ${
              taskList.length
                ? `<div class="mt-2 space-y-2">
                    <div class="text-xs font-semibold text-slate-700">任务</div>
                    <div class="space-y-2">${taskList.map((task) => renderTaskSummary(cidRaw, task)).join('')}</div>
                  </div>`
                : ''
            }
            <div class="mt-2 grid grid-cols-2 gap-2 text-[13px]">
              <button class="btn btn-primary btn-xxs" data-action="refresh" data-id="${cid}">刷新 IP</button>
              <button class="btn btn-primary btn-xxs" data-action="restart" data-id="${cid}">重启隧道</button>
              <button class="btn btn-secondary btn-xxs" data-action="start" data-id="${cid}">启动隧道</button>
              <button class="btn btn-secondary btn-xxs" data-action="stop" data-id="${cid}">停止隧道</button>
              <button class="btn btn-secondary btn-xxs col-span-2" data-action="restart-container" data-id="${cid}">重启容器</button>
            </div>
          </div>
        `;
      })
      .join('');
    listEl.innerHTML = html;
  }

  function applyContainerFilter() {
    const input = document.getElementById('container-filter');
    if (!input) {
      renderContainers(containersCache);
      return;
    }
    const q = input.value.trim().toLowerCase();
    if (!q) {
      renderContainers(containersCache);
      return;
    }
    const filtered = containersCache.filter((c) => {
      const name = (c.name || c.id || '').toLowerCase();
      return name.includes(q);
    });
    renderContainers(filtered);
  }

  async function loadContainers() {
    try {
      const data = await fetchJSON('/containers');
      containersCache = data || [];
      applyContainerFilter();
    } catch (e) {
      containersCache = [];
      renderContainers([]);
      console.error(e);
    }
  }

  async function containerAction(id, action) {
    const urlMap = {
      refresh: `/containers/${id}/refresh-ip`,
      restart: `/containers/${id}/restart`,
      start: `/containers/${id}/start`,
      stop: `/containers/${id}/stop`,
      'restart-container': `/containers/${id}/restart-container`,
    };
    const url = urlMap[action];
    if (!url) return;
    const data = await fetchJSON(url, { method: 'POST' });
    if (data?.message) showToast(data.message);
    else showToast('操作已提交');
    await loadContainers();
  }

  async function runContainerTask(id, taskId) {
    const data = await fetchJSON(`/containers/${id}/tasks/${taskId}/run`, { method: 'POST' });
    showToast(data.message || `任务 ${taskId} 已执行`);
    await loadContainers();
  }

  async function loadDashLogs() {
    const el = document.getElementById('dash-logs');
    if (!el) return;
    try {
      const data = await fetchJSON('/logs?lines=200');
      el.textContent = (data.content || []).join('\n');
      el.scrollTop = el.scrollHeight;
    } catch (e) {
      el.textContent = String(e);
    }
  }

  function initDashboard() {
    loadContainers();
    loadDashLogs();

    const refreshBtn = document.getElementById('dash-refresh');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        loadContainers();
      });
    }
    const refreshLogsBtn = document.getElementById('dash-refresh-logs');
    if (refreshLogsBtn) {
      refreshLogsBtn.addEventListener('click', loadDashLogs);
    }

    const listEl = document.getElementById('containers-list');
    if (listEl) {
      listEl.addEventListener('click', (ev) => {
        const btn = ev.target.closest('[data-action]');
        if (!btn) return;
        const id = btn.getAttribute('data-id');
        const action = btn.getAttribute('data-action');
        const taskId = btn.getAttribute('data-task-id');
        if (id && action === 'run-task' && taskId) {
          runContainerTask(id, taskId).catch((err) => {
            console.error(err);
            showToast(`任务执行失败: ${err}`, 'error');
          });
          return;
        }
        if (id && action) {
          containerAction(id, action).catch((err) => {
            console.error(err);
            showToast(`操作失败: ${err}`, 'error');
          });
        }
      });
    }

    const filterInput = document.getElementById('container-filter');
    if (filterInput) {
      filterInput.addEventListener('input', () => {
        applyContainerFilter();
      });
    }

    setInterval(() => {
      loadContainers();
    }, 5000);
  }

  // ---------- Config ----------
  let cfgVersion = null;

  function setValue(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    if (el.type === 'checkbox') {
      el.checked = Boolean(value);
    } else {
      el.value = value ?? '';
    }
  }

  function getValue(id) {
    const el = document.getElementById(id);
    if (!el) return null;
    if (el.type === 'checkbox') {
      return el.checked;
    }
    if (el.type === 'number') {
      const v = el.value;
      return v === '' ? null : Number(v);
    }
    return el.value;
  }

  function toNumberOrNull(value) {
    if (value === '' || value == null) return null;
    const num = Number(value);
    return Number.isFinite(num) ? num : null;
  }

  function parseForwardLines(text) {
    if (!text) return [];
    return text
      .split(/\n|,/)
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => l.split(':'))
      .filter((parts) => parts.length >= 2)
      .map((parts) => {
        const [local, remote] = parts;
        return { local: Number(local), remote: Number(remote) };
      })
      .filter((item) => !Number.isNaN(item.local) && !Number.isNaN(item.remote));
  }

  function parseReverseLines(text) {
    if (!text) return [];
    return text
      .split(/\n|,/)
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => l.split(':'))
      .filter((parts) => parts.length >= 2)
      .map((parts) => {
        const [local, remote, mid] = parts;
        return {
          local: Number(local),
          remote: Number(remote),
          mid: mid !== undefined ? Number(mid) : null,
        };
      })
      .filter((item) => !Number.isNaN(item.local) && !Number.isNaN(item.remote));
  }

  function forwardLines(list) {
    if (!Array.isArray(list)) return '';
    return list
      .map((item) => {
        if (item.local == null || item.remote == null) return null;
        return `${item.local}:${item.remote}`;
      })
      .filter(Boolean)
      .join('\n');
  }

  function reverseLines(list) {
    if (!Array.isArray(list)) return '';
    return list
      .map((item) => {
        if (item.local == null || item.remote == null) return null;
        if (item.mid != null) return `${item.local}:${item.remote}:${item.mid}`;
        return `${item.local}:${item.remote}`;
      })
      .filter(Boolean)
      .join('\n');
  }

  function normalizeRemoteDynamicForward(item) {
    if (typeof item === 'number') {
      return { bind: '127.0.0.1', remote: item, mid: null };
    }
    if (typeof item === 'string') {
      const parts = item.split(':');
      if (parts.length === 1) return { bind: '127.0.0.1', remote: toNumberOrNull(parts[0]), mid: null };
      if (parts.length === 2 && /^\d+$/.test(parts[0])) return { bind: '127.0.0.1', remote: toNumberOrNull(parts[0]), mid: toNumberOrNull(parts[1]) };
      if (parts.length === 2) return { bind: parts[0] || '127.0.0.1', remote: toNumberOrNull(parts[1]), mid: null };
      if (parts.length === 3) return { bind: parts[0] || '127.0.0.1', remote: toNumberOrNull(parts[1]), mid: toNumberOrNull(parts[2]) };
      return null;
    }
    if (item && typeof item === 'object') {
      return {
        bind: String(item.bind || '127.0.0.1'),
        remote: toNumberOrNull(item.remote ?? item.port),
        mid: toNumberOrNull(item.mid ?? item.intermediate),
      };
    }
    return null;
  }

  function renderForwardRow(type, values = {}) {
    const row = document.createElement('div');
    row.className = 'grid grid-cols-3 gap-2 items-center text-xs border rounded p-2 bg-slate-100';
    row.dataset.kind = type;
    const isReverse = type === 'reverse';
    row.innerHTML = `
      <label class="flex flex-col gap-1 text-[11px]">
        <span>本地端口</span>
        <input type="number" class="input input-xs" data-field="local" value="${escapeHtml(String(values.local ?? ''))}">
      </label>
      <label class="flex flex-col gap-1 text-[11px]">
        <span>容器端口</span>
        <input type="number" class="input input-xs" data-field="remote" value="${escapeHtml(String(values.remote ?? ''))}">
      </label>
      ${
        isReverse
          ? `<label class="flex flex-col gap-1 text-[11px]">
              <span>中间端口</span>
              <input type="number" class="input input-xs" data-field="mid" value="${escapeHtml(String(values.mid ?? ''))}">
            </label>`
          : `<div class="flex items-center justify-end">
              <button type="button" class="btn btn-danger btn-xxs" data-action="remove-row">删除</button>
            </div>`
      }
      ${
        isReverse
          ? `<div class="col-span-3 flex justify-end">
              <button type="button" class="btn btn-danger btn-xxs" data-action="remove-row">删除</button>
            </div>`
          : ''
      }
    `;
    return row;
  }

  function renderRemoteDynamicRow(values = {}) {
    const row = document.createElement('div');
    row.className = 'grid grid-cols-4 gap-2 items-center text-xs border rounded p-2 bg-slate-100';
    row.dataset.kind = 'dynamic';
    row.innerHTML = `
      <label class="flex flex-col gap-1 text-[11px]">
        <span>监听地址</span>
        <input type="text" class="input input-xs" data-field="bind" value="${escapeHtml(values.bind || '127.0.0.1')}">
      </label>
      <label class="flex flex-col gap-1 text-[11px]">
        <span>SOCKS 端口</span>
        <input type="number" class="input input-xs" data-field="remote" value="${escapeHtml(String(values.remote ?? ''))}">
      </label>
      <label class="flex flex-col gap-1 text-[11px]">
        <span>中间端口</span>
        <input type="number" class="input input-xs" data-field="mid" value="${escapeHtml(String(values.mid ?? ''))}">
      </label>
      <div class="flex items-center justify-end">
        <button type="button" class="btn btn-danger btn-xxs" data-action="remove-row">删除</button>
      </div>
    `;
    return row;
  }

  function appendForwardRow(listEl, type, values = {}) {
    const row = renderForwardRow(type, values);
    listEl.appendChild(row);
  }

  function appendRemoteDynamicRow(listEl, values = {}) {
    listEl.appendChild(renderRemoteDynamicRow(values));
  }

  function slugifyTaskId(value, fallback) {
    const normalized = String(value || '')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, '-')
      .replace(/^-+|-+$/g, '');
    return normalized || fallback;
  }

  function renderTaskEditor(task = {}, idx = 0) {
    const card = document.createElement('div');
    const runner = task.runner || {};
    const runnerType = ['screen', 'tmux', 'nohup', 'shell'].includes(runner.type) ? runner.type : 'nohup';
    card.className = 'rounded-2xl border border-slate-200/80 bg-slate-50/90 p-4 space-y-3';
    card.dataset.kind = 'task';
    card.dataset.taskIndex = String(idx);
    card.innerHTML = `
      <div class="flex items-center justify-between gap-2">
        <div class="text-sm font-semibold text-slate-900">任务 #${idx + 1}</div>
        <button type="button" class="btn btn-danger btn-xxs" data-action="remove-task">删除任务</button>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
        <label class="flex flex-col gap-1 text-xs text-slate-600">任务标题
          <input type="text" class="input" data-field="task_title" value="${escapeHtml(task.title || '')}" placeholder="如：启动 ComfyUI">
        </label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">任务 ID
          <input type="text" class="input" data-field="task_id" value="${escapeHtml(task.id || '')}" placeholder="如：start-comfyui">
        </label>
        <label class="flex items-center gap-2 text-xs text-slate-600 mt-6">
          <input type="checkbox" class="checkbox" data-field="task_enabled" ${task.enabled === false ? '' : 'checked'}>
          启用任务
        </label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">触发方式
          <select class="input" data-field="task_trigger">
            <option value="manual" ${task.trigger === 'auto_on_start' ? '' : 'selected'}>manual</option>
            <option value="auto_on_start" ${task.trigger === 'auto_on_start' ? 'selected' : ''}>auto_on_start</option>
          </select>
        </label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">运行模式
          <select class="input" data-field="task_mode">
            <option value="once" ${task.mode === 'ensure_running' ? '' : 'selected'}>once</option>
            <option value="ensure_running" ${task.mode === 'ensure_running' ? 'selected' : ''}>ensure_running</option>
          </select>
        </label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">运行器
          <select class="input" data-field="task_runner_type">
            <option value="nohup" ${runnerType === 'nohup' ? 'selected' : ''}>nohup</option>
            <option value="screen" ${runnerType === 'screen' ? 'selected' : ''}>screen</option>
            <option value="tmux" ${runnerType === 'tmux' ? 'selected' : ''}>tmux</option>
            <option value="shell" ${runnerType === 'shell' ? 'selected' : ''}>shell</option>
          </select>
        </label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">screen Session
          <input type="text" class="input" data-field="task_session" value="${escapeHtml(runner.session || '')}" placeholder="如：comfyui">
        </label>
        <label class="flex flex-col gap-1 text-xs text-slate-600 md:col-span-2 xl:col-span-1">工作目录
          <input type="text" class="input" data-field="task_workdir" value="${escapeHtml(task.workdir || '')}" placeholder="/workspace/project">
        </label>
        <label class="flex flex-col gap-1 text-xs text-slate-600 md:col-span-2">日志文件
          <input type="text" class="input" data-field="task_log_file" value="${escapeHtml(task.log_file || '')}" placeholder="/workspace/logs/task.log">
        </label>
        <label class="flex flex-col gap-1 text-xs text-slate-600 md:col-span-2 xl:col-span-3">命令
          <textarea class="input min-h-28" data-field="task_command" placeholder="如：python main.py --listen 0.0.0.0 --port 8188">${escapeHtml(task.command || '')}</textarea>
        </label>
      </div>
      <div class="text-[11px] text-slate-500">auto_on_start 会在容器进入 Running 后自动尝试执行；ensure_running + screen 适合常驻服务。</div>
    `;
    return card;
  }

  function appendTaskEditor(listEl, task = {}) {
    const idx = listEl.querySelectorAll('[data-kind="task"]').length;
    listEl.appendChild(renderTaskEditor(task, idx));
  }

  function renderContainerCard(container = {}, idx = 0) {
    const listEl = document.getElementById('container-form-list');
    if (!listEl) return;
    const card = document.createElement('div');
    card.className = 'rounded-2xl border border-white/60 bg-white/80 shadow-sm shadow-slate-900/10 p-4 sm:p-5 space-y-4';
    card.dataset.index = idx.toString();
    const acs = container.acs || {};
    const ssh = container.ssh || {};
    const restart = container.restart || {};
    const serviceType = acs.service_type || 'container';
    card.innerHTML = `
      <div class="flex items-center justify-between gap-2">
        <div class="text-sm font-semibold text-slate-900">容器 #${idx + 1}</div>
        <button type="button" class="px-3 py-1.5 text-xs rounded-xl bg-red-50 text-red-700 border border-red-100 hover:bg-red-100 transition duration-150" data-action="remove">删除</button>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        <label class="flex flex-col gap-1 text-xs text-slate-600">名称(name)
          <input type="text" class="input" data-field="name" value="${escapeHtml(container.name || '')}">
        </label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">ACS 任务名/实例名
          <input type="text" list="acs-task-options" class="input" data-field="container_name" value="${escapeHtml(acs.container_name || '')}">
          <span class="text-[11px] text-slate-400">notebook 模式可填基础名，如 Notebook_2603274032；后端会自动匹配到实际副本名。</span>
        </label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">重启策略
          <select class="input" data-field="restart_strategy">
            <option value="restart" ${restart.strategy === 'recreate' || restart.strategy === 'none' ? '' : 'selected'}>restart</option>
            <option value="recreate" ${restart.strategy === 'recreate' ? 'selected' : ''}>recreate</option>
            <option value="none" ${restart.strategy === 'none' ? 'selected' : ''}>none / 不重启</option>
          </select>
        </label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">SSH 模式
          <select class="input" data-field="ssh_mode">
            <option value="jump" ${ssh.mode === 'direct' || ssh.mode === 'double' ? '' : 'selected'}>jump</option>
            <option value="direct" ${ssh.mode === 'direct' ? 'selected' : ''}>direct</option>
            <option value="double" ${ssh.mode === 'double' ? 'selected' : ''}>double</option>
          </select>
        </label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">跳板/远端 Host<input type="text" class="input" data-field="bastion_host" value="${escapeHtml(ssh.bastion_host || '')}"></label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">跳板用户<input type="text" class="input" data-field="bastion_user" value="${escapeHtml(ssh.bastion_user || '')}"></label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">目标用户<input type="text" class="input" data-field="target_user" value="${escapeHtml(ssh.target_user || '')}"></label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">SSH 端口<input type="number" class="input" data-field="port" value="${escapeHtml(String(ssh.port ?? ''))}"></label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">容器 SSH 端口<input type="number" class="input" data-field="container_port" value="${escapeHtml(String(ssh.container_port ?? ''))}"></label>
        <label class="flex items-center gap-2 text-xs text-slate-600"><input type="checkbox" class="checkbox" data-field="password_login" ${ssh.password_login ? 'checked' : ''}>密码登录</label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">密码<input type="text" class="input" data-field="password" value="${escapeHtml(ssh.password || '')}"></label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">容器 IP(兜底)<input type="text" class="input" data-field="container_ip" value="${escapeHtml(ssh.container_ip || '')}"><span class="text-[11px] text-slate-400">自动解析失败时才需要手填；notebook 模式会优先走 /api/notebook/task 系列接口。</span></label>
      </div>
      <div class="space-y-2">
        <div class="flex items-center justify-between text-xs text-slate-600">
          <div>
            <div class="font-semibold">远端 SOCKS 代理 (-R dynamic)</div>
            <div class="text-[11px] text-slate-400">容器侧监听 SOCKS 端口，例如 127.0.0.1:17890。</div>
          </div>
          <button type="button" class="px-3 py-1.5 text-xs rounded-xl border border-slate-200 bg-white/80 text-slate-800 hover:border-indigo-200 hover:text-indigo-700 transition duration-150" data-action="add-dynamic">新增</button>
        </div>
        <div class="space-y-2" data-list="remote_dynamic_forwards"></div>
      </div>
      <div class="space-y-2">
        <div class="flex items-center justify-between text-xs text-slate-600">
          <span class="font-semibold">正向转发 (-L)</span>
          <button type="button" class="px-3 py-1.5 text-xs rounded-xl border border-slate-200 bg-white/80 text-slate-800 hover:border-indigo-200 hover:text-indigo-700 transition duration-150" data-action="add-forward">新增</button>
        </div>
        <div class="space-y-2" data-list="forwards"></div>
      </div>
      <div class="space-y-2">
        <div class="flex items-center justify-between text-xs text-slate-600">
          <span class="font-semibold">反向转发 (-R)</span>
          <button type="button" class="px-3 py-1.5 text-xs rounded-xl border border-slate-200 bg-white/80 text-slate-800 hover:border-indigo-200 hover:text-indigo-700 transition duration-150" data-action="add-reverse">新增</button>
        </div>
        <div class="space-y-2" data-list="reverse_forwards"></div>
      </div>
      <div class="space-y-2">
        <div class="flex items-center justify-between text-xs text-slate-600">
          <div>
            <div class="font-semibold">容器任务</div>
            <div class="text-[11px] text-slate-400">在容器启动后自动执行，或在仪表盘手动触发。</div>
          </div>
          <button type="button" class="px-3 py-1.5 text-xs rounded-xl border border-slate-200 bg-white/80 text-slate-800 hover:border-indigo-200 hover:text-indigo-700 transition duration-150" data-action="add-task">新增任务</button>
        </div>
        <div class="space-y-3" data-list="tasks"></div>
      </div>
    `;
    listEl.appendChild(card);

    const settingsGrid = card.querySelector('.grid');
    const restartField = card.querySelector('select[data-field="restart_strategy"]')?.closest('label');
    if (settingsGrid && restartField) {
      const serviceField = document.createElement('label');
      serviceField.className = 'flex flex-col gap-1 text-xs text-slate-600';
      serviceField.innerHTML = `
        服务类型
        <select class="input" data-field="service_type">
          <option value="container" ${serviceType === 'notebook' ? '' : 'selected'}>container</option>
          <option value="notebook" ${serviceType === 'notebook' ? 'selected' : ''}>notebook</option>
        </select>
        <span class="text-[11px] text-slate-400">container 使用 instance-service；notebook 使用 /api/notebook/task。</span>
      `;
      settingsGrid.insertBefore(serviceField, restartField);
    }

    const fList = card.querySelector('[data-list="forwards"]');
    const rList = card.querySelector('[data-list="reverse_forwards"]');
    const dList = card.querySelector('[data-list="remote_dynamic_forwards"]');
    const tList = card.querySelector('[data-list="tasks"]');
    const dynamicData = Array.isArray(ssh.remote_dynamic_forwards) && ssh.remote_dynamic_forwards.length ? ssh.remote_dynamic_forwards : [{ bind: '127.0.0.1', remote: '', mid: '' }];
    dynamicData.map(normalizeRemoteDynamicForward).filter(Boolean).forEach((f) => appendRemoteDynamicRow(dList, f));
    const forwardData = Array.isArray(ssh.forwards) && ssh.forwards.length ? ssh.forwards : [{ local: '', remote: '' }];
    forwardData.forEach((f) => appendForwardRow(fList, 'forward', f));
    const reverseData = Array.isArray(ssh.reverse_forwards) && ssh.reverse_forwards.length ? ssh.reverse_forwards : [{ local: '', remote: '', mid: '' }];
    reverseData.forEach((f) => appendForwardRow(rList, 'reverse', f));
    const taskData = Array.isArray(container.tasks) ? container.tasks : [];
    taskData.forEach((task) => appendTaskEditor(tList, task));
  }

  function collectContainerTasks(card) {
    const taskCards = Array.from(card.querySelectorAll('[data-kind="task"]'));
    const usedIds = new Set();
    return taskCards.map((taskCard, idx) => {
      const read = (field) => {
        const el = taskCard.querySelector(`[data-field="${field}"]`);
        if (!el) return '';
        if (el.type === 'checkbox') return el.checked;
        return el.value;
      };
      const title = String(read('task_title') || '').trim();
      const rawId = String(read('task_id') || '').trim();
      const baseId = slugifyTaskId(rawId || title, `task-${idx + 1}`);
      let taskId = baseId;
      let suffix = 2;
      while (usedIds.has(taskId)) {
        taskId = `${baseId}-${suffix++}`;
      }
      usedIds.add(taskId);
      return {
        id: taskId,
        title: title || taskId,
        enabled: Boolean(read('task_enabled')),
        trigger: read('task_trigger') || 'manual',
        mode: read('task_mode') || 'once',
        workdir: String(read('task_workdir') || '').trim(),
        command: String(read('task_command') || '').trim(),
        log_file: String(read('task_log_file') || '').trim(),
        runner: {
          type: read('task_runner_type') || 'nohup',
          session: String(read('task_session') || '').trim() || taskId,
        },
      };
    }).filter((task) => task.command);
  }

  function collectContainers() {
    const listEl = document.getElementById('container-form-list');
    if (!listEl) return [];
    const cards = Array.from(listEl.querySelectorAll('[data-index]'));
    return cards.map((card) => {
      const get = (selector) => {
        const el = card.querySelector(selector);
        if (!el) return '';
        if (el.type === 'checkbox') return el.checked;
        return el.value;
      };
      const name = get('input[data-field="name"]').trim();
      const containerName = get('input[data-field="container_name"]').trim() || name;
      const serviceType = get('select[data-field="service_type"]') || 'container';
      const restartStrategy = get('select[data-field="restart_strategy"]') || 'restart';
      const forwards = [];
      const remoteDynamicForwards = [];
      const dList = card.querySelector('[data-list="remote_dynamic_forwards"]');
      if (dList) {
        dList.querySelectorAll('[data-kind="dynamic"]').forEach((row) => {
          const bind = String(row.querySelector('input[data-field="bind"]')?.value || '127.0.0.1').trim() || '127.0.0.1';
          const remote = Number(row.querySelector('input[data-field="remote"]')?.value || '');
          const midRaw = row.querySelector('input[data-field="mid"]')?.value || '';
          const mid = midRaw === '' ? null : Number(midRaw);
          if (!Number.isNaN(remote)) {
            remoteDynamicForwards.push({ bind, remote, mid: Number.isNaN(mid) ? null : mid });
          }
        });
      }
      const fList = card.querySelector('[data-list="forwards"]');
      if (fList) {
        fList.querySelectorAll('[data-kind="forward"]').forEach((row) => {
          const l = Number(row.querySelector('input[data-field="local"]')?.value || '');
          const r = Number(row.querySelector('input[data-field="remote"]')?.value || '');
          if (!Number.isNaN(l) && !Number.isNaN(r)) {
            forwards.push({ local: l, remote: r });
          }
        });
      }
      const reverseForwards = [];
      const rList = card.querySelector('[data-list="reverse_forwards"]');
      if (rList) {
        rList.querySelectorAll('[data-kind="reverse"]').forEach((row) => {
          const l = Number(row.querySelector('input[data-field="local"]')?.value || '');
          const r = Number(row.querySelector('input[data-field="remote"]')?.value || '');
          const mRaw = row.querySelector('input[data-field="mid"]')?.value || '';
          const m = mRaw === '' ? null : Number(mRaw);
          if (!Number.isNaN(l) && !Number.isNaN(r)) {
            reverseForwards.push({ local: l, remote: r, mid: Number.isNaN(m) ? null : m });
          }
        });
      }
      const port = Number(get('input[data-field="port"]')) || null;
      const containerPort = Number(get('input[data-field="container_port"]')) || null;
      return {
        name,
        acs: {
          container_name: containerName,
          service_type: serviceType,
        },
        restart: {
          strategy: restartStrategy || 'restart',
        },
        ssh: {
          mode: get('select[data-field="ssh_mode"]') || 'jump',
          bastion_host: get('input[data-field="bastion_host"]').trim(),
          bastion_user: get('input[data-field="bastion_user"]').trim(),
          target_user: get('input[data-field="target_user"]').trim() || 'root',
          port: port || undefined,
          container_port: containerPort || undefined,
          password_login: Boolean(get('input[data-field="password_login"]')),
          password: get('input[data-field="password"]'),
          remote_dynamic_forwards: remoteDynamicForwards,
          forwards,
          reverse_forwards: reverseForwards,
          container_ip: get('input[data-field="container_ip"]').trim(),
        },
        tasks: collectContainerTasks(card),
      };
    });
  }

  function bindContainerActions() {
    const listEl = document.getElementById('container-form-list');
    if (!listEl) return;
    listEl.addEventListener('click', (ev) => {
      const btn = ev.target.closest('[data-action]');
      if (!btn) return;
      const action = btn.getAttribute('data-action');
      const card = btn.closest('[data-index]');
      if (!card) return;
      if (action === 'remove') {
        card.remove();
      }
      if (action === 'add-forward') {
        const list = card.querySelector('[data-list="forwards"]');
        if (list) appendForwardRow(list, 'forward', { local: '', remote: '' });
      }
      if (action === 'add-dynamic') {
        const list = card.querySelector('[data-list="remote_dynamic_forwards"]');
        if (list) appendRemoteDynamicRow(list, { bind: '127.0.0.1', remote: '', mid: '' });
      }
      if (action === 'add-reverse') {
        const list = card.querySelector('[data-list="reverse_forwards"]');
        if (list) appendForwardRow(list, 'reverse', { local: '', remote: '', mid: '' });
      }
      if (action === 'add-task') {
        const list = card.querySelector('[data-list="tasks"]');
        if (list) appendTaskEditor(list, {});
      }
      if (action === 'remove-row') {
        const row = btn.closest('[data-kind]');
        if (row) row.remove();
      }
      if (action === 'remove-task') {
        const taskCard = btn.closest('[data-kind="task"]');
        if (taskCard) taskCard.remove();
      }
    });
  }

  function loadForm(data) {
    cfgVersion = data.config_version || null;
    setValue('acs-base-url', data.acs?.base_url);
    setValue('acs-api-prefix', data.acs?.api_prefix);
    setValue('acs-login-user', data.acs?.login_user);
    setValue('acs-login-password', data.acs?.login_password);
    setValue('acs-user-type', data.acs?.user_type);
    setValue('acs-public-key', data.acs?.public_key);
    setValue('acs-verify-ssl', data.acs?.verify_ssl);
    setValue('acs-cookie-jsessionid', data.acs?.cookies?.JSESSIONID);
    setValue('acs-cookie-gv', data.acs?.cookies?.GV_JSESSIONID);

    setValue('webui-host', data.webui?.host);
    setValue('webui-port', data.webui?.port);
    setValue('webui-root-path', data.webui?.root_path);
    setValue('auth-enabled', data.webui?.auth?.enabled);
    setValue('auth-username', data.webui?.auth?.username);
    setValue('auth-password', data.webui?.auth?.password);
    setValue('auth-password-hash', data.webui?.auth?.password_hash);
    setValue('auth-secret-key', data.webui?.auth?.secret_key);
    setValue('auth-session-ttl', data.webui?.auth?.session_ttl);

    setValue('log-level', data.logging?.level);

    const containers = Array.isArray(data.containers) && data.containers.length
      ? data.containers
      : [{ name: DEFAULT_CONTAINER_NAME, acs: { container_name: DEFAULT_CONTAINER_NAME }, restart: { strategy: 'restart' }, ssh: {}, tasks: [] }];
    const listEl = document.getElementById('container-form-list');
    if (listEl) listEl.innerHTML = '';
    containers.forEach((c, idx) => renderContainerCard(c, idx));
    populateTaskDatalist(tasksCache);
  }

  async function loadConfig() {
    const status = document.getElementById('cfg-status');
    try {
      const data = await fetchJSON('/config?reload=true');
      loadForm(data || {});
      if (status) {
        status.textContent = '已加载最新配置';
        status.className = 'text-sm text-slate-600 mt-2';
      }
    } catch (e) {
      if (status) {
        status.textContent = String(e);
        status.className = 'text-sm text-red-600 mt-2';
      }
    }
  }

  async function saveConfig() {
    const status = document.getElementById('cfg-status');
    try {
      const payload = {
        config_version: cfgVersion,
        acs: {
          base_url: getValue('acs-base-url'),
          api_prefix: getValue('acs-api-prefix'),
          login_user: getValue('acs-login-user'),
          login_password: getValue('acs-login-password'),
          user_type: getValue('acs-user-type'),
          public_key: getValue('acs-public-key'),
          verify_ssl: Boolean(getValue('acs-verify-ssl')),
          cookies: {
            JSESSIONID: getValue('acs-cookie-jsessionid') || '',
            GV_JSESSIONID: getValue('acs-cookie-gv') || '',
          },
        },
        webui: {
          host: getValue('webui-host'),
          port: getValue('webui-port'),
          root_path: getValue('webui-root-path'),
          auth: {
            enabled: Boolean(getValue('auth-enabled')),
            username: getValue('auth-username'),
            password: getValue('auth-password'),
            password_hash: getValue('auth-password-hash'),
            secret_key: getValue('auth-secret-key'),
            session_ttl: getValue('auth-session-ttl'),
          },
        },
        logging: {
          level: getValue('log-level') || 'INFO',
        },
        containers: collectContainers(),
      };

      const res = await fetch(withBase('/config'), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(JSON.stringify(data));
      }
      if (status) {
        status.textContent = '保存成功';
        status.className = 'text-sm text-green-600 mt-2';
      }
    } catch (e) {
      if (status) {
        status.textContent = `保存失败: ${String(e)}`;
        status.className = 'text-sm text-red-600 mt-2';
      }
    }
  }

  async function updateApp() {
    const btn = document.getElementById('app-update');
    const originalText = btn ? btn.textContent : '';
    if (btn) btn.disabled = true;
    if (btn) btn.textContent = '检查中...';
    showToast('正在检查更新...');
    try {
      const resp = await fetchJSON('/update', { method: 'POST' });
      if (resp.status === 'up_to_date') {
        showToast(resp.message || '当前已是最新版本，无需重启。');
        if (btn) {
          btn.disabled = false;
          btn.textContent = originalText || '更新并重启';
        }
        return;
      }
      if (btn) btn.textContent = '更新中...';
      showToast(resp.message || '检测到新版本，正在更新并重启，请稍候刷新页面...');
    } catch (e) {
      showToast(`更新失败: ${String(e)}`, 'error');
      if (btn) {
        btn.disabled = false;
        btn.textContent = originalText || '更新并重启';
      }
    }
  }

  function initConfig() {
    if (window.ConfigWorkbench && typeof window.ConfigWorkbench.init === 'function') {
      Promise.resolve(window.ConfigWorkbench.init()).catch((err) => {
        console.error('Failed to initialize config workbench', err);
        showToast(`配置页初始化失败: ${err}`, 'error');
      });
      return;
    }
    loadTasks();
    loadConfig();
    bindContainerActions();
    const btnLoad = document.getElementById('cfg-load');
    const btnSave = document.getElementById('cfg-save');
    const btnAdd = document.getElementById('container-add');
    if (btnLoad) btnLoad.addEventListener('click', loadConfig);
    if (btnSave) btnSave.addEventListener('click', saveConfig);
    if (btnAdd) btnAdd.addEventListener('click', () => {
      const listEl = document.getElementById('container-form-list');
      const idx = listEl ? listEl.children.length : 0;
      renderContainerCard({ name: '', acs: { container_name: '' }, restart: { strategy: 'restart' }, ssh: {}, tasks: [] }, idx);
    });
  }

  // ---------- Logs ----------
  async function loadLogs() {
    const el = document.getElementById('log-view');
    if (!el) return;
    const lines = 400;
    try {
      const data = await fetchJSON(`/logs?lines=${lines}`);
      el.textContent = (data.content || []).join('\n');
      el.scrollTop = el.scrollHeight;
    } catch (e) {
      el.textContent = String(e);
    }
  }

  function initLogs() {
    const auto = document.getElementById('log-auto');
    const intervalSelect = document.getElementById('log-interval');
    const btn = document.getElementById('log-refresh');
    let timer = null;

    function schedule() {
      if (timer) clearInterval(timer);
      if (auto && auto.checked) {
        const ms = parseInt((intervalSelect && intervalSelect.value) || '5000', 10);
        timer = setInterval(loadLogs, ms);
      }
    }

    if (btn) btn.addEventListener('click', loadLogs);
    if (auto) auto.addEventListener('change', schedule);
    if (intervalSelect) intervalSelect.addEventListener('change', schedule);

    loadLogs();
    schedule();
  }

  // ---------- Boot ----------
  window.ACSManagerWebUI = {
    withBase,
    fetchJSON,
    showToast,
    hideToast,
  };

  const toastClose = document.getElementById('app-toast-close');
  if (toastClose) toastClose.addEventListener('click', hideToast);
  const updateBtn = document.getElementById('app-update');
  if (updateBtn) updateBtn.addEventListener('click', updateApp);
  if (page === 'dashboard') initDashboard();
  if (page === 'config') initConfig();
  if (page === 'logs') initLogs();
})();
