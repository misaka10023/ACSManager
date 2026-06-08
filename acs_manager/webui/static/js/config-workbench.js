window.ConfigWorkbench = (() => {
  'use strict';

  const state = {
    initialized: false,
    activeTab: 'containers',
    search: '',
    globalConfig: null,
    globalDraft: null,
    globalDirty: false,
    containers: [],
    containerDrafts: {},
    containerDirty: {},
    runtimeById: {},
    selectedContainerId: null,
    selectedTaskIndexByContainer: {},
    taskSuggestions: [],
    taskSuggestionsLoading: false,
    lastSavedAt: '',
    runtimeTimer: null,
    dialogResolve: null,
  };

  const refs = {};

  function api() {
    return window.ACSManagerWebUI || {};
  }

  function deepClone(value) {
    return JSON.parse(JSON.stringify(value ?? null));
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function slugify(value, fallback = 'task') {
    const normalized = String(value || '')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, '-')
      .replace(/^-+|-+$/g, '');
    return normalized || fallback;
  }

  function getByPath(obj, path) {
    return String(path || '')
      .split('.')
      .filter(Boolean)
      .reduce((acc, key) => (acc && typeof acc === 'object' ? acc[key] : undefined), obj);
  }

  function setByPath(obj, path, value) {
    const parts = String(path || '').split('.').filter(Boolean);
    if (!parts.length) return;
    let cursor = obj;
    parts.slice(0, -1).forEach((key) => {
      if (!cursor[key] || typeof cursor[key] !== 'object' || Array.isArray(cursor[key])) {
        cursor[key] = {};
      }
      cursor = cursor[key];
    });
    cursor[parts[parts.length - 1]] = value;
  }

  function toNumberOrNull(value) {
    if (value === '' || value == null) return null;
    const num = Number(value);
    return Number.isFinite(num) ? num : null;
  }

  function normalizeRemoteDynamicForward(item) {
    if (typeof item === 'number') {
      return { bind: '127.0.0.1', remote: item, mid: null };
    }
    if (typeof item === 'string') {
      const parts = item.split(':');
      if (parts.length === 1) {
        return { bind: '127.0.0.1', remote: toNumberOrNull(parts[0]), mid: null };
      }
      if (parts.length === 2 && /^\d+$/.test(parts[0])) {
        return { bind: '127.0.0.1', remote: toNumberOrNull(parts[0]), mid: toNumberOrNull(parts[1]) };
      }
      if (parts.length === 2) {
        return { bind: parts[0] || '127.0.0.1', remote: toNumberOrNull(parts[1]), mid: null };
      }
      if (parts.length === 3) {
        return { bind: parts[0] || '127.0.0.1', remote: toNumberOrNull(parts[1]), mid: toNumberOrNull(parts[2]) };
      }
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

  function nowLabel() {
    return new Date().toLocaleString('zh-CN', { hour12: false });
  }

  function formatSince(value) {
    if (!value) return '';
    const dt = new Date(value);
    if (Number.isNaN(dt.getTime())) return String(value);
    return dt.toLocaleString('zh-CN', { hour12: false });
  }

  function statusTone(status) {
    const normalized = String(status || '').toLowerCase();
    if (['running', 'ok', 'healthy'].includes(normalized)) return 'ok';
    if (['stopped', 'terminated', 'failed', 'error'].includes(normalized)) return 'danger';
    if (['pending', 'queue', 'queued', 'deploying'].includes(normalized)) return 'warn';
    return 'neutral';
  }

  function defaultTask(index = 0) {
    const taskId = `task-${index + 1}`;
    return {
      id: taskId,
      title: `Task ${index + 1}`,
      enabled: true,
      trigger: 'manual',
      mode: 'once',
      workdir: '',
      command: '',
      log_file: '',
      runner: {
        type: 'nohup',
        session: taskId,
      },
    };
  }

  function normalizeTask(task, index = 0) {
    const raw = task && typeof task === 'object' ? deepClone(task) : {};
    const id = slugify(raw.id || raw.title, `task-${index + 1}`);
    const runnerRaw = raw.runner && typeof raw.runner === 'object' ? raw.runner : {};
    const runnerType = runnerRaw.type === 'tmux' ? 'screen' : (runnerRaw.type || 'nohup');
    return {
      id,
      title: String(raw.title || id),
      enabled: raw.enabled !== false,
      trigger: raw.trigger === 'auto_on_start' ? 'auto_on_start' : 'manual',
      mode: raw.mode === 'ensure_running' ? 'ensure_running' : 'once',
      workdir: String(raw.workdir || ''),
      command: String(raw.command || ''),
      log_file: String(raw.log_file || ''),
      runner: {
        type: runnerType,
        session: String(runnerRaw.session || id),
      },
    };
  }

  function defaultContainer(name = 'container-1') {
    return {
      id: name,
      name,
      acs: {
        container_name: '',
        service_type: 'container',
      },
      restart: {
        strategy: 'restart',
      },
      ssh: {
        mode: 'jump',
        bastion_host: '',
        bastion_user: '',
        target_user: 'root',
        port: 22,
        container_port: 22,
        password_login: false,
        password: '',
        remote_dynamic_forwards: [],
        forwards: [],
        reverse_forwards: [],
        container_ip: '',
      },
      tasks: [],
    };
  }

  function normalizeContainer(container, index = 0) {
    const raw = container && typeof container === 'object' ? deepClone(container) : {};
    const name = String(raw.name || raw.id || `container-${index + 1}`).trim() || `container-${index + 1}`;
    const acs = raw.acs && typeof raw.acs === 'object' ? raw.acs : {};
    const ssh = raw.ssh && typeof raw.ssh === 'object' ? raw.ssh : {};
    const restart = raw.restart && typeof raw.restart === 'object' ? raw.restart : {};
    const forwards = Array.isArray(ssh.forwards)
      ? ssh.forwards
          .map((item) => ({ local: toNumberOrNull(item?.local), remote: toNumberOrNull(item?.remote) }))
          .filter((item) => item.local != null && item.remote != null)
      : [];
    const remoteDynamicForwards = Array.isArray(ssh.remote_dynamic_forwards)
      ? ssh.remote_dynamic_forwards
          .map((item) => normalizeRemoteDynamicForward(item))
          .filter((item) => item && item.remote != null)
      : [];
    const reverseForwards = Array.isArray(ssh.reverse_forwards)
      ? ssh.reverse_forwards
          .map((item) => ({ local: toNumberOrNull(item?.local), remote: toNumberOrNull(item?.remote), mid: toNumberOrNull(item?.mid) }))
          .filter((item) => item.local != null && item.remote != null)
      : [];
    const tasks = Array.isArray(raw.tasks) ? raw.tasks.map((item, idx) => normalizeTask(item, idx)) : [];
    return {
      id: name,
      name,
      acs: {
        container_name: String(acs.container_name || ''),
        service_type: String(acs.service_type || 'container').toLowerCase() === 'notebook' ? 'notebook' : 'container',
      },
      restart: {
        strategy: ['restart', 'recreate', 'none'].includes(String(restart.strategy || '').toLowerCase())
          ? String(restart.strategy).toLowerCase()
          : 'restart',
      },
      ssh: {
        mode: ['direct', 'jump', 'double'].includes(String(ssh.mode || 'jump')) ? String(ssh.mode || 'jump') : 'jump',
        bastion_host: String(ssh.bastion_host || ''),
        bastion_user: String(ssh.bastion_user || ''),
        target_user: String(ssh.target_user || 'root'),
        port: toNumberOrNull(ssh.port) ?? 22,
        container_port: toNumberOrNull(ssh.container_port) ?? 22,
        password_login: Boolean(ssh.password_login),
        password: String(ssh.password || ''),
        remote_dynamic_forwards: remoteDynamicForwards,
        forwards,
        reverse_forwards: reverseForwards,
        container_ip: String(ssh.container_ip || ''),
      },
      tasks,
    };
  }

  function normalizeGlobalConfig(raw) {
    const src = raw && typeof raw === 'object' ? deepClone(raw) : {};
    const acs = src.acs && typeof src.acs === 'object' ? src.acs : {};
    const webui = src.webui && typeof src.webui === 'object' ? src.webui : {};
    const auth = webui.auth && typeof webui.auth === 'object' ? webui.auth : {};
    const logging = src.logging && typeof src.logging === 'object' ? src.logging : {};
    const cookies = acs.cookies && typeof acs.cookies === 'object' ? acs.cookies : {};
    return {
      config_version: src.config_version ?? '',
      acs: {
        base_url: String(acs.base_url || ''),
        api_prefix: String(acs.api_prefix || ''),
        login_user: String(acs.login_user || ''),
        login_password: String(acs.login_password || ''),
        user_type: String(acs.user_type || 'os'),
        public_key: String(acs.public_key || ''),
        verify_ssl: Boolean(acs.verify_ssl),
        cookies: {
          JSESSIONID: String(cookies.JSESSIONID || ''),
          GV_JSESSIONID: String(cookies.GV_JSESSIONID || ''),
        },
      },
      webui: {
        host: String(webui.host || '0.0.0.0'),
        port: toNumberOrNull(webui.port) ?? 8000,
        root_path: String(webui.root_path || ''),
        auth: {
          enabled: Boolean(auth.enabled),
          username: String(auth.username || ''),
          password: String(auth.password || ''),
          password_hash: String(auth.password_hash || ''),
          secret_key: String(auth.secret_key || ''),
          session_ttl: toNumberOrNull(auth.session_ttl) ?? 43200,
        },
      },
      logging: {
        level: String(logging.level || 'INFO'),
      },
    };
  }

  function serialize(value) {
    return JSON.stringify(value);
  }

  function currentSavedContainer(id = state.selectedContainerId) {
    return state.containers.find((item) => item.name === id) || null;
  }

  function currentDraftContainer(id = state.selectedContainerId) {
    return id ? state.containerDrafts[id] || null : null;
  }

  function ensureSelectedTaskIndex(containerId) {
    const draft = currentDraftContainer(containerId);
    const count = draft?.tasks?.length || 0;
    if (!count) {
      state.selectedTaskIndexByContainer[containerId] = 0;
      return 0;
    }
    const current = state.selectedTaskIndexByContainer[containerId];
    if (typeof current !== 'number' || current < 0 || current >= count) {
      state.selectedTaskIndexByContainer[containerId] = 0;
      return 0;
    }
    return current;
  }

  function recomputeGlobalDirty() {
    state.globalDirty = serialize(state.globalDraft) !== serialize(state.globalConfig);
  }

  function recomputeContainerDirty(containerId) {
    const saved = currentSavedContainer(containerId);
    const draft = currentDraftContainer(containerId);
    state.containerDirty[containerId] = Boolean(saved && draft && serialize(draft) !== serialize(saved));
  }

  function dirtyCount() {
    return Object.values(state.containerDirty).filter(Boolean).length + (state.globalDirty ? 1 : 0);
  }

  function setStatus(message, tone = 'neutral') {
    if (!refs.status) return;
    refs.status.textContent = message;
    refs.status.className = `config-status-line is-${tone}`;
  }

  function updateLastSaved(label = '') {
    state.lastSavedAt = label || state.lastSavedAt;
    if (refs.lastSaved) {
      refs.lastSaved.textContent = state.lastSavedAt ? `最近保存：${state.lastSavedAt}` : '尚未保存';
    }
  }

  function showToast(message, tone = 'info') {
    if (api().showToast) api().showToast(message, tone);
  }

  async function fetchJSON(path, options) {
    return api().fetchJSON(path, options);
  }

  function cacheRefs() {
    refs.sidebar = document.getElementById('cfg-sidebar');
    refs.stage = document.getElementById('cfg-stage');
    refs.grid = document.getElementById('cfg-grid');
    refs.load = document.getElementById('cfg-load');
    refs.save = document.getElementById('cfg-save');
    refs.status = document.getElementById('cfg-status');
    refs.lastSaved = document.getElementById('cfg-last-saved');
    refs.versionBadge = document.getElementById('cfg-version-badge');
    refs.containerCount = document.getElementById('cfg-container-count');
    refs.dirtyCount = document.getElementById('cfg-dirty-count');
    refs.dialog = document.getElementById('cfg-dialog');
    refs.dialogTitle = document.getElementById('cfg-dialog-title');
    refs.dialogMessage = document.getElementById('cfg-dialog-message');
    refs.dialogActions = document.getElementById('cfg-dialog-actions');
  }

  function renderField({ label, tip = '', help = '', control = '', span = 1 }) {
    const spanClass = span > 1 ? ` field-span-${span}` : '';
    return `
      <label class="config-field${spanClass}">
        <div class="field-label">
          <span>${escapeHtml(label)}</span>
          ${tip ? `<span class="help-icon" tabindex="0" data-tooltip="${escapeHtml(tip)}">i</span>` : ''}
        </div>
        <div class="input-shell">${control}</div>
        ${help ? `<div class="field-help">${escapeHtml(help)}</div>` : ''}
      </label>
    `;
  }

  function inputControl(path, value, options = {}) {
    const type = options.type || 'text';
    const placeholder = options.placeholder || '';
    const attrs = options.attrs || '';
    const disabled = options.disabled ? 'disabled' : '';
    if (type === 'textarea') {
      return `<textarea class="input input-area" data-path="${escapeHtml(path)}" placeholder="${escapeHtml(placeholder)}" ${attrs} ${disabled}>${escapeHtml(value || '')}</textarea>`;
    }
    if (type === 'select') {
      const html = (options.choices || [])
        .map((choice) => {
          const selected = String(choice.value) === String(value) ? 'selected' : '';
          return `<option value="${escapeHtml(choice.value)}" ${selected}>${escapeHtml(choice.label)}</option>`;
        })
        .join('');
      return `<select class="input" data-path="${escapeHtml(path)}" ${attrs} ${disabled}>${html}</select>`;
    }
    if (type === 'checkbox') {
      return `
        <label class="toggle-row">
          <input type="checkbox" class="checkbox" data-path="${escapeHtml(path)}" ${value ? 'checked' : ''} ${attrs} ${disabled}>
          <span>${escapeHtml(options.checkboxLabel || '启用')}</span>
        </label>
      `;
    }
    const val = type === 'number' ? (value ?? '') : escapeHtml(value ?? '');
    return `<input type="${escapeHtml(type)}" class="input" data-path="${escapeHtml(path)}" value="${val}" placeholder="${escapeHtml(placeholder)}" ${attrs} ${disabled}>`;
  }

  function panelSection(title, description, body, extra = '') {
    return `
      <section class="card config-panel">
        <div class="config-section-header">
          <div>
            <div class="config-section-title">${escapeHtml(title)}</div>
            <div class="config-section-copy">${escapeHtml(description)}</div>
          </div>
          ${extra}
        </div>
        <div class="config-field-grid">${body}</div>
      </section>
    `;
  }

  function runtimePill(label, value, tone = 'neutral') {
    return `<span class="pill is-${escapeHtml(tone)}">${escapeHtml(label)}：${escapeHtml(value || '-')}</span>`;
  }

  function renderRuntimeHeader(containerId) {
    const runtime = state.runtimeById[containerId] || {};
    return `
      <div class="runtime-pills">
        ${runtimePill('容器状态', runtime.container_status || runtime.status || 'unknown', statusTone(runtime.container_status || runtime.status))}
        ${runtimePill('隧道状态', runtime.tunnel_status || 'unknown', statusTone(runtime.tunnel_status))}
        ${runtimePill('当前 IP', runtime.container_ip || '-', runtime.container_ip ? 'ok' : 'neutral')}
        ${runtimePill('剩余时间', runtime.remaining_time_str || '-', runtime.remaining_time_str ? 'warn' : 'neutral')}
      </div>
    `;
  }

  function renderGlobalPanel() {
    const draft = state.globalDraft || normalizeGlobalConfig({});
    const auth = draft.webui.auth || {};
    const acs = draft.acs || {};
    const logging = draft.logging || {};
    return `
      <div class="config-stack">
        ${panelSection(
          'Account / ACS',
          '共享的 ACS 登录与 Cookie 配置。修改后会触发统一的 ACS 会话刷新。',
          [
            renderField({ label: 'Base URL', tip: 'ACS 控制台基础地址，需包含协议和端口。', control: inputControl('acs.base_url', acs.base_url, { placeholder: 'http://192.168.10.200:6080' }) }),
            renderField({ label: 'API Prefix', tip: '多数环境为 /sothisai。', control: inputControl('acs.api_prefix', acs.api_prefix, { placeholder: '/sothisai' }) }),
            renderField({ label: '登录用户', tip: 'ACS 控制台用户名。', control: inputControl('acs.login_user', acs.login_user, { placeholder: 'your-acs-username' }) }),
            renderField({ label: '登录密码', tip: '用于自动登录 ACS；依赖 cookies 时可按需留空。', control: inputControl('acs.login_password', acs.login_password, { type: 'password', placeholder: 'change-me' }) }),
            renderField({ label: '用户类型', tip: '例如 os / gridview。', control: inputControl('acs.user_type', acs.user_type, { placeholder: 'os' }) }),
            renderField({ label: '公钥(Base64)', tip: '若 ACS 需要前端加密密码，可在此填写。', control: inputControl('acs.public_key', acs.public_key, { placeholder: 'optional' }) }),
            renderField({ label: '验证 SSL', tip: '自签证书环境可关闭；生产环境建议开启。', control: inputControl('acs.verify_ssl', acs.verify_ssl, { type: 'checkbox', checkboxLabel: '启用证书校验' }) }),
            renderField({ label: 'JSESSIONID', tip: '若填写，将优先复用而不是重新登录。', control: inputControl('acs.cookies.JSESSIONID', acs.cookies?.JSESSIONID, { placeholder: 'optional' }) }),
            renderField({ label: 'GV_JSESSIONID', tip: '和 JSESSIONID 配套使用。', control: inputControl('acs.cookies.GV_JSESSIONID', acs.cookies?.GV_JSESSIONID, { placeholder: 'optional' }) }),
          ].join('')
        )}
        ${panelSection(
          'Network',
          'Web UI 自身的监听地址、端口和子路径。',
          [
            renderField({ label: 'Host', tip: '0.0.0.0 表示对外监听。', control: inputControl('webui.host', draft.webui.host, { placeholder: '0.0.0.0' }) }),
            renderField({ label: 'Port', tip: 'Web UI 监听端口。', control: inputControl('webui.port', draft.webui.port, { type: 'number', placeholder: '8000' }) }),
            renderField({ label: 'Root Path', tip: '例如 /acsmanager；必须与反向代理一致。', control: inputControl('webui.root_path', draft.webui.root_path, { placeholder: '/acsmanager' }) }),
          ].join('')
        )}
        ${panelSection(
          'Security',
          '登录、会话与 Secret Key。填写 password_hash 后建议清空明文 password。',
          [
            renderField({ label: '启用登录', tip: '开启后，大部分页面和 API 都需要登录。', control: inputControl('webui.auth.enabled', auth.enabled, { type: 'checkbox', checkboxLabel: '启用 Web UI 登录' }) }),
            renderField({ label: '登录用户名', tip: 'Web UI 登录名。', control: inputControl('webui.auth.username', auth.username, { placeholder: 'admin' }) }),
            renderField({ label: '登录密码', tip: '若已配置 password_hash，可清空明文密码。', control: inputControl('webui.auth.password', auth.password, { type: 'password', placeholder: 'change-me' }) }),
            renderField({ label: '密码哈希', tip: 'sha256 哈希；非空时优先使用。', control: inputControl('webui.auth.password_hash', auth.password_hash, { placeholder: 'sha256' }) }),
            renderField({ label: 'Secret Key', tip: '用于签名 session cookie，生产环境请修改。', control: inputControl('webui.auth.secret_key', auth.secret_key, { placeholder: 'change-me-please' }) }),
            renderField({ label: 'Session TTL(秒)', tip: '登录态有效期。', control: inputControl('webui.auth.session_ttl', auth.session_ttl, { type: 'number', placeholder: '43200' }) }),
          ].join('')
        )}
        ${panelSection(
          'Observability',
          '控制日志等级，便于排查 ACS API、SSH 和 Web UI 问题。',
          renderField({ label: '日志等级', tip: '常用值：DEBUG / INFO / WARNING / ERROR。', control: inputControl('logging.level', logging.level, { placeholder: 'INFO' }) })
        )}
      </div>
    `;
  }

  function renderSuggestionOptions(container) {
    const currentValue = container.acs.container_name || '';
    if (state.taskSuggestionsLoading) {
      return '<option value="">正在刷新 ACS 任务列表...</option>';
    }
    if (!state.taskSuggestions.length) {
      return `<option value="">${currentValue ? '未找到匹配项，可直接手填' : '暂无可选任务，可直接手填'}</option>`;
    }
    return state.taskSuggestions
      .map((task) => {
        const selected = String(task.name) === String(currentValue) ? 'selected' : '';
        const meta = [task.service_type, task.status].filter(Boolean).join(' / ');
        return `<option value="${escapeHtml(task.name)}" ${selected}>${escapeHtml(task.name)}${meta ? ` (${escapeHtml(meta)})` : ''}</option>`;
      })
      .join('');
  }

  function updateSuggestionSelect() {
    const select = refs.stage?.querySelector('[data-action="pick-acs-task"]');
    const container = currentDraftContainer();
    if (!(select instanceof HTMLSelectElement) || !container) return;
    select.innerHTML = renderSuggestionOptions(container);
  }

  function renderForwardRows(rows, kind) {
    const isReverse = kind === 'reverse';
    const list = Array.isArray(rows) ? rows : [];
    if (!list.length) {
      return `
        <tr class="table-muted-row">
          <td colspan="${isReverse ? 4 : 3}">
            <div class="empty-inline">暂无转发规则，点击右上角新增。</div>
          </td>
        </tr>
      `;
    }
    return list
      .map((row, index) => `
        <tr>
          <td><input type="number" class="input input-sm" data-collection="${isReverse ? 'reverse_forwards' : 'forwards'}" data-index="${index}" data-key="local" value="${row.local ?? ''}" placeholder="本地端口"></td>
          <td><input type="number" class="input input-sm" data-collection="${isReverse ? 'reverse_forwards' : 'forwards'}" data-index="${index}" data-key="remote" value="${row.remote ?? ''}" placeholder="${isReverse ? '容器端口' : '远端端口'}"></td>
          ${isReverse ? `<td><input type="number" class="input input-sm" data-collection="reverse_forwards" data-index="${index}" data-key="mid" value="${row.mid ?? ''}" placeholder="中间端口"></td>` : ''}
          <td class="table-action-cell"><button type="button" class="btn btn-secondary btn-xxs" data-action="remove-${isReverse ? 'reverse' : 'forward'}" data-index="${index}">删除</button></td>
        </tr>
      `)
      .join('');
  }

  function renderRemoteDynamicRows(rows) {
    const list = Array.isArray(rows) ? rows : [];
    if (!list.length) {
      return `
        <tr class="table-muted-row">
          <td colspan="4">
            <div class="empty-inline">暂无 SOCKS 代理，点击右上角新增。</div>
          </td>
        </tr>
      `;
    }
    return list
      .map((row, index) => `
        <tr>
          <td><input type="text" class="input input-sm" data-collection="remote_dynamic_forwards" data-index="${index}" data-key="bind" value="${escapeHtml(row.bind || '127.0.0.1')}" placeholder="127.0.0.1"></td>
          <td><input type="number" class="input input-sm" data-collection="remote_dynamic_forwards" data-index="${index}" data-key="remote" value="${row.remote ?? ''}" placeholder="17890"></td>
          <td><input type="number" class="input input-sm" data-collection="remote_dynamic_forwards" data-index="${index}" data-key="mid" value="${row.mid ?? ''}" placeholder="double 模式填写"></td>
          <td class="table-action-cell"><button type="button" class="btn btn-secondary btn-xxs" data-action="remove-dynamic" data-index="${index}">删除</button></td>
        </tr>
      `)
      .join('');
  }

  function renderTaskList(containerId, tasks) {
    const runtimeTasks = state.runtimeById[containerId]?.tasks || [];
    const runtimeByTaskId = Object.fromEntries((Array.isArray(runtimeTasks) ? runtimeTasks : []).map((task) => [task.id, task]));
    const selectedIndex = ensureSelectedTaskIndex(containerId);
    if (!tasks.length) {
      return `
        <div class="empty-state compact">
          <div class="empty-state-title">还没有任务</div>
          <div class="empty-state-copy">适合配置 ComfyUI 常驻任务或训练脚本。</div>
        </div>
      `;
    }
    return tasks
      .map((task, index) => {
        const runtime = runtimeByTaskId[task.id] || {};
        const active = index === selectedIndex ? ' is-active' : '';
        const badge = runtime.last_status || (task.trigger === 'auto_on_start' ? 'auto' : 'manual');
        return `
          <button type="button" class="task-item${active}" data-action="select-task" data-index="${index}">
            <div class="task-item-title">${escapeHtml(task.title || task.id)}</div>
            <div class="task-item-meta">${escapeHtml(task.id)} · ${escapeHtml(task.runner?.type || 'nohup')}</div>
            <div class="task-item-badge">${escapeHtml(String(badge))}</div>
          </button>
        `;
      })
      .join('');
  }

  function renderTaskEditor(containerId, container) {
    const tasks = Array.isArray(container.tasks) ? container.tasks : [];
    if (!tasks.length) {
      return `
        <div class="task-board">
          <aside class="card config-panel task-list-panel">
            <div class="config-section-header">
              <div>
                <div class="config-section-title">容器任务</div>
                <div class="config-section-copy">支持自动启动任务与手动任务。</div>
              </div>
              <button type="button" class="btn btn-secondary btn-xxs" data-action="add-task">新增任务</button>
            </div>
            ${renderTaskList(containerId, tasks)}
          </aside>
          <div class="card config-panel task-editor-panel">
            <div class="empty-state">
              <div class="empty-state-title">未选择任务</div>
              <div class="empty-state-copy">先新增一个任务，再配置触发方式、运行器、日志和命令。</div>
            </div>
          </div>
        </div>
      `;
    }

    const selectedIndex = ensureSelectedTaskIndex(containerId);
    const task = tasks[selectedIndex] || tasks[0];
    const runtimeTasks = state.runtimeById[containerId]?.tasks || [];
    const runtime = (Array.isArray(runtimeTasks) ? runtimeTasks : []).find((item) => item.id === task.id) || {};
    const runnerType = task.runner?.type || 'nohup';
    const statusText = runtime.last_status ? `${runtime.last_status}${runtime.last_run_at ? ` · ${formatSince(runtime.last_run_at)}` : ''}` : '尚未执行';

    return `
      <div class="task-board">
        <aside class="card config-panel task-list-panel">
          <div class="config-section-header">
            <div>
              <div class="config-section-title">容器任务</div>
              <div class="config-section-copy">支持自动触发、手动触发与运行器选择。</div>
            </div>
            <button type="button" class="btn btn-secondary btn-xxs" data-action="add-task">新增任务</button>
          </div>
          <div class="task-list">${renderTaskList(containerId, tasks)}</div>
        </aside>
        <div class="card config-panel task-editor-panel">
          <div class="config-section-header">
            <div>
              <div class="config-section-title">任务详情</div>
              <div class="config-section-copy">当前状态：${escapeHtml(statusText)}</div>
            </div>
            <button type="button" class="btn btn-danger btn-xxs" data-action="remove-task" data-index="${selectedIndex}">删除任务</button>
          </div>
          <div class="config-field-grid">
            ${renderField({ label: '任务标题', tip: '仪表盘展示名。', control: `<input type="text" class="input" data-task-field="title" value="${escapeHtml(task.title)}" placeholder="例如：启动 ComfyUI">` })}
            ${renderField({ label: '任务 ID', tip: '唯一标识；建议使用英文 slug。', control: `<input type="text" class="input" data-task-field="id" value="${escapeHtml(task.id)}" placeholder="start-comfyui">` })}
            ${renderField({ label: '启用任务', tip: '关闭后不会自动执行，也不建议在仪表盘手动执行。', control: `<label class="toggle-row"><input type="checkbox" class="checkbox" data-task-field="enabled" ${task.enabled ? 'checked' : ''}><span>任务可用</span></label>` })}
            ${renderField({ label: '触发方式', tip: 'manual 仅手动执行；auto_on_start 会在容器 Running 后自动尝试。', control: `<select class="input" data-task-field="trigger"><option value="manual" ${task.trigger === 'manual' ? 'selected' : ''}>manual</option><option value="auto_on_start" ${task.trigger === 'auto_on_start' ? 'selected' : ''}>auto_on_start</option></select>` })}
            ${renderField({ label: '运行模式', tip: 'ensure_running 适合常驻服务；once 适合一次性脚本。', control: `<select class="input" data-task-field="mode"><option value="once" ${task.mode === 'once' ? 'selected' : ''}>once</option><option value="ensure_running" ${task.mode === 'ensure_running' ? 'selected' : ''}>ensure_running</option></select>` })}
            ${renderField({ label: '运行器', tip: 'screen 适合常驻服务；nohup 适合后台一次性脚本；shell 会同步等待命令结束。', control: `<select class="input" data-task-field="runner.type"><option value="screen" ${runnerType === 'screen' ? 'selected' : ''}>screen</option><option value="nohup" ${runnerType === 'nohup' ? 'selected' : ''}>nohup</option><option value="shell" ${runnerType === 'shell' ? 'selected' : ''}>shell</option></select>` })}
            ${renderField({ label: 'Screen Session', tip: 'screen 运行器下用于去重和手动 attach；其他运行器可留空。', control: `<input type="text" class="input" data-task-field="runner.session" value="${escapeHtml(task.runner?.session || '')}" placeholder="comfyui">` })}
            ${renderField({ label: '工作目录', tip: '执行命令前切换到此目录。', control: `<input type="text" class="input" data-task-field="workdir" value="${escapeHtml(task.workdir)}" placeholder="/workspace/project">` })}
            ${renderField({ label: '日志文件', tip: '若填写，输出会被重定向到该文件。', control: `<input type="text" class="input" data-task-field="log_file" value="${escapeHtml(task.log_file)}" placeholder="/workspace/logs/task.log">`, span: 2 })}
            ${renderField({ label: '命令', tip: '实际通过 SSH 在容器内执行的命令。', control: `<textarea class="input input-area" data-task-field="command" placeholder="python main.py --listen 0.0.0.0 --port 8188">${escapeHtml(task.command)}</textarea>`, span: 3 })}
            ${renderField({ label: '最近执行信息', tip: '来自 runtime_state，不会写回主配置。', control: `<div class="input-shell runtime-detail"><div>状态：${escapeHtml(runtime.last_status || 'idle')}</div><div>时间：${escapeHtml(formatSince(runtime.last_run_at) || '-')}</div><div>消息：${escapeHtml(runtime.last_message || '-')}</div></div>`, span: 3 })}
          </div>
        </div>
      </div>
    `;
  }

  function renderContainerPanel() {
    const container = currentDraftContainer();
    if (!container) {
      return `<div class="card config-panel"><div class="empty-state"><div class="empty-state-title">没有可编辑的容器</div><div class="empty-state-copy">请先在左侧新增一个容器。</div></div></div>`;
    }

    return `
      <div class="config-stack">
        <section class="card config-panel">
          <div class="config-section-header">
            <div>
              <div class="config-section-title">当前容器：${escapeHtml(container.name || container.id)}</div>
              <div class="config-section-copy">这里只编辑当前容器；左侧列表显示运行态、排序和脏状态。</div>
            </div>
            <div class="helper">${state.containerDirty[container.id] ? '当前容器有未保存修改' : '当前容器已同步到磁盘'}</div>
          </div>
          ${renderRuntimeHeader(container.id)}
        </section>

        ${panelSection(
          '基本信息',
          '容器标识、ACS 任务名和重启策略。',
          [
            renderField({ label: '容器名称', tip: '本地唯一标识，同时用于 Web UI 展示和 manager 键。', control: inputControl('name', container.name, { placeholder: 'E2SRLF' }) }),
            renderField({ label: '服务类型', tip: 'container 使用 instance-service；notebook 使用 /api/notebook/task。', control: inputControl('acs.service_type', container.acs.service_type, { type: 'select', choices: [{ value: 'container', label: 'container' }, { value: 'notebook', label: 'notebook' }] }) }),
            renderField({ label: '重启策略', tip: 'restart 会尝试重启原任务；recreate 会创建新任务；none 不自动重启或重建。', control: inputControl('restart.strategy', container.restart.strategy, { type: 'select', choices: [{ value: 'restart', label: 'restart' }, { value: 'recreate', label: 'recreate' }, { value: 'none', label: 'none / 不重启' }] }) }),
            renderField({ label: 'ACS 任务名称', tip: 'container 建议填实例名；notebook 可填基础名。', help: '下方列表来自 ACS 任务查询；选择后会自动填入此输入框。', control: inputControl('acs.container_name', container.acs.container_name, { placeholder: 'Notebook_2604107259' }), span: 2 }),
            renderField({ label: 'ACS 任务下拉', tip: '按当前服务类型和输入关键字过滤，可点击刷新重新拉取。', control: `<div class="stack-sm"><div class="inline-actions"><button type="button" class="btn btn-secondary btn-xxs" data-action="refresh-acs-tasks">刷新 ACS 列表</button></div><select class="input suggestion-select" size="6" data-action="pick-acs-task">${renderSuggestionOptions(container)}</select></div>`, span: 3 }),
          ].join('')
        )}

        ${panelSection(
          'SSH 与连接',
          '连接模式、跳板机、认证与容器兜底 IP。',
          [
            renderField({ label: 'SSH 模式', tip: 'direct 直连；jump 使用 -J；double 使用双层 SSH。', control: inputControl('ssh.mode', container.ssh.mode, { type: 'select', choices: [{ value: 'direct', label: 'direct' }, { value: 'jump', label: 'jump' }, { value: 'double', label: 'double' }] }) }),
            renderField({ label: '跳板/远端 Host', tip: 'direct 可留空；jump/double 通常填写跳板机地址。', control: inputControl('ssh.bastion_host', container.ssh.bastion_host, { placeholder: '192.168.10.200' }) }),
            renderField({ label: '跳板用户', tip: '跳板机登录用户名。', control: inputControl('ssh.bastion_user', container.ssh.bastion_user, { placeholder: 'lihuaitian25' }) }),
            renderField({ label: '目标用户', tip: '最终连接容器宿主机时使用的用户名。', control: inputControl('ssh.target_user', container.ssh.target_user, { placeholder: 'root' }) }),
            renderField({ label: 'SSH 端口', tip: '外层 SSH 端口。', control: inputControl('ssh.port', container.ssh.port, { type: 'number', placeholder: '22' }) }),
            renderField({ label: '容器 SSH 端口', tip: '内层容器侧 SSH 端口。', control: inputControl('ssh.container_port', container.ssh.container_port, { type: 'number', placeholder: '22' }) }),
            renderField({ label: '密码登录', tip: '关闭时默认走密钥或现有 SSH 配置。', control: inputControl('ssh.password_login', container.ssh.password_login, { type: 'checkbox', checkboxLabel: '使用密码登录' }) }),
            renderField({ label: '登录密码', tip: '仅在 password_login=true 时使用。', control: inputControl('ssh.password', container.ssh.password, { type: 'password', placeholder: 'optional' }) }),
            renderField({ label: '容器兜底 IP', tip: '自动解析失败时才会用到；后续刷新出新 IP 后会自动写回。', control: inputControl('ssh.container_ip', container.ssh.container_ip, { placeholder: '173.0.106.8' }) }),
          ].join('')
        )}

        <section class="card config-panel">
          <div class="config-section-header">
            <div>
              <div class="config-section-title">远端 SOCKS 代理 (-R dynamic)</div>
              <div class="config-section-copy">在容器侧监听 SOCKS4/5 端口，例如 127.0.0.1:17890；容器程序需显式设置 ALL_PROXY。</div>
            </div>
            <button type="button" class="btn btn-secondary btn-xxs" data-action="add-dynamic">新增代理</button>
          </div>
          <div class="forward-table-wrap"><table class="forward-table"><thead><tr><th>监听地址</th><th>SOCKS 端口</th><th>中间端口</th><th class="table-action-cell">操作</th></tr></thead><tbody>${renderRemoteDynamicRows(container.ssh.remote_dynamic_forwards)}</tbody></table></div>
        </section>

        <section class="card config-panel">
          <div class="config-section-header">
            <div>
              <div class="config-section-title">正向转发 (-L)</div>
              <div class="config-section-copy">只要这里有项，就会按配置拼接 -L；不再自动附带默认端口。</div>
            </div>
            <button type="button" class="btn btn-secondary btn-xxs" data-action="add-forward">新增转发</button>
          </div>
          <div class="forward-table-wrap"><table class="forward-table"><thead><tr><th>本地端口</th><th>远端端口</th><th class="table-action-cell">操作</th></tr></thead><tbody>${renderForwardRows(container.ssh.forwards, 'forward')}</tbody></table></div>
        </section>

        <section class="card config-panel">
          <div class="config-section-header">
            <div>
              <div class="config-section-title">反向转发 (-R)</div>
              <div class="config-section-copy">只要这里有项，就会按配置拼接 -R。double 模式需要填写中间端口。</div>
            </div>
            <button type="button" class="btn btn-secondary btn-xxs" data-action="add-reverse">新增转发</button>
          </div>
          <div class="forward-table-wrap"><table class="forward-table"><thead><tr><th>本地端口</th><th>容器端口</th><th>中间端口</th><th class="table-action-cell">操作</th></tr></thead><tbody>${renderForwardRows(container.ssh.reverse_forwards, 'reverse')}</tbody></table></div>
        </section>

        ${renderTaskEditor(container.id, container)}
      </div>
    `;
  }

  function renderGlobalSidebar() {
    const dirty = state.globalDirty ? '有未保存修改' : '全局设置已同步';
    return `
      <div class="config-sidebar-header">
        <div>
          <div class="config-sidebar-title">全局设置</div>
          <div class="config-sidebar-copy">适合低频修改的共享项。</div>
        </div>
      </div>
      <div class="config-sidebar-summary">
        <div class="summary-block"><div class="summary-label">当前状态</div><div class="summary-value">${escapeHtml(dirty)}</div></div>
        <div class="summary-block"><div class="summary-label">配置版本</div><div class="summary-value">${escapeHtml(String(state.globalDraft?.config_version || '-'))}</div></div>
        <div class="summary-block"><div class="summary-label">说明</div><div class="summary-copy">修改后会触发共享 ACS 配置与 Web UI 基础配置刷新。容器独有项请切换到“容器设置”。</div></div>
      </div>
    `;
  }

  function renderContainerSidebar() {
    const filter = state.search.trim().toLowerCase();
    const items = state.containers.filter((container) => {
      const draft = state.containerDrafts[container.name] || container;
      const combined = `${draft.name} ${draft.acs?.container_name || ''}`.toLowerCase();
      return !filter || combined.includes(filter);
    });

    return `
      <div class="config-sidebar-header">
        <div>
          <div class="config-sidebar-title">容器列表</div>
          <div class="config-sidebar-copy">搜索、复制、排序、删除都在这里完成。</div>
        </div>
        <button type="button" class="btn btn-primary btn-xxs" data-action="add-container">新增容器</button>
      </div>
      <label class="config-search">
        <span class="field-label"><span>搜索容器</span><span class="help-icon" tabindex="0" data-tooltip="按容器名称或 ACS 任务名过滤左侧列表。">i</span></span>
        <div class="input-shell"><input id="cfg-search" type="text" class="input" value="${escapeHtml(state.search)}" placeholder="输入 name 或 ACS 名称"></div>
      </label>
      <div class="config-list">
        ${
          items.length
            ? items.map((container, index) => {
                const savedId = container.name;
                const draft = state.containerDrafts[savedId] || container;
                const runtime = state.runtimeById[savedId] || {};
                const selected = state.selectedContainerId === savedId ? ' is-selected' : '';
                const dirty = state.containerDirty[savedId] ? ' is-dirty' : '';
                const status = runtime.container_status || 'unknown';
                const ip = runtime.container_ip || '-';
                return `
                  <div class="config-item${selected}${dirty}">
                    <button type="button" class="config-item-main" data-action="select-container" data-id="${escapeHtml(savedId)}">
                      <div class="config-item-top"><div class="config-item-title">${escapeHtml(draft.name)}</div>${state.containerDirty[savedId] ? '<span class="config-item-dot">未保存</span>' : ''}</div>
                      <div class="config-item-copy">${escapeHtml(draft.acs?.container_name || '未绑定 ACS 任务')}</div>
                      <div class="config-item-meta"><span class="mini-pill is-${escapeHtml(statusTone(status))}">${escapeHtml(status)}</span><span class="mini-pill">${escapeHtml(ip)}</span></div>
                    </button>
                    <div class="config-item-actions">
                      <button type="button" class="mini-btn" data-action="clone-container" data-id="${escapeHtml(savedId)}">复制</button>
                      <button type="button" class="mini-btn" data-action="move-up-container" data-id="${escapeHtml(savedId)}" ${index === 0 ? 'disabled' : ''}>上移</button>
                      <button type="button" class="mini-btn" data-action="move-down-container" data-id="${escapeHtml(savedId)}" ${index === state.containers.length - 1 ? 'disabled' : ''}>下移</button>
                      <button type="button" class="mini-btn is-danger" data-action="delete-container" data-id="${escapeHtml(savedId)}">删除</button>
                    </div>
                  </div>
                `;
              }).join('')
            : `<div class="empty-state compact"><div class="empty-state-title">没有匹配的容器</div><div class="empty-state-copy">调整搜索条件或直接新增容器。</div></div>`
        }
      </div>
    `;
  }

  function renderSidebar() {
    if (refs.sidebar) refs.sidebar.innerHTML = state.activeTab === 'global' ? renderGlobalSidebar() : renderContainerSidebar();
  }

  function renderStage() {
    if (refs.grid) refs.grid.classList.toggle('is-global', state.activeTab === 'global');
    if (refs.stage) refs.stage.innerHTML = state.activeTab === 'global' ? renderGlobalPanel() : renderContainerPanel();
  }

  function renderToolbar() {
    document.querySelectorAll('.config-tab').forEach((button) => {
      button.classList.toggle('is-active', button.dataset.tab === state.activeTab);
    });
    if (refs.save) {
      refs.save.textContent = state.activeTab === 'global' ? '保存全局设置' : '保存当前容器';
      refs.save.disabled = state.activeTab === 'global' ? !state.globalDirty : !state.containerDirty[state.selectedContainerId];
    }
    if (refs.versionBadge) refs.versionBadge.textContent = String(state.globalDraft?.config_version || '-');
    if (refs.containerCount) refs.containerCount.textContent = String(state.containers.length);
    if (refs.dirtyCount) refs.dirtyCount.textContent = String(dirtyCount());
    if (refs.lastSaved) refs.lastSaved.textContent = state.lastSavedAt ? `最近保存：${state.lastSavedAt}` : '尚未保存';
  }

  function renderAll() {
    renderToolbar();
    renderSidebar();
    renderStage();
  }

  function parseFieldValue(target) {
    if (!target) return '';
    if (target.type === 'checkbox') return target.checked;
    if (target.type === 'number') return toNumberOrNull(target.value);
    return target.value;
  }

  function touchGlobalDraft(path, value) {
    setByPath(state.globalDraft, path, value);
    recomputeGlobalDirty();
    renderToolbar();
  }

  function touchContainerDraft(mutator) {
    const containerId = state.selectedContainerId;
    const draft = currentDraftContainer(containerId);
    if (!containerId || !draft) return;
    mutator(draft);
    recomputeContainerDirty(containerId);
    renderToolbar();
    renderSidebar();
  }

  function syncContainersFromServer(containers, options = {}) {
    const normalized = (Array.isArray(containers) ? containers : []).map((item, index) => normalizeContainer(item, index));
    const ids = normalized.map((item) => item.name);
    const resetDrafts = Boolean(options.resetDrafts);

    Object.keys(state.containerDrafts).forEach((id) => {
      if (!ids.includes(id)) {
        delete state.containerDrafts[id];
        delete state.containerDirty[id];
        delete state.selectedTaskIndexByContainer[id];
      }
    });

    normalized.forEach((container) => {
      const id = container.name;
      if (resetDrafts || !state.containerDirty[id] || !state.containerDrafts[id]) {
        state.containerDrafts[id] = deepClone(container);
        state.containerDirty[id] = false;
      }
      if (!(id in state.selectedTaskIndexByContainer)) {
        state.selectedTaskIndexByContainer[id] = 0;
      }
    });

    state.containers = normalized;
    if (!state.selectedContainerId || !ids.includes(state.selectedContainerId)) {
      state.selectedContainerId = normalized[0]?.name || null;
    }
  }

  function replaceSavedContainer(oldId, container) {
    const normalized = normalizeContainer(container);
    const nextId = normalized.name;
    const index = state.containers.findIndex((item) => item.name === oldId);
    if (index >= 0) state.containers[index] = normalized;
    else state.containers.push(normalized);
    if (oldId !== nextId) {
      delete state.containerDrafts[oldId];
      delete state.containerDirty[oldId];
      delete state.selectedTaskIndexByContainer[oldId];
    }
    state.containerDrafts[nextId] = deepClone(normalized);
    state.containerDirty[nextId] = false;
    if (!(nextId in state.selectedTaskIndexByContainer)) {
      state.selectedTaskIndexByContainer[nextId] = 0;
    }
    state.selectedContainerId = nextId;
  }

  function buildNextContainerName() {
    const used = new Set(state.containers.map((item) => item.name));
    let index = state.containers.length + 1;
    while (used.has(`container-${index}`)) index += 1;
    return `container-${index}`;
  }

  async function refreshRuntime() {
    try {
      const runtime = await fetchJSON('/containers');
      state.runtimeById = Object.fromEntries((Array.isArray(runtime) ? runtime : []).map((item) => [item.id || item.name, item]));
      renderSidebar();
      if (state.activeTab === 'containers') renderStage();
    } catch (error) {
      console.error('Failed to refresh runtime containers', error);
    }
  }

  let taskRefreshTimer = null;
  function scheduleTaskSuggestionRefresh() {
    clearTimeout(taskRefreshTimer);
    taskRefreshTimer = setTimeout(() => {
      refreshTaskSuggestions().catch((error) => {
        console.error('Failed to refresh task suggestions', error);
      });
    }, 250);
  }

  async function refreshTaskSuggestions(force = false) {
    const container = currentDraftContainer();
    if (!container) {
      state.taskSuggestions = [];
      return;
    }
    const keyword = String(container.acs.container_name || '').trim();
    if (!force && state.taskSuggestionsLoading) return;
    state.taskSuggestionsLoading = true;
    updateSuggestionSelect();
    try {
      const query = new URLSearchParams();
      if (container.acs.service_type) query.set('service_type', container.acs.service_type);
      if (keyword) query.set('keyword', keyword);
      const data = await fetchJSON(`/acs/tasks?${query.toString()}`);
      state.taskSuggestions = Array.isArray(data.tasks) ? data.tasks : [];
    } catch (error) {
      state.taskSuggestions = [];
      console.error('Failed to load ACS task suggestions', error);
      showToast(`获取 ACS 任务列表失败: ${error}`, 'error');
    } finally {
      state.taskSuggestionsLoading = false;
      updateSuggestionSelect();
    }
  }

  async function loadWorkbench({ reload = true } = {}) {
    setStatus('正在加载配置...', 'neutral');
    const query = reload ? '?reload=true' : '?reload=false';
    const [globalConfig, containers] = await Promise.all([
      fetchJSON(`/config/global${query}`),
      fetchJSON(`/config/containers${query}`),
    ]);
    state.globalConfig = normalizeGlobalConfig(globalConfig || {});
    state.globalDraft = deepClone(state.globalConfig);
    state.globalDirty = false;
    syncContainersFromServer(containers?.containers || [], { resetDrafts: true });
    await refreshRuntime();
    await refreshTaskSuggestions(true);
    setStatus('已加载最新配置', 'success');
    renderAll();
  }

  async function saveGlobalConfig() {
    try {
      setStatus('正在保存全局设置...', 'neutral');
      const saved = await fetchJSON('/config/global', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(deepClone(state.globalDraft)),
      });
      state.globalConfig = normalizeGlobalConfig(saved || {});
      state.globalDraft = deepClone(state.globalConfig);
      state.globalDirty = false;
      state.lastSavedAt = nowLabel();
      setStatus('全局设置已保存', 'success');
      renderAll();
      showToast('全局设置已保存');
      await refreshRuntime();
      return true;
    } catch (error) {
      setStatus(`保存失败：${error}`, 'danger');
      showToast(`全局设置保存失败: ${error}`, 'error');
      return false;
    }
  }

  async function saveCurrentContainer() {
    const currentId = state.selectedContainerId;
    const draft = currentDraftContainer();
    if (!currentId || !draft) return false;
    try {
      setStatus(`正在保存容器 ${draft.name || currentId}...`, 'neutral');
      const saved = await fetchJSON(`/config/containers/${encodeURIComponent(currentId)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(draft),
      });
      replaceSavedContainer(currentId, saved);
      state.lastSavedAt = nowLabel();
      setStatus(`容器 ${state.selectedContainerId} 已保存`, 'success');
      renderAll();
      showToast(`容器 ${state.selectedContainerId} 已保存`);
      await refreshRuntime();
      await refreshTaskSuggestions(true);
      return true;
    } catch (error) {
      setStatus(`保存失败：${error}`, 'danger');
      showToast(`容器保存失败: ${error}`, 'error');
      return false;
    }
  }

  function closeDialog(result) {
    if (refs.dialog) {
      refs.dialog.classList.add('hidden');
      refs.dialog.setAttribute('aria-hidden', 'true');
    }
    const resolver = state.dialogResolve;
    state.dialogResolve = null;
    if (resolver) resolver(result);
  }

  function openDialog({ title, message, actions }) {
    if (!refs.dialog) return Promise.resolve('cancel');
    refs.dialogTitle.textContent = title;
    refs.dialogMessage.textContent = message;
    refs.dialogActions.innerHTML = (actions || []).map((action) => `
      <button type="button" class="btn ${action.variant || 'btn-secondary'}" data-dialog-action="${escapeHtml(action.id)}">${escapeHtml(action.label)}</button>
    `).join('');
    refs.dialog.classList.remove('hidden');
    refs.dialog.setAttribute('aria-hidden', 'false');
    return new Promise((resolve) => {
      state.dialogResolve = resolve;
    });
  }

  async function resolveUnsavedBeforeLeavingCurrent() {
    const currentId = state.selectedContainerId;
    if (!currentId || !state.containerDirty[currentId]) return true;
    const choice = await openDialog({
      title: '当前容器尚未保存',
      message: '你正在离开当前容器。是否先保存当前容器修改？',
      actions: [
        { id: 'save', label: '保存并继续', variant: 'btn-primary' },
        { id: 'discard', label: '放弃修改', variant: 'btn-secondary' },
        { id: 'cancel', label: '取消', variant: 'btn-secondary' },
      ],
    });
    if (choice === 'save') return saveCurrentContainer();
    if (choice === 'discard') {
      const saved = currentSavedContainer(currentId);
      if (saved) {
        state.containerDrafts[currentId] = deepClone(saved);
        state.containerDirty[currentId] = false;
      }
      renderAll();
      return true;
    }
    return false;
  }

  async function confirmDiscardAll() {
    const hasDirtyContainers = Object.values(state.containerDirty).some(Boolean);
    if (!state.globalDirty && !hasDirtyContainers) return true;
    const choice = await openDialog({
      title: '检测到未保存修改',
      message: '重新加载会丢弃当前页面中的未保存改动。是否继续？',
      actions: [
        { id: 'discard', label: '放弃并重新加载', variant: 'btn-primary' },
        { id: 'cancel', label: '取消', variant: 'btn-secondary' },
      ],
    });
    return choice === 'discard';
  }

  async function selectContainer(containerId) {
    if (!containerId || containerId === state.selectedContainerId) return;
    const canLeave = await resolveUnsavedBeforeLeavingCurrent();
    if (!canLeave) return;
    state.selectedContainerId = containerId;
    ensureSelectedTaskIndex(containerId);
    renderAll();
    await refreshTaskSuggestions(true);
  }

  async function addContainer() {
    const canLeave = await resolveUnsavedBeforeLeavingCurrent();
    if (!canLeave) return;
    try {
      const created = await fetchJSON('/config/containers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(defaultContainer(buildNextContainerName())),
      });
      syncContainersFromServer([...state.containers, created], { resetDrafts: false });
      replaceSavedContainer(created.name, created);
      state.lastSavedAt = nowLabel();
      setStatus(`已新增容器 ${created.name}`, 'success');
      renderAll();
      await refreshRuntime();
      await refreshTaskSuggestions(true);
      showToast(`已新增容器 ${created.name}`);
    } catch (error) {
      setStatus(`新增失败：${error}`, 'danger');
      showToast(`新增容器失败: ${error}`, 'error');
    }
  }

  async function cloneContainer(containerId) {
    if (!containerId) return;
    if (containerId === state.selectedContainerId && state.containerDirty[containerId]) {
      const canLeave = await resolveUnsavedBeforeLeavingCurrent();
      if (!canLeave) return;
    }
    try {
      const created = await fetchJSON(`/config/containers/${encodeURIComponent(containerId)}/clone`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      syncContainersFromServer([...state.containers, created], { resetDrafts: false });
      replaceSavedContainer(created.name, created);
      state.lastSavedAt = nowLabel();
      setStatus(`已复制容器为 ${created.name}`, 'success');
      renderAll();
      await refreshRuntime();
      await refreshTaskSuggestions(true);
      showToast(`已复制容器为 ${created.name}`);
    } catch (error) {
      setStatus(`复制失败：${error}`, 'danger');
      showToast(`复制容器失败: ${error}`, 'error');
    }
  }

  async function deleteContainer(containerId) {
    if (!containerId) return;
    if (containerId === state.selectedContainerId && state.containerDirty[containerId]) {
      const canLeave = await resolveUnsavedBeforeLeavingCurrent();
      if (!canLeave) return;
    }
    const choice = await openDialog({
      title: '删除容器配置',
      message: `确认删除容器 ${containerId} 吗？此操作会同步移除对应的运行态本地记录。`,
      actions: [
        { id: 'delete', label: '确认删除', variant: 'btn-danger' },
        { id: 'cancel', label: '取消', variant: 'btn-secondary' },
      ],
    });
    if (choice !== 'delete') return;
    try {
      const resp = await fetchJSON(`/config/containers/${encodeURIComponent(containerId)}`, { method: 'DELETE' });
      syncContainersFromServer(resp.containers || [], { resetDrafts: false });
      state.lastSavedAt = nowLabel();
      setStatus(`已删除容器 ${containerId}`, 'success');
      renderAll();
      await refreshRuntime();
      await refreshTaskSuggestions(true);
      showToast(`已删除容器 ${containerId}`);
    } catch (error) {
      setStatus(`删除失败：${error}`, 'danger');
      showToast(`删除容器失败: ${error}`, 'error');
    }
  }

  async function reorderContainer(containerId, direction) {
    const order = state.containers.map((item) => item.name);
    const index = order.indexOf(containerId);
    if (index < 0) return;
    const nextIndex = direction === 'up' ? index - 1 : index + 1;
    if (nextIndex < 0 || nextIndex >= order.length) return;
    [order[index], order[nextIndex]] = [order[nextIndex], order[index]];
    try {
      const resp = await fetchJSON('/config/containers/reorder', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ order }),
      });
      syncContainersFromServer(resp.containers || [], { resetDrafts: false });
      state.lastSavedAt = nowLabel();
      setStatus('容器顺序已更新', 'success');
      renderAll();
    } catch (error) {
      setStatus(`排序失败：${error}`, 'danger');
      showToast(`调整容器顺序失败: ${error}`, 'error');
    }
  }

  function mutateForward(kind, index, key, value) {
    touchContainerDraft((draft) => {
      const list = kind === 'remote_dynamic_forwards'
        ? draft.ssh.remote_dynamic_forwards
        : (kind === 'reverse_forwards' ? draft.ssh.reverse_forwards : draft.ssh.forwards);
      if (!Array.isArray(list) || !list[index]) return;
      list[index][key] = key === 'bind' ? String(value || '').trim() : toNumberOrNull(value);
    });
  }

  function addForward(kind) {
    touchContainerDraft((draft) => {
      const list = kind === 'remote_dynamic_forwards'
        ? draft.ssh.remote_dynamic_forwards
        : (kind === 'reverse_forwards' ? draft.ssh.reverse_forwards : draft.ssh.forwards);
      if (kind === 'remote_dynamic_forwards') list.push({ bind: '127.0.0.1', remote: null, mid: null });
      else list.push(kind === 'reverse_forwards' ? { local: null, remote: null, mid: null } : { local: null, remote: null });
    });
    renderAll();
  }

  function removeForward(kind, index) {
    touchContainerDraft((draft) => {
      const list = kind === 'remote_dynamic_forwards'
        ? draft.ssh.remote_dynamic_forwards
        : (kind === 'reverse_forwards' ? draft.ssh.reverse_forwards : draft.ssh.forwards);
      if (Array.isArray(list)) list.splice(index, 1);
    });
    renderAll();
  }

  function addTask() {
    touchContainerDraft((draft) => {
      draft.tasks.push(defaultTask(draft.tasks.length));
      state.selectedTaskIndexByContainer[state.selectedContainerId] = draft.tasks.length - 1;
    });
    renderAll();
  }

  function removeTask(index) {
    touchContainerDraft((draft) => {
      if (!Array.isArray(draft.tasks)) return;
      draft.tasks.splice(index, 1);
      state.selectedTaskIndexByContainer[state.selectedContainerId] = Math.max(0, Math.min(index, draft.tasks.length - 1));
    });
    renderAll();
  }

  function updateTaskField(index, path, value) {
    touchContainerDraft((draft) => {
      const task = draft.tasks?.[index];
      if (!task) return;
      setByPath(task, path, value);
      if (path === 'id') {
        const nextId = slugify(value, `task-${index + 1}`);
        task.id = nextId;
        if (!task.runner?.session) {
          task.runner = task.runner || {};
          task.runner.session = nextId;
        }
      }
    });
    renderToolbar();
    renderSidebar();
  }

  function handleStageInput(event) {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;

    const path = target.getAttribute('data-path');
    if (path) {
      if (state.activeTab === 'global') {
        touchGlobalDraft(path, parseFieldValue(target));
      } else {
        touchContainerDraft((draft) => {
          setByPath(draft, path, parseFieldValue(target));
          if (path === 'name') draft.id = draft.name;
        });
        if (path === 'name' || path === 'acs.container_name') renderSidebar();
        if (path === 'acs.service_type' || path === 'acs.container_name') scheduleTaskSuggestionRefresh();
      }
      return;
    }

    const collection = target.getAttribute('data-collection');
    if (collection) {
      mutateForward(collection, Number(target.getAttribute('data-index')), target.getAttribute('data-key'), target.value);
      return;
    }

    const taskField = target.getAttribute('data-task-field');
    if (taskField && state.selectedContainerId) {
      const index = ensureSelectedTaskIndex(state.selectedContainerId);
      const value = target.getAttribute('type') === 'checkbox' ? target.checked : target.value;
      updateTaskField(index, taskField, value);
    }
  }

  async function handleStageClick(event) {
    const button = event.target.closest('[data-action]');
    if (!button) return;
    const action = button.getAttribute('data-action');
    if (action === 'refresh-acs-tasks') return refreshTaskSuggestions(true);
    if (action === 'add-dynamic') return addForward('remote_dynamic_forwards');
    if (action === 'add-forward') return addForward('forwards');
    if (action === 'add-reverse') return addForward('reverse_forwards');
    if (action === 'remove-dynamic') return removeForward('remote_dynamic_forwards', Number(button.getAttribute('data-index')));
    if (action === 'remove-forward') return removeForward('forwards', Number(button.getAttribute('data-index')));
    if (action === 'remove-reverse') return removeForward('reverse_forwards', Number(button.getAttribute('data-index')));
    if (action === 'add-task') return addTask();
    if (action === 'select-task' && state.selectedContainerId) {
      state.selectedTaskIndexByContainer[state.selectedContainerId] = Number(button.getAttribute('data-index'));
      renderStage();
      return;
    }
    if (action === 'remove-task') return removeTask(Number(button.getAttribute('data-index')));
  }

  function handleStageChange(event) {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    if (target.matches('[data-action="pick-acs-task"]')) {
      touchContainerDraft((draft) => {
        draft.acs.container_name = target.value;
      });
      renderAll();
      scheduleTaskSuggestionRefresh();
    }
  }

  async function init() {
    if (state.initialized) return;
    if (!api().fetchJSON) throw new Error('Shared Web UI helpers are not ready.');

    cacheRefs();

    if (refs.load) {
      refs.load.addEventListener('click', async () => {
        const ok = await confirmDiscardAll();
        if (!ok) return;
        await loadWorkbench({ reload: true });
      });
    }
    if (refs.save) {
      refs.save.addEventListener('click', async () => {
        if (state.activeTab === 'global') await saveGlobalConfig();
        else await saveCurrentContainer();
      });
    }

    document.querySelectorAll('.config-tab').forEach((button) => {
      button.addEventListener('click', () => {
        state.activeTab = button.dataset.tab === 'global' ? 'global' : 'containers';
        renderAll();
      });
    });

    if (refs.sidebar) {
      refs.sidebar.addEventListener('click', (event) => {
        const button = event.target.closest('[data-action]');
        if (!button) return;
        const action = button.getAttribute('data-action');
        const id = button.getAttribute('data-id');
        (async () => {
          if (action === 'add-container') return addContainer();
          if (action === 'select-container' && id) return selectContainer(id);
          if (action === 'clone-container' && id) return cloneContainer(id);
          if (action === 'delete-container' && id) return deleteContainer(id);
          if (action === 'move-up-container' && id) return reorderContainer(id, 'up');
          if (action === 'move-down-container' && id) return reorderContainer(id, 'down');
        })().catch((error) => {
          console.error(error);
          showToast(String(error), 'error');
        });
      });
      refs.sidebar.addEventListener('input', (event) => {
        const target = event.target;
        if (target instanceof HTMLInputElement && target.id === 'cfg-search') {
          state.search = target.value;
          renderSidebar();
        }
      });
    }

    if (refs.stage) {
      refs.stage.addEventListener('input', handleStageInput);
      refs.stage.addEventListener('change', handleStageChange);
      refs.stage.addEventListener('click', (event) => {
        handleStageClick(event).catch((error) => {
          console.error(error);
          showToast(String(error), 'error');
        });
      });
    }

    if (refs.dialog) {
      refs.dialog.addEventListener('click', (event) => {
        const action = event.target.closest('[data-dialog-action]');
        if (action) {
          closeDialog(action.getAttribute('data-dialog-action') || 'cancel');
          return;
        }
        if (event.target === refs.dialog) {
          closeDialog('cancel');
        }
      });
    }

    window.addEventListener('beforeunload', (event) => {
      if (!state.globalDirty && !Object.values(state.containerDirty).some(Boolean)) return;
      event.preventDefault();
      event.returnValue = '';
    });

    state.initialized = true;
    await loadWorkbench({ reload: true });
    if (state.runtimeTimer) clearInterval(state.runtimeTimer);
    state.runtimeTimer = setInterval(() => {
      refreshRuntime().catch((error) => console.error(error));
    }, 8000);
  }

  return { init };
})();
