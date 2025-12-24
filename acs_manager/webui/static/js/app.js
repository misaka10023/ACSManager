(() => {
  'use strict';

  const basePath = (document.body.getAttribute('data-base-path') || '').replace(/\/+$/, '');
  const page = document.body.getAttribute('data-page') || '';

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

  // ---------- Dashboard (multi-container) ----------
  let containersCache = [];

  function renderContainers(containers) {
    const listEl = document.getElementById('containers-list');
    if (!listEl) return;
    if (!containers || !containers.length) {
      listEl.innerHTML = '<div class="text-slate-500 text-sm">No containers configured.</div>';
      return;
    }
    const html = containers
      .map((c) => {
        const cid = c.id || c.name || 'unknown';
        const name = c.name || cid;
        const ip = c.container_ip || 'unknown';
        const status = c.container_status || 'unknown';
        const tunnel = c.tunnel_status || 'stopped';
        const lastSeen = c.last_seen || '';
        const remaining = c.remaining_time_str || '';
        return `
          <div class="rounded-2xl border border-white/60 bg-white/80 shadow-sm shadow-slate-900/10 p-4 flex flex-col gap-2">
            <div class="flex items-center justify-between gap-2">
              <div class="font-semibold truncate text-slate-900" title="${name}">${name}</div>
              <div class="text-xs text-slate-500">Tunnel: ${tunnel}</div>
            </div>
            <div class="text-xs text-slate-600">Status: ${status}</div>
            <div class="text-xs text-slate-600 truncate">IP: <span class="font-mono">${ip}</span></div>
            ${remaining ? `<div class="text-xs text-slate-600">剩余时间: ${remaining}</div>` : ''}
            ${lastSeen ? `<div class="text-xs text-slate-500">Last seen: ${lastSeen}</div>` : ''}
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
    await fetchJSON(url, { method: 'POST' });
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
        if (id && action) {
          containerAction(id, action).catch((err) => {
            console.error(err);
            alert(`Action failed: ${err}`);
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

  function renderForwardRow(type, values = {}) {
    const row = document.createElement('div');
    row.className = 'grid grid-cols-3 gap-2 items-center text-xs border rounded p-2 bg-slate-100';
    row.dataset.kind = type;
    const isReverse = type === 'reverse';
    row.innerHTML = `
      <label class="flex flex-col gap-1 text-[11px]">
        <span>本地端口</span>
        <input type="number" class="input input-xs" data-field="local" value="${values.local ?? ''}">
      </label>
      <label class="flex flex-col gap-1 text-[11px]">
        <span>容器端口</span>
        <input type="number" class="input input-xs" data-field="remote" value="${values.remote ?? ''}">
      </label>
      ${
        isReverse
          ? `<label class="flex flex-col gap-1 text-[11px]">
              <span>中间端口</span>
              <input type="number" class="input input-xs" data-field="mid" value="${values.mid ?? ''}">
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

  function appendForwardRow(listEl, type, values = {}) {
    const row = renderForwardRow(type, values);
    listEl.appendChild(row);
  }

  function renderContainerCard(container = {}, idx = 0) {
    const listEl = document.getElementById('container-form-list');
    if (!listEl) return;
    const card = document.createElement('div');
    card.className = 'rounded-2xl border border-white/60 bg-white/80 shadow-sm shadow-slate-900/10 p-4 sm:p-5 space-y-3';
    card.dataset.index = idx.toString();
    const ssh = container.ssh || {};
    const restart = container.restart || {};
    card.innerHTML = `
      <div class="flex items-center justify-between gap-2">
        <div class="text-sm font-semibold text-slate-900">容器 #${idx + 1}</div>
        <button type="button" class="px-3 py-1.5 text-xs rounded-xl bg-red-50 text-red-700 border border-red-100 hover:bg-red-100 transition duration-150" data-action="remove">删除</button>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        <label class="flex flex-col gap-1 text-xs text-slate-600">名称(name)
          <input type="text" class="w-full rounded-xl border border-slate-200 bg-white/80 px-3 py-2 text-sm text-slate-800 shadow-inner shadow-white/40 transition duration-150 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 hover:border-slate-300" data-field="name" value="${container.name || ''}">
        </label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">ACS 容器名
          <input type="text" class="w-full rounded-xl border border-slate-200 bg-white/80 px-3 py-2 text-sm text-slate-800 shadow-inner shadow-white/40 transition duration-150 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 hover:border-slate-300" data-field="container_name" value="${(container.acs && container.acs.container_name) || ''}">
        </label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">重启策略
          <select class="w-full rounded-xl border border-slate-200 bg-white/80 px-3 py-2 text-sm text-slate-800 transition duration-150 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 hover:border-slate-300" data-field="restart_strategy">
            <option value="restart" ${restart.strategy === 'recreate' ? '' : 'selected'}>restart</option>
            <option value="recreate" ${restart.strategy === 'recreate' ? 'selected' : ''}>recreate</option>
          </select>
        </label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">SSH 模式
          <select class="w-full rounded-xl border border-slate-200 bg-white/80 px-3 py-2 text-sm text-slate-800 transition duration-150 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 hover:border-slate-300" data-field="ssh_mode">
            <option value="jump" ${ssh.mode === 'direct' || ssh.mode === 'double' ? '' : 'selected'}>jump</option>
            <option value="direct" ${ssh.mode === 'direct' ? 'selected' : ''}>direct</option>
            <option value="double" ${ssh.mode === 'double' ? 'selected' : ''}>double</option>
          </select>
        </label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">跳板/远端 Host<input type="text" class="w-full rounded-xl border border-slate-200 bg-white/80 px-3 py-2 text-sm text-slate-800 shadow-inner shadow-white/40 transition duration-150 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 hover:border-slate-300" data-field="bastion_host" value="${ssh.bastion_host || ''}"></label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">跳板用户<input type="text" class="w-full rounded-xl border border-slate-200 bg-white/80 px-3 py-2 text-sm text-slate-800 shadow-inner shadow-white/40 transition duration-150 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 hover:border-slate-300" data-field="bastion_user" value="${ssh.bastion_user || ''}"></label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">目标用户<input type="text" class="w-full rounded-xl border border-slate-200 bg-white/80 px-3 py-2 text-sm text-slate-800 shadow-inner shadow-white/40 transition duration-150 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 hover:border-slate-300" data-field="target_user" value="${ssh.target_user || ''}"></label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">SSH 端口<input type="number" class="w-full rounded-xl border border-slate-200 bg-white/80 px-3 py-2 text-sm text-slate-800 shadow-inner shadow-white/40 transition duration-150 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 hover:border-slate-300" data-field="port" value="${ssh.port ?? ''}"></label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">容器 SSH 端口<input type="number" class="w-full rounded-xl border border-slate-200 bg-white/80 px-3 py-2 text-sm text-slate-800 shadow-inner shadow-white/40 transition duration-150 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 hover:border-slate-300" data-field="container_port" value="${ssh.container_port ?? ''}"></label>
        <label class="flex items-center gap-2 text-xs text-slate-600"><input type="checkbox" class="h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-200" data-field="password_login" ${ssh.password_login ? 'checked' : ''}>密码登录</label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">密码<input type="text" class="w-full rounded-xl border border-slate-200 bg-white/80 px-3 py-2 text-sm text-slate-800 shadow-inner shadow-white/40 transition duration-150 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 hover:border-slate-300" data-field="password" value="${ssh.password || ''}"></label>
        <label class="flex flex-col gap-1 text-xs text-slate-600">容器 IP(兜底)<input type="text" class="w-full rounded-xl border border-slate-200 bg-white/80 px-3 py-2 text-sm text-slate-800 shadow-inner shadow-white/40 transition duration-150 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-200 hover:border-slate-300" data-field="container_ip" value="${ssh.container_ip || ''}"></label>
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
    `;
    listEl.appendChild(card);

    const fList = card.querySelector('[data-list="forwards"]');
    const rList = card.querySelector('[data-list="reverse_forwards"]');
    const forwardData = Array.isArray(ssh.forwards) && ssh.forwards.length ? ssh.forwards : [{ local: '', remote: '' }];
    forwardData.forEach((f) => appendForwardRow(fList, 'forward', f));
    const reverseData = Array.isArray(ssh.reverse_forwards) && ssh.reverse_forwards.length ? ssh.reverse_forwards : [{ local: '', remote: '', mid: '' }];
    reverseData.forEach((f) => appendForwardRow(rList, 'reverse', f));
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
      const restartStrategy = get('select[data-field="restart_strategy"]') || 'restart';
      const forwards = [];
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
          forwards,
          reverse_forwards: reverseForwards,
          container_ip: get('input[data-field="container_ip"]').trim(),
        },
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
      if (action === 'add-reverse') {
        const list = card.querySelector('[data-list="reverse_forwards"]');
        if (list) appendForwardRow(list, 'reverse', { local: '', remote: '', mid: '' });
      }
      if (action === 'remove-row') {
        const row = btn.closest('[data-kind]');
        if (row) row.remove();
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

    const containers = Array.isArray(data.containers) && data.containers.length ? data.containers : [{ name: '', acs: { container_name: '' }, restart: { strategy: 'restart' }, ssh: {} }];
    const listEl = document.getElementById('container-form-list');
    if (listEl) listEl.innerHTML = '';
    containers.forEach((c, idx) => renderContainerCard(c, idx));
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

  function initConfig() {
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
      renderContainerCard({ name: '', acs: { container_name: '' }, restart: { strategy: 'restart' }, ssh: {} }, idx);
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
  if (page === 'dashboard') initDashboard();
  if (page === 'config') initConfig();
  if (page === 'logs') initLogs();
})();
