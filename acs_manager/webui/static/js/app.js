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
        return `
          <div class="p-3 border rounded bg-white shadow-sm flex flex-col gap-1">
            <div class="flex items-center justify-between gap-2">
              <div class="font-semibold truncate" title="${name}">${name}</div>
              <div class="text-xs text-slate-500">Tunnel: ${tunnel}</div>
            </div>
            <div class="text-xs text-slate-600">Status: ${status}</div>
            <div class="text-xs text-slate-600 truncate">IP: <span class="font-mono">${ip}</span></div>
            ${lastSeen ? `<div class="text-xs text-slate-500">Last seen: ${lastSeen}</div>` : ''}
            <div class="mt-2 grid grid-cols-2 gap-2">
              <button class="btn btn-primary btn-xxs" data-action="refresh" data-id="${cid}">Refresh IP</button>
              <button class="btn btn-primary btn-xxs" data-action="restart" data-id="${cid}">Restart Tunnel</button>
              <button class="btn btn-secondary btn-xxs" data-action="start" data-id="${cid}">Start Tunnel</button>
              <button class="btn btn-secondary btn-xxs" data-action="stop" data-id="${cid}">Stop Tunnel</button>
              <button class="btn btn-accent btn-xxs col-span-2" data-action="restart-container" data-id="${cid}">Restart Container</button>
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
  async function loadConfig() {
    const area = document.getElementById('cfg-editor');
    const status = document.getElementById('cfg-status');
    if (!area || !status) return;
    try {
      const data = await fetchJSON('/config?reload=true');
      area.value = JSON.stringify(data, null, 2);
      status.textContent = '已加载最新配置';
      status.className = 'text-sm text-slate-600 mt-2';
    } catch (e) {
      status.textContent = String(e);
      status.className = 'text-sm text-red-600 mt-2';
    }
  }

  async function saveConfig() {
    const area = document.getElementById('cfg-editor');
    const status = document.getElementById('cfg-status');
    if (!area || !status) return;
    try {
      const parsed = JSON.parse(area.value);
      const res = await fetch(withBase('/config'), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(parsed),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(JSON.stringify(data));
      }
      status.textContent = '保存成功';
      status.className = 'text-sm text-green-600 mt-2';
    } catch (e) {
      status.textContent = `保存失败: ${String(e)}`;
      status.className = 'text-sm text-red-600 mt-2';
    }
  }

  function initConfig() {
    loadConfig();
    const btnLoad = document.getElementById('cfg-load');
    const btnSave = document.getElementById('cfg-save');
    if (btnLoad) btnLoad.addEventListener('click', loadConfig);
    if (btnSave) btnSave.addEventListener('click', saveConfig);
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
