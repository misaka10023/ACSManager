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

  // ---------- Dashboard ----------
  async function loadHealth() {
    const el = document.getElementById('health-status');
    if (!el) return;
    try {
      const data = await fetchJSON('/health');
      const ok = (data.status || '').toLowerCase() === 'ok';
      el.innerHTML = ok
        ? '<span class="text-green-600 font-semibold">OK</span>'
        : '<span class="text-red-600 font-semibold">DOWN</span>';
    } catch (e) {
      el.textContent = String(e);
    }
  }

  async function loadState() {
    const el = document.getElementById('state-block');
    const meta = document.getElementById('health-meta');
    if (!el) return;
    try {
      const data = await fetchJSON('/state');
      el.textContent = JSON.stringify(data, null, 2);
      if (meta) {
        const lines = [];
        if (data.container_start_time) {
          lines.push(`容器开始时间: ${data.container_start_time}`);
        }
        if (data.timeout_limit) {
          lines.push(`时间限制: ${data.timeout_limit}`);
        }
        if (data.remaining_time_str) {
          lines.push(`剩余时间: ${data.remaining_time_str}`);
        }
        if (data.next_shutdown) {
          lines.push(`预计自动停止时间: ${data.next_shutdown}`);
        }
        meta.innerHTML = lines.length
          ? lines.join('<br/>')
          : '暂未获取到自动停止/重启时间';
      }
    } catch (e) {
      el.textContent = String(e);
      if (meta) {
        meta.textContent = '获取状态失败，无法计算剩余时间';
      }
    }
  }

  async function loadIP() {
    const valEl = document.getElementById('ip-value');
    const metaEl = document.getElementById('ip-meta');
    if (!valEl || !metaEl) return;
    try {
      const data = await fetchJSON('/container-ip');
      const ip = data.ip || data.container_ip || '未知';
      valEl.textContent = ip;
      const parts = [`来源: ${data.source || 'unknown'}`];
      if (data.updated_at) {
        parts.push(`更新时间: ${data.updated_at}`);
      }
      metaEl.textContent = parts.join(' · ');
    } catch (e) {
      valEl.textContent = '未获取';
      metaEl.textContent = String(e);
    }
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
    loadHealth();
    loadState();
    loadIP();
    loadDashLogs();

    const btn = document.getElementById('dash-refresh');
    if (btn) {
      btn.addEventListener('click', () => {
        loadHealth();
        loadState();
        loadIP();
        loadDashLogs();
      });
    }

    setInterval(() => {
      loadHealth();
      loadState();
      loadIP();
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
