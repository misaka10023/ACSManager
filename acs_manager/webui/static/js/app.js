(() => {
  const page = document.querySelector("[data-page]")?.getAttribute("data-page");

  async function fetchJSON(url, options) {
    const res = await fetch(url, options);
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
  }

  // ---------- Dashboard ----------
  async function loadHealth() {
    try {
      const data = await fetchJSON("/health");
      const el = document.getElementById("health-status");
      if (!el) return;
      const ok = (data.status || "").toLowerCase() === "ok";
      el.innerHTML = ok
        ? '<span class="text-green-600 font-semibold">OK</span>'
        : '<span class="text-red-600 font-semibold">DOWN</span>';
    } catch (e) {
      const el = document.getElementById("health-status");
      if (el) el.textContent = e.toString();
    }
  }

  async function loadState() {
    const el = document.getElementById("state-block");
    if (!el) return;
    try {
      const data = await fetchJSON("/state");
      el.textContent = JSON.stringify(data, null, 2);
    } catch (e) {
      el.textContent = e.toString();
    }
  }

  async function loadIP() {
    const valEl = document.getElementById("ip-value");
    const metaEl = document.getElementById("ip-meta");
    if (!valEl || !metaEl) return;
    try {
      const data = await fetchJSON("/container-ip");
      valEl.textContent = data.ip || data.container_ip || "未知";
      metaEl.textContent = `来源: ${data.source || "unknown"}${data.updated_at ? " · 更新时间: " + data.updated_at : ""}`;
    } catch (e) {
      valEl.textContent = "未获取";
      metaEl.textContent = e.toString();
    }
  }

  async function loadDashLogs() {
    const el = document.getElementById("dash-logs");
    if (!el) return;
    try {
      const data = await fetchJSON("/logs?lines=200");
      el.textContent = (data.content || []).join("\n");
      el.scrollTop = el.scrollHeight;
    } catch (e) {
      el.textContent = e.toString();
    }
  }

  function initDashboard() {
    loadHealth();
    loadState();
    loadIP();
    loadDashLogs();
    const btn = document.getElementById("dash-refresh");
    if (btn) btn.addEventListener("click", () => {
      loadHealth(); loadState(); loadIP(); loadDashLogs();
    });
    setInterval(() => {
      loadHealth(); loadState(); loadIP();
    }, 5000);
  }

  // ---------- Config ----------
  async function loadConfig() {
    const area = document.getElementById("cfg-editor");
    const status = document.getElementById("cfg-status");
    if (!area || !status) return;
    try {
      const data = await fetchJSON("/config?reload=true");
      area.value = JSON.stringify(data, null, 2);
      status.textContent = "已加载最新配置";
      status.className = "text-sm text-slate-600 mt-2";
    } catch (e) {
      status.textContent = e.toString();
      status.className = "text-sm text-red-600 mt-2";
    }
  }

  async function saveConfig() {
    const area = document.getElementById("cfg-editor");
    const status = document.getElementById("cfg-status");
    if (!area || !status) return;
    try {
      const parsed = JSON.parse(area.value);
      const res = await fetch("/config", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(parsed),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(JSON.stringify(data));
      status.textContent = "保存成功";
      status.className = "text-sm text-green-600 mt-2";
    } catch (e) {
      status.textContent = "保存失败: " + e.toString();
      status.className = "text-sm text-red-600 mt-2";
    }
  }

  function initConfig() {
    loadConfig();
    const btnLoad = document.getElementById("cfg-load");
    const btnSave = document.getElementById("cfg-save");
    if (btnLoad) btnLoad.addEventListener("click", loadConfig);
    if (btnSave) btnSave.addEventListener("click", saveConfig);
  }

  // ---------- Logs ----------
  async function loadLogs() {
    const el = document.getElementById("log-view");
    const lines = 400;
    if (!el) return;
    try {
      const data = await fetchJSON(`/logs?lines=${lines}`);
      el.textContent = (data.content || []).join("\n");
      el.scrollTop = el.scrollHeight;
    } catch (e) {
      el.textContent = e.toString();
    }
  }

  function initLogs() {
    const auto = document.getElementById("log-auto");
    const intervalSelect = document.getElementById("log-interval");
    const btn = document.getElementById("log-refresh");
    let timer = null;

    function schedule() {
      if (timer) clearInterval(timer);
      if (auto && auto.checked) {
        const ms = parseInt(intervalSelect?.value || "5000", 10);
        timer = setInterval(loadLogs, ms);
      }
    }

    if (btn) btn.addEventListener("click", loadLogs);
    if (auto) auto.addEventListener("change", schedule);
    if (intervalSelect) intervalSelect.addEventListener("change", schedule);

    loadLogs();
    schedule();
  }

  // ---------- Boot ----------
  if (page === "dashboard") initDashboard();
  if (page === "config") initConfig();
  if (page === "logs") initLogs();
})();
