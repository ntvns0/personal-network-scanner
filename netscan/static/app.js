
const state = {
  currentScanId: null,
  pollTimer: null,
  lastReport: null,
  filter: ""
};

const els = {
  form: document.querySelector("#scan-form"),
  target: document.querySelector("#target"),
  ports: document.querySelector("#ports"),
  timeout: document.querySelector("#timeout"),
  workers: document.querySelector("#workers"),
  discovery: document.querySelector("#discovery"),
  banners: document.querySelector("#banners"),
  reverseDns: document.querySelector("#reverse-dns"),
  arp: document.querySelector("#arp"),
  allowPublic: document.querySelector("#allow-public"),
  status: document.querySelector("#server-status"),
  suggestions: document.querySelector("#suggestions"),
  refresh: document.querySelector("#suggest-refresh"),
  useLocal: document.querySelector("#use-local"),
  progressBar: document.querySelector("#progress-bar"),
  phase: document.querySelector("#phase"),
  progressCount: document.querySelector("#progress-count"),
  progressRate: document.querySelector("#progress-rate"),
  progressDetails: document.querySelector("#progress-details"),
  scanId: document.querySelector("#scan-id"),
  metrics: document.querySelector("#metrics"),
  deviceChart: document.querySelector("#device-chart"),
  serviceChart: document.querySelector("#service-chart"),
  hosts: document.querySelector("#hosts"),
  filter: document.querySelector("#host-filter"),
  downloadJson: document.querySelector("#download-json")
};

function setStatus(text, mode = "neutral") {
  els.status.textContent = text;
  els.status.dataset.mode = mode;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `Request failed: ${response.status}`);
  }
  return payload;
}

async function loadSuggestions() {
  els.suggestions.textContent = "Loading...";
  try {
    const data = await api("/api/suggestions");
    els.suggestions.innerHTML = "";
    if (!data.networks.length) {
      els.suggestions.textContent = "No local IPv4 networks found.";
      return;
    }
    data.networks.forEach((item) => {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = item.cidr;
      button.title = item.allowed ? "Default allowed target" : "Requires authorization flag";
      button.addEventListener("click", () => {
        els.target.value = item.allowed ? item.cidr : item.cidr;
        els.allowPublic.checked = !item.allowed;
      });
      els.suggestions.append(button);
    });
  } catch (error) {
    els.suggestions.textContent = error.message;
  }
}

function scanPayload() {
  return {
    target: els.target.value.trim() || "local",
    ports: els.ports.value.trim() || "top",
    timeout: Number(els.timeout.value || 0.6),
    workers: Number.parseInt(els.workers.value || "128", 10),
    discovery: els.discovery.checked,
    banners: els.banners.checked,
    reverse_dns: els.reverseDns.checked,
    arp: els.arp.checked,
    allow_public: els.allowPublic.checked
  };
}

async function startScan(event) {
  event.preventDefault();
  clearPoll();
  setStatus("Starting");
  state.lastReport = null;
  renderReport(null);
  try {
    const data = await api("/api/scans", {
      method: "POST",
      body: JSON.stringify(scanPayload())
    });
    state.currentScanId = data.id;
    els.scanId.textContent = data.id;
    setStatus("Running");
    pollScan();
    state.pollTimer = window.setInterval(pollScan, 500);
  } catch (error) {
    setStatus("Error");
    els.progressDetails.textContent = error.message;
  }
}

async function pollScan() {
  if (!state.currentScanId) return;
  try {
    const data = await api(`/api/scans/${state.currentScanId}`);
    renderProgress(data);
    if (data.report) {
      state.lastReport = data.report;
      renderReport(data.report);
    }
    if (data.status === "complete" || data.status === "failed") {
      clearPoll();
      setStatus(data.status === "complete" ? "Complete" : "Failed");
      if (data.error) els.progressDetails.textContent = data.error;
    }
  } catch (error) {
    clearPoll();
    setStatus("Error");
    els.progressDetails.textContent = error.message;
  }
}

function clearPoll() {
  if (state.pollTimer) {
    window.clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
}

function renderProgress(data) {
  const progress = data.progress || {};
  const total = progress.total || 0;
  const done = progress.done || 0;
  const percent = total ? Math.round((done / total) * 100) : 0;
  els.progressBar.style.width = `${percent}%`;
  els.phase.textContent = progress.phase || data.status || "Idle";
  els.progressCount.textContent = `${done}/${total}`;
  els.progressRate.textContent = `${Number(progress.rate || 0).toFixed(1)}/s`;
  const details = progress.details || {};
  els.progressDetails.textContent = Object.entries(details)
    .map(([key, value]) => `${key}=${value}`)
    .join(" ");
}

function renderReport(report) {
  if (!report) {
    renderMetrics({ host_count: 0, open_port_count: 0, risk_counts: {}, device_counts: {} });
    renderBars(els.deviceChart, {});
    renderBars(els.serviceChart, {});
    els.hosts.textContent = "No scan results yet.";
    els.hosts.className = "hosts empty";
    els.downloadJson.disabled = true;
    return;
  }
  renderMetrics(report.summary);
  renderBars(els.deviceChart, report.summary.device_counts || {});
  renderBars(els.serviceChart, report.summary.service_counts || {});
  renderHosts(report.hosts || []);
  els.downloadJson.disabled = false;
}

function renderMetrics(summary) {
  const highRisk = (summary.risk_counts && summary.risk_counts.high) || 0;
  const deviceTypes = Object.keys(summary.device_counts || {}).length;
  const values = [
    ["Hosts", summary.host_count || 0],
    ["Open Ports", summary.open_port_count || 0],
    ["High Risk", highRisk],
    ["Device Types", deviceTypes]
  ];
  els.metrics.innerHTML = values
    .map(([label, value]) => `<div class="metric"><span>${escapeHtml(label)}</span><strong>${value}</strong></div>`)
    .join("");
}

function renderBars(container, counts) {
  const entries = Object.entries(counts || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    container.className = "bar-list empty";
    container.textContent = "No data yet.";
    return;
  }
  const max = Math.max(...entries.map((entry) => entry[1]), 1);
  container.className = "bar-list";
  container.innerHTML = entries.map(([label, count]) => {
    const width = Math.max(5, Math.round((count / max) * 100));
    return `
      <div class="bar-row">
        <div class="bar-label" title="${escapeHtml(label)}">${escapeHtml(label)}</div>
        <div class="bar-shell"><div class="bar-value" style="width:${width}%"></div></div>
        <div class="bar-count">${count}</div>
      </div>`;
  }).join("");
}

function renderHosts(hosts) {
  const filter = state.filter.toLowerCase();
  const filtered = hosts.filter((host) => JSON.stringify(host).toLowerCase().includes(filter));
  if (!filtered.length) {
    els.hosts.className = "hosts empty";
    els.hosts.textContent = hosts.length ? "No hosts match the filter." : "No live hosts found.";
    return;
  }
  els.hosts.className = "hosts";
  els.hosts.innerHTML = filtered.map((host) => hostCard(host)).join("");
}

function hostCard(host) {
  const profile = host.profile || {};
  const ports = host.ports || [];
  const portHtml = ports.length
    ? ports.map((port) => `<span class="port">${port.port}${port.service ? "/" + escapeHtml(port.service) : ""}</span>`).join("")
    : `<span class="port">no open ports</span>`;
  const recommendations = (profile.recommendations || []).slice(0, 3);
  const recHtml = recommendations.length
    ? `<ul class="recommendations">${recommendations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`
    : "";
  return `
    <article class="host-card">
      <div class="host-main">
        <div class="host-title">
          <strong>${escapeHtml(host.address)}</strong>
          <span class="chip">${escapeHtml(profile.device_type || "unknown device")}</span>
          <span class="chip risk-${escapeHtml(profile.risk_level || "low")}">${escapeHtml(profile.risk_level || "low")}</span>
        </div>
        <div class="host-meta">
          ${host.hostname ? `<span>${escapeHtml(host.hostname)}</span>` : ""}
          ${host.vendor ? `<span>${escapeHtml(host.vendor)}</span>` : ""}
          ${host.mac ? `<span>${escapeHtml(host.mac)}</span>` : ""}
          <span>confidence ${Math.round((profile.confidence || 0) * 100)}%</span>
        </div>
      </div>
      <div class="port-list">${portHtml}</div>
      ${recHtml}
    </article>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

els.form.addEventListener("submit", startScan);
els.refresh.addEventListener("click", loadSuggestions);
els.useLocal.addEventListener("click", () => { els.target.value = "local"; els.allowPublic.checked = false; });
els.filter.addEventListener("input", () => {
  state.filter = els.filter.value;
  if (state.lastReport) renderHosts(state.lastReport.hosts || []);
});
els.downloadJson.addEventListener("click", () => {
  if (!state.lastReport) return;
  const blob = new Blob([JSON.stringify(state.lastReport, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "network-scan-report.json";
  link.click();
  URL.revokeObjectURL(link.href);
});

loadSuggestions();
