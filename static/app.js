const form = document.querySelector("#scan-form");
const profileSelect = document.querySelector("#profile");
const scanButton = document.querySelector("#scan-button");
const downloadButton = document.querySelector("#download-report");
const output = document.querySelector("#json-output");
const findingsList = document.querySelector("#findings-list");
const moduleResults = document.querySelector("#module-results");
const portsTable = document.querySelector("#ports-table");
const scanStatus = document.querySelector("#scan-status");
const findingCount = document.querySelector("#finding-count");
const capabilities = document.querySelector("#capabilities");
const metrics = {
  open: document.querySelector("#metric-open"),
  findings: document.querySelector("#metric-findings"),
  modules: document.querySelector("#metric-modules"),
  duration: document.querySelector("#metric-duration"),
};
let lastReport = null;

async function bootstrap() {
  const [profilesResponse, capabilitiesResponse] = await Promise.all([
    fetch("/api/profiles"),
    fetch("/api/capabilities"),
  ]);
  const profilesData = await profilesResponse.json();
  const capabilitiesData = await capabilitiesResponse.json();
  profileSelect.innerHTML = profilesData.profiles.map((profile) =>
    `<option value="${escapeHtml(profile.name)}">${escapeHtml(profile.name)} — ${escapeHtml(profile.description)}</option>`
  ).join("");
  capabilities.innerHTML = capabilitiesData.capabilities.map((item) => {
    const state = item.available ? "available" : "unavailable";
    return `<div class="capability ${state}"><strong>${escapeHtml(item.name)}</strong><span>${escapeHtml(item.description)}</span></div>`;
  }).join("");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(form);
  const payload = {
    target: formData.get("target"),
    ports: formData.get("ports"),
    profile: formData.get("profile"),
    authorized: formData.get("authorized") === "on",
  };
  setBusy(true);
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Scan failed.");
    lastReport = data;
    renderReport(data);
  } catch (error) {
    lastReport = null;
    downloadButton.disabled = true;
    renderError(error.message);
  } finally {
    setBusy(false);
  }
});

downloadButton.addEventListener("click", () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `garuda-${lastReport.target.host}-${Date.now()}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
});

function setBusy(isBusy) {
  scanButton.disabled = isBusy;
  scanButton.textContent = isBusy ? "Assessment running..." : "Run assessment";
  scanStatus.textContent = isBusy ? "Running" : "Idle";
}

function renderReport(report) {
  output.textContent = JSON.stringify(report, null, 2);
  downloadButton.disabled = false;
  scanStatus.textContent = "Completed";
  metrics.open.textContent = report.summary.open_ports;
  metrics.findings.textContent = report.summary.findings_total;
  metrics.modules.textContent = report.summary.modules_completed;
  metrics.duration.textContent = `${report.duration_ms} ms`;
  renderFindings(report.findings || []);
  renderModules(report.modules || []);
  renderPorts(report.open_ports || []);
}

function renderFindings(findings) {
  findingCount.textContent = findings.length;
  if (!findings.length) {
    findingsList.className = "findings empty";
    findingsList.textContent = "No findings produced by this assessment.";
    return;
  }
  findingsList.className = "findings";
  findingsList.innerHTML = findings.map((finding) => `
    <article class="finding ${escapeHtml(finding.severity)}">
      <div class="finding-title"><strong>${escapeHtml(finding.title)}</strong><span>${escapeHtml(finding.severity)}</span></div>
      <p>${escapeHtml(finding.evidence.summary)}</p>
      <p class="muted">${escapeHtml(finding.recommendation)}</p>
      <small>${escapeHtml(finding.module)} · ${escapeHtml(finding.confidence)} · ${escapeHtml(finding.category)}</small>
    </article>
  `).join("");
}

function renderModules(modules) {
  moduleResults.className = "module-grid";
  moduleResults.innerHTML = modules.map((module) => `
    <article class="module-card">
      <div><strong>${escapeHtml(module.module)}</strong><span class="status ${escapeHtml(module.status)}">${escapeHtml(module.status)}</span></div>
      <p>${module.findings.length} findings · ${module.duration_ms} ms</p>
      ${module.message ? `<small>${escapeHtml(module.message)}</small>` : ""}
    </article>
  `).join("");
}

function renderPorts(ports) {
  portsTable.innerHTML = ports.length ? ports.map((item) => `
    <tr><td>${escapeHtml(item.address)}</td><td>TCP/${item.port}</td><td>${escapeHtml(item.service)}</td><td>${item.latency_ms} ms</td></tr>
  `).join("") : `<tr><td colspan="4">No open ports found in the selected list.</td></tr>`;
}

function renderError(message) {
  output.textContent = JSON.stringify({error: message}, null, 2);
  scanStatus.textContent = "Failed";
  findingCount.textContent = "0";
  findingsList.className = "findings empty";
  findingsList.textContent = message;
  moduleResults.className = "module-grid empty";
  moduleResults.textContent = "Assessment did not complete.";
  portsTable.innerHTML = `<tr><td colspan="4">${escapeHtml(message)}</td></tr>`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

bootstrap().catch((error) => {
  capabilities.textContent = `Unable to load capabilities: ${error.message}`;
});
