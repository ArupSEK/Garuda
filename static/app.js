const form = document.querySelector("#scan-form");
const scanButton = document.querySelector("#scan-button");
const downloadButton = document.querySelector("#download-report");
const output = document.querySelector("#json-output");
const findingsList = document.querySelector("#findings-list");
const portsTable = document.querySelector("#ports-table");
const findingCount = document.querySelector("#finding-count");
const metrics = {
  target: document.querySelector("#metric-target"),
  open: document.querySelector("#metric-open"),
  http: document.querySelector("#metric-http"),
  duration: document.querySelector("#metric-duration"),
};

let lastReport = null;

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(form);
  const payload = {
    target: formData.get("target"),
    ports: formData.get("ports"),
    authorized: formData.get("authorized") === "on",
  };

  setBusy(true);
  renderMessage("Scan running...");

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Scan failed.");
    }
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
  if (!lastReport) {
    return;
  }
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `garuda-${lastReport.host || "scan"}-${Date.now()}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
});

function setBusy(isBusy) {
  scanButton.disabled = isBusy;
  scanButton.textContent = isBusy ? "Scanning..." : "Run Scan";
}

function renderReport(report) {
  output.textContent = JSON.stringify(report, null, 2);
  downloadButton.disabled = false;
  metrics.target.textContent = report.host;
  metrics.open.textContent = report.summary.open_ports;
  metrics.http.textContent = report.summary.http_services;
  metrics.duration.textContent = `${report.duration_ms} ms`;
  renderFindings(report.findings || []);
  renderPorts(report.ports || []);
}

function renderFindings(findings) {
  findingCount.textContent = findings.length;
  if (!findings.length) {
    findingsList.className = "findings-list empty-state";
    findingsList.textContent = "No findings produced by this scan.";
    return;
  }

  findingsList.className = "findings-list";
  findingsList.innerHTML = findings.map((finding) => `
    <article class="finding-card ${escapeHtml(finding.severity)}">
      <div class="finding-title">
        <span>${escapeHtml(finding.title)}</span>
        <span class="severity">${escapeHtml(finding.severity)}</span>
      </div>
      <p>${escapeHtml(finding.evidence)}</p>
      <p>${escapeHtml(finding.recommendation)}</p>
    </article>
  `).join("");
}

function renderPorts(ports) {
  if (!ports.length) {
    portsTable.innerHTML = `<tr><td colspan="4">No scan results yet.</td></tr>`;
    return;
  }

  portsTable.innerHTML = ports.map((port) => {
    const evidence = port.state === "open"
      ? `${port.address} responded in ${port.latency_ms} ms`
      : port.error || "No response";
    return `
      <tr>
        <td>TCP/${port.port}</td>
        <td>${escapeHtml(port.state)}</td>
        <td>${escapeHtml(port.service || "unknown")}</td>
        <td>${escapeHtml(evidence)}</td>
      </tr>
    `;
  }).join("");
}

function renderMessage(message) {
  findingsList.className = "findings-list empty-state";
  findingsList.textContent = message;
}

function renderError(message) {
  output.textContent = JSON.stringify({error: message}, null, 2);
  findingCount.textContent = "0";
  findingsList.className = "findings-list empty-state";
  findingsList.textContent = message;
  portsTable.innerHTML = `<tr><td colspan="4">${escapeHtml(message)}</td></tr>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

