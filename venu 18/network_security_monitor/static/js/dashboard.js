(() => {
  "use strict";

  const toast = document.getElementById("toast");
  let toastTimer;
  let trafficChart;
  let protocolChart;
  let dailyChart;

  function notify(message, isError = false) {
    if (!toast) return;
    toast.textContent = message;
    toast.classList.toggle("error", isError);
    toast.classList.add("visible");
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => toast.classList.remove("visible"), 4200);
  }

  async function requestJson(url, options = {}) {
    const response = await fetch(url, options);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
    return data;
  }

  function setText(id, value) {
    const node = document.getElementById(id);
    if (node) node.textContent = value;
  }

  function chartOptions() {
    return {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: "#a6b4c6", usePointStyle: true, boxWidth: 7, font: { size: 10 } } },
      },
      scales: {
        x: { ticks: { color: "#78889e", maxRotation: 0, autoSkip: true, maxTicksLimit: 8, font: { size: 9 } }, grid: { color: "#ffffff08" } },
        y: { beginAtZero: true, ticks: { color: "#78889e", precision: 0, font: { size: 9 } }, grid: { color: "#ffffff0c" } },
      },
    };
  }

  function renderCharts(traffic) {
    if (typeof Chart === "undefined") {
      notify("Charts require access to the Chart.js CDN.", true);
      return;
    }
    const line = document.getElementById("trafficTrendChart");
    if (line) {
      if (trafficChart) trafficChart.destroy();
      trafficChart = new Chart(line, {
        type: "line",
        data: {
          labels: traffic.hourly.labels,
          datasets: [{ label: "Traffic records", data: traffic.hourly.values, borderColor: "#36aaff", backgroundColor: "#238fdf22", fill: true, tension: 0.35, pointRadius: 2, borderWidth: 2 }],
        },
        options: chartOptions(),
      });
    }
    const doughnut = document.getElementById("protocolChart");
    if (doughnut) {
      if (protocolChart) protocolChart.destroy();
      protocolChart = new Chart(doughnut, {
        type: "doughnut",
        data: {
          labels: ["TCP", "UDP", "ICMP"],
          datasets: [{ data: [traffic.protocols.TCP, traffic.protocols.UDP, traffic.protocols.ICMP], backgroundColor: ["#32a8ff", "#28d6a0", "#ffbd5b"], borderColor: "#111b2b", borderWidth: 4, hoverOffset: 5 }],
        },
        options: { responsive: true, maintainAspectRatio: false, cutout: "68%", plugins: { legend: { position: "bottom", labels: { color: "#a6b4c6", usePointStyle: true, padding: 15, font: { size: 10 } } } } },
      });
    }
    const daily = document.getElementById("dailyTrafficChart");
    if (daily) {
      if (dailyChart) dailyChart.destroy();
      dailyChart = new Chart(daily, {
        type: "bar",
        data: { labels: traffic.daily.labels, datasets: [{ label: "Traffic records", data: traffic.daily.values, backgroundColor: "#228edeaa", borderColor: "#42adff", borderWidth: 1, borderRadius: 4 }] },
        options: chartOptions(),
      });
    }
    setText("traffic-bytes", Number(traffic.bytes_total).toLocaleString());
    setText("protocol-tcp", Number(traffic.protocols.TCP).toLocaleString());
    setText("protocol-udp", Number(traffic.protocols.UDP).toLocaleString());
    setText("protocol-icmp", Number(traffic.protocols.ICMP).toLocaleString());
  }

  function renderAlerts(alerts) {
    const body = document.getElementById("recent-alerts");
    if (!body) return;
    if (!alerts.length) {
      body.innerHTML = '<tr><td colspan="4" class="empty-cell">No alerts stored yet.</td></tr>';
      return;
    }
    body.innerHTML = alerts.map((alert) => `
      <tr>
        <td><span class="severity severity-${escapeHtml(alert.severity.toLowerCase())}">${escapeHtml(alert.severity)}</span></td>
        <td>${escapeHtml(alert.category)}</td>
        <td>${escapeHtml(alert.src_ip)}</td>
        <td>${escapeHtml(alert.timestamp)}</td>
      </tr>`).join("");
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (character) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[character]);
  }

  async function loadOverview() {
    const data = await requestJson("/api/overview");
    setText("stat-connections", Number(data.connections).toLocaleString());
    setText("stat-suspicious", Number(data.suspicious).toLocaleString());
    setText("stat-alerts", Number(data.alerts).toLocaleString());
    setText("stat-open-alerts", Number(data.open_alerts).toLocaleString());
    setText("stat-normal", Number(data.normal).toLocaleString());
    setText("stat-anomalies", Number(data.anomalies).toLocaleString());
    setText("stat-model-records", Number(data.model_records).toLocaleString());
    setText("model-latest", data.model_records ? "Scored" : "Not run");
    setText("monitoring-status", data.session ? "Last batch completed" : "Ready");
    setText("monitoring-source", data.session ? `${data.session.source} · ${data.session.records_count} records` : "No recent session");
    renderCharts(data.traffic);
    renderAlerts(data.recent_alerts);
  }

  async function loadTraffic() {
    const body = document.getElementById("traffic-table");
    if (!body) return;
    const records = await requestJson("/api/traffic");
    if (!records.length) {
      body.innerHTML = '<tr><td colspan="7" class="empty-cell">No traffic records found.</td></tr>';
      return;
    }
    body.innerHTML = records.map((record) => `
      <tr>
        <td>${escapeHtml(record.timestamp)}</td><td>${escapeHtml(record.src_ip)}</td>
        <td>${escapeHtml(record.dst_ip)}</td><td>${escapeHtml(record.dst_port)}</td>
        <td>${escapeHtml(record.protocol)}</td><td>${Number(record.byte_count).toLocaleString()}</td>
        <td><span class="severity severity-${record.action === "blocked" ? "high" : "low"}">${escapeHtml(record.action)}</span></td>
      </tr>`).join("");
  }

  async function handleForm(form, endpoint, bodyBuilder, successMessage) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = form.querySelector("button[type='submit']");
      if (button) button.disabled = true;
      try {
        const data = await requestJson(endpoint, { method: "POST", body: bodyBuilder(form) });
        notify(`${successMessage} ${data.records_added ?? ""} records added; ${data.alerts_created ?? 0} alerts generated.`);
        await Promise.all([loadOverview(), loadTraffic()]);
        if (document.body.dataset.page === "alerts") window.location.reload();
      } catch (error) {
        notify(error.message, true);
      } finally {
        if (button) button.disabled = false;
      }
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    loadOverview().catch((error) => notify(error.message, true));
    loadTraffic().catch((error) => notify(error.message, true));

    const simulate = document.getElementById("simulate-button");
    if (simulate) {
      simulate.addEventListener("click", async () => {
        simulate.disabled = true;
        try {
          const count = Number(document.getElementById("simulation-count").value);
          const result = await requestJson("/api/simulate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ count }),
          });
          notify(`${result.message} ${result.records_added} records; ${result.alerts_created} alerts.`);
          await Promise.all([loadOverview(), loadTraffic()]);
        } catch (error) {
          notify(error.message, true);
        } finally {
          simulate.disabled = false;
        }
      });
    }

    const csvForm = document.getElementById("csv-import-form");
    if (csvForm) handleForm(csvForm, "/api/import/csv", (form) => new FormData(form), "CSV analyzed.");
    const pcapForm = document.getElementById("pcap-import-form");
    if (pcapForm) handleForm(pcapForm, "/api/import/pcap", (form) => new FormData(form), "PCAP analyzed.");

    const refresh = document.getElementById("refresh-traffic");
    if (refresh) refresh.addEventListener("click", () => loadTraffic().catch((error) => notify(error.message, true)));

    const anomalyButton = document.getElementById("run-anomaly-button");
    if (anomalyButton) {
      anomalyButton.addEventListener("click", async () => {
        anomalyButton.disabled = true;
        try {
          const result = await requestJson("/api/anomalies/run", { method: "POST" });
          notify(`${result.message} ${result.anomalies} potential anomalies in ${result.records_analyzed} records.`);
          window.location.reload();
        } catch (error) {
          notify(error.message, true);
        } finally {
          anomalyButton.disabled = false;
        }
      });
    }

    const settingsForm = document.getElementById("settings-form");
    if (settingsForm) {
      settingsForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const values = Object.fromEntries(new FormData(settingsForm).entries());
        try {
          await requestJson("/api/settings", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(values),
          });
          notify("Detection settings saved.");
        } catch (error) {
          notify(error.message, true);
        }
      });
    }

    document.querySelectorAll(".status-select").forEach((select) => {
      select.addEventListener("change", async () => {
        try {
          await requestJson(`/api/alerts/${select.dataset.alertId}/status`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: select.value }),
          });
          notify(`Alert status updated to ${select.value}.`);
          await loadOverview();
        } catch (error) {
          notify(error.message, true);
        }
      });
    });
  });
})();
