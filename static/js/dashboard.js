(() => {
  if (!window.CYBERGUARD_DASHBOARD || typeof Chart === "undefined") return;
  fetch(window.CYBERGUARD_DASHBOARD).then((r) => r.json()).then((data) => {
    const colors = { critical: "#ff667d", high: "#ff9b63", medium: "#f6c85f", low: "#62d5a0" };
    const severity = ["critical", "high", "medium", "low"];
    const canvas = document.getElementById("severityChart");
    if (canvas) new Chart(canvas, { type: "doughnut", data: { labels: severity, datasets: [{ data: severity.map((s) => data.severity[s] || 0), backgroundColor: severity.map((s) => colors[s]), borderWidth: 0 }] }, options: { cutout: "78%", plugins: { legend: { display: false } } } });
    const labels = data.threat_timeline.map((item) => item.day.slice(5));
    const posture = document.getElementById("postureChart");
    if (posture) new Chart(posture, { type: "line", data: { labels, datasets: [{ label: "Incidents", data: data.threat_timeline.map((item) => item.total), borderColor: "#8ce5c0", backgroundColor: "rgba(140,229,192,.08)", fill: true, tension: .42, pointRadius: 2, borderWidth: 2 }] }, options: chartOptions() });
    const status = document.getElementById("statusChart");
    if (status) new Chart(status, { type: "bar", data: { labels: Object.keys(data.status), datasets: [{ label: "Cases", data: Object.values(data.status), backgroundColor: "#70b8ee", borderRadius: 3 }] }, options: chartOptions() });
    const login = document.getElementById("loginChart");
    if (login) new Chart(login, { type: "line", data: { labels: data.login_activity.map((item) => item.day.slice(5)), datasets: [{ label: "Auth events", data: data.login_activity.map((item) => item.total), borderColor: "#f5a267", backgroundColor: "rgba(245,162,103,.08)", fill: true, tension: .35, pointRadius: 2 }] }, options: chartOptions() });
  }).catch(() => {});

  function chartOptions() {
    return { responsive: true, maintainAspectRatio: false, scales: { x: { grid: { display: false }, ticks: { color: "#718078", font: { family: "DM Mono" } } }, y: { grid: { color: "rgba(131,153,143,.1)" }, ticks: { color: "#718078", font: { family: "DM Mono" } }, beginAtZero: true } }, plugins: { legend: { display: false } } };
  }
})();
