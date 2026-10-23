// C-UAS Platform SOC Dashboard - application logic.
//
// Every value shown here comes from the FastAPI REST API at API_BASE
// (default http://127.0.0.1:8000) polled in real time. When the API is
// unreachable the panels keep their last known state and the status
// badge goes offline; no metric is ever fabricated.
//
//
// Drone positions are a visualization mirror: /swarm/simulate returns the
// swarm config (seed, count, spread, speed), and this client renders drone
// positions with the platform's own deterministic swarm model so the
// scatter view moves in real time. All metrics (leak rate, kills, counts,
// compliance, spot size) are read straight from API responses.

"use strict";

const API_BASE = (function () {
  const meta = document.body && document.body.dataset.apiBase;
  if (meta) return meta.replace(/\/$/, "");
  return "http://127.0.0.1:8000";
})();

const POLL_MS = 4000;
const FETCH_TIMEOUT_MS = 3000;

const state = {
  online: false,
  lastUpdated: null,
  health: null,
  swarm: null,
  engagement: null,
  benchmarks: null,
  compliance: null,
  systems: [],
  risks: [],
  controls: [],
  dew: [],
};

// ---------------------------------------------------------------------------
// Seeded PRNG (simple LCG) for the client-side swarm mirror. Deterministic
// for a given seed, same as the server-side SwarmSimulator seed contract.
function makePrng(seed) {
  let s = (seed >>> 0) || 1;
  return function () {
    s = (s * 1664525 + 1013904223) >>> 0;
    return (s >>> 8) / 16777216;
  };
}

// Drone positions at simulation time `now`, derived from the swarm config
// returned by /swarm/simulate. Mirrors c_uas.swarm.SwarmSimulator:
// approach from a random bearing at start_distance_km, climbing 100m->500m.
function swarmPositions(config, now) {
  const prng = makePrng(config.seed);
  const startDistanceM = config.start_distance_km * 1000;
  return config.tracks_generated > 0 ? Array.from({ length: config.num_drones || config.tracks_generated }, (_, i) => {
    // Arrival times mirror the server: uniform in [5, 5 + spread].
    const arrival = 5 + prng() * config.arrival_spread_s;
    const progress = Math.min(Math.max(now / arrival, 0), 1);
    const distanceM = startDistanceM * (1 - progress);
    const bearing = prng() * 2 * Math.PI;
    const evading = prng() < config.evasion_probability;
    return {
      id: i,
      x: distanceM * Math.cos(bearing),
      y: distanceM * Math.sin(bearing),
      z: 100 + progress * 400,
      evading,
      arrival,
    };
  }) : [];
}

// ---------------------------------------------------------------------------
// Fetch helpers

async function fetchJson(path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(API_BASE + path, {
      ...options,
      signal: controller.signal,
      headers: { "Content-Type": "application/json", ...options.headers },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch (err) {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function postJson(path, body) {
  return fetchJson(path, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

// ---------------------------------------------------------------------------
// Charts

Chart.defaults.animation = false;
Chart.defaults.responsive = true;
Chart.defaults.maintainAspectRatio = false;

const tracksChart = new Chart(document.getElementById("tracksChart"), {
  type: "scatter",
  data: {
    datasets: [
      {
        label: "tracked",
        data: [],
        pointBackgroundColor: "#22d3ee",
        pointBorderColor: "#0ea5e9",
        pointRadius: 4,
      },
      {
        label: "evading",
        data: [],
        pointBackgroundColor: "#f59e0b",
        pointBorderColor: "#b45309",
        pointRadius: 5,
      },
    ],
  },
  options: {
    plugins: {
      legend: { labels: { color: "#8a97ad", font: { size: 11 } } },
      title: { display: true, text: "Drone positions relative to defended asset (m)", color: "#8a97ad", font: { size: 12 } },
    },
    scales: {
      x: { type: "linear", min: -2400, max: 2400, title: { display: true, text: "x (m)", color: "#8a97ad" }, ticks: { color: "#8a97ad", font: { size: 10 } }, grid: { color: "#1f2a3d" } },
      y: { type: "linear", min: -2400, max: 2400, title: { display: true, text: "y (m)", color: "#8a97ad" }, ticks: { color: "#8a97ad", font: { size: 10 } }, grid: { color: "#1f2a3d" } },
    },
  },
});

const engagementChart = new Chart(document.getElementById("engagementChart"), {
  type: "bar",
  data: { datasets: [] },
  options: {
    indexAxis: "y",
    plugins: {
      legend: { display: false },
      title: { display: true, text: "Engagement timeline (seconds) — from /engagement/schedule", color: "#8a97ad", font: { size: 12 } },
      tooltip: { callbacks: { label: (ctx) => `track ${ctx.raw.y}: ${ctx.raw.x[0].toFixed(1)}s - ${ctx.raw.x[1].toFixed(1)}s (pk ${ctx.raw.customPk})` } },
    },
    scales: {
      x: { type: "linear", min: 0, title: { display: true, text: "time (s)", color: "#8a97ad" }, ticks: { color: "#8a97ad", font: { size: 10 } }, grid: { color: "#1f2a3d" } },
      y: { ticks: { color: "#8a97ad", font: { size: 10 } }, grid: { drawOnChartArea: false } },
    },
  },
});

const saturationChart = new Chart(document.getElementById("saturationChart"), {
  type: "line",
  data: { labels: [], datasets: [{ label: "leak rate", data: [], borderColor: "#ef4444", backgroundColor: "rgba(239, 68, 68, 0.1)", pointBackgroundColor: "#ef4444", tension: 0.3, fill: true }] },
  options: {
    plugins: {
      legend: { labels: { color: "#8a97ad", font: { size: 11 } } },
      title: { display: true, text: "Swarm saturation: leak rate vs drone count — from /benchmarks", color: "#8a97ad", font: { size: 12 } },
    },
    scales: {
      x: { title: { display: true, text: "drones in swarm", color: "#8a97ad" }, ticks: { color: "#8a97ad", font: { size: 10 } }, grid: { color: "#1f2a3d" } },
      y: { min: 0, max: 1, title: { display: true, text: "leak rate", color: "#8a97ad" }, ticks: { color: "#8a97ad", font: { size: 10 }, callback: (v) => (v * 100).toFixed(0) + "%" }, grid: { color: "#1f2a3d" } },
    },
  },
});

const dewChart = new Chart(document.getElementById("dewChart"), {
  type: "line",
  data: { labels: [], datasets: [{ label: "spot diameter (cm)", data: [], borderColor: "#a78bfa", backgroundColor: "rgba(167, 139, 250, 0.1)", pointBackgroundColor: "#a78bfa", tension: 0.3, fill: true }] },
  options: {
    plugins: {
      legend: { labels: { color: "#8a97ad", font: { size: 11 } } },
      title: { display: true, text: "DEW beam spot size vs range — from /dew/model", color: "#8a97ad", font: { size: 12 } },
    },
    scales: {
      x: { title: { display: true, text: "range (m)", color: "#8a97ad" }, ticks: { color: "#8a97ad", font: { size: 10 } }, grid: { color: "#1f2a3d" } },
      y: { min: 0, title: { display: true, text: "spot diameter (cm)", color: "#8a97ad" }, ticks: { color: "#8a97ad", font: { size: 10 } }, grid: { color: "#1f2a3d" } },
    },
  },
});

// Compliance gauge: custom canvas arc.
const gaugeCanvas = document.getElementById("complianceGauge");
const gaugeCtx = gaugeCanvas.getContext("2d");
let gaugeDpr = window.devicePixelRatio || 1;
function gaugeResize() {
  const cssW = gaugeCanvas.clientWidth;
  const cssH = gaugeCanvas.clientHeight;
  gaugeCanvas.width = cssW * gaugeDpr;
  gaugeCanvas.height = cssH * gaugeDpr;
  gaugeCtx.scale(gaugeDpr, gaugeDpr);
}
gaugeResize();
window.addEventListener("resize", gaugeResize);

function drawGauge(value, status) {
  const w = gaugeCanvas.clientWidth;
  const h = gaugeCanvas.clientHeight;
  const cx = w / 2;
  const cy = h / 2 + 8;
  const r = Math.min(cx, cy) - 24;
  gaugeCtx.clearRect(0, 0, w, h);

  // background arc
  gaugeCtx.beginPath();
  gaugeCtx.arc(cx, cy, r, -0.75 * Math.PI, 0.25 * Math.PI, false);
  gaugeCtx.lineWidth = 10;
  gaugeCtx.strokeStyle = "#1f2a3d";
  gaugeCtx.lineCap = "round";
  gaugeCtx.stroke();

  // value arc
  if (value != null) {
    const pct = Math.min(Math.max(value, 0), 100) / 100;
    const endAngle = -0.75 * Math.PI + pct * 1.5 * Math.PI;
    let color;
    if (value >= 90) color = "#22c55e";
    else if (value >= 60) color = "#f59e0b";
    else color = "#ef4444";
    gaugeCtx.beginPath();
    gaugeCtx.arc(cx, cy, r, -0.75 * Math.PI, endAngle, false);
    gaugeCtx.lineWidth = 10;
    gaugeCtx.strokeStyle = color;
    gaugeCtx.lineCap = "round";
    gaugeCtx.stroke();
  }

  gaugeCtx.fillStyle = "#e8eef6";
  gaugeCtx.font = "bold 20px ui-monospace, monospace";
  gaugeCtx.textAlign = "center";
  gaugeCtx.textBaseline = "middle";
  gaugeCtx.fillText(value == null ? "--" : value.toFixed(1) + "%", cx, cy - 6);

  gaugeCtx.fillStyle = "#8a97ad";
  gaugeCtx.font = "11px system-ui, sans-serif";
  gaugeCtx.fillText(status == null ? "--" : status.replace(/_/g, " "), cx, cy + 16);
}

// ---------------------------------------------------------------------------
// Renderers

function setStatus(online, text) {
  const el = document.getElementById("apiStatus");
  const ind = document.getElementById("statusIndicator");
  const txt = document.getElementById("statusText");
  ind.className = "indicator " + (online ? "live" : "offline");
  txt.textContent = online ? text : "API offline";
  el.setAttribute("aria-label", online ? "API online: " + text : "API offline");
}

function renderStats() {
  const swarm = state.swarm || {};
  const eng = state.engagement || {};
  document.getElementById("statTracks").textContent = swarm.tracks_generated == null ? "--" : swarm.tracks_generated;
  document.getElementById("statDensity").textContent =
    swarm.swarm_density_drones_per_s == null ? "swarm density --" : "swarm density " + swarm.swarm_density_drones_per_s + "/s";
  document.getElementById("statExpectedKills").textContent = eng.expected_kills == null ? "--" : eng.expected_kills.toFixed(2);
  document.getElementById("statEngaged").textContent =
    "engaged " + (eng.engaged_targets == null ? "--" : eng.engaged_targets) + " / leaked " + (eng.leaked_targets == null ? "--" : eng.leaked_targets);
  if (eng.leak_rate != null) {
    document.getElementById("statLeakRate").textContent = (eng.leak_rate * 100).toFixed(1) + "%";
    document.getElementById("statLeakNote").textContent = "from /engagement/schedule";
  } else if (swarm.leak_rate != null) {
    document.getElementById("statLeakRate").textContent = (swarm.leak_rate * 100).toFixed(1) + "%";
    document.getElementById("statLeakNote").textContent = "from /swarm/simulate";
  } else {
    document.getElementById("statLeakRate").textContent = "-- %";
    document.getElementById("statLeakNote").textContent = "no data";
  }
  if (state.compliance) {
    document.getElementById("statCompliance").textContent = state.compliance.compliance_percentage + "%";
    document.getElementById("statComplianceStatus").textContent = state.compliance.overall_status;
  }
}

function renderTracks() {
  const swarm = state.swarm;
  const tracked = [];
  const evading = [];
  let now = state.lastUpdated ? Date.now() : 0;
  if (swarm) {
    // Advance a visualization clock through the arrival window so the swarm moves.
    const tick = ((state.visualClock || 0) + 2) % (15 + swarm.arrival_spread_s);
    state.visualClock = tick;
    const positions = swarmPositions(swarm.config || swarm, tick);
    for (const p of positions) {
      (p.evading ? evading : tracked).push({ x: p.x, y: p.y });
    }
  }
  tracksChart.data.datasets[0].data = tracked;
  tracksChart.data.datasets[1].data = evading;
  tracksChart.update();
}

function renderEngagement() {
  const eng = state.engagement;
  if (!eng) return;
  const bars = [];
  for (const s of (eng.sequence || [])) {
    bars.push({
      x: [s.engage_start_s, s.engage_end_s],
      y: "track " + s.track_id,
      customPk: s.pk,
    });
  }
  engagementChart.data.datasets = [
    {
      label: "engaged",
      data: bars,
      backgroundColor: "#22d3ee",
      borderColor: "#0ea5e9",
      borderWidth: 0,
    },
  ];
  engagementChart.options.scales.x.max = eng.total_time_s > 0 ? Math.ceil(eng.total_time_s) : 40;
  engagementChart.update();
}

function renderSaturation() {
  const bench = state.benchmarks;
  const sat = bench && bench.swarm_saturation ? bench.swarm_saturation : {};
  const counts = Object.keys(sat).map(Number).sort((a, b) => a - b);
  saturationChart.data.labels = counts;
  saturationChart.data.datasets[0].data = counts.map((c) => sat[c]);
  saturationChart.update();
}

function renderCompliance() {
  const rep = state.compliance;
  drawGauge(rep && rep.compliance_percentage != null ? rep.compliance_percentage : null, rep ? rep.overall_status : null);
  const sysTable = document.getElementById("govSystemsTable");
  sysTable.replaceChildren();
  for (const sys of state.systems) {
    const tr = document.createElement("tr");
    const td1 = document.createElement("td");
    td1.textContent = sys.name;
    const td2 = document.createElement("td");
    td2.textContent = sys.lifecycle_stage;
    const td3 = document.createElement("td");
    td3.textContent = sys.risk_level;
    tr.appendChild(td1);
    tr.appendChild(td2);
    tr.appendChild(td3);
    sysTable.appendChild(tr);
  }
  const rcTable = document.getElementById("govRisksControlsTable");
  rcTable.replaceChildren();
  const tr = document.createElement("tr");
  const a = document.createElement("td");
  a.textContent = state.risks.length ? String(state.risks.length) : "--";
  const b = document.createElement("td");
  b.textContent = state.controls.filter((c) => c.implemented).length + "/" + state.controls.length;
  const c = document.createElement("td");
  c.textContent = state.compliance ? state.compliance.overall_status : "--";
  tr.appendChild(a);
  tr.appendChild(b);
  tr.appendChild(c);
  rcTable.appendChild(tr);
  document.getElementById("govSystems").textContent = state.systems.length || "--";
  document.getElementById("govOpenRisks").textContent = state.compliance ? state.compliance.open_risks : "--";
  document.getElementById("govControls").textContent = state.controls.filter(c => c.implemented).length + " / " + state.controls.length;
  document.getElementById("govIncidents").textContent = state.compliance ? state.compliance.open_incidents : "--";
}

function renderDew() {
  const series = state.dew;
  dewChart.data.labels = series.map((d) => d.range_m);
  dewChart.data.datasets[0].data = series.map((d) => d.spot_cm);
  dewChart.update();
  const at3km = series.find((d) => d.range_m === 3000) || series[0] || {};
  document.getElementById("dewSpot").textContent = at3km.spot_cm == null ? "-- cm" : at3km.spot_cm + " cm";
  document.getElementById("dewDwell").textContent = at3km.dwell_s == null ? "-- s" : at3km.dwell_s + " s";
  document.getElementById("dewTransmission").textContent = at3km.transmission == null ? "--" : (at3km.transmission * 100).toFixed(1) + "%";
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

async function tick() {
  const started = Date.now();

  const [health, swarm, engagement, benchmarks, compliance, systems, risks, controls] = await Promise.all([
    fetchJson("/"),
    postJson("/swarm/simulate", { num_drones: 16, spread_s: 10, speed_mps: 30, evasion: 0.3, seed: 42 }),
    postJson("/engagement/schedule", { num_drones: 8, dwell_s: 4, slew_s: 1.5, time_limit_s: 40 }),
    fetchJson("/benchmarks"),
    fetchJson("/compliance"),
    fetchJson("/systems"),
    fetchJson("/risks"),
    fetchJson("/controls"),
  ]);

  const online = health != null && swarm != null && engagement != null && compliance != null;
  setStatus(online, online ? "live" : "degraded");
  state.online = online;
  state.lastUpdated = started;

  if (swarm) state.swarm = swarm;
  if (engagement) state.engagement = engagement;
  if (benchmarks) state.benchmarks = benchmarks;
  if (compliance) state.compliance = compliance;
  if (systems) state.systems = systems.systems || [];
  if (risks) state.risks = risks.risks || [];
  if (controls) state.controls = controls.controls || [];

  // DEW spot size vs range: one model call per range point, real API values.
  const dewResults = [];
  for (const range of [1000, 1500, 2000, 3000, 4000, 5000]) {
    const res = await postJson("/dew/model", { laser: "fiber_50kw", range_m: range, material: "aluminum" });
    if (res) dewResults.push(res);
  }
  if (dewResults.length) state.dew = dewResults;

  document.getElementById("lastUpdated").textContent = "last updated: " + new Date(started).toLocaleTimeString();

  renderStats();
  renderTracks();
  renderEngagement();
  renderSaturation();
  renderCompliance();
  renderDew();
}

document.getElementById("pollNow").addEventListener("click", () => {
  void tick();
});

tick();
setInterval(tick, POLL_MS);
