"use strict";
/* Dashboard for Engine 4. Everything shown on screen is set with textContent (never innerHTML),
   so data coming from logs can never run as code. */
const $app = document.getElementById("app");
let token = sessionStorage.getItem("token") || null;
let user = null;
let tab = "overview";

// ---------- helpers ----------
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null) e.setAttribute(k, v);
  }
  for (const kid of kids.flat(Infinity)) if (kid !== null && kid !== undefined) e.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return e;
}
const svgEl = (tag, attrs, text) => {
  const e = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  if (text !== undefined) e.textContent = text;
  return e;
};
const fmtTime = (t) => (t ? String(t).replace("T", " ").replace(/\.\d+Z$/, "Z") : "-");
const num = (n, d = 0) => (n === null || n === undefined ? "-" : Number(n).toLocaleString(undefined, { maximumFractionDigits: d }));

async function api(path, opts = {}) {
  const isFormData = typeof FormData !== "undefined" && opts.body instanceof FormData;
  const headers = { ...(token ? { Authorization: "Bearer " + token } : {}) };
  if (!isFormData) {
    headers["Content-Type"] = "application/json";
  }
  if (opts.headers) Object.assign(headers, opts.headers);
  const res = await fetch("/api/v1" + path, {
    method: opts.method || "GET",
    headers,
    body: isFormData ? opts.body : (opts.body ? JSON.stringify(opts.body) : undefined),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && token) { logoutLocal(); }
    throw new Error((data.error && data.error.message) || "Request failed (" + res.status + ")");
  }
  return data;
}
const qs = (o) => { const p = new URLSearchParams(); for (const [k, v] of Object.entries(o)) if (v !== "" && v != null) p.set(k, v); return p.toString(); };
const can = (perm) => user && user.permissions.includes(perm);
const showMsg = (box, text, err) => { box.replaceChildren(text ? el("div", { class: "msg" + (err ? " err" : "") }, text) : ""); };

// ---------- login ----------
function renderLogin(message) {
  const msg = el("div");
  const u = el("input", { id: "u", autocomplete: "username", required: "" });
  const p = el("input", { id: "p", type: "password", autocomplete: "current-password", required: "" });
  const form = el("form", { class: "login", onsubmit: async (ev) => {
    ev.preventDefault();
    try {
      const r = await api("/auth/login", { method: "POST", body: { username: u.value, password: p.value } });
      token = r.token; user = r.user; sessionStorage.setItem("token", token); renderShell();
    } catch (e) { showMsg(msg, e.message, true); }
  } },
    el("h1", {}, "Network Traffic Monitor"), el("p", {}, "Sign in to continue"), msg,
    el("label", {}, "Username", u), el("label", {}, "Password", p), el("button", { class: "btn", type: "submit" }, "Sign in"));
  if (message) showMsg(msg, message, true);
  $app.replaceChildren(form);
}
function logoutLocal() { token = null; user = null; sessionStorage.removeItem("token"); renderLogin("Your session ended. Please sign in again."); }

// ---------- shell ----------
const TABS = [["overview", "Overview"], ["alerts", "Alerts"], ["logs", "Log search"], ["bench", "Benchmarks"], ["runs", "Runs"]];
function renderShell() {
  const main = el("main");
  const nav = el("nav", {}, TABS.map(([id, label]) => el("button", { class: id === tab ? "on" : "", onclick: () => { tab = id; renderShell(); } }, label)));
  const head = el("header", {}, el("h1", {}, "Network Traffic Monitor"),
    el("span", { class: "who" }, (user.fullName || user.username) + " · " + user.role),
    el("button", { class: "btn alt", onclick: async () => { try { await api("/auth/logout", { method: "POST" }); } catch (e) {} token = null; user = null; sessionStorage.removeItem("token"); renderLogin(); } }, "Sign out"));
  $app.replaceChildren(head, nav, main);
  ({ overview: viewOverview, alerts: viewAlerts, logs: viewLogs, bench: viewBench, runs: viewRuns })[tab](main).catch((e) => main.replaceChildren(el("div", { class: "msg err" }, e.message)));
}

// ---------- overview ----------
function barChart(items, colors) {
  const w = 520, h = 190, pad = 34, max = Math.max(1, ...items.map((i) => i[1]));
  const svg = svgEl("svg", { viewBox: `0 0 ${w} ${h}`, width: "100%", role: "img", "aria-label": "Bar chart" });
  const bw = (w - pad * 2) / items.length;
  items.forEach(([label, value], i) => {
    const bh = ((h - pad * 2) * value) / max, x = pad + i * bw + bw * 0.2;
    svg.append(svgEl("rect", { x, y: h - pad - bh, width: bw * 0.6, height: bh, rx: 4, fill: colors[i] }));
    svg.append(svgEl("text", { x: x + bw * 0.3, y: h - pad - bh - 6, "text-anchor": "middle" }, String(value)));
    svg.append(svgEl("text", { x: x + bw * 0.3, y: h - pad + 16, "text-anchor": "middle" }, label));
  });
  svg.append(svgEl("line", { x1: pad, x2: w - pad, y1: h - pad, y2: h - pad, stroke: "currentColor", opacity: ".25" }));
  return svg;
}
const SEV_COLOR = { CRITICAL: "#b3261e", HIGH: "#d9622b", MEDIUM: "#c79a1a", LOW: "#3f7f5f" };
async function viewOverview(main) {
  const s = await api("/dashboard/summary");
  const card = (n, l) => el("div", { class: "card" }, el("div", { class: "n" }, num(n)), el("div", { class: "l" }, l));
  main.replaceChildren(
    el("div", { class: "cards" }, card(s.runs, "Processing runs"), card(s.eventsStored, "Events stored"), card(s.recordsMalformed, "Malformed rows skipped"),
      card(s.alertsTotal, "Alerts"), card(s.alertsByStatus.OPEN, "Open alerts")),
    el("div", { class: "panel" }, el("h2", {}, "Alerts by severity"),
      barChart(Object.entries(s.alertsBySeverity), Object.keys(s.alertsBySeverity).map((k) => SEV_COLOR[k]))),
    el("div", { class: "panel" }, el("h2", {}, "Alerts by status"),
      barChart(Object.entries(s.alertsByStatus), ["#2f5d62", "#6a9fa5", "#9bbfc3"])));
}

// ---------- paging ----------
function pager(res, go) {
  const pages = Math.max(1, Math.ceil(res.total / res.size));
  return el("div", { class: "pager" },
    el("button", { class: "btn alt", disabled: res.page <= 1 ? "" : null, onclick: () => go(res.page - 1) }, "Previous"),
    el("span", {}, `Page ${res.page} of ${pages} · ${num(res.total)} results`),
    el("button", { class: "btn alt", disabled: res.page >= pages ? "" : null, onclick: () => go(res.page + 1) }, "Next"));
}
function table(cols, rows, onRow) {
  if (!rows.length) return el("div", { class: "empty" }, "Nothing matches these filters.");
  return el("table", {}, el("thead", {}, el("tr", {}, cols.map((c) => el("th", {}, c[0])))),
    el("tbody", {}, rows.map((r) => el("tr", { class: onRow ? "click" : "", onclick: onRow ? () => onRow(r) : null }, cols.map((c) => el("td", {}, c[1](r)))))));
}
const sevBadge = (s) => el("span", { class: "badge " + s }, s);

// ---------- alerts ----------
async function viewAlerts(main) {
  const msg = el("div"), out = el("div"), detail = el("div");
  const sev = el("select", {}, ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((v) => el("option", { value: v }, v || "Any severity")));
  const st = el("select", {}, ["OPEN", "ACKNOWLEDGED", "RESOLVED"].map((v) => el("option", { value: v }, v)));
  const ip = el("input", { placeholder: "e.g. 192.168.1.5" });
  async function load(page = 1) {
    showMsg(msg, "");
    try {
      const r = await api("/alerts?" + qs({ severity: sev.value, status: st.value, ip: ip.value.trim(), page, size: 15 }));
      out.replaceChildren(table([["Severity", (a) => sevBadge(a.severityName)], ["Rule", (a) => a.ruleCode], ["IP", (a) => a.affectedIp],
        ["Detected", (a) => fmtTime(a.detectedAt)], ["Status", (a) => a.alertStatus], ["Repeats hidden", (a) => a.suppressionCount]], r.items, showDetail), pager(r, load));
    } catch (e) { showMsg(msg, e.message, true); }
  }
  async function showDetail(a) {
    const d = await api("/alerts/" + encodeURIComponent(a.alertId));
    const buttons = can("update_alert") ? ["OPEN", "ACKNOWLEDGED", "RESOLVED"].filter((s) => s !== d.alertStatus).map((s) =>
      el("button", { class: "btn alt", onclick: async () => { try { await api("/alerts/" + encodeURIComponent(d.alertId), { method: "PATCH", body: { status: s } }); await load(); showDetail(a); } catch (e) { showMsg(msg, e.message, true); } } }, "Mark " + s.toLowerCase())) : [];
    detail.replaceChildren(el("div", { class: "panel" }, el("h2", {}, d.ruleCode + " · " + d.affectedIp), sevBadge(d.severityName), " ",
      el("span", {}, " status: " + d.alertStatus + (d.statusUpdatedAt ? " (changed " + fmtTime(d.statusUpdatedAt) + ")" : "")),
      d.alertDescription ? el("p", {}, d.alertDescription) : null, el("div", {}, buttons.map((b) => [b, " "])),
      el("h2", { class: "gap" }, "Events behind this alert (" + d.events.length + ")"),
      table([["Time", (e) => fmtTime(e.eventTimestamp)], ["Source", (e) => e.sourceIp + ":" + (e.sourcePort ?? "-")], ["Destination", (e) => e.destinationIp + ":" + (e.destinationPort ?? "-")], ["State", (e) => e.connStateCode || "-"]], d.events)));
    detail.scrollIntoView({ behavior: "smooth" });
  }
  main.replaceChildren(el("div", { class: "panel" }, el("h2", {}, "Alerts (most urgent first)"),
    el("form", { class: "filters", onsubmit: (e) => { e.preventDefault(); load(); } }, el("label", {}, "Severity", sev), el("label", {}, "Status", st), el("label", {}, "Affected IP", ip), el("button", { class: "btn", type: "submit" }, "Search")),
    msg, out), detail);
  load();
}

// ---------- logs ----------
async function viewLogs(main) {
  const runs = await api("/runs?size=100");
  const msg = el("div"), out = el("div");
  const run = el("select", {}, [el("option", { value: "" }, "Any run"), ...runs.items.map((r) => el("option", { value: r.runId }, r.fileName + " · " + fmtTime(r.startedAt)))]);
  if (runs.items.length) run.value = runs.items[0].runId;
  const ip = el("input", { placeholder: "source or destination" }), proto = el("input", { placeholder: "tcp / udp / icmp", size: 10 });
  const from = el("input", { type: "datetime-local" }), to = el("input", { type: "datetime-local" });
  const iso = (v) => (v ? new Date(v).toISOString() : "");
  async function load(page = 1) {
    showMsg(msg, "");
    try {
      const r = await api("/logs?" + qs({ runId: run.value, ip: ip.value.trim(), protocol: proto.value.trim(), from: iso(from.value), to: iso(to.value), page, size: 25 }));
      out.replaceChildren(table([["Time", (e) => fmtTime(e.eventTimestamp)], ["Source", (e) => e.sourceIp + ":" + (e.sourcePort ?? "-")], ["Destination", (e) => e.destinationIp + ":" + (e.destinationPort ?? "-")],
        ["Proto", (e) => e.protocolName || "-"], ["State", (e) => e.connStateCode || "-"], ["Bytes out/in", (e) => num(e.origBytes) + " / " + num(e.respBytes)], ["Duration (s)", (e) => num(e.duration, 3)]], r.items), pager(r, load));
    } catch (e) { showMsg(msg, e.message, true); }
  }
  main.replaceChildren(el("div", { class: "panel" }, el("h2", {}, "Search network logs"),
    el("form", { class: "filters", onsubmit: (e) => { e.preventDefault(); load(); } }, el("label", {}, "Run", run), el("label", {}, "IP address", ip), el("label", {}, "Protocol", proto), el("label", {}, "From", from), el("label", {}, "To", to), el("button", { class: "btn", type: "submit" }, "Search")),
    msg, out));
  load();
}

// ---------- benchmarks ----------
function timeChart(items) {
  const w = 640, h = 230, pad = 40, max = Math.max(0.001, ...items.flatMap((i) => i.metrics.map((m) => m.executionTimeSec)));
  const svg = svgEl("svg", { viewBox: `0 0 ${w} ${h}`, width: "100%", role: "img", "aria-label": "Execution time by run" });
  const gw = (w - pad * 2) / items.length;
  items.forEach((it, i) => {
    [...it.metrics].sort((a, b) => (a.executionMode < b.executionMode ? 1 : -1)).forEach((m, j) => {
      const bh = ((h - pad * 2) * m.executionTimeSec) / max, x = pad + i * gw + gw * 0.12 + j * gw * 0.38;
      svg.append(svgEl("rect", { x, y: h - pad - bh, width: gw * 0.34, height: bh, rx: 3, fill: m.executionMode === "SEQUENTIAL" ? "#8aa5a8" : "#2f5d62" }));
      svg.append(svgEl("text", { x: x + gw * 0.17, y: h - pad - bh - 5, "text-anchor": "middle" }, num(m.executionTimeSec, 2) + "s"));
    });
    svg.append(svgEl("text", { x: pad + i * gw + gw / 2, y: h - pad + 16, "text-anchor": "middle" }, it.speedupRatio ? "S = " + num(it.speedupRatio, 2) + "x" : "run " + (i + 1)));
  });
  svg.append(svgEl("line", { x1: pad, x2: w - pad, y1: h - pad, y2: h - pad, stroke: "currentColor", opacity: ".25" }));
  return svg;
}
async function viewBench(main) {
  const r = await api("/benchmarks?size=8");
  if (!r.items.length) { main.replaceChildren(el("div", { class: "panel empty" }, "No benchmark data yet. Start a run first.")); return; }
  main.replaceChildren(
    el("div", { class: "panel" }, el("h2", {}, "Execution time: sequential vs multithreaded (newest runs, speedup S = T_seq / T_mt)"), timeChart([...r.items].reverse()),
      el("div", { class: "legend" }, el("span", {}, el("i", { class: "sw-seq" }), "Sequential"), el("span", {}, el("i", { class: "sw-mt" }), "Multithreaded"))),
    el("div", { class: "panel" }, el("h2", {}, "Details"), table([["Run", (x) => x.fileName + " · " + fmtTime(x.startedAt)], ["Mode", (x) => x.metrics.map((m) => m.executionMode + " ×" + m.workerCount).join(", ")],
      ["Time (s)", (x) => x.metrics.map((m) => num(m.executionTimeSec, 2)).join(" / ")], ["Throughput (rec/s)", (x) => x.metrics.map((m) => num(m.throughputRecSec)).join(" / ")],
      ["CPU %", (x) => x.metrics.map((m) => num(m.cpuUsagePct, 1)).join(" / ")], ["Peak RAM (MB)", (x) => x.metrics.map((m) => num(m.peakMemoryMb, 1)).join(" / ")],
      ["Speedup", (x) => (x.speedupRatio ? num(x.speedupRatio, 2) + "x" : "-")], ["Outputs match", (x) => x.equivalenceStatus || "-"]], r.items)));
}

// ---------- runs ----------
async function viewRuns(main) {
  const msg = el("div"), list = el("div");
  const mode = el("select", {}, ["MULTITHREADED", "SEQUENTIAL", "BENCHMARK"].map((v) => el("option", { value: v }, v)));
  const threads = el("input", { type: "number", min: 1, max: 16, value: 4, required: "" });
  const fileUpload = el("input", { type: "file", accept: ".log,.txt,.jsonl" });
  const fileSelect = el("select", {}, el("option", { value: "" }, "-- Or choose existing file on server --"));
  const manualFile = el("input", { placeholder: "sample_conn.log" });

  async function refreshServerFiles() {
    try {
      const res = await api("/logs/files");
      fileSelect.replaceChildren(el("option", { value: "" }, "-- Or choose existing file on server --"));
      for (const f of res.files || []) {
        fileSelect.append(el("option", { value: f.fileName }, f.fileName + " (" + num(f.sizeBytes) + " B)"));
      }
    } catch (_) {}
  }

  fileSelect.addEventListener("change", () => {
    if (fileSelect.value) {
      manualFile.value = fileSelect.value;
      fileUpload.value = "";
    }
  });

  fileUpload.addEventListener("change", () => {
    if (fileUpload.files && fileUpload.files.length > 0) {
      fileSelect.value = "";
    }
  });

  async function load(page = 1) {
    const r = await api("/runs?" + qs({ page, size: 10 }));
    list.replaceChildren(
      table(
        [
          ["File", (x) => x.fileName],
          ["Mode", (x) => x.runMode],
          ["Status", (x) => x.status],
          ["Started", (x) => fmtTime(x.startedAt)],
          ["Valid", (x) => num(x.validCount)],
          ["Malformed", (x) => num(x.malformedCount)],
        ],
        r.items
      ),
      pager(r, load)
    );
  }

  const form = can("start_run")
    ? el(
        "form",
        {
          class: "filters upload-form",
          onsubmit: async (e) => {
            e.preventDefault();
            try {
              if (fileUpload.files && fileUpload.files.length > 0) {
                showMsg(msg, "Uploading " + fileUpload.files[0].name + " and starting analysis...");
                const fd = new FormData();
                fd.append("file", fileUpload.files[0]);
                fd.append("mode", mode.value);
                fd.append("threads", threads.value);
                fd.append("runImmediately", "true");
                const r = await api("/logs/upload", { method: "POST", body: fd });
                showMsg(msg, "Run started for " + r.fileName + " (" + r.status + "). Refreshing...");
                fileUpload.value = "";
                await refreshServerFiles();
                setTimeout(load, 1500);
                setTimeout(load, 4000);
              } else {
                const targetFile = fileSelect.value || manualFile.value.trim();
                if (!targetFile) {
                  throw new Error("Please select a file to upload or choose an existing server log.");
                }
                const r = await api("/runs", {
                  method: "POST",
                  body: { mode: mode.value, threads: Number(threads.value), logFile: targetFile },
                });
                showMsg(msg, "Run started (" + r.status + "). Refreshing...");
                setTimeout(load, 1500);
                setTimeout(load, 4000);
              }
            } catch (err) {
              showMsg(msg, err.message, true);
            }
          },
        },
        el("label", {}, "Upload Log File (.log, .txt)", fileUpload),
        el("label", {}, "Existing Server Logs", fileSelect),
        el("label", {}, "Mode", mode),
        el("label", {}, "Threads (1–16)", threads),
        el("button", { class: "btn", type: "submit" }, "Start Run")
      )
    : el("p", { class: "empty" }, "Your role can view runs but not start them.");

  main.replaceChildren(
    el("div", { class: "panel" },
      el("h2", {}, "Processing Runs & Log Upload"),
      form,
      msg,
      list,
      el("button", { class: "btn alt", onclick: () => { load(); refreshServerFiles(); } }, "Refresh")
    )
  );
  load();
  refreshServerFiles();
}

// ---------- start ----------
(async function start() {
  if (!token) return renderLogin();
  try { user = await api("/auth/me"); renderShell(); } catch (e) { renderLogin(); }
})();
