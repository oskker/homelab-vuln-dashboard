// Dashboard front end. No framework, no build step, no third-party requests.
//
// Security rule for this file: scan data and model output are untrusted text. They are
// only ever written with textContent (never innerHTML), so a hostile banner, hostname
// or model reply cannot become markup or script. The page's Content-Security-Policy
// backs that up by refusing inline script.

const SEVERITIES = [
  { level: 4, key: "critical", label: "Critical" },
  { level: 3, key: "high", label: "High" },
  { level: 2, key: "medium", label: "Medium" },
  { level: 1, key: "low", label: "Low" },
];
const SEVERITY_LABEL = { 0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical" };
const WRITE_HEADERS = { "X-Requested-With": "vulndash" };
const VIEWS = ["overview", "trends", "scans"];
const PAGE_SIZE = 100;
const MAX_COLUMNS = 24;
const POLL_MS = 15000;
const ACTIVE_TASK = new Set(["Requested", "Queued", "Running", "Stop Requested", "Processing"]);
const SVG_NS = "http://www.w3.org/2000/svg";

const state = {
  view: "overview",
  summary: null,
  scans: [],
  hosts: [],
  findings: [],
  total: 0,
  trendDays: 90,
  openvas: null,
  lastSyncAt: null,
  pollTimer: null,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (name === "class") node.className = value;
    else if (name === "text") node.textContent = value;
    else node.setAttribute(name, value === true ? "" : String(value));
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function svgEl(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, String(value));
  return node;
}

function svgText(attrs, text) {
  const node = svgEl("text", attrs);
  node.textContent = text;
  return node;
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (!response.ok) {
    const detail = body && typeof body.detail === "string" ? body.detail : `Request failed (${response.status}).`;
    throw new Error(detail);
  }
  return body;
}

function postJson(path, data) {
  return api(path, {
    method: "POST",
    headers: { ...WRITE_HEADERS, "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}

// ---------- Formatting ----------

const dateFormat = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", year: "numeric" });
const shortDateFormat = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" });
const dateTimeFormat = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit" });
const timeFormat = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });
const numberFormat = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });

function parseDate(value) {
  if (!value) return null;
  // Date-only values would be read as UTC and can shift a day, so build them locally.
  const dateOnly = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  const date = dateOnly ? new Date(+dateOnly[1], +dateOnly[2] - 1, +dateOnly[3]) : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function formatDate(value, formatter = dateFormat) {
  const date = parseDate(value);
  return date ? formatter.format(date) : "";
}

function timeAgo(value) {
  const date = parseDate(value);
  if (!date) return "";
  const minutes = Math.round((Date.now() - date.getTime()) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  return formatDate(value);
}

function plural(count, word, many = `${word}s`) {
  return `${count} ${count === 1 ? word : many}`;
}

function totalOpen(open) {
  return SEVERITIES.reduce((sum, s) => sum + (open?.[s.key] ?? 0), 0);
}

function hostLabel(host) {
  return host.hostname || host.ip;
}

function setNotice(text, isError = false) {
  const notice = $("#notice");
  notice.textContent = text;
  notice.classList.toggle("error", isError);
  notice.hidden = !text;
}

// ---------- Tooltip (hover and keyboard focus show the same thing) ----------

const tooltip = $("#tooltip");

function showTooltip(target, title, rows) {
  tooltip.replaceChildren(el("div", { class: "tip-title", text: title }));
  for (const row of rows) {
    tooltip.append(
      el(
        "div",
        { class: "tip-row" },
        row.key ? el("span", { class: `tip-key ${row.key}` }) : null,
        el("span", { class: "tip-value", text: row.value }),
        el("span", { text: row.label }),
      ),
    );
  }
  tooltip.hidden = false;
  const box = target.getBoundingClientRect();
  const tip = tooltip.getBoundingClientRect();
  let left = box.left + box.width / 2 - tip.width / 2;
  left = Math.max(8, Math.min(left, window.innerWidth - tip.width - 8));
  let top = box.top - tip.height - 8;
  if (top < 8) top = Math.min(box.bottom + 8, window.innerHeight - tip.height - 8);
  tooltip.style.left = `${left}px`;
  tooltip.style.top = `${top}px`;
}

function hideTooltip() {
  tooltip.hidden = true;
}

function attachTooltip(target, title, rows, onShow, onHide) {
  const show = () => {
    showTooltip(target, title, rows);
    onShow?.();
  };
  const hide = () => {
    hideTooltip();
    onHide?.();
  };
  target.addEventListener("pointerenter", show);
  target.addEventListener("focus", show);
  target.addEventListener("pointerleave", hide);
  target.addEventListener("blur", hide);
}

const sevRows = (open) => SEVERITIES.map((s) => ({ key: `sev-${s.level}`, value: String(open[s.key]), label: s.label }));

// ---------- Header and stat strip ----------

function renderMeta(summary) {
  const parts = [];
  const scan = summary.last_scan;
  if (scan) {
    parts.push(`Last scan ${formatDate(scan.scan_time)}: ${scan.new} new, ${scan.fixed} fixed, ${scan.reopened} reopened.`);
  }
  parts.push(
    summary.intel_updated_at
      ? `Threat intel updated ${formatDate(summary.intel_updated_at)}.`
      : "Threat intel not loaded yet. Choose Update threat intel to add KEV and EPSS data.",
  );
  $("#scan-meta").textContent = parts.join(" ");
  $("#version").textContent = `Version ${summary.version}`;
}

function statTile(label, value, note, unit) {
  const dd = el("dd", {}, String(value));
  if (unit) dd.append(" ", el("small", { text: unit }));
  return el("div", {}, el("dt", { text: label }), dd, note ? el("p", { class: "stat-note", text: note }) : null);
}

function renderStats(summary) {
  const oldest = summary.oldest_open_high_or_critical_days;
  $("#stats").replaceChildren(
    statTile("Open critical", summary.open.critical),
    statTile("Open high", summary.open.high),
    statTile(
      "Known exploited",
      summary.kev_open,
      summary.intel_updated_at ? "Open findings on the CISA KEV list" : "Needs threat intel",
    ),
    statTile("Hosts", summary.hosts),
    statTile(
      "Oldest high or critical",
      oldest === null ? "None" : oldest,
      "Time it has stayed open",
      oldest === null ? "" : oldest === 1 ? "day" : "days",
    ),
  );
}

// ---------- Horizontal bars (severity counts, days to fix) ----------

function renderHBars(container, rows, { unit = "", empty = "" } = {}) {
  const max = Math.max(1, ...rows.map((r) => r.value ?? 0));
  container.replaceChildren();
  for (const row of rows) {
    const value = row.value ?? 0;
    const fill = el("span", { class: `fill sev-${row.level}${value ? "" : " zero"}` });
    fill.style.width = `calc((100% - 64px) * ${value / max})`;
    const shown = row.value === null || row.value === undefined ? empty : `${numberFormat.format(value)}${unit}`;
    const track = el(
      "div",
      { class: "hbar-track", tabindex: "0", role: "img", "aria-label": `${row.label}: ${shown}` },
      fill,
      el("span", { class: "value", text: shown }),
    );
    attachTooltip(track, row.label, row.tip);
    container.append(el("span", {}, el("span", { class: `swatch sev-${row.level}` }), row.label), track);
  }
}

function renderSeverityBars(open) {
  const total = totalOpen(open);
  renderHBars(
    $("#severity-bars"),
    SEVERITIES.map((s) => ({
      level: s.level,
      label: s.label,
      value: open[s.key],
      tip: [
        { value: String(open[s.key]), label: "open" },
        { value: total ? `${Math.round((open[s.key] / total) * 100)}%` : "0%", label: "of open findings" },
      ],
    })),
  );
}

// ---------- Shared chart pieces ----------

function niceAxis(maxValue) {
  if (maxValue <= 4) return { top: Math.max(maxValue, 1), step: 1 };
  const rough = maxValue / 4;
  const magnitude = 10 ** Math.floor(Math.log10(rough));
  const step = [1, 2, 5, 10].map((m) => m * magnitude).find((s) => s >= rough);
  return { top: Math.ceil(maxValue / step) * step, step };
}

// A bar with its data end rounded and its baseline end square.
function barPath(x, y, width, height, radius, up = true) {
  const r = Math.min(radius, width / 2, height);
  if (up) {
    return `M${x},${y + height} V${y + r} Q${x},${y} ${x + r},${y} H${x + width - r} Q${x + width},${y} ${x + width},${y + r} V${y + height} Z`;
  }
  return `M${x},${y} V${y + height - r} Q${x},${y + height} ${x + r},${y + height} H${x + width - r} Q${x + width},${y + height} ${x + width},${y + height - r} V${y} Z`;
}

function chartFrame(label, { width = 640, height = 250, left = 40 } = {}) {
  const margin = { top: 22, right: 14, bottom: 28, left };
  const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, role: "group", "aria-label": label });
  return { svg, width, height, margin, plotWidth: width - margin.left - margin.right, plotHeight: height - margin.top - margin.bottom };
}

function gridLines(frame, y, axis, { from = 0, format = String } = {}) {
  const { svg, margin, width } = frame;
  for (let tick = from; tick <= axis.top; tick += axis.step) {
    svg.append(svgEl("line", { class: tick === 0 ? "baseline" : "grid", x1: margin.left, x2: width - margin.right, y1: y(tick), y2: y(tick) }));
    svg.append(svgText({ x: margin.left - 8, y: y(tick) + 4, "text-anchor": "end" }, format(Math.abs(tick))));
  }
}

function dateLabels(frame, points, centre) {
  const every = Math.ceil(points.length / 8);
  points.forEach((point, index) => {
    if (index % every === 0 || index === points.length - 1) {
      frame.svg.append(
        svgText({ x: centre(index), y: frame.height - 8, "text-anchor": "middle" }, formatDate(point.scan_time, shortDateFormat)),
      );
    }
  });
}

function columnGroup(frame, centre, band, label) {
  const group = svgEl("g", { class: "column", tabindex: "0", role: "img", "aria-label": label });
  group.append(svgEl("rect", { class: "hit", x: centre - band / 2, y: frame.margin.top - 14, width: band, height: frame.plotHeight + 14, rx: 4 }));
  return group;
}

function figureParts(figureId) {
  const figure = document.getElementById(figureId);
  if (!figure) throw new Error(`Missing figure ${figureId}`);
  return { figure, chart: $(".chart", figure), table: $(".table-wrap", figure), legend: $(".severity-legend", figure) };
}

function simpleTable(headers, rows) {
  return el(
    "table",
    { class: "data" },
    el("thead", {}, el("tr", {}, ...headers.map((h, i) => el("th", { scope: "col", class: i ? "num" : null, text: h })))),
    el("tbody", {}, ...rows.map((cells) => el("tr", {}, ...cells.map((c, i) => el("td", { class: i ? "num" : null, text: c }))))),
  );
}

function emptyChart(container, text) {
  container.replaceChildren(el("p", { class: "muted chart-empty", text }));
}

// ---------- Open findings after each scan (stacked columns) ----------

function renderOpenColumns(figureId, points) {
  const { chart, table, legend } = figureParts(figureId);
  legend.replaceChildren(...SEVERITIES.map((s) => el("li", {}, el("span", { class: `swatch sev-${s.level}` }), s.label)));
  table.replaceChildren(
    simpleTable(
      ["Scan", ...SEVERITIES.map((s) => s.label), "Total"],
      points.map((p) => [formatDate(p.scan_time), ...SEVERITIES.map((s) => p.open[s.key]), totalOpen(p.open)]),
    ),
  );
  if (!points.length) return emptyChart(chart, "No scans in this range.");

  const shown = points.slice(-MAX_COLUMNS);
  const frame = chartFrame("Stacked columns: open findings by severity after each scan");
  const totals = shown.map((p) => totalOpen(p.open));
  const axis = niceAxis(Math.max(1, ...totals));
  const y = (value) => frame.margin.top + frame.plotHeight - (value / axis.top) * frame.plotHeight;
  const band = frame.plotWidth / Math.max(shown.length, 1);
  const width = Math.min(24, band * 0.6);
  const centre = (i) => frame.margin.left + band * i + band / 2;
  gridLines(frame, y, axis);

  shown.forEach((point, index) => {
    const rows = sevRows(point.open);
    const group = columnGroup(
      frame,
      centre(index),
      band,
      `${formatDate(point.scan_time)}: ${rows.map((r) => `${r.value} ${r.label.toLowerCase()}`).join(", ")}`,
    );
    // Critical sits on the baseline so its change between scans is the easiest to read.
    const present = SEVERITIES.filter((s) => point.open[s.key] > 0);
    let running = 0;
    present.forEach((severity, position) => {
      const count = point.open[severity.key];
      const bottom = y(running);
      const top = y(running + count);
      running += count;
      const isTop = position === present.length - 1;
      const segmentHeight = Math.max(1, bottom - top - (isTop ? 0 : 2)); // 2px surface gap
      const segmentTop = bottom - segmentHeight;
      const left = centre(index) - width / 2;
      group.append(
        isTop
          ? svgEl("path", { class: `seg sev-${severity.level}`, d: barPath(left, segmentTop, width, segmentHeight, 4) })
          : svgEl("rect", { class: `seg sev-${severity.level}`, x: left, y: segmentTop, width, height: segmentHeight }),
      );
    });
    if (index === shown.length - 1) {
      group.append(svgText({ class: "total", x: centre(index), y: y(totals[index]) - 6, "text-anchor": "middle" }, String(totals[index])));
    }
    attachTooltip(group, formatDate(point.scan_time), [...rows, { value: String(totals[index]), label: "total open" }]);
    frame.svg.append(group);
  });
  dateLabels(frame, shown, centre);
  chart.replaceChildren(frame.svg);
}

// ---------- Found and fixed in each scan (columns above and below the baseline) ----------

function renderFlow(figureId, allPoints) {
  const { chart, table, figure } = figureParts(figureId);
  // The first scan ever finds everything at once; it says nothing about change.
  const points = allPoints.filter((p) => !p.first_scan);
  $(".figure-note", figure).hidden = points.length === allPoints.length;
  table.replaceChildren(
    simpleTable(
      ["Scan", "New", "Reopened", "Fixed"],
      points.map((p) => [formatDate(p.scan_time), p.new, p.reopened, p.fixed]),
    ),
  );
  if (!points.length) return emptyChart(chart, "No scans in this range.");

  const shown = points.slice(-MAX_COLUMNS);
  const frame = chartFrame("Columns: findings found above the line and fixed below it, for each scan");
  const found = shown.map((p) => p.new + p.reopened);
  const fixed = shown.map((p) => p.fixed);
  const axis = niceAxis(Math.max(1, ...found, ...fixed));
  const half = frame.plotHeight / 2;
  const zero = frame.margin.top + half;
  const y = (value) => zero - (value / axis.top) * half;
  const band = frame.plotWidth / Math.max(shown.length, 1);
  const width = Math.min(24, band * 0.6);
  const centre = (i) => frame.margin.left + band * i + band / 2;

  for (let tick = -axis.top; tick <= axis.top; tick += axis.step) {
    frame.svg.append(svgEl("line", { class: tick === 0 ? "baseline" : "grid", x1: frame.margin.left, x2: frame.width - frame.margin.right, y1: y(tick), y2: y(tick) }));
    frame.svg.append(svgText({ x: frame.margin.left - 8, y: y(tick) + 4, "text-anchor": "end" }, String(Math.abs(tick))));
  }

  shown.forEach((point, index) => {
    const label = `${formatDate(point.scan_time)}: ${found[index]} found, ${fixed[index]} fixed`;
    const group = columnGroup(frame, centre(index), band, label);
    const left = centre(index) - width / 2;
    if (found[index]) {
      const top = y(found[index]);
      group.append(svgEl("path", { class: "flow-found", d: barPath(left, top, width, zero - top - 1, 4, true) }));
    }
    if (fixed[index]) {
      const bottom = y(-fixed[index]);
      group.append(svgEl("path", { class: "flow-fixed", d: barPath(left, zero + 1, width, bottom - zero - 1, 4, false) }));
    }
    attachTooltip(group, formatDate(point.scan_time), [
      { key: "series-found", value: String(point.new), label: "new" },
      { key: "series-found", value: String(point.reopened), label: "reopened" },
      { key: "series-fixed", value: String(point.fixed), label: "fixed" },
    ]);
    frame.svg.append(group);
  });
  dateLabels(frame, shown, centre);
  chart.replaceChildren(frame.svg);
}

// ---------- Total risk (a single line) ----------

function renderRiskLine(figureId, points) {
  const { chart, table } = figureParts(figureId);
  const usable = points.filter((p) => p.risk_total !== null && p.risk_total !== undefined);
  table.replaceChildren(
    simpleTable(
      ["Scan", "Total risk", "Known exploited"],
      usable.map((p) => [formatDate(p.scan_time), numberFormat.format(p.risk_total), p.kev_open]),
    ),
  );
  if (!usable.length) return emptyChart(chart, "No scans with history in this range.");

  const shown = usable.slice(-MAX_COLUMNS);
  const frame = chartFrame("Line: total risk of open findings after each scan", { left: 48 });
  const axis = niceAxis(Math.max(1, ...shown.map((p) => p.risk_total)));
  const y = (value) => frame.margin.top + frame.plotHeight - (value / axis.top) * frame.plotHeight;
  const band = frame.plotWidth / Math.max(shown.length, 1);
  const centre = (i) => frame.margin.left + band * i + band / 2;
  gridLines(frame, y, axis, { format: (v) => numberFormat.format(v) });

  const path = shown.map((p, i) => `${i ? "L" : "M"}${centre(i)},${y(p.risk_total)}`).join(" ");
  frame.svg.append(svgEl("path", { class: "line", d: path }));
  const guide = svgEl("line", { class: "guide", y1: frame.margin.top, y2: frame.margin.top + frame.plotHeight, visibility: "hidden" });
  frame.svg.append(guide);

  shown.forEach((point, index) => {
    const group = columnGroup(frame, centre(index), band, `${formatDate(point.scan_time)}: total risk ${numberFormat.format(point.risk_total)}`);
    group.append(svgEl("circle", { class: "dot", cx: centre(index), cy: y(point.risk_total), r: 4 }));
    if (index === shown.length - 1) {
      group.append(svgText({ class: "total", x: centre(index), y: y(point.risk_total) - 10, "text-anchor": "middle" }, numberFormat.format(point.risk_total)));
    }
    attachTooltip(
      group,
      formatDate(point.scan_time),
      [
        { key: "series-found", value: numberFormat.format(point.risk_total), label: "total risk" },
        { value: String(point.kev_open), label: "known exploited" },
        { value: String(totalOpen(point.open)), label: "open findings" },
      ],
      () => {
        guide.setAttribute("x1", centre(index));
        guide.setAttribute("x2", centre(index));
        guide.setAttribute("visibility", "visible");
      },
      () => guide.setAttribute("visibility", "hidden"),
    );
    frame.svg.append(group);
  });
  dateLabels(frame, shown, centre);
  chart.replaceChildren(frame.svg);
}

// ---------- Open findings by age (one segmented bar per age band) ----------

function renderAgeBars(buckets) {
  const container = $("#age-bars");
  const max = Math.max(1, ...buckets.map((b) => totalOpen(b.open)));
  container.replaceChildren();
  for (const bucket of buckets) {
    const count = totalOpen(bucket.open);
    const bar = el("div", { class: "split wide", role: "img", tabindex: "0", "aria-label": `${bucket.label}: ${plural(count, "open finding")}` });
    bar.style.width = `calc((100% - 48px) * ${count / max})`;
    for (const severity of SEVERITIES) {
      const n = bucket.open[severity.key];
      if (!n) continue;
      const part = el("span", { class: `fill sev-${severity.level}` });
      part.style.flex = `${n} 1 0`;
      bar.append(part);
    }
    attachTooltip(bar, bucket.label, sevRows(bucket.open));
    container.append(
      el("span", { class: "age-label", text: bucket.label }),
      el("div", { class: "age-track" }, count ? bar : null, el("span", { class: "value", text: count })),
    );
  }
}

// ---------- Sparklines ----------

function sparkline(values, label) {
  const width = 120;
  const height = 28;
  if (!values.length) return el("span", { class: "muted", text: "No history" });
  const max = Math.max(1, ...values);
  const step = values.length > 1 ? (width - 8) / (values.length - 1) : 0;
  const x = (i) => 4 + i * step;
  const y = (v) => height - 4 - (v / max) * (height - 8);
  const svg = svgEl("svg", { class: "spark", viewBox: `0 0 ${width} ${height}`, width, height, role: "img", "aria-label": label });
  svg.append(svgEl("line", { class: "spark-base", x1: 0, x2: width, y1: height - 4, y2: height - 4 }));
  if (values.length > 1) svg.append(svgEl("path", { class: "spark-line", d: values.map((v, i) => `${i ? "L" : "M"}${x(i)},${y(v)}`).join(" ") }));
  const last = values.length - 1;
  svg.append(svgEl("circle", { class: "spark-dot", cx: x(last), cy: y(values[last]), r: 3 }));
  return svg;
}

// ---------- Overview: hosts ----------

function countCell(count) {
  return el("td", { class: `num${count ? "" : " zero"}`, text: count });
}

function renderHosts(hosts) {
  const rows = hosts.map((host) => {
    const select = el("select", { "aria-label": `Criticality of ${hostLabel(host)}` });
    for (let level = 1; level <= 5; level += 1) {
      select.append(el("option", { value: level, selected: level === host.criticality, text: level }));
    }
    select.addEventListener("change", () => updateCriticality(host, Number(select.value)));
    const values = host.history.map((p) => p.total);
    const spark = sparkline(values, `Open findings after the last ${plural(values.length, "scan")}: ${values.join(", ")}`);
    return el(
      "tr",
      {},
      el("td", {}, el("strong", { text: hostLabel(host) }), el("span", { class: "sub", text: host.ip })),
      el("td", { class: "hide-narrow", text: host.os || "Unknown" }),
      el("td", {}, select),
      el("td", { class: "num", text: Math.round(host.max_risk) }),
      ...SEVERITIES.map((s) => countCell(host.open[s.key])),
      el("td", { class: "hide-narrow" }, spark),
    );
  });
  $("#hosts-table tbody").replaceChildren(...rows);

  const hostFilter = $("#filters select[name=host_id]");
  const current = hostFilter.value;
  hostFilter.replaceChildren(
    el("option", { value: "", text: "All hosts" }),
    ...hosts.map((host) => el("option", { value: host.id, text: host.hostname ? `${host.hostname} (${host.ip})` : host.ip })),
  );
  hostFilter.value = current;
}

async function updateCriticality(host, criticality) {
  try {
    await api(`/api/hosts/${host.id}`, {
      method: "PATCH",
      headers: { ...WRITE_HEADERS, "Content-Type": "application/json" },
      body: JSON.stringify({ criticality }),
    });
    setNotice(`${hostLabel(host)} set to criticality ${criticality}. Risk scores updated.`);
    await refresh();
  } catch (error) {
    setNotice(error.message, true);
  }
}

// ---------- Overview: worklist ----------

function severityCell(level) {
  return el("td", { class: "sev-cell" }, el("span", { class: `swatch sev-${level}` }), SEVERITY_LABEL[level] ?? "Unknown");
}

function exploitedCell(finding) {
  if (finding.in_kev) {
    return el(
      "td",
      {},
      el("span", { class: "tag", text: "CISA KEV" }),
      finding.kev_due_date ? el("span", { class: "sub", text: `Federal due date ${formatDate(finding.kev_due_date)}` }) : null,
    );
  }
  if (finding.exploit_available) return el("td", { class: "muted", text: "Exploit exists" });
  return el("td", { class: "zero", text: "No" });
}

function findingButton(finding) {
  const button = el("button", { type: "button", class: "name-button", text: finding.plugin_name });
  button.addEventListener("click", () => openDetail(finding.id));
  return button;
}

function findingRow(finding) {
  const cves = finding.cves.slice(0, 3).join(", ") + (finding.cves.length > 3 ? ` and ${finding.cves.length - 3} more` : "");
  const fixed = finding.status === "fixed";
  return el(
    "tr",
    { class: `sev-${finding.severity}${fixed ? " fixed" : ""}` },
    el("td", { class: "num", text: Math.round(finding.risk_score) }),
    severityCell(finding.severity),
    el(
      "td",
      {},
      findingButton(finding),
      fixed ? el("span", { class: "sub" }, el("span", { class: "tag fixed", text: `Fixed ${formatDate(finding.fixed_at)}` })) : null,
      cves ? el("span", { class: "sub", text: cves }) : null,
    ),
    el("td", {}, hostLabel(finding.host), finding.host.hostname ? el("span", { class: "sub", text: finding.host.ip }) : null),
    el("td", { class: "num hide-narrow", text: finding.port ? `${finding.port}/${finding.protocol}` : "" }),
    el("td", { class: "num hide-narrow", text: finding.cvss_base === null ? "" : finding.cvss_base.toFixed(1) }),
    el("td", { class: "num", text: finding.epss === null ? "" : `${(finding.epss * 100).toFixed(finding.epss < 0.1 ? 1 : 0)}%` }),
    exploitedCell(finding),
    el("td", { class: "num", text: `${finding.age_days} d` }),
  );
}

function filterQuery(offset) {
  const form = new FormData($("#filters"));
  const params = new URLSearchParams({
    status: form.get("status"),
    min_severity: form.get("min_severity"),
    limit: String(PAGE_SIZE),
    offset: String(offset),
  });
  if (form.get("host_id")) params.set("host_id", form.get("host_id"));
  if (form.get("q")?.trim()) params.set("q", form.get("q").trim());
  if (form.get("kev_only")) params.set("kev_only", "true");
  return params;
}

async function loadFindings({ append = false } = {}) {
  const offset = append ? state.findings.length : 0;
  const table = $("#findings-table");
  table.style.opacity = "0.6"; // hold the previous rows while the new slice loads
  try {
    const page = await api(`/api/findings?${filterQuery(offset)}`);
    state.findings = append ? [...state.findings, ...page.items] : page.items;
    state.total = page.total;
    const body = $("#findings-table tbody");
    if (state.findings.length) {
      body.replaceChildren(...state.findings.map(findingRow));
    } else {
      body.replaceChildren(el("tr", {}, el("td", { colspan: "9", class: "muted", text: "Nothing matches these filters." })));
    }
    $("#worklist-count").textContent = `Showing ${state.findings.length} of ${plural(state.total, "finding")}, highest risk first.`;
    $("#load-more").hidden = state.findings.length >= state.total;
  } catch (error) {
    setNotice(error.message, true);
  } finally {
    table.style.opacity = "";
  }
}

// ---------- Trends view ----------

function changeNote(now, then, days) {
  if (then === null || then === undefined || now === null) return "";
  const start = days ? "at the start of the range" : "after the first scan";
  const delta = now - then;
  if (delta === 0) return `Same as ${start}`;
  return `${Math.abs(delta)} ${delta < 0 ? "fewer" : "more"} than ${start} (${then})`;
}

async function loadTrends() {
  try {
    const query = state.trendDays ? `?days=${state.trendDays}` : "";
    const trends = await api(`/api/trends${query}`);
    renderTrends(trends);
  } catch (error) {
    setNotice(`Could not load trends. ${error.message}`, true);
  }
}

function renderTrends(trends) {
  const s = trends.summary;
  const urgent = trends.fix_times.critical_and_high;
  const foundNote = [s.reopened ? `${s.new} new and ${s.reopened} reopened` : "New findings", s.includes_first_scan ? "after the first scan" : ""];
  $("#trend-stats").replaceChildren(
    statTile("Open findings", s.open_now ?? 0, changeNote(s.open_now, s.open_at_start, trends.range_days)),
    statTile("Found", s.new + s.reopened, foundNote.filter(Boolean).join(", ")),
    statTile("Fixed", s.fixed, "Closed by a later scan"),
    statTile(
      "Days to fix high and critical",
      urgent.median_days === null ? "None" : urgent.median_days,
      urgent.fixed ? `Median of ${plural(urgent.fixed, "fix", "fixes")}` : "Nothing fixed in this range",
      urgent.median_days === null ? "" : "days",
    ),
    statTile("Scans", s.scans, trends.range_days ? `In the last ${trends.range_days} days` : "Since the first scan"),
  );
  $("#range-note").textContent = trends.points.length
    ? `${formatDate(trends.points[0].scan_time)} to ${formatDate(trends.points.at(-1).scan_time)}`
    : "No scans in this range.";

  renderOpenColumns("trend-open", trends.points);
  renderFlow("trend-flow", trends.points);
  renderRiskLine("trend-risk", trends.points);
  renderHBars(
    $("#fix-bars"),
    SEVERITIES.map((sev) => {
      const fix = trends.fix_times[sev.key];
      return {
        level: sev.level,
        label: sev.label,
        value: fix.median_days,
        tip: fix.fixed
          ? [
              { value: String(fix.median_days), label: "median days" },
              { value: String(fix.mean_days), label: "average days" },
              { value: String(fix.fixed), label: fix.fixed === 1 ? "fix" : "fixes" },
            ]
          : [{ value: "0", label: "fixes in this range" }],
      };
    }),
    { unit: " d", empty: "None fixed" },
  );
  renderAgeBars(trends.open_by_age);
  renderHostTrends(trends.hosts);
}

function renderHostTrends(hosts) {
  const rows = hosts.map((host) => {
    const values = host.points.map((p) => totalOpen(p.open));
    const now = totalOpen(host.open_now);
    const then = host.open_then ? totalOpen(host.open_then) : null;
    const delta = then === null ? null : now - then;
    return el(
      "tr",
      {},
      el("td", {}, el("strong", { text: hostLabel(host) }), el("span", { class: "sub", text: host.ip })),
      el("td", {}, sparkline(values, `${hostLabel(host)}: ${values.join(", ")}`)),
      el("td", { class: "num", text: then ?? "" }),
      el("td", { class: "num", text: now }),
      el("td", { class: `num delta${delta < 0 ? " down" : delta > 0 ? " up" : ""}`, text: delta === null ? "" : delta === 0 ? "No change" : `${delta > 0 ? "+" : "−"}${Math.abs(delta)}` }),
    );
  });
  $("#host-trend-table tbody").replaceChildren(
    ...(rows.length ? rows : [el("tr", {}, el("td", { colspan: "5", class: "muted", text: "No host was scanned in this range." }))]),
  );
}

// ---------- Scans view: OpenVAS ----------

function taskStatusCell(task) {
  const cell = el("td", {});
  if (task.status === "Running" && task.progress >= 0) {
    const meter = el("span", { class: "meter", role: "img", "aria-label": `${task.progress}% done` }, el("span", { class: "meter-fill" }));
    meter.firstChild.style.width = `${Math.min(100, task.progress)}%`;
    cell.append(`Running, ${task.progress}%`, meter);
  } else {
    cell.append(task.status || "Unknown");
  }
  return cell;
}

function renderTasks(tasks) {
  const body = $("#ov-tasks tbody");
  if (!tasks.length) {
    body.replaceChildren(el("tr", {}, el("td", { colspan: "6", class: "muted", text: "No scan tasks yet. Choose New scan to create one." })));
    return;
  }
  body.replaceChildren(
    ...tasks.map((task) => {
      const start = el("button", { type: "button", class: "button small", text: "Start", disabled: ACTIVE_TASK.has(task.status) || !state.openvas?.ready });
      start.addEventListener("click", () => startTask(task, start));
      const last = task.last_report_time
        ? el("span", {}, formatDate(task.last_report_time), el("span", { class: "sub", text: task.last_report_imported ? "In the dashboard" : "Not imported yet" }))
        : el("span", { class: "muted", text: "None yet" });
      return el(
        "tr",
        {},
        el("td", {}, el("strong", { text: task.name }), el("span", { class: "sub", text: `${plural(task.reports, "report")}` })),
        el("td", { class: "hide-narrow", text: task.target || "" }),
        taskStatusCell(task),
        el("td", { class: "hide-narrow", text: task.schedule || "None" }),
        el("td", {}, last),
        el("td", { class: "actions" }, start),
      );
    }),
  );
}

function describeSync(sync) {
  if (!sync) return "";
  if (sync.error) return ` Last sync ${timeAgo(sync.at)} failed: ${sync.error}`;
  const parts = [`Last sync ${timeAgo(sync.at)}: ${plural(sync.imported.length, "report")} imported`];
  if (sync.waiting) parts.push(`${plural(sync.waiting, "scan")} still running`);
  if (sync.unfinished) parts.push(`${plural(sync.unfinished, "stopped scan")} skipped`);
  if (sync.errors?.length) parts.push(`${plural(sync.errors.length, "report")} could not be read`);
  return ` ${parts.join(", ")}.`;
}

async function loadOpenvas() {
  let status;
  try {
    status = await api("/api/openvas/status");
  } catch (error) {
    $("#ov-status").textContent = `Could not check OpenVAS. ${error.message}`;
    return;
  }
  state.openvas = status;
  const line = $("#ov-status");
  line.classList.toggle("ok", status.ready);
  let text = status.message;
  if (status.ready) {
    text = `Connected to OpenVAS (GMP ${status.version}). ${
      status.sync_minutes ? `Finished reports are imported every ${plural(status.sync_minutes, "minute")}.` : "Automatic import is off."
    }${describeSync(status.last_sync)}`;
  }
  line.textContent = text;

  const web = $("#ov-web");
  web.hidden = !status.configured;
  if (status.web_url) web.href = status.web_url;
  $("#ov-sync").hidden = !status.connected;
  $("#ov-new").hidden = !status.configured;
  $("#ov-new").disabled = !status.ready;
  $("#ov-tasks-wrap").hidden = !status.connected;

  if (status.connected) {
    try {
      renderTasks(await api("/api/openvas/tasks"));
    } catch (error) {
      setNotice(error.message, true);
    }
  }
  // A sync in the background brought in new reports: refresh everything else.
  const syncAt = status.last_sync?.at ?? null;
  if (syncAt && syncAt !== state.lastSyncAt) {
    const imported = status.last_sync.imported.length;
    if (state.lastSyncAt !== null && imported) {
      setNotice(`${plural(imported, "new OpenVAS report")} imported.`);
      await refresh({ skipOpenvas: true });
    }
    state.lastSyncAt = syncAt;
  }
}

async function startTask(task, button) {
  button.disabled = true;
  try {
    await api(`/api/openvas/tasks/${encodeURIComponent(task.id)}/start`, { method: "POST", headers: WRITE_HEADERS });
    setNotice(`${task.name} started. Its report is imported automatically when the scan finishes.`);
    await loadOpenvas();
  } catch (error) {
    setNotice(error.message, true);
    button.disabled = false;
  }
}

async function syncNow() {
  const button = $("#ov-sync");
  button.disabled = true;
  setNotice("Checking OpenVAS for finished reports");
  try {
    const result = await api("/api/openvas/sync", { method: "POST", headers: WRITE_HEADERS });
    const count = result.imported.length;
    const errors = result.errors.length ? ` ${result.errors.join(" ")}` : "";
    setNotice(count ? `Imported ${plural(count, "report")}.${errors}` : `Nothing new to import.${errors}`, Boolean(errors));
    state.lastSyncAt = null; // the refresh below owns this one
    await refresh();
  } catch (error) {
    setNotice(`Sync failed. ${error.message}`, true);
  } finally {
    button.disabled = false;
  }
}

function nextTwoAm() {
  const date = new Date();
  date.setDate(date.getDate() + (date.getHours() >= 2 ? 1 : 0));
  date.setHours(2, 0, 0, 0);
  const pad = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T02:00`;
}

function openNewScan() {
  const dialog = $("#new-scan");
  const form = $("#new-scan-form");
  form.reset();
  form.start_at.value = nextTwoAm();
  updateNewScanForm();
  $("#new-scan-error").hidden = true;
  dialog.showModal();
  form.targets.focus();
}

function updateNewScanForm() {
  const form = $("#new-scan-form");
  const repeat = form.repeat.value;
  $("#start-field").hidden = repeat === "none";
  $("#new-scan-submit").textContent = repeat === "none" ? "Start scan" : "Create schedule";
}

async function submitNewScan(event) {
  event.preventDefault();
  const form = $("#new-scan-form");
  const repeat = form.repeat.value;
  const payload = {
    name: form.name.value.trim(),
    targets: form.targets.value,
    consider_alive: form.consider_alive.checked,
    repeat,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
  };
  if (repeat !== "none") {
    const start = new Date(form.start_at.value);
    if (Number.isNaN(start.getTime())) {
      showFormError("Pick when the first scan should run.");
      return;
    }
    payload.start_at = start.toISOString();
  }
  const submit = $("#new-scan-submit");
  submit.disabled = true;
  try {
    const result = await postJson("/api/openvas/tasks", payload);
    $("#new-scan").close();
    setNotice(
      result.started
        ? `Scan started for ${result.targets.join(", ")}. The report is imported automatically when it finishes.`
        : `Scheduled. The first scan runs ${dateTimeFormat.format(new Date(payload.start_at))}.`,
    );
    await loadOpenvas();
  } catch (error) {
    showFormError(error.message);
  } finally {
    submit.disabled = false;
  }
}

function showFormError(text) {
  const box = $("#new-scan-error");
  box.textContent = text;
  box.hidden = false;
}

// ---------- Scans view: history ----------

function sourceText(scan) {
  const scanner = scan.source === "openvas" ? "OpenVAS" : "Nessus";
  return scan.origin === "openvas-sync" ? `${scanner}, synced` : `${scanner}, imported file`;
}

function openSplit(open) {
  const total = totalOpen(open);
  const split = el("div", { class: "split", role: "img", "aria-label": plural(total, "open finding") });
  for (const severity of SEVERITIES) {
    const count = open[severity.key];
    if (!count) continue;
    const part = el("span", { class: `fill sev-${severity.level}` });
    part.style.flex = `${count} 1 0`;
    split.append(part);
  }
  return el("div", { class: "open-after" }, el("span", { class: "value", text: total }), total ? split : null);
}

function renderHistory(scans) {
  const body = $("#history-table tbody");
  if (!scans.length) {
    body.replaceChildren(el("tr", {}, el("td", { colspan: "8", class: "muted", text: "No scans imported yet." })));
    return;
  }
  body.replaceChildren(
    ...[...scans].reverse().map((scan) => {
      const when = parseDate(scan.scan_time);
      const name = el("button", { type: "button", class: "name-button history-time", text: dateFormat.format(when) });
      name.addEventListener("click", () => openScan(scan.id));
      const report = scan.archived
        ? el("a", { href: `/api/scans/${scan.id}/report`, download: "", class: "link", text: "Original" })
        : el("span", { class: "muted", text: "None" });
      return el(
        "tr",
        {},
        el("td", {}, name, el("span", { class: "sub", text: `${timeFormat.format(when)}, ${scan.task_name || scan.filename}` })),
        el("td", { class: "hide-narrow", text: sourceText(scan) }),
        el("td", { class: "num", text: scan.host_count }),
        countCell(scan.new),
        countCell(scan.fixed),
        el("td", { class: `num hide-narrow${scan.reopened ? "" : " zero"}`, text: scan.reopened }),
        el("td", {}, openSplit(scan.open)),
        el("td", {}, report),
      );
    }),
  );
}

// ---------- Detail sheet: one scan ----------

function findingList(findings) {
  return el(
    "ul",
    { class: "finding-list" },
    ...findings.map((finding) =>
      el(
        "li",
        {},
        el("span", { class: `swatch sev-${finding.severity}`, title: SEVERITY_LABEL[finding.severity] }),
        el("span", {}, findingButton(finding), el("span", { class: "sub", text: `${hostLabel(finding.host)}${finding.port ? `, port ${finding.port}/${finding.protocol}` : ""}` })),
      ),
    ),
  );
}

function listSection(title, findings, note) {
  if (!findings.length) return null;
  return el("section", {}, el("h3", { text: `${title} (${findings.length})` }), note ? el("p", { class: "ai-note", text: note }) : null, findingList(findings));
}

function openSheet(title, subtitle, sections, hash) {
  $("#detail-title").textContent = title;
  $("#detail-subtitle").textContent = subtitle;
  $("#detail-body").replaceChildren(...sections.filter(Boolean));
  const dialog = $("#detail");
  if (!dialog.open) dialog.showModal();
  dialog.scrollTop = 0;
  history.replaceState(null, "", hash);
}

async function openScan(id) {
  let scan;
  try {
    scan = await api(`/api/scans/${id}`);
  } catch (error) {
    setNotice(error.message, true);
    return;
  }
  const facts = el("dl", { class: "facts" });
  factRow(facts, "Source", sourceText(scan));
  factRow(facts, "Report", scan.filename);
  const unfinished = scan.hosts.filter((h) => !h.complete).length;
  factRow(facts, "Hosts", `${scan.host_count}${unfinished ? `, ${unfinished} not finished` : ""}`);
  factRow(facts, "Open after this scan", `${totalOpen(scan.open)} (${SEVERITIES.map((s) => `${scan.open[s.key]} ${s.label.toLowerCase()}`).join(", ")})`);
  factRow(facts, "Imported", formatDate(scan.imported_at));

  const sections = [el("section", {}, facts)];
  if (scan.archived) {
    sections.push(el("section", {}, el("a", { class: "button", href: `/api/scans/${scan.id}/report`, download: "", text: "Download the original report" })));
  }
  if (!scan.has_history) {
    sections.push(el("p", { class: "ai-note", text: "This scan was imported before the dashboard recorded history, so only its totals are known." }));
  }
  sections.push(
    listSection("New", scan.changes.new),
    listSection("Fixed", scan.changes.fixed),
    listSection("Reopened", scan.changes.reopened),
    listSection(
      "Not re-checked",
      scan.carried,
      "The scanner could not test these this time (a host did not finish or a check errored), so they stay open rather than counting as fixed.",
    ),
  );
  if (scan.has_history && !scan.changes.new.length && !scan.changes.fixed.length && !scan.changes.reopened.length) {
    sections.push(el("p", { class: "muted", text: "Nothing changed in this scan." }));
  }
  if (scan.hosts.length) {
    sections.push(
      el(
        "section",
        {},
        el("h3", { text: "Hosts covered" }),
        el(
          "ul",
          { class: "host-list" },
          ...scan.hosts.map((h) => el("li", {}, hostLabel(h), h.hostname ? el("span", { class: "muted", text: ` ${h.ip}` }) : null, h.complete ? null : el("span", { class: "tag warn-tag", text: "Did not finish" }))),
        ),
      ),
    );
  }
  openSheet(`Scan of ${dateTimeFormat.format(parseDate(scan.scan_time))}`, scan.task_name || "", sections, `#scan-${scan.id}`);
}

// ---------- Detail sheet: one finding ----------

function factRow(list, label, value) {
  if (value === "" || value === null || value === undefined) return;
  list.append(el("dt", { text: label }), el("dd", { text: value }));
}

function textSection(title, text, { pre = false, note = "" } = {}) {
  if (!text) return null;
  return el("section", {}, el("h3", { text: title }), note ? el("p", { class: "ai-note", text: note }) : null, pre ? el("pre", { text }) : el("p", { text }));
}

function breakdownSection(finding) {
  const b = finding.risk_breakdown;
  const row = (label, sum, points, cls = "") =>
    el("tr", { class: cls }, el("td", { text: label }), el("td", { class: "muted", text: sum }), el("td", { class: "num", text: points }));
  const epssText = finding.epss === null ? "no EPSS score" : `${finding.epss.toFixed(3)} × 25`;
  return el(
    "section",
    {},
    el("h3", { text: "Why it ranks here" }),
    el(
      "table",
      { class: "breakdown" },
      el(
        "tbody",
        {},
        row("Impact (CVSS)", `${b.cvss_used.toFixed(1)} × 6`, b.cvss_points.toFixed(1)),
        row("Likelihood (EPSS)", epssText, b.epss_points.toFixed(1)),
        row("Known exploited (CISA KEV)", finding.in_kev ? "listed" : "not listed", b.kev_points.toFixed(1)),
        row("Host criticality", `level ${finding.host.criticality}`, `× ${b.criticality_multiplier.toFixed(1)}`),
        row("Risk score", "capped at 100", b.score.toFixed(1), "total"),
      ),
    ),
    el("p", { class: "ai-note", text: "This score is calculated by code. The AI can explain it but cannot change it." }),
  );
}

const EVENT_TEXT = { new: "First seen", fixed: "Fixed", reopened: "Reopened" };

function timelineSection(finding) {
  const { events, sightings } = finding.timeline;
  if (!events.length) return null;
  const list = el(
    "ol",
    { class: "timeline" },
    ...events.map((event) => {
      const item = el("li", { class: `event-${event.kind}` }, el("span", { class: "event-kind", text: EVENT_TEXT[event.kind] ?? event.kind }), " ", formatDate(event.at));
      if (event.scan_id) {
        const link = el("button", { type: "button", class: "link-button", text: "View scan" });
        link.addEventListener("click", () => openScan(event.scan_id));
        item.append(" ", link);
      }
      return item;
    }),
  );
  const carried = sightings.filter((s) => s.carried).length;
  const seen = sightings.length - carried;
  const note = `Reported by ${plural(seen, "scan")}${carried ? `. Kept open without a re-check in ${plural(carried, "scan")}` : ""}.`;
  return el("section", {}, el("h3", { text: "History" }), list, el("p", { class: "ai-note", text: note }));
}

function triageSection(finding) {
  const section = el("section", {}, el("h3", { text: "AI triage" }));
  const output = el("div", {});
  section.append(output);

  const render = (triage) => {
    const result = triage.result;
    output.replaceChildren(
      el("p", { text: result.summary }),
      el("h3", { text: "Why this priority" }),
      el("p", { text: result.priority_rationale }),
      el("h3", { text: "Remediation" }),
      el("ol", {}, ...result.remediation_steps.map((step) => el("li", { text: step }))),
    );
    if (result.verification_steps.length) {
      output.append(el("h3", { text: "Confirm the fix" }), el("ol", {}, ...result.verification_steps.map((step) => el("li", { text: step }))));
    }
    if (result.unverified_cves.length) {
      output.append(
        el("p", {
          class: "warn",
          text: `The model mentioned CVE IDs that are not part of this finding: ${result.unverified_cves.join(", ")}. Treat them as unverified.`,
        }),
      );
    }
    output.append(
      el("p", { class: "ai-note", text: `Generated by ${triage.model} on ${formatDate(triage.created_at)}. A model can be wrong, so check the steps before acting.` }),
    );
  };

  if (finding.triage) render(finding.triage);

  if (!state.summary.ai.enabled) {
    if (!finding.triage) {
      output.append(el("p", { class: "muted", text: "AI triage is off. Set AI_PROVIDER=ollama and OLLAMA_MODEL in the .env file, then restart, to turn it on." }));
    }
    return section;
  }

  const button = el("button", { type: "button", class: "button", text: finding.triage ? "Generate again" : "Explain with AI" });
  button.addEventListener("click", async () => {
    button.disabled = true;
    button.textContent = "Asking the model (this can take a minute)";
    try {
      const triage = await api(`/api/findings/${finding.id}/triage?refresh=${finding.triage ? "true" : "false"}`, { method: "POST", headers: WRITE_HEADERS });
      finding.triage = triage;
      render(triage);
      button.textContent = "Generate again";
    } catch (error) {
      output.append(el("p", { class: "warn", text: error.message }));
      button.textContent = finding.triage ? "Generate again" : "Explain with AI";
    } finally {
      button.disabled = false;
    }
  });
  section.append(button);
  return section;
}

async function openDetail(id) {
  let finding;
  try {
    finding = await api(`/api/findings/${id}`);
  } catch (error) {
    setNotice(error.message, true);
    return;
  }
  const openvas = finding.source === "openvas";
  const facts = el("dl", { class: "facts" });
  factRow(facts, "Severity", finding.severity_label);
  factRow(facts, "Status", finding.status === "fixed" ? `Fixed ${formatDate(finding.fixed_at)}` : "Open");
  factRow(facts, "Host", finding.host.hostname ? `${finding.host.hostname} (${finding.host.ip})` : finding.host.ip);
  factRow(facts, "Operating system", finding.host.os);
  factRow(facts, "Port", finding.port ? `${finding.port}/${finding.protocol} ${finding.service}`.trim() : finding.protocol ? `General (${finding.protocol})` : "");
  factRow(facts, "CVEs", finding.cves.join(", "));
  factRow(facts, "CVSS", finding.cvss_base === null ? "" : `${finding.cvss_base.toFixed(1)} ${finding.cvss_vector}`.trim());
  factRow(facts, "First seen", `${formatDate(finding.first_seen)} (${plural(finding.age_days, "day")} ${finding.status === "fixed" ? "to fix" : "open"})`);
  factRow(facts, "Last seen", formatDate(finding.last_seen));
  factRow(facts, openvas ? "OpenVAS check (NVT)" : "Nessus plugin", `${finding.plugin_id} ${finding.plugin_family}`.trim());
  if (finding.qod !== null && finding.qod !== undefined) factRow(facts, "Quality of detection", `${finding.qod}%`);

  openSheet(
    finding.plugin_name,
    "",
    [
      el("section", {}, facts),
      breakdownSection(finding),
      timelineSection(finding),
      triageSection(finding),
      textSection("Summary", finding.synopsis),
      textSection("Details", finding.description),
      textSection("Solution", finding.solution),
      textSection("Scanner output", finding.plugin_output, {
        pre: true,
        note: "Raw text returned by the scanned device. Shown as plain text and treated as untrusted.",
      }),
    ],
    `#finding-${finding.id}`,
  );
}

// ---------- Views and routing ----------

function showView(view) {
  state.view = view;
  for (const name of VIEWS) $(`#view-${name}`).hidden = name !== view || (name !== "scans" && !state.scans.length);
  $("#empty-state").hidden = view === "scans" || state.scans.length > 0;
  for (const link of $$(".tabs a")) {
    if (link.dataset.view === view) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  clearInterval(state.pollTimer);
  state.pollTimer = null;
  if (view === "trends" && state.scans.length) loadTrends();
  if (view === "scans") {
    renderHistory(state.scans);
    loadOpenvas();
    state.pollTimer = setInterval(() => {
      if (!document.hidden) loadOpenvas();
    }, POLL_MS);
  }
}

function route() {
  const hash = location.hash;
  const finding = /^#finding-(\d+)$/.exec(hash);
  const scan = /^#scan-(\d+)$/.exec(hash);
  if (finding) return openDetail(Number(finding[1]));
  if (scan) return openScan(Number(scan[1]));
  const view = hash.slice(1);
  if ($("#detail").open) $("#detail").close();
  showView(VIEWS.includes(view) ? view : "overview");
}

// ---------- Actions ----------

async function importScans(files) {
  const button = $("#import-button");
  button.disabled = true;
  // Oldest first keeps the import messages in order; the server handles any order.
  const ordered = [...files].sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
  let imported = 0;
  const problems = [];
  for (const [index, file] of ordered.entries()) {
    setNotice(`Importing ${file.name}${ordered.length > 1 ? ` (${index + 1} of ${ordered.length})` : ""}`);
    try {
      const body = new FormData();
      body.append("file", file);
      await api("/api/scans", { method: "POST", headers: WRITE_HEADERS, body });
      imported += 1;
    } catch (error) {
      problems.push(`${file.name}: ${error.message}`);
    }
  }
  const summary = `Imported ${plural(imported, "report")}.`;
  setNotice(problems.length ? `${summary} ${problems.join(" ")}` : summary, problems.length > 0);
  button.disabled = false;
  $("#scan-file").value = "";
  await refresh();
}

async function updateIntel() {
  const button = $("#intel-button");
  button.disabled = true;
  setNotice("Fetching the CISA KEV list and EPSS scores");
  try {
    const result = await api("/api/intel/refresh", { method: "POST", headers: WRITE_HEADERS });
    const parts = [`Checked ${plural(result.cves_checked, "CVE")}.`];
    if (result.kev_matches !== null) parts.push(`${result.kev_matches} on the CISA KEV list.`);
    if (result.epss_scores !== null) parts.push(`${result.epss_scores} with an EPSS score.`);
    parts.push("Risk scores updated.", ...result.warnings);
    setNotice(parts.join(" "), result.warnings.length > 0);
    await refresh();
  } catch (error) {
    setNotice(`Threat intel update failed. ${error.message}`, true);
  } finally {
    button.disabled = false;
  }
}

async function refresh({ skipOpenvas = false } = {}) {
  const [summary, scans, hosts] = await Promise.all([api("/api/summary"), api("/api/scans"), api("/api/hosts")]);
  Object.assign(state, { summary, scans, hosts });
  renderMeta(summary);
  $("#intel-button").hidden = !scans.length;
  if (scans.length) {
    renderStats(summary);
    renderSeverityBars(summary.open);
    renderOpenColumns("overview-trend", scans);
    renderHosts(hosts);
    await loadFindings();
  }
  if (state.view === "scans") renderHistory(scans);
  if (skipOpenvas && state.view === "scans") {
    // Re-apply visibility without restarting the polling loop.
    $("#view-scans").hidden = false;
    return;
  }
  showView(state.view);
}

function wireEvents() {
  const fileInput = $("#scan-file");
  const chooseFile = () => fileInput.click();
  $("#import-button").addEventListener("click", chooseFile);
  $("#empty-import").addEventListener("click", chooseFile);
  fileInput.addEventListener("change", () => {
    if (fileInput.files.length) importScans(fileInput.files);
  });
  $("#intel-button").addEventListener("click", updateIntel);
  $("#load-more").addEventListener("click", () => loadFindings({ append: true }));

  let timer = null;
  const filters = $("#filters");
  filters.addEventListener("submit", (event) => event.preventDefault());
  filters.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(() => loadFindings(), 250);
  });

  for (const figure of $$("figure[data-toggle]")) {
    const toggle = $(".table-toggle", figure);
    toggle.addEventListener("click", () => {
      const showTable = toggle.getAttribute("aria-pressed") !== "true";
      toggle.setAttribute("aria-pressed", String(showTable));
      toggle.textContent = showTable ? "Show as chart" : "Show as table";
      $(".table-wrap", figure).hidden = !showTable;
      $(".chart", figure).hidden = showTable;
      const legend = $(".legend", figure);
      if (legend) legend.hidden = showTable;
    });
  }

  for (const button of $$("#range button")) {
    button.addEventListener("click", () => {
      for (const other of $$("#range button")) other.setAttribute("aria-pressed", String(other === button));
      state.trendDays = button.dataset.days ? Number(button.dataset.days) : null;
      loadTrends();
    });
  }

  $("#ov-sync").addEventListener("click", syncNow);
  $("#ov-new").addEventListener("click", openNewScan);
  const newScan = $("#new-scan");
  $("#new-scan-form").addEventListener("submit", submitNewScan);
  $("#new-scan-form").addEventListener("change", updateNewScanForm);
  $("#new-scan-cancel").addEventListener("click", () => newScan.close());

  const dialog = $("#detail");
  $("#detail-close").addEventListener("click", () => dialog.close());
  dialog.addEventListener("close", () => history.replaceState(null, "", `#${state.view}`));
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close(); // click on the backdrop
  });
  window.addEventListener("hashchange", route);
  window.addEventListener("scroll", hideTooltip, { passive: true });
}

wireEvents();
const initial = location.hash.slice(1);
state.view = VIEWS.includes(initial) ? initial : "overview";
refresh()
  .then(() => {
    if (/^#(finding|scan)-\d+$/.test(location.hash)) route();
  })
  .catch((error) => setNotice(`Could not load the dashboard. ${error.message}`, true));
