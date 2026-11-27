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
const PAGE_SIZE = 100;
const MAX_TREND_COLUMNS = 24;
const SVG_NS = "http://www.w3.org/2000/svg";

const state = { summary: null, scans: [], hosts: [], findings: [], total: 0 };

const $ = (selector) => document.querySelector(selector);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (name === "class") node.className = value;
    else if (name === "text") node.textContent = value;
    else node.setAttribute(name, value === true ? "" : String(value));
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function svgEl(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, String(value));
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

const dateFormat = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", year: "numeric" });
const shortDateFormat = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" });

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

function plural(count, word) {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
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
        row.level ? el("span", { class: `tip-key sev-${row.level}` }) : null,
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

function attachTooltip(target, title, rows) {
  const show = () => showTooltip(target, title, rows);
  target.addEventListener("pointerenter", show);
  target.addEventListener("focus", show);
  target.addEventListener("pointerleave", hideTooltip);
  target.addEventListener("blur", hideTooltip);
}

// ---------- Header and stat strip ----------

function renderMeta(summary) {
  const parts = [];
  const scan = summary.last_scan;
  if (scan) {
    parts.push(
      `Last scan ${formatDate(scan.scan_time)}: ${scan.new} new, ${scan.fixed} fixed, ${scan.reopened} reopened.`,
    );
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

// ---------- Open findings by severity (horizontal bars) ----------

function renderSeverityBars(open) {
  const container = $("#severity-bars");
  const total = SEVERITIES.reduce((sum, s) => sum + open[s.key], 0);
  const max = Math.max(1, ...SEVERITIES.map((s) => open[s.key]));
  container.replaceChildren();
  for (const severity of SEVERITIES) {
    const count = open[severity.key];
    const fill = el("span", { class: `fill sev-${severity.level}${count ? "" : " zero"}` });
    fill.style.width = `calc((100% - 48px) * ${count / max})`;
    const track = el(
      "div",
      { class: "hbar-track", tabindex: "0", role: "img", "aria-label": `${severity.label}: ${count} open` },
      fill,
      el("span", { class: "value", text: count }),
    );
    const share = total ? `${Math.round((count / total) * 100)}%` : "0%";
    attachTooltip(track, severity.label, [
      { value: String(count), label: "open" },
      { value: share, label: "of open findings" },
    ]);
    container.append(
      el("span", {}, el("span", { class: `swatch sev-${severity.level}` }), severity.label),
      track,
    );
  }
}

// ---------- Open findings after each scan (stacked columns) ----------

function niceAxis(maxValue) {
  if (maxValue <= 4) return { top: Math.max(maxValue, 1), step: 1 };
  const rough = maxValue / 4;
  const magnitude = 10 ** Math.floor(Math.log10(rough));
  const step = [1, 2, 5, 10].map((m) => m * magnitude).find((s) => s >= rough);
  return { top: Math.ceil(maxValue / step) * step, step };
}

function roundedTopPath(x, y, width, height, radius) {
  const r = Math.min(radius, width / 2, height);
  return [
    `M${x},${y + height}`,
    `V${y + r}`,
    `Q${x},${y} ${x + r},${y}`,
    `H${x + width - r}`,
    `Q${x + width},${y} ${x + width},${y + r}`,
    `V${y + height}`,
    "Z",
  ].join(" ");
}

function renderTrend(scans) {
  $("#trend-legend").replaceChildren(
    ...SEVERITIES.map((s) => el("li", {}, el("span", { class: `swatch sev-${s.level}` }), s.label)),
  );
  renderTrendTable(scans);

  const shown = scans.slice(-MAX_TREND_COLUMNS);
  const width = 640;
  const height = 250;
  const margin = { top: 22, right: 12, bottom: 28, left: 34 };
  const plotWidth = width - margin.left - margin.right;
  const plotHeight = height - margin.top - margin.bottom;
  const totals = shown.map((scan) => SEVERITIES.reduce((sum, s) => sum + scan.open[s.key], 0));
  const axis = niceAxis(Math.max(1, ...totals));
  const y = (value) => margin.top + plotHeight - (value / axis.top) * plotHeight;
  const band = plotWidth / Math.max(shown.length, 1);
  const columnWidth = Math.min(24, band * 0.6);
  const labelEvery = Math.ceil(shown.length / 8);

  const svg = svgEl("svg", {
    viewBox: `0 0 ${width} ${height}`,
    role: "group",
    "aria-label": "Stacked columns: open findings by severity after each scan",
  });

  for (let tick = 0; tick <= axis.top; tick += axis.step) {
    svg.append(
      svgEl("line", {
        class: tick === 0 ? "baseline" : "grid",
        x1: margin.left,
        x2: width - margin.right,
        y1: y(tick),
        y2: y(tick),
      }),
    );
    const label = svgEl("text", { x: margin.left - 8, y: y(tick) + 4, "text-anchor": "end" });
    label.textContent = String(tick);
    svg.append(label);
  }

  shown.forEach((scan, index) => {
    const centre = margin.left + band * index + band / 2;
    const left = centre - columnWidth / 2;
    const dateLabel = formatDate(scan.scan_time, shortDateFormat);
    const rows = SEVERITIES.map((s) => ({ level: s.level, value: String(scan.open[s.key]), label: s.label }));
    const group = svgEl("g", {
      class: "column",
      tabindex: "0",
      role: "img",
      "aria-label": `${formatDate(scan.scan_time)}: ${rows.map((r) => `${r.value} ${r.label.toLowerCase()}`).join(", ")}`,
    });
    group.append(
      svgEl("rect", { class: "hit", x: centre - band / 2, y: margin.top - 14, width: band, height: plotHeight + 14, rx: 4 }),
    );

    // Critical sits on the baseline so its change between scans is the easiest to read.
    const present = SEVERITIES.filter((s) => scan.open[s.key] > 0);
    let running = 0;
    present.forEach((severity, position) => {
      const count = scan.open[severity.key];
      const bottom = y(running);
      const top = y(running + count);
      running += count;
      const isTop = position === present.length - 1;
      const gap = isTop ? 0 : 2; // 2px of surface between stacked segments
      const segmentHeight = Math.max(1, bottom - top - gap);
      const segmentTop = bottom - segmentHeight;
      if (isTop) {
        group.append(
          svgEl("path", {
            class: `seg sev-${severity.level}`,
            d: roundedTopPath(left, segmentTop, columnWidth, segmentHeight, 4),
          }),
        );
      } else {
        group.append(
          svgEl("rect", {
            class: `seg sev-${severity.level}`,
            x: left,
            y: segmentTop,
            width: columnWidth,
            height: segmentHeight,
          }),
        );
      }
    });

    if (index === shown.length - 1) {
      const total = svgEl("text", { class: "total", x: centre, y: y(totals[index]) - 6, "text-anchor": "middle" });
      total.textContent = String(totals[index]);
      group.append(total);
    }
    if (index % labelEvery === 0 || index === shown.length - 1) {
      const label = svgEl("text", { x: centre, y: height - 8, "text-anchor": "middle" });
      label.textContent = dateLabel;
      group.append(label);
    }

    attachTooltip(group, formatDate(scan.scan_time), [
      ...rows,
      { value: String(totals[index]), label: "total open" },
    ]);
    svg.append(group);
  });

  $("#trend-chart").replaceChildren(svg);
}

function renderTrendTable(scans) {
  const head = el(
    "tr",
    {},
    el("th", { scope: "col", text: "Scan" }),
    ...SEVERITIES.map((s) => el("th", { scope: "col", class: "num", text: s.label })),
    el("th", { scope: "col", class: "num", text: "Total" }),
  );
  const body = scans.map((scan) =>
    el(
      "tr",
      {},
      el("td", { text: formatDate(scan.scan_time) }),
      ...SEVERITIES.map((s) => el("td", { class: "num", text: scan.open[s.key] })),
      el("td", { class: "num", text: SEVERITIES.reduce((sum, s) => sum + scan.open[s.key], 0) }),
    ),
  );
  $("#trend-table").replaceChildren(el("table", { class: "data" }, el("thead", {}, head), el("tbody", {}, ...body)));
}

// ---------- Hosts ----------

function countCell(count) {
  return el("td", { class: `num${count ? "" : " zero"}`, text: count });
}

function renderHosts(hosts) {
  const rows = hosts.map((host) => {
    const select = el("select", { "aria-label": `Criticality of ${host.hostname || host.ip}` });
    for (let level = 1; level <= 5; level += 1) {
      select.append(el("option", { value: level, selected: level === host.criticality, text: level }));
    }
    select.addEventListener("change", () => updateCriticality(host, Number(select.value)));

    const total = SEVERITIES.reduce((sum, s) => sum + host.open[s.key], 0);
    const split = el("div", { class: "split", role: "img", "aria-label": `${plural(total, "open finding")}` });
    for (const severity of SEVERITIES) {
      const count = host.open[severity.key];
      if (!count) continue;
      const part = el("span", { class: `fill sev-${severity.level}` });
      part.style.flex = `${count} 1 0`;
      split.append(part);
    }

    return el(
      "tr",
      {},
      el("td", {}, el("strong", { text: host.hostname || host.ip }), el("span", { class: "sub", text: host.ip })),
      el("td", { class: "hide-narrow", text: host.os || "Unknown" }),
      el("td", {}, select),
      el("td", { class: "num", text: Math.round(host.max_risk) }),
      ...SEVERITIES.map((s) => countCell(host.open[s.key])),
      el("td", { class: "hide-narrow" }, total ? split : el("span", { class: "muted", text: "None" })),
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
    setNotice(`${host.hostname || host.ip} set to criticality ${criticality}. Risk scores updated.`);
    await refresh();
  } catch (error) {
    setNotice(error.message, true);
  }
}

// ---------- Worklist ----------

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

function findingRow(finding) {
  const name = el("button", { type: "button", class: "name-button", text: finding.plugin_name });
  name.addEventListener("click", () => openDetail(finding.id));
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
      name,
      fixed ? el("span", { class: "sub" }, el("span", { class: "tag fixed", text: `Fixed ${formatDate(finding.fixed_at)}` })) : null,
      cves ? el("span", { class: "sub", text: cves }) : null,
    ),
    el(
      "td",
      {},
      finding.host.hostname || finding.host.ip,
      finding.host.hostname ? el("span", { class: "sub", text: finding.host.ip }) : null,
    ),
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
      body.replaceChildren(
        el("tr", {}, el("td", { colspan: "9", class: "muted", text: "Nothing matches these filters." })),
      );
    }
    $("#worklist-count").textContent = `Showing ${state.findings.length} of ${plural(state.total, "finding")}, highest risk first.`;
    $("#load-more").hidden = state.findings.length >= state.total;
  } catch (error) {
    setNotice(error.message, true);
  } finally {
    table.style.opacity = "";
  }
}

// ---------- Finding detail ----------

function factRow(list, label, value) {
  if (value === "" || value === null || value === undefined) return;
  list.append(el("dt", { text: label }), el("dd", { text: value }));
}

function textSection(title, text, { pre = false, note = "" } = {}) {
  if (!text) return null;
  return el(
    "section",
    {},
    el("h3", { text: title }),
    note ? el("p", { class: "ai-note", text: note }) : null,
    pre ? el("pre", { text }) : el("p", { text }),
  );
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
      output.append(
        el("h3", { text: "Confirm the fix" }),
        el("ol", {}, ...result.verification_steps.map((step) => el("li", { text: step }))),
      );
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
      el("p", {
        class: "ai-note",
        text: `Generated by ${triage.model} on ${formatDate(triage.created_at)}. A model can be wrong, so check the steps before acting.`,
      }),
    );
  };

  if (finding.triage) render(finding.triage);

  if (!state.summary.ai.enabled) {
    if (!finding.triage) {
      output.append(
        el("p", { class: "muted", text: "AI triage is off. Set AI_PROVIDER=ollama and OLLAMA_MODEL in the .env file, then restart, to turn it on." }),
      );
    }
    return section;
  }

  const button = el("button", { type: "button", class: "button", text: finding.triage ? "Generate again" : "Explain with AI" });
  button.addEventListener("click", async () => {
    button.disabled = true;
    button.textContent = "Asking the model (this can take a minute)";
    try {
      const triage = await api(`/api/findings/${finding.id}/triage?refresh=${finding.triage ? "true" : "false"}`, {
        method: "POST",
        headers: WRITE_HEADERS,
      });
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
  $("#detail-title").textContent = finding.plugin_name;

  const facts = el("dl", { class: "facts" });
  factRow(facts, "Severity", finding.severity_label);
  factRow(facts, "Status", finding.status === "fixed" ? `Fixed ${formatDate(finding.fixed_at)}` : "Open");
  factRow(facts, "Host", finding.host.hostname ? `${finding.host.hostname} (${finding.host.ip})` : finding.host.ip);
  factRow(facts, "Operating system", finding.host.os);
  factRow(facts, "Port", finding.port ? `${finding.port}/${finding.protocol} ${finding.service}`.trim() : "");
  factRow(facts, "CVEs", finding.cves.join(", "));
  factRow(facts, "CVSS", finding.cvss_base === null ? "" : `${finding.cvss_base.toFixed(1)} ${finding.cvss_vector}`.trim());
  factRow(facts, "First seen", `${formatDate(finding.first_seen)} (${plural(finding.age_days, "day")} ${finding.status === "fixed" ? "to fix" : "open"})`);
  factRow(facts, "Last seen", formatDate(finding.last_seen));
  factRow(facts, "Plugin", `${finding.plugin_id} ${finding.plugin_family}`.trim());

  $("#detail-body").replaceChildren(
    el("section", {}, facts),
    breakdownSection(finding),
    triageSection(finding),
    ...[
      textSection("Synopsis", finding.synopsis),
      textSection("Description", finding.description),
      textSection("Vendor solution", finding.solution),
      textSection("Scanner output", finding.plugin_output, {
        pre: true,
        note: "Raw text returned by the scanned device. Shown as plain text and treated as untrusted.",
      }),
    ].filter(Boolean),
  );
  const dialog = $("#detail");
  if (!dialog.open) dialog.showModal();
  dialog.scrollTop = 0;
  history.replaceState(null, "", `#finding-${finding.id}`); // a link straight to this finding
}

function openDetailFromLink() {
  const match = /^#finding-(\d+)$/.exec(location.hash);
  if (match) openDetail(Number(match[1]));
}

// ---------- Actions ----------

async function importScan(file) {
  const button = $("#import-button");
  button.disabled = true;
  setNotice(`Importing ${file.name}`);
  try {
    const body = new FormData();
    body.append("file", file);
    const scan = await api("/api/scans", { method: "POST", headers: WRITE_HEADERS, body });
    setNotice(
      `Imported ${scan.filename}: ${plural(scan.host_count, "host")}, ${scan.new} new, ${scan.fixed} fixed, ${scan.reopened} reopened.`,
    );
    await refresh();
  } catch (error) {
    setNotice(`Import failed. ${error.message}`, true);
  } finally {
    button.disabled = false;
    $("#scan-file").value = "";
  }
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

async function refresh() {
  const [summary, scans, hosts] = await Promise.all([api("/api/summary"), api("/api/scans"), api("/api/hosts")]);
  Object.assign(state, { summary, scans, hosts });
  renderMeta(summary);
  const hasData = scans.length > 0;
  $("#empty-state").hidden = hasData;
  $("#dashboard").hidden = !hasData;
  $("#intel-button").hidden = !hasData;
  if (!hasData) return;
  renderStats(summary);
  renderSeverityBars(summary.open);
  renderTrend(scans);
  renderHosts(hosts);
  await loadFindings();
}

function wireEvents() {
  const fileInput = $("#scan-file");
  const chooseFile = () => fileInput.click();
  $("#import-button").addEventListener("click", chooseFile);
  $("#empty-import").addEventListener("click", chooseFile);
  fileInput.addEventListener("change", () => {
    if (fileInput.files.length) importScan(fileInput.files[0]);
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

  const toggle = $("#trend-toggle");
  toggle.addEventListener("click", () => {
    const showTable = toggle.getAttribute("aria-pressed") !== "true";
    toggle.setAttribute("aria-pressed", String(showTable));
    toggle.textContent = showTable ? "Show as chart" : "Show as table";
    $("#trend-table").hidden = !showTable;
    $("#trend-chart").hidden = showTable;
    $("#trend-legend").hidden = showTable;
  });

  const dialog = $("#detail");
  $("#detail-close").addEventListener("click", () => dialog.close());
  dialog.addEventListener("close", () => history.replaceState(null, "", location.pathname));
  window.addEventListener("hashchange", openDetailFromLink);
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close(); // click on the backdrop
  });
  window.addEventListener("scroll", hideTooltip, { passive: true });
}

wireEvents();
refresh()
  .then(openDetailFromLink)
  .catch((error) => setNotice(`Could not load the dashboard. ${error.message}`, true));
