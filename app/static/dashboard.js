// Dashboard charts (ECharts). Palette = dataviz reference palette, validated light + dark.
// Colour follows the entity (device order by id, fixed severity colours), never its rank.
(() => {
  const root = document.getElementById("dash");
  if (!root) return;
  const range = root.dataset.range;
  const staff = root.dataset.staff === "true";
  const dark = () => window.matchMedia("(prefers-color-scheme: dark)").matches;

  const PALETTE = {
    light: ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"],
    dark: ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"],
  };
  // Severity is a state, so it uses the reserved status colours (always shown with a label).
  const SEVERITY = { critical: "#d03b3b", high: "#ec835a", medium: "#fab219", low: "#898781" };
  const SEV_ORDER = ["low", "medium", "high", "critical"];
  const OTHER = "#898781";

  const ink = () => dark()
    ? { text: "#ffffff", text2: "#c3c2b7", muted: "#898781", grid: "#2c2c2a", axis: "#383835", surface: "#1a1a19" }
    : { text: "#0b0b0b", text2: "#52514e", muted: "#898781", grid: "#e1e0d9", axis: "#c3c2b7", surface: "#fcfcfb" };

  const nf = new Intl.NumberFormat();
  let tz = "UTC";
  const fmtTime = (ms, withDate) => new Intl.DateTimeFormat(undefined, {
    timeZone: tz, hour: "2-digit", minute: "2-digit", hour12: false,
    ...(withDate ? { month: "short", day: "numeric" } : {}),
  }).format(new Date(ms));
  const fmtFull = (ms) => new Intl.DateTimeFormat(undefined, {
    timeZone: tz, year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  }).format(new Date(ms));
  const longRange = range === "7d";

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const bytes = (n) => { const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return `${n.toFixed(i ? 1 : 0)} ${u[i]}`; };

  function table(el, headers, rows) {
    if (!el) return;
    if (!rows.length) { el.innerHTML = '<p class="muted">No data in this range.</p>'; return; }
    el.innerHTML = `<table class="dense"><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${
      rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
  }

  function baseOption(extra) {
    const c = ink();
    return {
      backgroundColor: "transparent",
      textStyle: { fontFamily: 'system-ui, -apple-system, "Segoe UI", sans-serif', color: c.text2 },
      grid: { left: 8, right: 16, top: 36, bottom: 8, containLabel: true },
      legend: { top: 0, left: 0, icon: "roundRect", itemWidth: 12, itemHeight: 8, textStyle: { color: c.text2 } },
      tooltip: {
        trigger: "axis", axisPointer: { type: "line", lineStyle: { color: c.muted } },
        backgroundColor: c.surface, borderColor: c.grid, textStyle: { color: c.text },
      },
      xAxis: {
        type: "time", axisLine: { lineStyle: { color: c.axis } }, axisTick: { show: false },
        axisLabel: { color: c.muted, hideOverlap: true, formatter: (v) => fmtTime(v, longRange) },
        splitLine: { show: false },
      },
      yAxis: {
        type: "value", axisLabel: { color: c.muted, formatter: (v) => nf.format(v) },
        splitLine: { lineStyle: { color: c.grid, width: 1 } },
      },
      ...extra,
    };
  }

  const charts = {};
  function chart(id, option) {
    const el = document.getElementById(id);
    if (!el || !window.echarts) return;
    charts[id] = charts[id] || echarts.init(el, null, { renderer: "svg" });
    charts[id].setOption(option, true);
  }

  // ---- click-to-drill (staff: Log View is staff-only) ----------------------------------------------
  // Chart buckets match the server's: 1h -> 1 min, 6h -> 5 min, 24h -> 15 min, 7d -> 2 h.
  const BUCKET_MS = { "1h": 60e3, "6h": 300e3, "24h": 900e3, "7d": 7200e3 }[range] || 900e3;
  const localIso = (ms) => new Intl.DateTimeFormat("sv-SE", {
    timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
  }).format(new Date(ms)).replace(" ", "T");
  const logsUrl = (params) => "/logs?" + new URLSearchParams(params).toString();
  const windowParams = (ms) => {
    const start = Math.floor(ms / BUCKET_MS) * BUCKET_MS;
    return { range: "custom", from: localIso(start), to: localIso(start + BUCKET_MS) };
  };
  const rangeParams = () => (["1h", "24h", "7d"].includes(range) ? { range }
    : { range: "custom", from: localIso(Date.now() - 6 * 3600e3) });
  function drillTime(id, extra) {           // click anywhere in the plot: that time bucket in Log View
    const c = charts[id];
    if (!staff || !c || c.__drillTime) return;
    c.__drillTime = true;
    document.getElementById(id).classList.add("drillable");
    c.getZr().on("click", (ev) => {
      const pt = [ev.offsetX, ev.offsetY];
      if (!c.containPixel("grid", pt)) return;
      const x = c.convertFromPixel("grid", pt)[0];
      if (Number.isFinite(x)) location.href = logsUrl({ ...windowParams(x), ...(extra || {}) });
    });
  }
  const linkCell = (label, params) => (staff ? `<a href="${esc(logsUrl(params))}">${label}</a>` : label);
  const q = (v) => (/[\s'",]/.test(v) ? `"${String(v).replace(/"/g, "")}"` : v);

  function axisTooltip(unit) {
    return (params) => {
      if (!params.length) return "";
      const head = `<strong>${esc(fmtFull(params[0].value[0]))}</strong>`;
      return head + params.map((p) => `<br>${p.marker} ${esc(p.seriesName)}: <strong>${nf.format(Math.round(p.value[1]))}</strong>${unit}`).join("");
    };
  }

  function render(d) {
    tz = d.tz;
    const pal = dark() ? PALETTE.dark : PALETTE.light;
    const t = d.tiles;
    const set = (k, v) => { const el = root.querySelector(`[data-tile="${k}"]`); if (el) el.textContent = nf.format(v); };
    set("lines", t.lines); set("events", t.events); set("critical", t.severity.critical);
    set("high", t.severity.high); set("medium", t.severity.medium); set("silent", t.devices_silent);
    if (d.ingest) { set("unknown", d.ingest.unknown_senders); set("failures", t.parse_failures); }

    // --- Log receive monitor: stacked area per device (colour by device order) --------
    const order = d.receive.order;
    const byName = Object.fromEntries(d.receive.series.map((s) => [s.name, s.points]));
    const recvSeries = order.filter((n) => byName[n]).map((name) => {
      const color = name === "Other" ? OTHER : pal[order.indexOf(name) % pal.length];
      return { name, type: "line", stack: "lines", showSymbol: false, smooth: false, color,
               lineStyle: { width: 2 }, areaStyle: { opacity: 0.18 }, data: byName[name] };
    });
    chart("c-receive", baseOption({ series: recvSeries, tooltip: { ...baseOption({}).tooltip, formatter: axisTooltip(" lines") },
                                    legend: { ...baseOption({}).legend, show: recvSeries.length > 1 } }));
    drillTime("c-receive");
    const times = [...new Set(d.receive.series.flatMap((s) => s.points.map((p) => p[0])))].sort((a, b) => a - b);
    table(root.querySelector('[data-table="receive"]'), ["Time", ...order],
          times.map((tm) => [esc(fmtFull(tm)), ...order.map((n) => nf.format((byName[n] || []).find((p) => p[0] === tm)?.[1] || 0))]));

    // --- Ingest rates + lag (staff) ---------------------------------------------------
    if (staff && d.ingest) {
      const rec = d.ingest.rates.filter((r) => r.component === "receiver");
      const par = d.ingest.rates.filter((r) => r.component === "parser");
      const line = (name, data, color) => ({ name, type: "line", showSymbol: false, color, lineStyle: { width: 2 }, data });
      chart("c-rates", baseOption({
        series: [
          line("Received", rec.map((r) => [r.t, r.received]), pal[0]),
          line("Stored", rec.map((r) => [r.t, r.stored]), pal[1]),
          line("Parsed", par.map((r) => [r.t, r.parsed + r.failed]), pal[2]),
        ],
        tooltip: { ...baseOption({}).tooltip, formatter: axisTooltip("") },
      }));
      table(root.querySelector('[data-table="rates"]'), ["Time", "Received", "Stored", "Parsed", "Failed"],
            rec.map((r) => { const p = par.find((x) => x.t === r.t) || {}; return [esc(fmtFull(r.t)), nf.format(r.received), nf.format(r.stored), nf.format(p.parsed || 0), nf.format(p.failed || 0)]; }));
      chart("c-lag", baseOption({
        series: [line("Average", par.map((r) => [r.t, r.lag_avg]), pal[0]), line("Maximum", par.map((r) => [r.t, r.lag_max]), pal[1])],
        tooltip: { ...baseOption({}).tooltip, formatter: axisTooltip(" ms") },
      }));
      table(root.querySelector('[data-table="lag"]'), ["Time", "Average ms", "Maximum ms"],
            par.filter((r) => r.lag_max !== null).map((r) => [esc(fmtFull(r.t)), nf.format(Math.round(r.lag_avg)), nf.format(r.lag_max)]));
      const st = d.ingest.storage;
      table(root.querySelector('[data-table="storage"]'), ["Data", "Size on disk"],
            [["Raw logs", bytes(st.raw_logs || 0)], ["Normalised events", bytes(st.events || 0)]]);
    }

    // --- Severity over time: stacked bars with status colours -----------------------
    const sevTimes = [...new Set(d.severity.map((x) => x.t))].sort((a, b) => a - b);
    const sevSeries = SEV_ORDER.map((s) => ({
      name: s[0].toUpperCase() + s.slice(1), type: "bar", stack: "sev", color: SEVERITY[s], barMaxWidth: 18,
      itemStyle: { borderColor: ink().surface, borderWidth: 1, borderRadius: s === "critical" ? [4, 4, 0, 0] : 0 },
      data: d.severity.filter((x) => x.severity === s).map((x) => [x.t, x.n]),
    })).filter((s) => s.data.length);
    chart("c-severity", baseOption({ series: sevSeries, tooltip: { ...baseOption({}).tooltip, axisPointer: { type: "shadow" }, formatter: axisTooltip("") } }));
    drillTime("c-severity");
    table(root.querySelector('[data-table="severity"]'), ["Time", "Critical", "High", "Medium", "Low"],
          sevTimes.map((tm) => [esc(fmtFull(tm)), ...["critical", "high", "medium", "low"].map((s) => nf.format(d.severity.find((x) => x.t === tm && x.severity === s)?.n || 0))]));

    // --- Category bar: one series, one colour ----------------------------------------
    const cats = [...d.categories].reverse();
    const c = ink();
    chart("c-category", {
      backgroundColor: "transparent",
      textStyle: { fontFamily: 'system-ui, -apple-system, "Segoe UI", sans-serif', color: c.text2 },
      grid: { left: 8, right: 48, top: 8, bottom: 8, containLabel: true },
      tooltip: { trigger: "item", backgroundColor: c.surface, borderColor: c.grid, textStyle: { color: c.text },
                 formatter: (p) => `${esc(p.name)}: <strong>${nf.format(p.value)}</strong>` },
      xAxis: { type: "value", axisLabel: { color: c.muted, formatter: (v) => nf.format(v) }, splitLine: { lineStyle: { color: c.grid } } },
      yAxis: { type: "category", data: cats.map((x) => x.category), axisLabel: { color: c.text2 }, axisTick: { show: false }, axisLine: { lineStyle: { color: c.axis } } },
      series: [{ type: "bar", data: cats.map((x) => x.n), color: pal[0], barMaxWidth: 14, itemStyle: { borderRadius: [0, 4, 4, 0] },
                 label: { show: true, position: "right", color: c.text2, formatter: (p) => nf.format(p.value) } }],
    });
    if (staff && charts["c-category"] && !charts["c-category"].__drill) {
      charts["c-category"].__drill = true;
      document.getElementById("c-category").classList.add("drillable");
      charts["c-category"].on("click", (p) => { if (p.name) location.href = logsUrl({ ...rangeParams(), category: p.name }); });
    }
    table(root.querySelector('[data-table="category"]'), ["Category", "Events"],
          d.categories.map((x) => [linkCell(esc(x.category), { ...rangeParams(), category: x.category }), nf.format(x.n)]));

    // --- VPN tile + device health --------------------------------------------------------
    const up = d.vpn.filter((t) => t.state === "up").length;
    const vt = root.querySelector('[data-tile="vpn"]');
    if (vt) vt.textContent = d.vpn.length ? `${up} / ${d.vpn.length}` : "–";
    const drops = d.vpn.reduce((a, t) => a + Number(t.drops || 0), 0);
    const vd = root.querySelector('[data-tile="vpn-drops"]');
    if (vd) vd.textContent = d.vpn.length ? `${nf.format(drops)} drop${drops === 1 ? "" : "s"} in ${range}` : "no tunnels";
    const meter = (v, warn, crit) => {
      if (v === null || v === undefined) return '<span class="muted">–</span>';
      const cls = v >= crit ? "crit" : v >= warn ? "hot" : "";
      const pct = Math.max(0, Math.min(100, v));
      return `<span class="meter ${cls}"><span class="track"><span class="fill" style="width:${pct}%"></span></span><span class="v">${v.toFixed(0)} %</span></span>`;
    };
    const stateLabel = { up: '<span class="state state-up">▲ up</span>', down: '<span class="state state-down">▼ down</span>',
                         maintenance: '<span class="state state-unknown">◆ maint.</span>' };
    const dur = (s) => {
      if (s == null) return "–";
      const dd = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600);
      return dd ? `${dd}d ${hh}h` : `${hh}h ${Math.floor((s % 3600) / 60)}m`;
    };
    table(root.querySelector('[data-table="health"]'),
          ["Device", "State", "CPU", "Memory", "Temp", "Uptime", "Clients", "Availability", "Firmware"],
          d.health.map((h) => [esc(h.name) + (h.model ? ` <span class="muted">${esc(h.model)}</span>` : ""),
                               stateLabel[h.state] || '<span class="muted">–</span>',
                               meter(h.cpu_pct, 70, 90), meter(h.mem_pct, 80, 92),
                               h.temp_c != null ? `${h.temp_c.toFixed(1)} °C` : '<span class="muted">–</span>',
                               dur(h.uptime_s), h.client_count != null ? nf.format(h.client_count) : "–",
                               h.availability != null ? `${h.availability.toFixed(2)} %` : "–",
                               esc(h.firmware || "") + (h.upgradable ? ` <span class="badge warn" title="${esc(h.firmware_latest || "update available")}">▲ update</span>` : "")]));

    // --- Internet traffic: one colour pair per WAN (download = slot n, upload = slot n+1) -------
    const gb = (n) => `${(n / 1e9).toLocaleString(undefined, { maximumFractionDigits: 2 })} GB`;
    const tsr = d.traffic || [];
    const tt = root.querySelector('[data-tile="traffic-total"]');
    if (tt) tt.textContent = tsr.length ? tsr.map((s) => `${s.name}: ↓ ${gb(s.rx_bytes)} · ↑ ${gb(s.tx_bytes)} in ${range}`).join("  ·  ")
                                          + (d.traffic_links > tsr.length ? `  ·  busiest ${tsr.length} of ${d.traffic_links} WAN links shown; pick a client for all of its links` : "")
                                        : "No WAN traffic counters yet (polled every minute).";
    const trSeries = (idxDown, idxUp, unitDown, unitUp) => tsr.flatMap((s, i) => [
      { name: `${s.name} ${unitDown}`, type: "line", showSymbol: false, color: pal[(2 * i) % pal.length], lineStyle: { width: 2 },
        connectNulls: false, data: s.points.map((p) => [p[0], p[idxDown]]) },
      { name: `${s.name} ${unitUp}`, type: "line", showSymbol: false, color: pal[(2 * i + 1) % pal.length], lineStyle: { width: 2 },
        connectNulls: false, data: s.points.map((p) => [p[0], p[idxUp]]) },
    ]);
    const fmtRate = (unit, digits) => (params) => {
      if (!params.length) return "";
      return `<strong>${esc(fmtFull(params[0].value[0]))}</strong>` + params.map((p) =>
        `<br>${p.marker} ${esc(p.seriesName)}: <strong>${p.value[1] == null ? "–" : p.value[1].toFixed(digits)}</strong> ${unit}`).join("");
    };
    chart("c-traffic", baseOption({ series: trSeries(1, 2, "download", "upload"),
                                    tooltip: { ...baseOption({}).tooltip, formatter: fmtRate("Mbps", 2) } }));
    chart("c-packets", baseOption({ series: trSeries(3, 4, "in", "out"),
                                    tooltip: { ...baseOption({}).tooltip, formatter: fmtRate("pkt/s", 0) } }));
    drillTime("c-traffic", { type: "traffic" });
    drillTime("c-packets", { type: "traffic" });
    const f2 = (v, n = 2) => (v == null ? "–" : v.toFixed(n));
    table(root.querySelector('[data-table="traffic"]'), ["Time", ...tsr.flatMap((s) => [`${s.name} ↓ Mbps`, `${s.name} ↑ Mbps`])],
          (tsr[0] ? tsr[0].points : []).map((p, k) => [esc(fmtFull(p[0])), ...tsr.flatMap((s) => [f2(s.points[k][1]), f2(s.points[k][2])])]));
    table(root.querySelector('[data-table="packets"]'), ["Time", ...tsr.flatMap((s) => [`${s.name} in pkt/s`, `${s.name} out pkt/s`])],
          (tsr[0] ? tsr[0].points : []).map((p, k) => [esc(fmtFull(p[0])), ...tsr.flatMap((s) => [f2(s.points[k][3], 0), f2(s.points[k][4], 0)])]));

    // --- WAN & internet -------------------------------------------------------------------
    const wanStatus = {
      up: '<span class="state state-up">▲ up</span>',
      down: '<span class="state state-down">▼ down</span>',
      unused: '<span class="muted">not in use</span>',
    };
    table(root.querySelector('[data-table="wan"]'),
          ["Gateway", "Link", "Port", "Status", "Uplink", "IP", "Latency", "Availability", "Drops", "Since"],
          (d.wan || []).map((w) => [
            esc(w.device),
            w.wan_name === "internet" ? "<strong>Internet</strong>" : `${esc(w.label || w.wan_name)} <span class="muted">${esc(w.wan_name)}</span>`,
            esc([w.ifname, w.media].filter(Boolean).join(" · ")),
            wanStatus[w.status] || esc(w.status),
            w.is_uplink ? '<span class="badge">active</span>' : "",
            esc(w.ip || ""),
            w.latency_ms != null ? `${nf.format(w.latency_ms)} ms` : "",
            w.status === "unused" || w.availability == null ? "–" : `${w.availability.toFixed(2)} %`,
            w.status === "unused" ? "" : nf.format(w.downs),
            w.status === "unused" ? "" : esc(fmtFull(w.started_at)),
          ]));

    // --- Site-to-site VPN (as in the UniFi UI) ---------------------------------------------
    const upFor = (s) => { if (s == null) return "–"; const dd = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
                           return (dd ? `${dd}d ` : "") + `${h}h ${m}m`; };
    const s2s = d.s2s || [];
    const s2sState = (st) => st === "established" ? '<span class="state state-up">● Established</span>'
      : st === "not established" ? '<span class="state state-down">● Not established ⚠</span>' : `<span class="muted">${esc(st)}</span>`;
    const wanLabel = (w) => (w === "WAN" ? "WAN1" : (w || ""));
    table(root.querySelector('[data-table="ipsec"]'),
          ["Name", "Status", "VPN type", "Local IP", "Interface", "Remote IP / host", "Uptime", `Drops (${range})`]
            .concat(new Set(s2s.map((t) => t.device)).size > 1 ? ["Gateway"] : []),
          s2s.map((t) => [esc(t.name), s2sState(t.status), esc(t.vpn_type || ""), esc(t.local_ip || ""), esc(wanLabel(t.interface)),
                          esc(t.peer || ""), t.status === "established" ? upFor(t.uptime_s) : "–", nf.format(t.drops)]
                         .concat(new Set(s2s.map((x) => x.device)).size > 1 ? [esc(t.device)] : [])));

    // --- Tables -----------------------------------------------------------------------
    const status = { ok: "● receiving", silent: "▲ silent", never: "○ never seen", disabled: "– disabled" };
    table(root.querySelector('[data-table="devices"]'), ["Device", "Client", "Status", "Last log", `Lines (${range})`],
          d.devices.map((x) => [esc(x.name), esc(x.client), `<span class="status-${x.status}">${status[x.status]}</span>`,
                                x.last_log_at ? esc(fmtFull(x.last_log_at)) : "–", nf.format(x.lines)]));
    const apps = d.apps || [];
    const byBytes = apps.some((a) => a.flow);
    const appVal = (a) => (byBytes ? a.bytes : a.n);
    const appsMax = Math.max(1, ...apps.map(appVal));
    table(root.querySelector('[data-table="apps"]'), ["Application", "Category", byBytes ? "Data" : "Lookups"],
          apps.map((a) => [linkCell(esc(a.app), { ...rangeParams(), type: "traffic", q: `app=${q(a.app)}` }), `<span class="muted">${esc(a.category)}</span>`,
            `<span class="barcell-inline"><span class="bar" style="width:${(100 * appVal(a) / appsMax).toFixed(1)}%"></span>` +
            `<span class="barval">${byBytes ? bytes(a.bytes) : nf.format(a.n)}</span></span>`]));
    const barCell = (v, max, label) => `<span class="barcell-inline"><span class="bar" style="width:${(100 * v / Math.max(1, max)).toFixed(1)}%"></span>` +
      `<span class="barval">${label}</span></span>`;
    const sites = d.sites || [];
    const sitesByBytes = sites.some((s) => s.flow);
    const siteVal = (s) => (sitesByBytes ? s.bytes : s.n);
    const sitesMax = Math.max(0, ...sites.map(siteVal));
    table(root.querySelector('[data-table="sites"]'), ["Website", "Application", sitesByBytes ? "Data" : "Lookups"],
          sites.map((s) => [linkCell(esc(s.domain), { ...rangeParams(), type: "traffic", q: `domain=${q(s.domain)}` }), `<span class="muted">${esc(s.app || "")}</span>`,
                            barCell(siteVal(s), sitesMax, sitesByBytes ? bytes(s.bytes) : nf.format(s.n))]));
    const talkers = d.talkers || [];
    const talkMax = Math.max(0, ...talkers.map((t) => t.down + t.up));
    table(root.querySelector('[data-table="talkers"]'), ["Device", "Download", "Upload", "Total"],
          talkers.map((t) => [
            (staff ? `<a href="/ip/${encodeURIComponent(t.ip)}">${esc(t.ip)}</a>` : esc(t.ip)) +
              (t.hostname ? ` <span class="muted">${esc(t.hostname)}</span>` : ""),
            bytes(t.down), bytes(t.up), barCell(t.down + t.up, talkMax, bytes(t.down + t.up))]));
    table(root.querySelector('[data-table="threats"]'), ["Signature / policy", "Hits", "Sources", "Last seen"],
          d.threats.map((x) => [x.rule ? linkCell(esc(x.rule), { ...rangeParams(), type: "security", q: `policy=${q(x.rule)}` }) : "(unnamed)",
                                nf.format(x.n), nf.format(x.sources), esc(fmtFull(x.last))]));
    table(root.querySelector('[data-table="changes"]'), ["When", "Admin", "From", "Device", "Change"],
          d.changes.map((x) => [esc(fmtFull(x.ts)), esc(x.admin_user || ""), esc(x.source_ip || ""), esc(x.device), esc(x.summary)]));

    document.getElementById("dash-status").textContent = `Updated ${fmtFull(d.now)} · refreshes every 60 s`;
  }

  // --- Saved-search widgets: big count + trend line, one request each ------------------------
  async function loadSearches() {
    const pal = dark() ? PALETTE.dark : PALETTE.light;
    await Promise.all([...root.querySelectorAll("[data-search]")].map(async (box) => {
      const countEl = box.querySelector('[data-role="count"]');
      try {
        const r = await fetch(`/api/dashboard/search/${encodeURIComponent(box.dataset.search)}?range=${encodeURIComponent(range)}`,
                              { headers: { Accept: "application/json" } });
        if (!r.ok) { countEl.textContent = "–"; countEl.title = `Could not load (${r.status})`; return; }
        const d = await r.json();
        countEl.textContent = nf.format(d.count);
        countEl.href = d.link;
        countEl.title = `Open “${d.name}” in Log View`;
        const id = box.querySelector(".chart")?.id;
        if (id) {
          chart(id, baseOption({
            grid: { left: 8, right: 8, top: 8, bottom: 8, containLabel: true }, legend: { show: false },
            series: [{ name: d.name, type: "line", showSymbol: false, color: pal[0], lineStyle: { width: 2 },
                       areaStyle: { opacity: 0.15 }, data: d.points }],
            tooltip: { ...baseOption({}).tooltip, formatter: axisTooltip(" events") },
          }));
        }
      } catch {
        countEl.textContent = "–";
      }
    }));
  }

  async function load() {
    root.classList.add("loading");
    try {
      const r = await fetch(`/api/dashboard?range=${encodeURIComponent(range)}`, { headers: { Accept: "application/json" } });
      if (r.redirected || !r.ok) { document.getElementById("dash-status").textContent = `Could not load data (${r.status}).`; return; }
      render(await r.json());
      loadSearches();   // after render: uses the scope's time zone
    } catch (e) {
      document.getElementById("dash-status").textContent = "Could not load data.";
    } finally {
      root.classList.remove("loading");
    }
  }

  window.addEventListener("resize", () => Object.values(charts).forEach((c) => c.resize()));
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", load);
  load();
  setInterval(load, 60000);
})();
