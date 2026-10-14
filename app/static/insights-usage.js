// Insights → Devices & usage: bandwidth over time (ECharts), stacked by app / website, or download vs upload for one item.
// Colours: the validated categorical palette in fixed order; "Other" is neutral grey.
(() => {
  const el = document.getElementById("usage-chart");
  const dataEl = document.getElementById("usage-data");
  if (!el || !dataEl || !window.echarts) return;
  const cfg = JSON.parse(dataEl.textContent);
  if (!cfg.series.length || !cfg.series.some((s) => s.data.some((v) => v > 0))) { el.style.display = "none"; return; }
  const dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const palette = dark ? ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"]
                       : ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"];
  const ink = dark ? { text: "#e6e9ed", muted: "#9aa4b0", grid: "#2c333b", surface: "#1a1f25" }
                   : { text: "#1b1f24", muted: "#5d6673", grid: "#e6e8eb", surface: "#ffffff" };
  const bytes = (v) => {
    for (const [u, d] of [["TB", 1e12], ["GB", 1e9], ["MB", 1e6], ["KB", 1e3]]) if (v >= d) return (v / d).toFixed(1) + " " + u;
    return Math.round(v) + " B";
  };
  const daily = cfg.step_s >= 86400;
  const fmt = new Intl.DateTimeFormat(undefined, daily ? { month: "short", day: "numeric" }
                                                        : { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const chart = echarts.init(el, null, { renderer: "svg" });
  chart.setOption({
    backgroundColor: "transparent",
    color: cfg.series.map((s, i) => (s.name === "Other" ? (dark ? "#5d6673" : "#c3c2b7") : palette[i % palette.length])),
    grid: { left: 64, right: 16, top: 40, bottom: 32 },
    legend: { top: 0, type: "scroll", textStyle: { color: ink.muted } },
    tooltip: {
      trigger: "axis", backgroundColor: ink.surface, borderColor: ink.grid, textStyle: { color: ink.text },
      formatter: (ps) => `<strong>${esc(fmt.format(new Date(ps[0].axisValue)))}</strong><br>` +
        ps.filter((p) => p.value > 0).map((p) => `${p.marker} ${esc(p.seriesName)}: ${bytes(p.value)}`).join("<br>"),
    },
    xAxis: { type: "category", data: cfg.x, boundaryGap: false, axisLabel: { color: ink.muted, formatter: (v) => fmt.format(new Date(v)) },
             axisLine: { lineStyle: { color: ink.grid } } },
    yAxis: { type: "value", axisLabel: { color: ink.muted, formatter: bytes }, splitLine: { lineStyle: { color: ink.grid } } },
    series: cfg.series.map((s) => ({ name: s.name, type: "line", stack: "total", areaStyle: { opacity: 0.35 },
                                     symbol: "none", lineStyle: { width: 1.5 }, data: s.data })),
  });
  window.addEventListener("resize", () => chart.resize());
})();
