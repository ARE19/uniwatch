// Insights → Countries: world map (ECharts) of attack sources or traffic destinations. Click a country (staff) to open
// its events in Log View. Sequential palette: one hue, light (few) to dark (many); countries without data stay neutral.
(() => {
  const el = document.getElementById("worldmap");
  const dataEl = document.getElementById("worldmap-data");
  if (!el || !dataEl || !window.echarts) return;
  const cfg = JSON.parse(dataEl.textContent);
  const dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const ink = dark ? { text: "#e6e9ed", muted: "#9aa4b0", empty: "#2c333b", border: "#1a1f25", surface: "#1a1f25" }
                   : { text: "#1b1f24", muted: "#5d6673", empty: "#e6e8eb", border: "#ffffff", surface: "#ffffff" };
  const ramp = dark ? ["#1e3a5f", "#2f5f9e", "#3987e5", "#86b6f0"] : ["#d6e6fa", "#8fbcef", "#3f86d9", "#1f5fbf"];
  const nf = new Intl.NumberFormat();
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  fetch("/static/world.geo.json").then((r) => r.json()).then((geo) => {
    const label = Object.fromEntries(geo.features.map((f) => [f.properties.name, f.properties.label]));
    echarts.registerMap("world", geo);
    const chart = echarts.init(el, null, { renderer: "svg" });
    const max = Math.max(1, ...cfg.data.map((d) => d.value));
    chart.setOption({
      backgroundColor: "transparent",
      tooltip: {
        trigger: "item", backgroundColor: ink.surface, borderColor: ink.empty, textStyle: { color: ink.text },
        formatter: (p) => `<strong>${esc(label[p.name] || p.name)}</strong><br>` +
          (p.value > 0 ? `${nf.format(p.value)} ${esc(cfg.unit)}` : `<span style="color:${ink.muted}">no ${esc(cfg.unit)}</span>`),
      },
      visualMap: {
        min: 0, max, left: 8, bottom: 8, calculable: false, itemWidth: 10, itemHeight: 90,
        text: [nf.format(max), "0"], textStyle: { color: ink.muted }, inRange: { color: ramp },
      },
      series: [{
        type: "map", map: "world", roam: true, zoom: 1.15, center: [20, 15],
        itemStyle: { areaColor: ink.empty, borderColor: ink.border, borderWidth: 0.6 },
        emphasis: { label: { show: false }, itemStyle: { areaColor: dark ? "#fab219" : "#eda100" } },
        select: { disabled: true },
        data: cfg.data,
      }],
    });
    if (cfg.staff) {
      el.classList.add("drillable");
      chart.on("click", (p) => {
        if (p.value > 0) location.href = cfg.link.replace("__CC__", encodeURIComponent(p.name));
      });
    }
    window.addEventListener("resize", () => chart.resize());
  }).catch(() => { el.textContent = "The map could not be loaded."; });
})();
