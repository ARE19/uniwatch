// NOC wall: one client at a time, full screen, rotating. Data comes from /api/dashboard?client=<id>.
(() => {
  const root = document.getElementById("wall");
  if (!root) return;
  const clients = JSON.parse(document.getElementById("wall-clients").textContent);
  const every = Math.max(10, Number(root.dataset.seconds) || 30) * 1000;
  const range = root.dataset.range || "24h";
  const nf = new Intl.NumberFormat();
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  let i = 0, paused = false, timer = null;

  const tile = (label, value, cls = "") => `<div class="wtile ${cls}"><span>${esc(label)}</span><strong>${value}</strong></div>`;
  const state = (s) => ({ up: '<span class="state state-up">▲ up</span>', down: '<span class="state state-down">▼ down</span>',
                          unused: '<span class="muted">not in use</span>' }[s] || esc(s || "–"));

  async function show() {
    const c = clients[i % clients.length];
    root.querySelector("[data-client]").textContent = c.name;
    root.querySelector("[data-pos]").textContent = `${(i % clients.length) + 1} / ${clients.length}`;
    try {
      const r = await fetch(`/api/dashboard?range=${encodeURIComponent(range)}&client=${c.id}`, { headers: { Accept: "application/json" } });
      if (!r.ok) throw new Error(r.status);
      const d = await r.json();
      const t = d.tiles;
      const up = d.vpn.filter((v) => v.state === "up").length;
      const wanDown = (d.wan || []).filter((w) => w.status === "down").length;
      root.querySelector("[data-tiles]").innerHTML =
        tile("Open alerts", nf.format(d.open_alerts || 0), d.open_alerts ? "warn" : "ok") +
        tile("Critical", nf.format(t.severity.critical), t.severity.critical ? "crit" : "") +
        tile("High", nf.format(t.severity.high)) +
        tile("Devices silent", nf.format(t.devices_silent), t.devices_silent ? "warn" : "ok") +
        tile("WAN links down", nf.format(wanDown), wanDown ? "crit" : "ok") +
        tile("VPN tunnels up", d.vpn.length ? `${up} / ${d.vpn.length}` : "–", d.vpn.length && up < d.vpn.length ? "warn" : "") +
        tile("Events", nf.format(t.events));
      root.querySelector("[data-wan]").innerHTML = (d.wan || []).length
        ? (d.wan || []).map((w) => `<tr><td>${esc(w.device)}</td><td>${w.wan_name === "internet" ? "<strong>Internet</strong>" : esc(w.label || w.wan_name)}</td>
             <td>${state(w.status)}</td><td>${w.latency_ms != null ? nf.format(w.latency_ms) + " ms" : ""}</td>
             <td>${w.status === "unused" || w.availability == null ? "" : w.availability.toFixed(2) + " %"}</td></tr>`).join("")
        : '<tr><td class="muted">No WAN data (this firewall is not polled through the API).</td></tr>';
      root.querySelector("[data-threats]").innerHTML = d.threats.length
        ? d.threats.map((x) => `<tr><td>${esc(x.rule || "(unnamed)")}</td><td class="num">${nf.format(x.n)}</td></tr>`).join("")
        : '<tr><td class="muted">No IDS/IPS alerts.</td></tr>';
      root.querySelector("[data-apps]").innerHTML = (d.apps || []).slice(0, 6).length
        ? d.apps.slice(0, 6).map((a) => `<tr><td>${esc(a.app)}</td><td class="num muted">${esc(a.category)}</td></tr>`).join("")
        : '<tr><td class="muted">No app data.</td></tr>';
      root.querySelector("[data-updated]").textContent = `Updated ${new Date().toLocaleTimeString()} · ${range}`;
    } catch (e) {
      root.querySelector("[data-updated]").textContent = `Could not load ${c.name} (${e.message}).`;
    }
  }

  function next(step = 1) {
    i = (i + step + clients.length) % clients.length;
    show();
  }
  function schedule() {
    clearInterval(timer);
    timer = setInterval(() => { if (!paused) next(); }, every);
  }
  document.getElementById("wall-full").addEventListener("click", () => {
    if (document.fullscreenElement) document.exitFullscreen(); else document.documentElement.requestFullscreen?.();
  });
  document.getElementById("wall-pause").addEventListener("click", (e) => {
    paused = !paused;
    e.target.textContent = paused ? "▶ Resume" : "❚❚ Pause";
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "ArrowRight") { next(1); schedule(); }
    if (e.key === "ArrowLeft") { next(-1); schedule(); }
    if (e.key === " ") { e.preventDefault(); document.getElementById("wall-pause").click(); }
  });
  show();
  schedule();
})();
