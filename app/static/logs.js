// Log View: time range / device auto-submit, search-field helpers, right-click "filter by value", live tail (SSE),
// selected-row highlight. No inline handlers: the Content-Security-Policy forbids them.
(() => {
  const form = document.getElementById("logfilter");
  const q = document.getElementById("lf-q");
  const range = document.querySelector("[data-custom-toggle]");
  if (range) {
    range.addEventListener("change", () => {
      const custom = range.value === "custom";
      document.querySelectorAll(".custom-range").forEach((el) => { el.hidden = !custom; });
      if (!custom && form) form.submit();
    });
  }
  // Close other open menus when one opens; Escape closes all.
  document.querySelectorAll("details.menu").forEach((d) => d.addEventListener("toggle", () => {
    if (d.open) document.querySelectorAll("details.menu[open]").forEach((o) => { if (o !== d) o.open = false; });
  }));

  // ---- search box: insert "field=" from the ⊕ menu ----------------------------------------
  const insert = (text, submit) => {
    if (!q) return;
    const cur = q.value.trim();
    q.value = cur ? `${cur} ${text}` : text;
    if (submit && form) { form.submit(); return; }
    q.focus();
    q.setSelectionRange(q.value.length, q.value.length);
  };
  document.querySelectorAll("[data-insert]").forEach((b) => b.addEventListener("click", () => {
    b.closest("details").open = false;
    insert(b.dataset.insert, false);
  }));

  // ---- right-click a value: filter by it / exclude it ----------------------------------------
  const menu = document.getElementById("ctxmenu");
  const quote = (v) => (/[\s'",]/.test(v) ? `"${v.replace(/"/g, "")}"` : v);
  const hideMenu = () => { if (menu) menu.hidden = true; };
  document.addEventListener("contextmenu", (e) => {
    const td = e.target.closest("td[data-f]");
    if (!td || !menu || !q) return;
    e.preventDefault();
    const f = td.dataset.f, v = td.dataset.v;
    menu.innerHTML = "";
    [["=", "Filter"], ["!=", "Exclude"]].forEach(([op, label]) => {
      const b = document.createElement("button");
      b.type = "button";
      b.setAttribute("role", "menuitem");
      b.textContent = `${label}: ${f} ${op} ${v}`;
      b.addEventListener("click", () => { hideMenu(); insert(`${f}${op}${quote(v)}`, true); });
      menu.appendChild(b);
    });
    const copy = document.createElement("button");
    copy.type = "button";
    copy.setAttribute("role", "menuitem");
    copy.textContent = "Copy value";
    copy.addEventListener("click", () => { hideMenu(); navigator.clipboard?.writeText(v); });
    menu.appendChild(copy);
    menu.style.left = `${Math.min(e.clientX, window.innerWidth - 300)}px`;
    menu.style.top = `${Math.min(e.clientY, window.innerHeight - 120)}px`;
    menu.hidden = false;
    menu.querySelector("button").focus();
  });
  document.addEventListener("click", (e) => { if (menu && !menu.contains(e.target)) hideMenu(); });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    hideMenu();
    document.querySelectorAll("details.menu[open]").forEach((o) => { o.open = false; });
  });
  window.addEventListener("scroll", hideMenu, { passive: true });

  const tbody = document.getElementById("logrows");
  const logview = document.querySelector(".logview");
  // Details pane only takes space once something is selected.
  document.body.addEventListener("htmx:afterSwap", (e) => {
    if (logview && e.target.id === "detail") logview.classList.add("has-detail");
  });
  document.addEventListener("click", (e) => {
    if (!e.target.closest("[data-close-detail]")) return;
    const d = document.getElementById("detail");
    if (d) d.innerHTML = "";
    if (logview) logview.classList.remove("has-detail");
    document.querySelectorAll("tr.logrow.selected").forEach((x) => x.classList.remove("selected"));
  });
  document.addEventListener("click", (e) => {
    const tr = e.target.closest("tr.logrow");
    if (!tr || e.target.closest("a")) return;
    document.querySelectorAll("tr.logrow.selected").forEach((x) => x.classList.remove("selected"));
    tr.classList.add("selected");
  });

  // Keyboard: Enter on a focused row opens its details (htmx filter expressions need eval, which CSP forbids).
  document.addEventListener("keyup", (e) => {
    if (e.key === "Enter" && e.target.matches && e.target.matches("tr.logrow")) e.target.click();
  });

  const live = document.getElementById("live");
  if (!live || !tbody) return;
  const MAX_ROWS = 500;
  let es = null;
  live.addEventListener("change", () => {
    if (live.checked) {
      es = new EventSource(live.dataset.tail);
      es.addEventListener("rows", (ev) => {
        tbody.insertAdjacentHTML("afterbegin", ev.data); // server-rendered, escaped by Jinja
        if (window.htmx) htmx.process(tbody);
        tbody.querySelectorAll("tr.logrow").forEach((tr, i) => { if (i >= MAX_ROWS) tr.remove(); });
      });
    } else if (es) {
      es.close();
      es = null;
    }
  });
})();
