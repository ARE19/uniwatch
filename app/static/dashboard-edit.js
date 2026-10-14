// Dashboard customisation: reorder (drag or ◀ ▶), resize, remove and add widgets, then save the layout.
// Changes stay in the page until Save; the server re-validates every layout.
(() => {
  const root = document.getElementById("dash");
  const grid = document.getElementById("widgets");
  const bar = document.getElementById("edit-bar");
  const editBtn = document.getElementById("dash-edit");
  if (!root || !grid || !bar || !editBtn) return;
  const addDialog = document.getElementById("add-dialog");
  const saveDialog = document.getElementById("save-dialog");
  const saveForm = document.getElementById("save-form");
  const SIZES = ["third", "half", "full"];
  let editing = false;

  const widgets = () => [...grid.querySelectorAll(":scope > .widget")];
  const resizeCharts = () => window.dispatchEvent(new Event("resize"));

  function setEditing(on) {
    editing = on;
    root.classList.toggle("editing", on);
    bar.hidden = !on;
    editBtn.hidden = on;
    widgets().forEach((w) => { w.draggable = on; });
    refreshCatalogue();
  }

  function setSize(w, size) {
    if (!SIZES.includes(size)) return;
    SIZES.forEach((s) => w.classList.remove(`w-${s}`));
    w.classList.add(`w-${size}`);
    w.dataset.size = size;
    w.querySelectorAll('[data-act="size"]').forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.size === size)));
    resizeCharts();
  }

  // ---- toolbar buttons -----------------------------------------------------------------
  grid.addEventListener("click", (e) => {
    const b = e.target.closest(".widget-tools button");
    if (!b || !editing) return;
    const w = b.closest(".widget");
    const act = b.dataset.act;
    if (act === "left" && w.previousElementSibling) grid.insertBefore(w, w.previousElementSibling);
    else if (act === "right" && w.nextElementSibling) grid.insertBefore(w.nextElementSibling, w);
    else if (act === "size") setSize(w, b.dataset.size);
    else if (act === "remove") { w.remove(); refreshCatalogue(); }
    b.focus();
    resizeCharts();
  });

  // ---- drag and drop (mouse); ◀ ▶ cover keyboard and touch -------------------------------
  let dragged = null;
  grid.addEventListener("dragstart", (e) => {
    const w = e.target.closest(".widget");
    if (!editing || !w) return;
    dragged = w;
    w.classList.add("dragging");
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", w.dataset.w);
  });
  grid.addEventListener("dragover", (e) => {
    if (!dragged) return;
    e.preventDefault();
    const target = e.target.closest(".widget");
    widgets().forEach((w) => w.classList.toggle("drop-target", w === target && w !== dragged));
    if (!target || target === dragged) return;
    const r = target.getBoundingClientRect();
    const after = (e.clientY - r.top) / r.height > 0.5 || ((e.clientX - r.left) / r.width > 0.5 && e.clientY - r.top < r.height);
    grid.insertBefore(dragged, after ? target.nextElementSibling : target);
  });
  grid.addEventListener("dragend", () => {
    if (dragged) dragged.classList.remove("dragging");
    widgets().forEach((w) => w.classList.remove("drop-target"));
    dragged = null;
    resizeCharts();
  });

  // ---- add widgets --------------------------------------------------------------------------
  function refreshCatalogue() {
    if (!addDialog) return;
    const present = new Set(widgets().map((w) => w.dataset.w));
    addDialog.querySelectorAll("button[data-add]").forEach((b) => {
      const single = b.dataset.add !== "search";
      b.disabled = single && present.has(b.dataset.add);
      b.textContent = b.disabled ? "Added" : "Add";
    });
  }

  function placeholder(id, size, title, cfg) {
    const s = document.createElement("section");
    s.className = `card widget w-${size}`;
    s.dataset.w = id;
    s.dataset.size = size;
    s.dataset.cfg = JSON.stringify(cfg || {});
    s.draggable = true;
    const tools = grid.querySelector(".widget-tools");
    if (tools) s.appendChild(tools.cloneNode(true));
    s.querySelectorAll('[data-act="size"]').forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.size === size)));
    const h = document.createElement("h2");
    h.textContent = title;
    const p = document.createElement("p");
    p.className = "widget-placeholder";
    p.textContent = "New widget: it shows data once the dashboard is saved.";
    s.append(h, p);
    if (!tools) s.prepend(toolsFallback(size));
    return s;
  }

  function toolsFallback(size) {   // first widget on an empty dashboard: build the toolbar from scratch
    const t = document.createElement("div");
    t.className = "widget-tools";
    t.innerHTML = '<span class="drag-handle" aria-hidden="true">⠿</span>' +
      '<button type="button" data-act="left" aria-label="Move earlier">◀</button>' +
      '<button type="button" data-act="right" aria-label="Move later">▶</button>' +
      SIZES.map((s) => `<button type="button" data-act="size" data-size="${s}" aria-pressed="${s === size}">${{ third: "⅓", half: "½", full: "Full" }[s]}</button>`).join("") +
      '<button type="button" data-act="remove" aria-label="Remove widget">✕</button>';
    return t;
  }

  document.getElementById("edit-add").addEventListener("click", () => { refreshCatalogue(); addDialog.showModal(); });
  addDialog.addEventListener("click", (e) => {
    const b = e.target.closest("button[data-add]");
    if (!b || b.disabled) return;
    let cfg = {}, title = b.dataset.title || b.closest("li").querySelector("strong").textContent;
    if (b.dataset.add === "search") {
      const sel = document.getElementById("add-search-id");
      cfg = { search_id: Number(sel.value) };
      title = sel.options[sel.selectedIndex].textContent;
    }
    const w = placeholder(b.dataset.add, b.dataset.size, title, cfg);
    grid.querySelector(":scope > p.muted")?.remove();
    grid.appendChild(w);
    refreshCatalogue();
    w.scrollIntoView({ behavior: "smooth", block: "nearest" });
  });

  // ---- reset / cancel ---------------------------------------------------------------------
  document.getElementById("edit-cancel").addEventListener("click", () => location.reload());
  document.getElementById("edit-reset").addEventListener("click", () => {
    if (!confirm("Replace the widgets on this dashboard with the standard set? (Nothing is saved until you press Save.)")) return;
    const layout = JSON.parse(document.getElementById("default-layout").textContent);
    widgets().forEach((w) => w.remove());
    layout.forEach((it) => {
      const title = addDialog.querySelector(`button[data-add="${it.w}"]`)?.dataset.title || it.w;
      grid.appendChild(placeholder(it.w, it.size, title, it.cfg));
    });
    refreshCatalogue();
  });

  // ---- save -----------------------------------------------------------------------------------
  const layout = () => widgets().map((w) => {
    const item = { w: w.dataset.w, size: w.dataset.size };
    const cfg = JSON.parse(w.dataset.cfg || "{}");
    if (Object.keys(cfg).length) item.cfg = cfg;
    return item;
  });

  document.getElementById("edit-save").addEventListener("click", () => {
    const share = saveForm.elements.share;
    if (share) share.value = root.dataset.share || "private";
    if (saveForm.elements.is_default) saveForm.elements.is_default.checked = root.dataset.default === "true";
    document.getElementById("save-error").hidden = true;
    saveDialog.showModal();
  });

  saveForm.addEventListener("submit", async (e) => {
    const mode = e.submitter ? e.submitter.value : "new";
    if (mode === "cancel") return;   // let the dialog close
    e.preventDefault();
    const err = document.getElementById("save-error");
    if (!layout().length) { err.textContent = "Add at least one widget first."; err.hidden = false; return; }
    const f = saveForm.elements;
    const body = {
      id: mode === "update" ? Number(root.dataset.board) || null : null,
      as_new: mode !== "update",
      name: f.name.value.trim(),
      share: f.share ? f.share.value : "private",
      is_default: f.is_default ? f.is_default.checked : false,
      layout: layout(),
    };
    try {
      const r = await fetch("/dashboards/save", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": root.dataset.csrf, Accept: "application/json" },
        body: JSON.stringify(body),
      });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        err.textContent = d.detail || `Could not save (${r.status}).`;
        err.hidden = false;
        return;
      }
      location.href = `/?range=${encodeURIComponent(root.dataset.range)}`;
    } catch {
      err.textContent = "Could not save: the server did not answer.";
      err.hidden = false;
    }
  });

  editBtn.addEventListener("click", () => setEditing(true));
})();
