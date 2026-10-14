// Small progressive enhancements, shared by every page. Inline handlers are blocked by the
// Content-Security-Policy, so data attributes are wired up here instead.
document.addEventListener("change", (e) => {
  const form = e.target.closest("form[data-autosubmit]");
  if (form) { form.requestSubmit(); return; }
  if (e.target.matches("select[data-autosubmit]") && e.target.form) e.target.form.requestSubmit();
});
// <form data-confirm="Question?">: ask before submitting (also for buttons outside the form via form="id").
document.addEventListener("submit", (e) => {
  const q = e.target.dataset ? e.target.dataset.confirm : null;
  if (q && !confirm(q)) e.preventDefault();
});

// "Create new" pop-ups: <button data-dialog="id"> opens <dialog id="id">; [data-dialog-close] closes it.
document.addEventListener("click", (e) => {
  const open = e.target.closest("[data-dialog]");
  if (open) {
    const d = document.getElementById(open.dataset.dialog);
    if (d && d.showModal) { e.preventDefault(); d.showModal(); const f = d.querySelector("input:not([type=hidden]), select, textarea"); if (f) f.focus(); }
    return;
  }
  const close = e.target.closest("[data-dialog-close]");
  if (close) { const d = close.closest("dialog"); if (d) { e.preventDefault(); d.close(); } }
});

// Date-range presets: <button data-range-from="YYYY-MM-DD" data-range-to="..."> fills the date inputs of its form.
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-range-from]");
  if (!b || !b.form) return;
  e.preventDefault();
  b.form.elements.date_from.value = b.dataset.rangeFrom;
  b.form.elements.date_to.value = b.dataset.rangeTo;
});

// "/" jumps to the top search box (unless already typing somewhere).
document.addEventListener("keydown", (e) => {
  if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
  const t = e.target;
  if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
  const box = document.getElementById("topq");
  if (box) { e.preventDefault(); box.focus(); box.select(); }
});

// Main menu: collapse to icons, and remember which groups were folded open (per browser; storage may be unavailable).
(function () {
  const store = {
    get(k) { try { return JSON.parse(localStorage.getItem(k)); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* private mode */ } },
  };
  if (store.get("navMini")) document.body.classList.add("nav-mini");
  const btn = document.querySelector("[data-nav-mini]");
  if (btn) btn.addEventListener("click", () => {
    const mini = document.body.classList.toggle("nav-mini");
    store.set("navMini", mini);
    btn.setAttribute("aria-label", mini ? "Expand menu" : "Collapse menu");
    btn.title = btn.getAttribute("aria-label");
  });
  const burger = document.querySelector("[data-nav-open]");     // phones: the menu folds away behind a button
  if (burger) burger.addEventListener("click", () => {
    burger.setAttribute("aria-expanded", String(document.body.classList.toggle("nav-open")));
  });
  // Accordion: one group open at a time (opening a group folds the others; clicking an open group folds it).
  const groups = Array.from(document.querySelectorAll("details.side-group"));
  groups.forEach((d) => {
    d.addEventListener("toggle", () => {
      if (!d.open) return;
      if (document.body.classList.contains("nav-mini")) {   // icon mode: a click on a group expands the menu
        document.body.classList.remove("nav-mini"); store.set("navMini", false);
      }
      groups.forEach((o) => { if (o !== d && o.open) o.open = false; });
    });
  });
})();
