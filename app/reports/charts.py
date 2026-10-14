"""Report charts as inline SVG (WeasyPrint renders SVG; PDFs run no JavaScript).

Colours: the validated categorical palette in fixed slot order (never cycled; past the last slot, data folds into
"Other"), status colours only for status meaning, hairline grid, muted axis text. Every chart is paired with a legend
or table that carries the labels and values, so identity never rests on colour alone."""

import math
from datetime import date, datetime
from html import escape

SERIES = ("#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948")
OTHER = "#c3c2b7"
STATUS = {"good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a", "critical": "#d03b3b"}
SEVERITY = {"critical": STATUS["critical"], "high": STATUS["serious"], "medium": STATUS["warning"], "low": "#898781"}
GRID, AXIS, INK2, INK = "#e1e0d9", "#898781", "#52514e", "#0b0b0b"
FONT = 'font-family="Montserrat, DejaVu Sans" font-size="8"'


def _fmt(v: float, unit: str = "") -> str:
    if unit == "bytes":
        for u, d in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
            if abs(v) >= d:
                return f"{v / d:.1f} {u}"
        return f"{v:.0f} B"
    if unit == "%":
        return f"{v:.0f} %"
    for u, d in (("M", 1e6), ("k", 1e3)):
        if abs(v) >= d:
            return f"{v / d:.1f}{u}"
    return f"{v:.0f}" if v == int(v) else f"{v:.1f}"


def _nice_max(v: float) -> float:
    if v <= 0:
        return 1.0
    exp = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * exp:
            return m * exp
    return 10 * exp


def _xlabel(x) -> str:
    if isinstance(x, datetime):
        return x.strftime("%d %b %H:%M") if (x.hour or x.minute) else x.strftime("%d %b")
    if isinstance(x, date):
        return x.strftime("%d %b")
    return str(x)


def legend(items: list[tuple[str, str]]) -> str:
    """HTML legend: (colour, label) pairs."""
    return "".join(f'<span class="lg"><span class="sw" style="background:{c}"></span>{escape(str(lbl))}</span>'
                   for c, lbl in items)


def colours(n: int) -> list[str]:
    return [SERIES[i] if i < len(SERIES) else OTHER for i in range(n)]


def fold(items: list[tuple[str, float]], keep: int = 6) -> list[tuple[str, float]]:
    """Largest `keep` slices, the rest summed into "Other" (never a generated colour)."""
    items = [(k, v) for k, v in items if v and v > 0]
    items.sort(key=lambda kv: -kv[1])
    if len(items) <= keep + 1:
        return items
    head, rest = items[:keep], items[keep:]
    return head + [("Other", sum(v for _, v in rest))]


def donut(items: list[tuple[str, float]], unit: str = "", size: int = 150, keep: int = 6,
          palette: dict | None = None, stacked: bool = False) -> str:
    """Pie (donut) chart with a legend table: label, value, share. `palette` maps label -> colour (e.g. severity).
    stacked: legend under the pie (two pies side by side, or one centred) instead of beside it."""
    items = fold(items, keep)
    total = sum(v for _, v in items)
    if not total:
        return '<p class="note">No data in this period.</p>'
    cols = [(palette or {}).get(k) or (OTHER if k == "Other" else c) for (k, _), c in zip(items, colours(len(items)))]
    r, r_in, cx, cy = size / 2 - 2, size / 2 - 2 - size * 0.17, size / 2, size / 2
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" {FONT}>']
    a0 = -math.pi / 2
    for (k, v), c in zip(items, cols):
        frac = v / total
        if frac >= 0.9999:
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{(r + r_in) / 2:.1f}" fill="none" stroke="{c}" stroke-width="{r - r_in:.1f}"/>')
            break
        a1 = a0 + frac * 2 * math.pi
        large = 1 if frac > 0.5 else 0
        p = (f"M{cx + r * math.cos(a0):.2f},{cy + r * math.sin(a0):.2f} "
             f"A{r:.1f},{r:.1f} 0 {large} 1 {cx + r * math.cos(a1):.2f},{cy + r * math.sin(a1):.2f} "
             f"L{cx + r_in * math.cos(a1):.2f},{cy + r_in * math.sin(a1):.2f} "
             f"A{r_in:.1f},{r_in:.1f} 0 {large} 0 {cx + r_in * math.cos(a0):.2f},{cy + r_in * math.sin(a0):.2f} Z")
        parts.append(f'<path d="{p}" fill="{c}" stroke="#ffffff" stroke-width="1.5"/>')   # 2px surface gap between slices
        a0 = a1
    parts.append(f'<text x="{cx}" y="{cy - 1}" text-anchor="middle" font-size="11" fill="{INK}">{_fmt(total, unit)}</text>')
    parts.append(f'<text x="{cx}" y="{cy + 10}" text-anchor="middle" fill="{AXIS}">total</text></svg>')
    rows = "".join(f'<tr><td><span class="sw" style="background:{c}"></span>{escape(str(k))}</td>'
                   f'<td class="n">{_fmt(v, unit)}</td><td class="n">{v / total * 100:.1f} %</td></tr>'
                   for (k, v), c in zip(items, cols))
    if stacked:
        return f'<div class="pie-stack">{"".join(parts)}<table class="pie-legend">{rows}</table></div>'
    return (f'<table class="pie"><tr><td class="pie-svg">{"".join(parts)}</td><td>'
            f'<table class="pie-legend">{rows}</table></td></tr></table>')


def line_chart(x: list, series: list[tuple[str, list[float]]], unit: str = "", width: int = 640, height: int = 170,
               area: bool = False) -> str:
    """Time series, one 2px line per series (fixed slot colours), shared axis; legend above via `legend()`."""
    if not x or not series or not any(any(v for v in s if v is not None) for _, s in series):
        return '<p class="note">No data in this period.</p>'
    top = _nice_max(max(max((v for v in s if v is not None), default=0) for _, s in series))
    left, bottom, right, tp = 54, 20, 6, 6
    w, h = width - left - right, height - bottom - tp
    step = w / max(1, len(x) - 1)
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" {FONT}>']
    for frac in (0, 0.25, 0.5, 0.75, 1):
        y = tp + h * (1 - frac)
        parts.append(f'<line x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}" stroke="{GRID}" stroke-width="0.5"/>')
        parts.append(f'<text x="{left - 4}" y="{y + 3:.1f}" text-anchor="end" fill="{AXIS}">{_fmt(top * frac, unit)}</text>')
    for (name, vals), c in zip(series, colours(len(series))):
        runs, run = [], []                       # missing values (None) break the line instead of dropping to zero
        for i, v in enumerate(vals):
            if v is None:
                if run:
                    runs.append(run)
                run = []
            else:
                run.append((left + i * step, tp + h * (1 - v / top)))
        if run:
            runs.append(run)
        for pts in runs:
            d = " ".join(f"{px:.1f},{py:.1f}" for px, py in pts)
            if area and len(pts) > 1:
                parts.append(f'<polygon points="{pts[0][0]:.1f},{tp + h:.1f} {d} {pts[-1][0]:.1f},{tp + h:.1f}" fill="{c}" fill-opacity="0.12"/>')
            if len(pts) == 1:
                parts.append(f'<circle cx="{pts[0][0]:.1f}" cy="{pts[0][1]:.1f}" r="2" fill="{c}"/>')
            else:
                parts.append(f'<polyline points="{d}" fill="none" stroke="{c}" stroke-width="1.6" stroke-linejoin="round"/>')
    every = max(1, len(x) // 8)
    for i, xv in enumerate(x):
        if i % every == 0 or i == len(x) - 1:
            anchor = "end" if i == len(x) - 1 and len(x) > 1 else ("start" if i == 0 else "middle")
            parts.append(f'<text x="{left + i * step:.1f}" y="{height - 6}" text-anchor="{anchor}" fill="{INK2}">{escape(_xlabel(xv))}</text>')
    parts.append("</svg>")
    return legend([(c, n) for (n, _), c in zip(series, colours(len(series)))]) + "".join(parts) if len(series) > 1 else "".join(parts)


def stacked_bars(x: list, series: list[tuple[str, list[float]]], unit: str = "", width: int = 640, height: int = 170,
                 palette: dict | None = None) -> str:
    """Daily (or hourly) stacked columns; segments separated by a surface gap; legend above."""
    totals = [sum((s[i] or 0) for _, s in series) for i in range(len(x))]
    if not x or not any(totals):
        return '<p class="note">No data in this period.</p>'
    top = _nice_max(max(totals))
    left, bottom, right, tp = 54, 20, 6, 6
    w, h = width - left - right, height - bottom - tp
    slot = w / len(x)
    bw = max(1.5, slot * 0.7)
    cols = [(palette or {}).get(n) or c for (n, _), c in zip(series, colours(len(series)))]
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" {FONT}>']
    for frac in (0, 0.5, 1):
        y = tp + h * (1 - frac)
        parts.append(f'<line x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}" stroke="{GRID}" stroke-width="0.5"/>')
        parts.append(f'<text x="{left - 4}" y="{y + 3:.1f}" text-anchor="end" fill="{AXIS}">{_fmt(top * frac, unit)}</text>')
    for i in range(len(x)):
        y = tp + h
        bx = left + i * slot + (slot - bw) / 2
        for (_, vals), c in zip(series, cols):
            v = vals[i] or 0
            if v <= 0:
                continue
            bh = h * v / top
            parts.append(f'<rect x="{bx:.1f}" y="{y - bh:.1f}" width="{bw:.1f}" height="{max(0.5, bh - 0.6):.1f}" fill="{c}"/>')
            y -= bh
    every = max(1, len(x) // 10)
    for i, xv in enumerate(x):
        if i % every == 0:
            parts.append(f'<text x="{left + i * slot + slot / 2:.1f}" y="{height - 6}" text-anchor="middle" fill="{INK2}">{escape(_xlabel(xv))}</text>')
    parts.append("</svg>")
    lg = legend([(c, n) for (n, _), c in zip(series, cols)]) if len(series) > 1 else ""
    return lg + "".join(parts)


def hbars(items: list[tuple[str, float]], unit: str = "", width: int = 640, colour: str = SERIES[0], top_n: int = 10) -> str:
    """Top-N horizontal bars with the label left and the value at the bar end (direct labels, one series)."""
    items = [(k, v) for k, v in items if v][:top_n]
    if not items:
        return '<p class="note">No data in this period.</p>'
    row, label_w, val_w = 15, 200, 60
    top = max(v for _, v in items)
    bar_w = width - label_w - val_w
    height = row * len(items) + 4
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" {FONT}>']
    for i, (k, v) in enumerate(items):
        y = i * row + 2
        lbl = str(k)
        lbl = lbl if len(lbl) <= 38 else lbl[:37] + "…"
        parts.append(f'<text x="{label_w - 6}" y="{y + 10}" text-anchor="end" fill="{INK}">{escape(lbl)}</text>')
        bw = max(1.0, bar_w * v / top)
        parts.append(f'<rect x="{label_w}" y="{y + 2}" width="{bw:.1f}" height="{row - 5}" rx="1.5" fill="{colour}"/>')
        parts.append(f'<text x="{label_w + bw + 4:.1f}" y="{y + 10}" fill="{INK2}">{_fmt(v, unit)}</text>')
    parts.append("</svg>")
    return "".join(parts)
