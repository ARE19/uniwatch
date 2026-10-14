"""Interval arithmetic for availability: clip state intervals to a period and reclassify down time that
falls inside maintenance windows. Pure functions, so report numbers can be checked by hand in tests."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass
class Summary:
    seconds: dict[str, float] = field(default_factory=dict)   # state -> seconds within the period
    outages: list[tuple[datetime, datetime]] = field(default_factory=list)  # down spans (clipped, maintenance removed)
    drops: int = 0                                            # down intervals that START inside the period

    @property
    def availability(self) -> float | None:
        """Share of known, unplanned time that was up. Maintenance and no-data time are excluded."""
        up, down = self.seconds.get("up", 0.0), self.seconds.get("down", 0.0)
        return None if up + down <= 0 else up / (up + down)


def _subtract(span: tuple[datetime, datetime], holes: list[tuple[datetime, datetime]]) -> list[tuple[datetime, datetime]]:
    pieces = [span]
    for hs, he in holes:
        nxt = []
        for s, e in pieces:
            if he <= s or hs >= e:
                nxt.append((s, e))
                continue
            if hs > s:
                nxt.append((s, hs))
            if he < e:
                nxt.append((he, e))
        pieces = nxt
    return pieces


def summarize(intervals: list[tuple[str, datetime, datetime | None]], start: datetime, end: datetime,
              maintenance: list[tuple[datetime, datetime]] | None = None, now: datetime | None = None) -> Summary:
    """intervals: (state, started_at, ended_at or None for still open). States: up/down/unknown/maintenance."""
    now = now or end
    windows = sorted((max(s, start), min(e, end)) for s, e in (maintenance or []) if e > start and s < end)
    out = Summary()
    for state, s, e in intervals:
        e = e or min(now, end)
        cs, ce = max(s, start), min(e, end)
        if ce <= cs:
            continue
        if state == "down":
            unplanned = _subtract((cs, ce), windows)
            if start <= s < end and unplanned:
                out.drops += 1  # a drop wholly inside a maintenance window is planned, not counted
            down = sum((b - a for a, b in unplanned), timedelta())
            out.seconds["down"] = out.seconds.get("down", 0.0) + down.total_seconds()
            planned = (ce - cs) - down
            if planned:
                out.seconds["maintenance"] = out.seconds.get("maintenance", 0.0) + planned.total_seconds()
            out.outages.extend(unplanned)
        else:
            out.seconds[state] = out.seconds.get(state, 0.0) + (ce - cs).total_seconds()
    out.outages.sort()
    return out
