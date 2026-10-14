"""Severity normalisation. Vendors can pass their own mapping tables."""

# CEF severity 0-10 -> normalised (brief default: 0-3 low, 4-6 medium, 7-8 high, 9-10 critical)
CEF_NUMERIC_DEFAULT = {**{i: "low" for i in range(0, 4)}, **{i: "medium" for i in range(4, 7)},
                       7: "high", 8: "high", 9: "critical", 10: "critical"}
CEF_TEXT_DEFAULT = {"unknown": "low", "low": "low", "medium": "medium", "high": "high", "very-high": "critical"}

SYSLOG_NAMES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")
# RFC 5424 severity -> normalised
SYSLOG_DEFAULT = {0: "critical", 1: "critical", 2: "critical", 3: "high", 4: "medium", 5: "low", 6: "low", 7: "low"}


def from_cef(raw: str, numeric: dict | None = None, text: dict | None = None) -> str:
    numeric = numeric or CEF_NUMERIC_DEFAULT
    text = text or CEF_TEXT_DEFAULT
    v = raw.strip()
    if v.isdigit():
        return numeric.get(min(int(v), 10), "low")
    return text.get(v.lower(), "low")


def from_syslog(sev: int | None, mapping: dict | None = None) -> str:
    if sev is None:
        return "low"
    return (mapping or SYSLOG_DEFAULT).get(sev, "low")
