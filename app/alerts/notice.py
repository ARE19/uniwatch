"""Alert notification text in the NOC's UniFi alert format:

    Subject: UniFi Alert: <what happened> at <client>
    Hello Team, / A UniFi Network alert has been triggered:
    Alert Details:          Message, Severity, Time (UTC)
    Client/Device Details:  Client, Device, then what fits the alert type (Tunnel Name, WAN ISP, Remote GW, ...)

The facts are looked up when the notification is sent (current WAN links, tunnel display name, peer), so e-mail, Teams
and Slack all carry the same text. Alert titles in the UI are unchanged."""

from datetime import UTC, datetime

from sqlalchemy import text


async def _rows(s, sql: str, **p) -> list[dict]:
    return [dict(r._mapping) for r in (await s.execute(text(sql), p)).all()]


def iso(dt: datetime | None) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


async def _device(s, device_id) -> dict | None:
    if not device_id:
        return None
    rows = await _rows(s, """
        SELECT d.name, d.model, host(coalesce(d.mgmt_ip, d.syslog_source_ip)) AS ip, h.isp
        FROM devices d LEFT JOIN sitemanager_hosts h ON h.device_id = d.id WHERE d.id = :d""", d=device_id)
    return rows[0] if rows else None


async def _wan_isp(s, device_id, isp: str | None) -> str | None:
    """The gateway's WAN links that are up now, as 'WAN2| 11.133.111.195' (the format of the NOC's UniFi alerts)."""
    if not device_id:
        return None
    wans = await _rows(s, """
        SELECT wan_name, host(ip) AS ip FROM wan_state
        WHERE device_id = :d AND ended_at IS NULL AND state = 'up' AND wan_name <> 'internet' ORDER BY wan_name""", d=device_id)
    text_ = ", ".join(f"{w['wan_name']}| {w['ip']}" if w["ip"] else w["wan_name"] for w in wans)
    if isp:
        text_ = f"{text_} ({isp})" if text_ else isp
    return text_ or None


async def build_notice(s, alert: dict) -> dict:
    """headline, message, event_time and the ordered Client/Device facts for one alert row (with rule_type)."""
    rt, key = alert.get("rule_type"), alert.get("dedup_key") or ""
    dev = await _device(s, alert.get("device_id"))
    facts: list[tuple[str, str]] = [("Client", alert["client"])]
    if dev:
        facts.append(("Device", f"{dev['name']}" + (f" ({dev['model']})" if dev["model"] else "")))
    headline, message, event_time = alert["title"], alert["message"], alert.get("first_seen")
    details = alert.get("details") or {}

    if rt in ("vpn_tunnel_down", "vpn_flapping") and key.startswith("tunnel:"):
        _, device_id, tunnel = key.split(":", 2)
        name = (await _rows(s, "SELECT display_name FROM vpn_tunnel_names WHERE device_id = :d AND tunnel_name = :t",
                            d=int(device_id), t=tunnel))
        label = name[0]["display_name"] if name else (tunnel[6:] if tunnel.startswith("ipsec:") else tunnel)
        last = await _rows(s, """SELECT peer, state, started_at FROM vpn_tunnel_state WHERE device_id = :d AND tunnel_name = :t
                                 ORDER BY started_at DESC LIMIT 1""", d=int(device_id), t=tunnel)
        peer = (last[0]["peer"] if last else None) or "?"
        kind = "Site-to-Site VPN" if tunnel.startswith(("ipsec", "IPsec")) or "s2s" in tunnel.lower() else "VPN"
        if rt == "vpn_tunnel_down":
            headline = f"{label} - {kind} Tunnel Disconnected"
            message = f"{label}'s {kind} tunnel to {peer} has disconnected."
            if last and last[0]["state"] == "down":
                event_time = last[0]["started_at"]
        else:
            headline = f"{label} - {kind} Tunnel Flapping"
            message = f"{label}'s {kind} tunnel to {peer} dropped {details.get('drops', 'several')} times recently."
        facts += [("Tunnel Name", label), ("WAN ISP", await _wan_isp(s, alert.get("device_id"), dev and dev["isp"])),
                  ("Remote GW", peer)]
    elif rt == "device_offline":
        headline = f"{dev['name'] if dev else 'Device'} Offline"
        if details.get("since"):
            event_time = datetime.fromisoformat(details["since"])
        facts += [("IP Address", dev and dev["ip"])]
    elif rt in ("wan_down", "internet_down", "wan_failover", "isp_degraded"):
        facts += [("WAN ISP (up now)", await _wan_isp(s, alert.get("device_id"), dev and dev["isp"]))]
        if rt == "wan_failover" and details:
            facts += [("Previous WAN IP", details.get("from")), ("New WAN IP", details.get("to"))]
    elif rt in ("unifi_event", "vpn_disconnect"):
        name = details.get("event_name") or alert["title"]
        subject = details.get("vpn_name") or details.get("wan_name")
        headline = f"{subject} -{name}" if subject else name          # as UniFi's own alert: "CTSKL-PartnerNet -Site-to-Site ..."
        if details.get("event_time"):
            event_time = datetime.fromisoformat(details["event_time"])
        if details.get("vpn_name"):
            facts += [("Tunnel Name", details.get("vpn_name")),
                      ("WAN ISP", f"{details.get('wan_id')}| {details.get('vpn_local_ip')}" if details.get("wan_id") else None),
                      ("Remote GW", details.get("vpn_remote_gateway"))]
        elif details.get("wan_id"):
            wan = lambda p: (f"{details.get(p + 'wan_id')}| {(details.get(p + 'wan_subnet') or '').split('/')[0]}"  # noqa: E731
                             + (f" ({details.get(p + 'wan_isp')})" if details.get(p + "wan_isp") else ""))
            facts += [("WAN ISP", wan("")), ("Failover To", wan("failover_") if details.get("failover_wan_id") else None)]
        else:
            facts += [("IP Address", details.get("device_ip") or (dev and dev["ip"]))]
    elif rt in ("ap_offline", "wifi_quality", "poe_issue"):
        labels = {"ap": "Access Point", "switch": "Switch", "uplink": "Connected To", "model": "Model", "band": "Band",
                  "utilisation_pct": "Channel Utilisation (%)", "experience_pct": "Wi-Fi Experience (%)",
                  "weak_clients": "Weak-signal Clients", "weakest_dbm": "Weakest Signal (dBm)", "poe": "PoE Status",
                  "used_w": "PoE Used (W)", "max_w": "PoE Budget (W)", "ports": "Ports", "ap_mac": "AP MAC"}
        facts += [(label, ", ".join(map(str, details[k])) if isinstance(details.get(k), list) else
                   (str(details[k]) if details.get(k) not in (None, "") else None)) for k, label in labels.items()]
        if rt == "ap_offline" and details.get("since"):
            event_time = datetime.fromisoformat(details["since"])
    elif rt == "failed_logins":
        facts += [("Source IP", details.get("source_ip")), ("Attempts", str(details.get("count", "")) or None)]
    elif rt == "ioc_match":
        facts += [("Indicator", key[4:] if key.startswith("ioc:") else None),
                  ("Threat Feeds", ", ".join(details.get("feeds") or []) or None)]
    elif dev:
        facts += [("IP Address", dev["ip"])]
    return {"headline": headline, "message": message, "event_time": event_time,
            "facts": [(k, v) for k, v in facts if v not in (None, "")]}


def render(alert: dict, kind: str, prefix: str, link: str = "") -> tuple[str, str]:
    """Subject and plain-text body (also used for Teams / Slack)."""
    n = alert.get("notice") or {"headline": alert["title"], "message": alert["message"],
                                "event_time": alert.get("first_seen"), "facts": [("Client", alert["client"])]}
    resolved = kind == "resolve"
    subject = f"{prefix}: {'RESOLVED - ' if resolved else ''}{n['headline']} at {alert['client']}"
    lines = ["Hello Team,", "",
             f"A UniFi Network alert has been {'resolved' if resolved else 'triggered'}:", "",
             "Alert Details",
             f"Message: {n['message']}",
             f"Severity: {str(alert.get('severity', '')).title()}",
             f"Time (UTC): {iso(n['event_time'])}"]
    if resolved:
        lines.append(f"Resolved (UTC): {iso(alert.get('resolved_at') or datetime.now(UTC))}")
    lines += ["", "Client/Device Details"] + [f"{k}: {v}" for k, v in n["facts"]]
    if link:
        lines += ["", f"Open in the log server (acknowledge, comment, related events): {link}"]
    if alert.get("id"):
        lines += ["", f"Alert #{alert['id']}"]
    return subject, "\n".join(lines)


LOGO_CID = "brand-logo"


def _local_time(tz_name: str | None):
    """The device's local time (its client's time zone): label 'Kuala Lumpur, UTC+08:00' and a formatter."""
    from zoneinfo import ZoneInfo
    try:
        tz = ZoneInfo(tz_name or "UTC")
    except Exception:  # noqa: BLE001 - unknown zone name: UTC
        tz, tz_name = ZoneInfo("UTC"), "UTC"
    off = datetime.now(tz).strftime("%z")
    city = (tz_name or "UTC").split("/")[-1].replace("_", " ")
    zone = "UTC" if city == "UTC" else f"{city}, UTC{off[:3]}:{off[3:]}"
    return zone, lambda dt: dt.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S") if dt else ""
SEVERITY_COLOUR = {"critical": "#C62828", "high": "#C62828", "medium": "#B54708", "low": "#52514E"}


def render_html(alert: dict, kind: str, link: str = "") -> str:   # link: kept for the caller; not shown
    """The same notice as an HTML e-mail in the house style of the MSP's documents (app/brand.py): logo header,
    'Alert Details' and 'Client/Device Details' as tables with a red (green when resolved) header row. Inline styles
    and table layout only, so Outlook renders it; the logo is attached inline as cid:brand-logo."""
    from html import escape

    from app import brand

    n = alert.get("notice") or {"headline": alert["title"], "message": alert["message"],
                                "event_time": alert.get("first_seen"), "facts": [("Client", alert["client"])]}
    resolved = kind == "resolve"
    head = brand.GOOD if resolved else brand.RED
    font = "font-family:Montserrat,Arial,Helvetica,sans-serif;"
    cell = f"padding:7px 10px;border:1px solid {brand.BORDER};font-size:13px;vertical-align:top;{font}"
    sev = str(alert.get("severity", "")).lower()
    zone, local = _local_time(alert.get("client_tz"))

    def table(title: str, rows: list[tuple[str, str, str]]) -> str:
        out = [f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin:0 0 18px">'
               f'<tr><th colspan="2" align="left" style="{cell}background:{head};color:#ffffff;font-weight:bold">{escape(title)}</th></tr>']
        for i, (k, v, style) in enumerate(rows):
            bg = brand.ROW_TINT if i % 2 == 0 else "#ffffff"
            out.append(f'<tr><td width="32%" style="{cell}background:{bg};font-weight:bold">{escape(k)}</td>'
                       f'<td style="{cell}background:{bg};{style}">{escape(str(v))}</td></tr>')
        return "".join(out) + "</table>"

    details = [("Alert", n["headline"], "font-weight:bold"), ("Message", n["message"], ""),
               ("Severity", sev.title(), f"color:{SEVERITY_COLOUR.get(sev, '#000000')};font-weight:bold"),
               ("Status", "Resolved" if resolved else "Triggered", f"color:{head};font-weight:bold"),
               (f"Time ({zone})", local(n["event_time"]), "")]
    if resolved:
        details.append((f"Resolved ({zone})", local(alert.get("resolved_at") or datetime.now(UTC)), ""))
    return f"""<!doctype html><html><body style="margin:0;padding:0;background:#f3f4f6">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6"><tr><td align="center" style="padding:20px 10px">
<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="width:640px;max-width:100%;background:#ffffff;border-collapse:collapse">
<tr><td style="padding:18px 24px 12px;border-bottom:2px solid {brand.RED}">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
    <td width="48" style="vertical-align:middle"><img src="cid:{LOGO_CID}" width="43" height="48" alt="Example MSP" style="display:block;border:0"></td>
    <td style="vertical-align:middle;padding-left:12px;font-size:16px;font-weight:bold;letter-spacing:0.5px;color:{brand.HEADING};{font}">{brand.COMPANY_SHORT}</td>
    <td align="right" style="vertical-align:middle;font-size:12px;color:{brand.HEADER_TEXT};{font}">Uniwatch · {escape(alert["client"])}</td>
  </tr></table></td></tr>
<tr><td style="padding:20px 24px 4px;font-size:14px;color:#000000;{font}">
  <p style="margin:0 0 6px">Hello Team,</p>
  <p style="margin:0 0 18px">A UniFi Network alert has been <b style="color:{head}">{"resolved" if resolved else "triggered"}</b>:</p>
  {table("Alert Details", details)}
  {table("Client/Device Details", [(k, v, "") for k, v in n["facts"]])}
</td></tr>
<tr><td style="padding:6px 24px 16px;font-size:11px;color:{brand.FOOTER_TEXT};{font}">
  {escape(brand.CONFIDENTIAL)}{f" · Alert #{alert['id']}" if alert.get("id") else ""} · Sent by Uniwatch{f" for {escape(brand.COMPANY)}" if brand.COMPANY != "Uniwatch" else ""}
</td></tr>
</table></td></tr></table></body></html>"""
