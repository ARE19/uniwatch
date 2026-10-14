"""Configuration backup and change history of each UniFi console, through the Site Manager connector. Read-only.

Verified 2026-10-11 (CTS KL, NW HK, TSP-HK; Network 10.x) via https://api.ui.com/v1/connector/consoles/<host>/proxy/network:
every section below answers HTTP 200 with a list of objects keyed by "_id" (settings also carry "key", e.g. "mgmt").
Fetched twice 120 s apart, only firewall-policies' hit counters (hits, last_hit) changed on their own: they are dropped.
Secrets are never stored: every "x_*" field (UniFi's convention: x_passphrase, x_ipsec_pre_shared_key, x_server_key ...)
and the known secret fields below are replaced by "redacted:<fingerprint>", so a changed password still shows as a change."""

import hashlib
import json

import httpx

BASE = "https://api.ui.com/v1/connector/consoles/{host}/proxy/network"
SECTIONS = (  # key, label, path
    ("networkconf", "Networks & VPN", "/api/s/default/rest/networkconf"),
    ("wlanconf", "Wi-Fi networks", "/api/s/default/rest/wlanconf"),
    ("firewall-policies", "Firewall policies", "/v2/api/site/default/firewall-policies"),
    ("firewall-zones", "Firewall zones", "/v2/api/site/default/firewall/zone"),
    ("firewallgroup", "Firewall groups", "/api/s/default/rest/firewallgroup"),
    ("firewallrule", "Firewall rules (legacy)", "/api/s/default/rest/firewallrule"),
    ("portforward", "Port forwarding", "/api/s/default/rest/portforward"),
    ("nat", "NAT", "/v2/api/site/default/nat"),
    ("routing", "Static routes", "/api/s/default/rest/routing"),
    ("trafficrules", "Traffic rules", "/v2/api/site/default/trafficrules"),
    ("trafficroutes", "Traffic routes", "/v2/api/site/default/trafficroutes"),
    ("portconf", "Switch port profiles", "/api/s/default/rest/portconf"),
    ("usergroup", "Bandwidth groups", "/api/s/default/rest/usergroup"),
    ("radiusprofile", "RADIUS profiles", "/api/s/default/rest/radiusprofile"),
    ("dynamicdns", "Dynamic DNS", "/api/s/default/rest/dynamicdns"),
    ("setting", "Site settings", "/api/s/default/rest/setting"),
)
LABELS = {k: label for k, label, _ in SECTIONS}
VOLATILE = {"hits", "last_hit"}
SECRETS = {"psk", "sae_psk", "passphrase", "password", "private_preshared_keys", "dh_key", "server_certificate_key",
           "private_key", "secret", "auth_key", "shared_secret", "radius_secret"}


def _fingerprint(v) -> str:
    return "redacted:" + hashlib.sha256(json.dumps(v, sort_keys=True, default=str).encode()).hexdigest()[:12]


def redact(o):
    """Copy of `o` with every secret value replaced by a fingerprint (nested objects and lists included)."""
    if isinstance(o, dict):
        return {k: (_fingerprint(v) if (k.startswith("x_") or k in SECRETS) and v not in (None, "", [], {}) else redact(v))
                for k, v in o.items() if k not in VOLATILE}
    if isinstance(o, list):
        return [redact(v) for v in o]
    return o


def normalize(objs: list) -> list[dict]:
    return sorted((redact(o) for o in objs if isinstance(o, dict)), key=lambda o: str(o.get("_id") or o.get("key") or ""))


def digest(objs: list[dict]) -> str:
    return hashlib.sha256(json.dumps(objs, sort_keys=True, default=str).encode()).hexdigest()


def name_of(o: dict) -> str:
    return str(o.get("name") or o.get("key") or o.get("description") or o.get("_id") or "?")


def _short(v) -> str:
    s = v if isinstance(v, str) else json.dumps(v, sort_keys=True, default=str)
    return s if len(s) <= 160 else s[:157] + "..."


def diff(prev: list[dict], cur: list[dict]) -> list[dict]:
    """Object-level changes between two normalized snapshots of one section."""
    a = {str(o.get("_id") or o.get("key")): o for o in prev}
    b = {str(o.get("_id") or o.get("key")): o for o in cur}
    out = []
    for k in b.keys() - a.keys():
        out.append({"change": "added", "object": name_of(b[k])})
    for k in a.keys() - b.keys():
        out.append({"change": "removed", "object": name_of(a[k])})
    for k in a.keys() & b.keys():
        fields = [{"field": f, "before": _short(a[k].get(f)) if f in a[k] else "", "after": _short(b[k].get(f)) if f in b[k] else ""}
                  for f in sorted(a[k].keys() | b[k].keys()) if a[k].get(f) != b[k].get(f)]
        if fields:
            out.append({"change": "changed", "object": name_of(b[k]), "fields": fields})
    return sorted(out, key=lambda c: (c["change"], c["object"]))


def summarize(section: str, changes: list[dict]) -> str:
    parts = []
    for c in changes[:6]:
        if c["change"] == "changed":
            fields = ", ".join(f["field"].removeprefix("x_") + (" (secret)" if f["after"].startswith("redacted:") else "")
                               for f in c["fields"][:4])
            parts.append(f"'{c['object']}' changed: {fields}" + (" ..." if len(c["fields"]) > 4 else ""))
        else:
            parts.append(f"'{c['object']}' {c['change']}")
    more = f" (+{len(changes) - 6} more)" if len(changes) > 6 else ""
    return f"{LABELS.get(section, section)}: " + "; ".join(parts) + more


async def fetch_config(api_key: str, host_id: str, transport=None) -> dict[str, list]:
    """{section: [objects]} for the sections this console answers (missing / failing sections are left out)."""
    out: dict[str, list] = {}
    async with httpx.AsyncClient(timeout=60, headers={"X-API-KEY": api_key, "Accept": "application/json"},
                                 transport=transport) as http:
        base = BASE.format(host=host_id)
        for key, _, path in SECTIONS:
            r = await http.get(base + path)
            if r.status_code == 429:
                raise RuntimeError("Site Manager rate limit (HTTP 429)")
            if r.status_code != 200:
                continue
            body = r.json()
            data = body if isinstance(body, list) else (body.get("data") if isinstance(body, dict) else None)
            if isinstance(data, list):
                out[key] = data
    return out


async def store(conn, host_id: str, client_id: int, device_id: int | None, config: dict[str, list], now) -> int:
    """A new version per section whose content changed since the last backup; returns how many sections changed."""
    n = 0
    async with conn.transaction():
        for section, objs in config.items():
            cur = normalize(objs)
            h = digest(cur)
            cursor = await conn.execute("""SELECT hash, data FROM config_snapshots WHERE host_id = %s AND section = %s
                                           ORDER BY taken_at DESC LIMIT 1""", (host_id, section))
            last = await cursor.fetchone()
            if last and last[0] == h:
                continue
            changes = diff(last[1], cur) if last else None
            summary = summarize(section, changes) if changes else ("First backup" if not last else "No visible change")
            await conn.execute("""
                INSERT INTO config_snapshots (host_id, client_id, device_id, section, taken_at, hash, objects, data, changes, summary)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (host_id, client_id, device_id, section, now, h, len(cur), json.dumps(cur, default=str),
                 json.dumps(changes) if changes is not None else None, summary))
            n += 1 if last else 0
    return n
