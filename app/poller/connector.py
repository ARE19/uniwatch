"""Traffic flows from consoles that are not polled locally, through the UniFi Site Manager connector
(https://api.ui.com/v1/connector/consoles/<host id>/proxy/network/...), read-only.

Verified 2026-10-08 on CTS KL (Network 10.6.106): POST v2/api/site/default/traffic-flows through the connector returns
the same records as the local API (samples/unifi-api-traffic-flows-2026-10-07.log), including the VPN network's flows.
Facts learned there: a query reports at most 10,000 records (total_element_count stops at 10000), and the console keeps
only a short buffer (about 25 minutes at CTS KL), so windows are kept small and split further when a window is full."""

import httpx

from app.drivers.base import PollError

CONNECTOR = "https://api.ui.com/v1/connector/consoles/{host}/proxy/network"
PAGE = 5000
CAP = 10000            # the API never reports more than this per query: a full window may be truncated
MIN_SPLIT_MS = 5000


async def fetch_flows_connector(api_key: str, host_id: str, since_ms: int, until_ms: int, site: str = "default",
                                transport=None) -> list[dict]:
    """Records with since_ms < time <= until_ms. A window that hits the cap is split in two and fetched again."""
    async with httpx.AsyncClient(timeout=90, headers={"X-API-KEY": api_key, "Accept": "application/json"},
                                 transport=transport) as http:
        url = CONNECTOR.format(host=host_id) + f"/v2/api/site/{site}/traffic-flows"

        async def window(a: int, b: int) -> list[dict]:
            out: list[dict] = []
            for page in range(CAP // PAGE + 1):
                r = await http.post(url, json={"timestampFrom": a, "timestampTo": b, "pageNumber": page, "pageSize": PAGE})
                if r.status_code in (401, 403):
                    raise PollError(f"Site Manager key rejected by the console (HTTP {r.status_code})")
                if r.status_code != 200:
                    raise PollError(f"HTTP {r.status_code} for traffic-flows via Site Manager")
                body = r.json()
                if page == 0 and (body.get("total_element_count") or 0) >= CAP and b - a > MIN_SPLIT_MS:
                    mid = (a + b) // 2
                    return await window(a, mid) + await window(mid, b)
                out.extend(f for f in body.get("data", []) if isinstance(f, dict) and isinstance(f.get("time"), int)
                           and a < f["time"] <= b)
                if not body.get("has_next"):
                    break
            return out

        return await window(since_ms, until_ms)
