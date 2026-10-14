"""Country + ASN lookup for public IPs from MMDB files.

Prefers MaxMind GeoLite2 (GeoLite2-City.mmdb / GeoLite2-ASN.mmdb) if present in the directory,
otherwise DB-IP Lite (free, CC BY 4.0, no account: https://db-ip.com/db/lite.php). Both use the same
record layout for the fields read here. Private/reserved addresses are never looked up.

    python -m app.enrich.geoip update      # download/refresh DB-IP Lite into GEOIP_DIR
"""

import gzip
import ipaddress
import logging
import os
import shutil
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path

import maxminddb

log = logging.getLogger("geoip")
GEOIP_DIR = Path(os.environ.get("GEOIP_DIR", "/srv/geoip"))
CITY_FILES = ("GeoLite2-City.mmdb", "dbip-city-lite.mmdb")
ASN_FILES = ("GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb")
DBIP_URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{ym}.mmdb.gz"
MAX_AGE_DAYS = 35


@dataclass(frozen=True)
class GeoResult:
    country: str | None
    asn: int | None
    as_org: str | None


class GeoIP:
    def __init__(self, directory: Path = GEOIP_DIR):
        self.dir = directory
        self.city = self._open(CITY_FILES)
        self.asn = self._open(ASN_FILES)
        self.lookup = lru_cache(maxsize=65536)(self._lookup)

    def _open(self, names):
        for n in names:
            p = self.dir / n
            if p.exists():
                log.info("geoip: using %s", p)
                return maxminddb.open_database(str(p))
        return None

    @property
    def available(self) -> bool:
        return self.city is not None or self.asn is not None

    def _lookup(self, ip: str) -> GeoResult | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if not addr.is_global:
            return None
        country = asn = org = None
        if self.city is not None:
            rec = self.city.get(ip) or {}
            country = (rec.get("country") or {}).get("iso_code")
        if self.asn is not None:
            rec = self.asn.get(ip) or {}
            asn, org = rec.get("autonomous_system_number"), rec.get("autonomous_system_organization")
        return GeoResult(country, asn, org)


def is_internal(ip: str | None) -> bool | None:
    if not ip:
        return None
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return None


def _months_to_try(now: datetime) -> list[str]:
    prev = now.replace(day=1) - timedelta(days=1)
    return [now.strftime("%Y-%m"), prev.strftime("%Y-%m")]


def update(directory: Path = GEOIP_DIR, force: bool = False) -> bool:
    """Download DB-IP Lite city + ASN for this month (or last month if not yet published).
    Returns True if anything changed. Never raises on network errors."""
    directory.mkdir(parents=True, exist_ok=True)
    changed = False
    for kind, target in (("city", "dbip-city-lite.mmdb"), ("asn", "dbip-asn-lite.mmdb")):
        dest = directory / target
        if not force and dest.exists() and time.time() - dest.stat().st_mtime < MAX_AGE_DAYS * 86400:
            continue
        for ym in _months_to_try(datetime.now(UTC)):
            url = DBIP_URL.format(kind=kind, ym=ym)
            tmp_name = None
            try:
                # DB-IP rejects Python's default User-Agent with 403.
                req = urllib.request.Request(url, headers={"User-Agent": "uniwatch/0.1 (+geoip update)"})
                with urllib.request.urlopen(req, timeout=120) as resp, tempfile.NamedTemporaryFile(
                    dir=directory, delete=False, suffix=".tmp"
                ) as tmp:
                    tmp_name = tmp.name
                    with gzip.GzipFile(fileobj=resp) as gz:
                        shutil.copyfileobj(gz, tmp)
                maxminddb.open_database(tmp_name).close()  # validate before swapping in
                os.replace(tmp_name, dest)
                log.info("geoip: updated %s from %s", dest, url)
                changed = True
                break
            except Exception as e:  # noqa: BLE001
                log.warning("geoip: %s failed: %s", url, e)
                if tmp_name and os.path.exists(tmp_name):
                    os.unlink(tmp_name)
    return changed


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if sys.argv[1:2] == ["update"]:
        update(force="--force" in sys.argv)
    else:
        print(__doc__)
