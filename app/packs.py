"""Report packs: extra report types that are not part of the open-source core, added by uploading two files
(Admin -> Report packs):

  <id>.uwpack   the pack: its name, version and the report code
  <id>.uwlic    the licence for it: who it was issued to and until when

Both are signed (Ed25519) by the publisher whose public key is in PACK_PUBLIC_KEY, and nothing is loaded unless both
signatures are good: a pack contains program code, so an unsigned or altered file must never run. The signature is a
safety check, not copy protection: the core is open source and the check can be removed by anyone who rebuilds it.

A pack's code is one Python module with TITLES and BUILDERS (as in app.reports.data) and optionally BUNDLES,
BUNDLE_TITLES and TYPE_LABELS. Files are made with scripts/make_pack.py."""

import base64
import binascii
import json
import logging
import re
import sys
import types
from datetime import UTC, date, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.config import get_settings

log = logging.getLogger("packs")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
MAX_BYTES = 2 * 1024 * 1024
SETTINGS = None                    # tests put their own settings here
_stamp = None                      # what the pack directory looked like at the last refresh
_registered: dict[str, dict] = {}  # pack id -> the report types it added, by registry
_from_files: set[str] = set()      # the packs loaded from the pack directory (not those registered directly)


class PackError(ValueError):
    """A pack or licence file that cannot be used; the message is shown to the admin."""


def _s():
    return SETTINGS or get_settings()


def signed_message(kind: str, payload: bytes) -> bytes:
    """What is signed: the kind is part of it, so a licence can never be passed off as a pack."""
    return kind.encode() + b"\n" + payload


def open_signed(blob: bytes, kind: str, public_key: str) -> dict:
    """Check the signature of a pack ('pack') or licence ('licence') file and return its content."""
    if not public_key:
        raise PackError("Report packs are switched off: PACK_PUBLIC_KEY is not set.")
    if len(blob) > MAX_BYTES:
        raise PackError("The file is too large.")
    try:
        env = json.loads(blob)
        if env.get("kind") != kind:
            raise PackError(f"This is not a {kind} file.")
        payload, sig = base64.b64decode(env["payload"], validate=True), base64.b64decode(env["signature"], validate=True)
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True))
        key.verify(sig, signed_message(kind, payload))
        data = json.loads(payload)
    except InvalidSignature:
        raise PackError(f"The {kind} file is not signed by this system's pack publisher, or it was changed.") from None
    except (ValueError, KeyError, TypeError, AttributeError, binascii.Error) as e:
        if isinstance(e, PackError):
            raise
        raise PackError(f"The {kind} file cannot be read.") from None
    if not isinstance(data, dict) or not ID_RE.match(str(data.get("id" if kind == "pack" else "pack", ""))):
        raise PackError(f"The {kind} file has no valid pack id.")
    return data


def licence_problem(lic: dict, today: date | None = None) -> str | None:
    """Why a (correctly signed) licence does not allow its pack today; None = valid."""
    exp = lic.get("expires")
    if exp:
        try:
            if date.fromisoformat(exp) < (today or datetime.now(UTC).date()):
                return f"the licence expired on {exp}"
        except ValueError:
            return "the licence has an unreadable expiry date"
    return None


REMIND_DAYS = 30
REMIND_DAYS_SHORT = 7              # for a licence issued for 45 days or less (a trial)


def _remind_from(issued: str, expires: date) -> int:
    try:
        return REMIND_DAYS_SHORT if (expires - date.fromisoformat(issued)).days <= 45 else REMIND_DAYS
    except ValueError:
        return REMIND_DAYS


def expiry_notices(today: date | None = None) -> list[str]:
    """Reminders for admins: a report pack licence that ends soon (REMIND_DAYS, or the last week of a trial) or has ended."""
    today = today or datetime.now(UTC).date()
    items = []
    for row in status(today):
        if row["expires"]:
            items.append((row["name"], row["expires"], "its reports are no longer available", row.get("issued", "")))
    out = []
    for name, exp, effect, issued in items:
        try:
            end = date.fromisoformat(exp)
        except ValueError:
            continue
        left = (end - today).days
        if left < 0:
            out.append(f"{name} ended on {exp}: {effect}.")
        elif left <= _remind_from(issued, end):
            out.append(f"{name} ends {'today' if left == 0 else 'in ' + str(left) + (' day' if left == 1 else ' days')} ({exp}).")
    return out


def _paths(pack_id: str) -> tuple[Path, Path]:
    d = Path(_s().packs_dir)
    return d / f"{pack_id}.uwpack", d / f"{pack_id}.uwlic"


def status(today: date | None = None) -> list[dict]:
    """Every pack file in the pack directory with its licence and whether it is in use (for the admin page)."""
    d, key, out = Path(_s().packs_dir), _s().pack_public_key, []
    for f in sorted(d.glob("*.uwpack")) if d.is_dir() else []:
        row = {"id": f.stem, "name": f.stem, "version": "", "description": "", "customer": "", "expires": "", "problem": None,
               "source": None, "edition": "", "issued": ""}
        try:
            pack = open_signed(f.read_bytes(), "pack", key)
            if pack["id"] != f.stem:
                raise PackError("the file name does not match the pack")
            row.update(name=pack.get("name") or f.stem, version=str(pack.get("version", "")),
                       description=pack.get("description", ""))
            lic_file = _paths(f.stem)[1]
            if not lic_file.is_file():
                raise PackError("no licence file has been uploaded for this pack")
            lic = open_signed(lic_file.read_bytes(), "licence", key)
            if lic["pack"] != pack["id"]:
                raise PackError("the licence is for another pack")
            row.update(customer=lic.get("customer", ""), expires=lic.get("expires") or "",
                       edition=str(lic.get("edition") or "")[:40], issued=str(lic.get("issued") or ""))
            row["problem"] = licence_problem(lic, today)
            row["source"] = None if row["problem"] else pack.get("source", "")
        except PackError as e:
            row["problem"] = str(e)[:1].lower() + str(e)[1:].rstrip(".")
        except OSError as e:
            row["problem"] = f"cannot be read ({type(e).__name__})"
        out.append(row)
    return out


def register_module(pack_id: str, mod) -> None:
    """Add a pack module's report types to the report registries (also used directly by a pack's own tests)."""
    from app.reports import data
    unregister(pack_id)
    added = {}
    for name in ("TITLES", "BUILDERS", "BUNDLES", "BUNDLE_TITLES", "TYPE_LABELS"):
        new = dict(getattr(mod, name, None) or {})
        target = getattr(data, name)
        added[name] = [k for k in new if k not in target]            # a pack never replaces a core report type
        target.update({k: new[k] for k in added[name]})
    _registered[pack_id] = added


def unregister(pack_id: str) -> None:
    from app.reports import data
    for name, keys in _registered.pop(pack_id, {}).items():
        for k in keys:
            getattr(data, name).pop(k, None)


def refresh(today: date | None = None) -> None:
    """Bring the loaded packs in line with the pack directory. Cheap when nothing changed, so it is called before every
    use of the report types; that is also how the reporter and each web worker notice an upload made in another process."""
    global _stamp
    d = Path(_s().packs_dir)
    today = today or datetime.now(UTC).date()
    try:
        files = tuple(sorted((f.name, f.stat().st_mtime_ns, f.stat().st_size) for f in d.iterdir()
                             if f.suffix in (".uwpack", ".uwlic"))) if d.is_dir() else ()
    except OSError:
        files = ()
    stamp = (str(d), _s().pack_public_key, today, files)
    if stamp == _stamp:
        return
    _stamp = stamp
    for pack_id in list(_from_files):
        unregister(pack_id)
    _from_files.clear()
    for row in status(today):
        if row["problem"]:
            log.warning("report pack %s not loaded: %s", row["id"], row["problem"])
            continue
        try:
            mod = types.ModuleType(f"uniwatch_pack_{row['id'].replace('-', '_')}")
            mod.__file__ = str(_paths(row["id"])[0])
            sys.modules[mod.__name__] = mod
            exec(compile(row["source"], mod.__file__, "exec"), mod.__dict__)   # noqa: S102 - signed by the pack publisher
            register_module(row["id"], mod)
            _from_files.add(row["id"])
            log.info("report pack %s %s loaded (licensed to %s)", row["id"], row["version"], row["customer"] or "?")
        except Exception:  # noqa: BLE001 - a broken pack must not take the reports down
            log.exception("report pack %s failed to load", row["id"])


def loaded() -> set[str]:
    return set(_from_files)


def install(pack_blob: bytes | None, licence_blob: bytes | None) -> dict:
    """Check and store an uploaded pack and/or licence. Returns {"pack": id, "stored": [...]}. Raises PackError."""
    key, stored = _s().pack_public_key, []
    pack = open_signed(pack_blob, "pack", key) if pack_blob else None
    lic = open_signed(licence_blob, "licence", key) if licence_blob else None
    if pack is None and lic is None:
        raise PackError("Choose a pack file, a licence file or both.")
    if pack is not None and not isinstance(pack.get("source"), str):
        raise PackError("The pack file has no report code.")
    pack_id = pack["id"] if pack else lic["pack"]
    if pack and lic and lic["pack"] != pack["id"]:
        raise PackError("The licence is for another pack.")
    pack_file, lic_file = _paths(pack_id)
    if lic and not pack and not pack_file.is_file():
        raise PackError(f"Upload the pack file for '{pack_id}' as well: it is not installed yet.")
    if lic and (problem := licence_problem(lic)):
        raise PackError(f"Not installed: {problem}.")
    pack_file.parent.mkdir(parents=True, exist_ok=True)
    for blob, target in ((pack_blob if pack else None, pack_file), (licence_blob if lic else None, lic_file)):
        if blob:
            tmp = target.with_suffix(target.suffix + ".tmp")
            tmp.write_bytes(blob)
            tmp.replace(target)
            stored.append(target.name)
    refresh()
    return {"pack": pack_id, "stored": stored, "name": (pack or {}).get("name", pack_id),
            "customer": (lic or {}).get("customer", ""), "expires": (lic or {}).get("expires") or ""}


def remove(pack_id: str) -> bool:
    if not ID_RE.match(pack_id):
        return False
    found = False
    for f in _paths(pack_id):
        if f.is_file():
            f.unlink()
            found = True
    refresh()
    return found
