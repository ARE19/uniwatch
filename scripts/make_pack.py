#!/usr/bin/env python3
"""Make report pack files (for the publisher of packs; a normal installation never needs this).

  python scripts/make_pack.py keygen KEYFILE
      New signing key. KEYFILE is the PRIVATE key: keep it off the server and out of the repository. The line printed
      is the public key for PACK_PUBLIC_KEY (.env) of every installation that should accept your packs.

  python scripts/make_pack.py pack KEYFILE --id executive-reports --name "Executive report pack" --version 1.0 \
         --source reports.py --out executive-reports.uwpack [--description "..."]

  python scripts/make_pack.py licence KEYFILE --pack executive-reports --customer "Example Ltd" \
         [--expires 2027-12-31] --out executive-reports.uwlic
      --edition "Trial" (or any name) is shown next to the customer on the Report packs page.

  python scripts/make_pack.py trial KEYFILE --customer "Example Ltd" --outdir trials/
         [--days 30] [--packs executive-reports,other-pack]
      A trial in one step: a licence for each pack, marked "Trial" and ending after --days days.
      Send the customer these files together with the pack files.

Needs only the 'cryptography' package."""

import argparse
import base64
import json
import re
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")


def public_of(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def load_key(path: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(Path(path).read_text().strip()))


def sign(key: Ed25519PrivateKey, kind: str, data: dict) -> bytes:
    payload = json.dumps(data, sort_keys=True).encode()
    sig = key.sign(kind.encode() + b"\n" + payload)
    return json.dumps({"kind": kind, "payload": base64.b64encode(payload).decode(),
                       "signature": base64.b64encode(sig).decode()}).encode()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("keyfile")
    p = sub.add_parser("pack")
    p.add_argument("keyfile")
    for a in ("--id", "--name", "--version", "--source", "--out"):
        p.add_argument(a, required=True)
    p.add_argument("--description", default="")
    lic = sub.add_parser("licence")
    lic.add_argument("keyfile")
    for a in ("--pack", "--customer", "--out"):
        lic.add_argument(a, required=True)
    lic.add_argument("--expires", default="", help="last valid day, YYYY-MM-DD (empty = no end date)")
    lic.add_argument("--edition", default="", help='shown on the Report packs page, e.g. "Trial"')
    tr = sub.add_parser("trial")
    tr.add_argument("keyfile")
    tr.add_argument("--customer", required=True)
    tr.add_argument("--outdir", required=True)
    tr.add_argument("--days", type=int, default=30)
    tr.add_argument("--packs", default="executive-reports", help="comma-separated pack ids")
    args = ap.parse_args(argv)

    if args.cmd == "keygen":
        path = Path(args.keyfile)
        if path.exists():
            sys.exit(f"{path} exists; refusing to overwrite a signing key.")
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        path.write_text(base64.b64encode(raw).decode() + "\n")
        print("PACK_PUBLIC_KEY=" + public_of(key))
        return 0
    key = load_key(args.keyfile)
    if args.cmd == "trial":
        if args.days < 1:
            sys.exit("--days: at least 1.")
        today = datetime.now(UTC).date()
        common = {"customer": args.customer, "expires": (today + timedelta(days=args.days)).isoformat(),
                  "issued": today.isoformat(), "edition": "Trial"}
        slug = re.sub(r"[^a-z0-9]+", "-", args.customer.lower()).strip("-")[:40] or "customer"
        out = Path(args.outdir) / f"{slug}-trial-{today.isoformat()}"
        out.mkdir(parents=True, exist_ok=True)
        packs_ = [p.strip() for p in args.packs.split(",") if p.strip()]
        for p in packs_:
            if not ID_RE.match(p):
                sys.exit(f"--packs: '{p}' is not a pack id.")
        if not packs_:
            sys.exit("--packs: at least one pack id.")
        for p in packs_:
            (out / f"{p}.uwlic").write_bytes(sign(key, "licence", {**common, "pack": p}))
        print(f"trial for {args.customer} until {common['expires']}: {len(packs_)} licence file(s) in {out}")
        return 0
    if args.cmd == "pack":
        if not ID_RE.match(args.id):
            sys.exit("--id: lower-case letters, digits and dashes, at most 40 characters.")
        source = Path(args.source).read_text(encoding="utf-8")
        compile(source, args.source, "exec")                      # refuse to ship code that does not even parse
        blob = sign(key, "pack", {"id": args.id, "name": args.name, "version": args.version,
                                  "description": args.description, "source": source})
    else:
        if not ID_RE.match(args.pack):
            sys.exit("--pack: the pack id.")
        if args.expires:
            date.fromisoformat(args.expires)
        content = {"pack": args.pack, "customer": args.customer, "expires": args.expires or None,
                   "issued": datetime.now(UTC).date().isoformat()}
        if args.edition:
            content["edition"] = args.edition
        blob = sign(key, "licence", content)
    Path(args.out).write_bytes(blob)
    print(f"wrote {args.out} ({len(blob)} bytes), verifies with PACK_PUBLIC_KEY={public_of(key)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
