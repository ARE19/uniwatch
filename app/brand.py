"""Branding of the PDF reports and the alert e-mails: name, contact lines, colours and logo.

Neutral Uniwatch defaults; an MSP puts its own in .env, for example:
    BRAND_COMPANY="Example MSP Ltd"   BRAND_SHORT="EXAMPLE MSP"
    BRAND_ADDRESS="1 Example Street|Example City"   BRAND_PHONES="T: +1 555 0100"
    BRAND_CONFIDENTIAL="Example MSP – Confidential"
    BRAND_COLOR="#EE0000"   BRAND_COLOR_DARK="#740000"   BRAND_HEADING="#0F4761"
    BRAND_ASSETS=/srv/brand   (a folder with logo.png, logo-email.png, optionally cover.jpg; mount it into the containers)
Files missing from BRAND_ASSETS fall back to app/assets."""

import os
from pathlib import Path

_DEFAULT_ASSETS = Path(__file__).resolve().parent / "assets"
_custom = Path(os.environ["BRAND_ASSETS"]) if os.environ.get("BRAND_ASSETS") else None


def asset(name: str) -> Path:
    """A branding file: the MSP's own if present, else the default."""
    if _custom is not None and (_custom / name).exists():
        return _custom / name
    return _DEFAULT_ASSETS / name


def _lines(var: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in os.environ.get(var, "").split("|") if x.strip())


ASSETS = _DEFAULT_ASSETS               # fonts and defaults; base_url for the PDF (logo / cover resolved with asset())
COMPANY = os.environ.get("BRAND_COMPANY", "Uniwatch")
COMPANY_SHORT = os.environ.get("BRAND_SHORT", COMPANY.upper())
ADDRESS = _lines("BRAND_ADDRESS")
PHONES = _lines("BRAND_PHONES")
CONFIDENTIAL = os.environ.get("BRAND_CONFIDENTIAL", "Confidential")

RED = os.environ.get("BRAND_COLOR", "#1F6FB2")             # table headers, rules, title bar
RED_DARK = os.environ.get("BRAND_COLOR_DARK", "#123F66")
HEADING = os.environ.get("BRAND_HEADING", "#0F3D5E")
HEADER_TEXT = "#93A4B1"
ROW_TINT = "#F5F9FC"
BORDER = "#CCCCCC"
FOOTER_TEXT = "#888888"
GOOD = "#4EA72E"
