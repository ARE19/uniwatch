import base64
import hashlib
import time

import pyotp
import segno
from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings

STEP_SECONDS = 30
VALID_WINDOW = 1  # accept one step either side for clock drift


def _fernet() -> Fernet:
    key = hashlib.sha256(("totp:" + get_settings().secret_key).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def new_secret() -> str:
    return pyotp.random_base32()


def encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_secret(token: str) -> str | None:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        return None


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=get_settings().totp_issuer)


def qr_svg(uri: str) -> str:
    """Inline SVG (no external request, no inline script/style) for the authenticator app."""
    return segno.make(uri, error="m").svg_inline(scale=5, dark="#111", light="#fff", border=2)


def verify_code(secret: str, code: str, last_step: int | None, now: float | None = None) -> int | None:
    """Return the matched time-step if the code is valid and newer than last_step, else None.
    Rejecting steps <= last_step stops a code being replayed within its validity window."""
    code = "".join(ch for ch in code if ch.isdigit())
    if len(code) != 6:
        return None
    now = time.time() if now is None else now
    totp = pyotp.TOTP(secret)
    current = int(now // STEP_SECONDS)
    for step in range(current - VALID_WINDOW, current + VALID_WINDOW + 1):
        if pyotp.utils.strings_equal(totp.at(step * STEP_SECONDS), code):
            if last_step is not None and step <= last_step:
                return None
            return step
    return None
