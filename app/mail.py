"""Effective SMTP settings: the row saved in Admin -> Mail when there is one, otherwise SMTP_* from .env.

Every sender (alert e-mails, report e-mails, the test button) asks `effective()` just before sending, so a change in the
web UI applies at once without restarting the services."""

import smtplib
import ssl
from email.message import EmailMessage

from sqlalchemy import text

from app.config import Settings
from app.drivers.base import decrypt_secret


async def saved(session) -> dict | None:
    row = (await session.execute(text("SELECT * FROM mail_settings WHERE id = 1"))).first()
    return dict(row._mapping) if row else None


def apply(st: Settings, row: dict | None) -> Settings:
    if not row:
        return st
    pw = (decrypt_secret(row["password_enc"]) or {}).get("password", "") if row["password_enc"] else ""
    return st.model_copy(update={"smtp_host": row["host"], "smtp_port": row["port"], "smtp_user": row["username"],
                                 "smtp_password": pw, "smtp_from": row["from_addr"], "smtp_starttls": row["starttls"],
                                 **({"alert_subject_prefix": row["subject_prefix"]} if row.get("subject_prefix") else {})})


async def effective(st: Settings, session=None) -> Settings:
    """`st` with the saved mail settings applied. Without a session, a short one of the service (app) role is used."""
    if session is not None:
        return apply(st, await saved(session))
    from app import db
    async with db.sessionmaker()() as s:
        return apply(st, await saved(s))


def send_test(st: Settings, to: str) -> None:
    msg = EmailMessage()
    msg["From"], msg["To"] = st.smtp_from or st.smtp_user, to
    msg["Subject"] = f"{st.alert_subject_prefix}: test e-mail"
    msg.set_content("This is a test e-mail from the Uniwatch (Admin -> Mail). Mail delivery works.")
    with smtplib.SMTP(st.smtp_host, st.smtp_port, timeout=30) as smtp:
        if st.smtp_starttls:
            smtp.starttls(context=ssl.create_default_context())
        if st.smtp_user:
            smtp.login(st.smtp_user, st.smtp_password)
        smtp.send_message(msg)
