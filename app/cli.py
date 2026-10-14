"""Admin CLI, run inside the app container:  docker compose run --rm web python -m app.cli <command>"""

import argparse
import asyncio
import getpass
import sys

from sqlalchemy import func, select

from app import db
from app.audit import audit
from app.config import get_settings
from app.models import Role, User
from app.models.auth import ROLE_ADMIN
from app.security import passwords, sessions


async def bootstrap_admin() -> int:
    """Create the first admin from INITIAL_ADMIN_* if no admin exists. Idempotent."""
    s = get_settings()
    async with db.sessionmaker()() as session:
        role = (await session.execute(select(Role).where(Role.name == ROLE_ADMIN))).scalar_one()
        if (await session.execute(select(User).where(User.role_id == role.id))).first():
            print("bootstrap-admin: an admin already exists, nothing to do")
            return 0
        if passwords.password_problems(s.initial_admin_password, s.initial_admin_username):
            print("bootstrap-admin: INITIAL_ADMIN_PASSWORD is missing or too weak", file=sys.stderr)
            return 1
        user = User(
            username=s.initial_admin_username,
            display_name="Administrator",
            password_hash=passwords.hash_password(s.initial_admin_password),
            role_id=role.id,
            must_change_password=True,
        )
        session.add(user)
        await session.flush()
        await audit(session, "user_create", username="system", target=user.username, details={"via": "bootstrap"})
        await session.commit()
        print(f"bootstrap-admin: created '{user.username}' (must change password and enrol MFA at first sign-in)")
    return 0


async def _find(session, username: str) -> User:
    user = (await session.execute(select(User).where(func.lower(User.username) == username.lower()))).scalar_one_or_none()
    if user is None:
        raise SystemExit(f"no such user: {username}")
    return user


async def reset_mfa(username: str) -> int:
    async with db.sessionmaker()() as session:
        user = await _find(session, username)
        user.totp_enabled, user.totp_secret_enc, user.totp_last_step = False, None, None
        await sessions.end_all_sessions(session, user.id)
        await audit(session, "mfa_reset", username="cli", target=user.username)
        await session.commit()
    print(f"MFA reset for {username}; they will enrol again at next sign-in")
    return 0


async def set_password(username: str) -> int:
    pw = getpass.getpass("New password: ")
    if pw != getpass.getpass("Repeat: "):
        raise SystemExit("passwords do not match")
    if problems := passwords.password_problems(pw, username):
        raise SystemExit("; ".join(problems))
    async with db.sessionmaker()() as session:
        user = await _find(session, username)
        user.password_hash = passwords.hash_password(pw)
        user.must_change_password = True
        await sessions.end_all_sessions(session, user.id)
        await audit(session, "password_reset", username="cli", target=user.username)
        await session.commit()
    print(f"password set for {username}; they must change it at next sign-in")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="app.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("bootstrap-admin")
    sub.add_parser("reset-mfa").add_argument("username")
    sub.add_parser("set-password").add_argument("username")
    a = p.parse_args()

    async def run() -> int:
        try:
            if a.cmd == "bootstrap-admin":
                return await bootstrap_admin()
            if a.cmd == "reset-mfa":
                return await reset_mfa(a.username)
            return await set_password(a.username)
        finally:
            await db.dispose()

    return asyncio.run(run())


if __name__ == "__main__":
    sys.exit(main())
