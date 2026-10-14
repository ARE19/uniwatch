from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# argon2id with library defaults (RFC 9106 low-memory profile). Hashes self-describe their
# parameters, so raising them later only needs needs_rehash() on the next successful login.
_hasher = PasswordHasher()

# Verified against when the username does not exist, so response time does not reveal valid usernames.
_DUMMY_HASH = _hasher.hash("not-a-real-password-just-burning-cpu")

MIN_LENGTH = 12


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def password_problems(password: str, username: str = "") -> list[str]:
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f"Password must be at least {MIN_LENGTH} characters.")
    if username and username.lower() in password.lower():
        problems.append("Password must not contain the username.")
    if len(set(password)) < 5:
        problems.append("Password is too repetitive.")
    return problems
