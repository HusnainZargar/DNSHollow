"""API key helpers. Keys are shown once; only a SHA-256 hash is stored."""
import hashlib
import hmac
import os
import secrets


def new_key(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


# ---------- passwords (PBKDF2-SHA256, standard library) ----------

def _iterations() -> int:
    return int(os.environ.get("DNSHOLLOW_PW_ITERATIONS", "600000"))


def hash_password(password: str) -> str:
    """-> 'pbkdf2_sha256$iterations$salt$hash' (the salt is random per password)."""
    salt = secrets.token_bytes(16)
    n = _iterations()
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, n)
    return "pbkdf2_sha256$%d$%s$%s" % (n, salt.hex(), digest.hex())


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, salt, want = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(n))
        return hmac.compare_digest(got.hex(), want)
    except (ValueError, TypeError):
        return False


_DUMMY = None


def burn_time(password: str) -> None:
    """Spend the same time as a real check, so an unknown username is not
    distinguishable from a wrong password by response time."""
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password("not-a-real-password")
    verify_password(password, _DUMMY)


def make_temp_password() -> str:
    """Readable temporary password, e.g. 'k7mq-x3vd-9hrt' (no look-alike characters)."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))


_WEAK = {"password", "passw0rd", "admin", "administrator", "dnshollow", "changeme", "letmein",
         "welcome", "qwerty", "123456", "12345678", "1234567890"}


def check_new_password(new: str, username: str, current: str) -> list:
    """Friendly problems with a new password (empty list = fine)."""
    problems = []
    if len(new) < 10:
        problems.append("Use at least 10 characters.")
    if len(new) > 128:
        problems.append("Use at most 128 characters.")
    low = new.lower()
    if new == current:
        problems.append("The new password must be different from the current one.")
    if username and username.lower() in low:
        problems.append("Do not put your username in the password.")
    if low in _WEAK or any(w in low for w in ("password", "dnshollow")) or len(set(new)) < 4:
        problems.append("This password is too easy to guess. Try a few unrelated words.")
    return problems
