"""Passwords, login tokens and who-may-do-what."""
import hashlib
import hmac
import os
import secrets
import time

# What each role may do. "view" = read logs, alerts, runs and benchmarks.
PERMISSIONS = {
    "System Admin":     {"view", "start_run", "update_alert"},
    "Security Analyst": {"view", "update_alert"},
    "NetOps Admin":     {"view"},
}


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt, digest = stored.split("$")
        test = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1)
        return hmac.compare_digest(test, bytes.fromhex(digest))
    except (ValueError, TypeError):
        return False


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    """Only this hash is stored, so a stolen database cannot be used to log in."""
    return hashlib.sha256(token.encode()).hexdigest()


class LoginLimiter:
    """After 5 wrong passwords for one username, wait 5 minutes before trying again."""
    MAX_FAILS, WINDOW = 5, 300

    def __init__(self):
        self._fails = {}

    def blocked(self, username) -> bool:
        times = [t for t in self._fails.get(username, []) if time.time() - t < self.WINDOW]
        self._fails[username] = times
        return len(times) >= self.MAX_FAILS

    def fail(self, username):
        self._fails.setdefault(username, []).append(time.time())

    def clear(self, username):
        self._fails.pop(username, None)
