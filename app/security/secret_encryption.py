"""Symmetric encryption for secrets that must be stored (not just
hashed) because the application needs to read them back -- e.g. an
IMAP mailbox password, which we must supply on every poll.

This is a different concern from password hashing (app/security/passwords.py):
user passwords are one-way hashed because we never need the plaintext
back. IMAP credentials are the opposite -- we genuinely need to
reconstruct the plaintext to log in, so they're encrypted (reversible)
rather than hashed (irreversible), using a key derived from the
application's own SECRET_KEY via Fernet (AES-128-CBC + HMAC, from the
`cryptography` package already a project dependency).

If SECRET_KEY ever rotates, every stored encrypted credential becomes
unreadable and must be re-entered -- this is expected and by design;
treat SECRET_KEY rotation as equivalent to a mailbox re-configuration
event.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


class SecretEncryptionError(Exception):
    pass


def _derive_fernet_key(secret_key: str) -> bytes:
    """Fernet requires a 32-byte urlsafe-base64-encoded key; SECRET_KEY
    can be any string, so we deterministically derive a valid key from
    it via SHA-256.
    """
    digest = hashlib.sha256(secret_key.encode()).digest()
    return base64.urlsafe_b64encode(digest)


_fernet = Fernet(_derive_fernet_key(settings.SECRET_KEY))


def encrypt_secret(plaintext: str) -> str:
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise SecretEncryptionError(
            "Could not decrypt stored credential -- SECRET_KEY may have changed "
            "since it was encrypted. Re-configure this mailbox's credentials."
        ) from exc
