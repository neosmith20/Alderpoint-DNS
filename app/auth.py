#!/usr/bin/env python3
"""Shared Argon2 password hashing, used by both the web app (app/webapp.py)
and the root-only local recovery CLI (scripts/alderpointdns-admin), so a
password reset performed from either path produces and verifies hashes the
exact same way."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


MIN_PASSWORD_LENGTH = 12


def validate_password_length(password: str) -> str | None:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    return None
