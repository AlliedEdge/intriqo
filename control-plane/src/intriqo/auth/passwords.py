"""Password hashing using bcrypt directly.

Uses the ``bcrypt`` package rather than passlib — passlib 1.7 is not
compatible with bcrypt >= 4.1 on Python 3.14 due to a version-detection
probe that exceeds bcrypt's 72-byte input limit.
"""

from __future__ import annotations

import bcrypt


def hash_password(plain: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return bcrypt.checkpw(plain.encode(), hashed.encode())
