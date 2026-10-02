"""Unit tests for auth utilities (no DB, no FastAPI)."""

from __future__ import annotations

import pytest
from jose import JWTError

from intriqo.auth.passwords import hash_password, verify_password
from intriqo.auth.tokens import create_access_token, decode_access_token


class TestPasswords:
    def test_hash_and_verify(self):
        h = hash_password("mysecret")
        assert h != "mysecret"
        assert verify_password("mysecret", h)

    def test_wrong_password_fails(self):
        h = hash_password("correct")
        assert not verify_password("wrong", h)

    def test_different_hashes_for_same_password(self):
        h1 = hash_password("pw")
        h2 = hash_password("pw")
        assert h1 != h2  # bcrypt uses a random salt


class TestTokens:
    def test_create_and_decode(self):
        token = create_access_token(subject="alice", role="ANALYST")
        payload = decode_access_token(token)
        assert payload["sub"] == "alice"
        assert payload["role"] == "ANALYST"

    def test_extra_claims(self):
        token = create_access_token(subject="bob", role="AGENT", extra={"user_id": "u-123"})
        payload = decode_access_token(token)
        assert payload["user_id"] == "u-123"

    def test_invalid_token_raises(self):
        with pytest.raises(JWTError):
            decode_access_token("not.a.valid.token")

    def test_tampered_token_raises(self):
        token = create_access_token(subject="charlie", role="ADMIN")
        # Corrupt the signature
        parts = token.split(".")
        parts[2] = parts[2][:-4] + "XXXX"
        tampered = ".".join(parts)
        with pytest.raises(JWTError):
            decode_access_token(tampered)
