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


class TestTokenRoleClaims:
    """JWT must embed role correctly and resist client-side tampering."""

    def test_admin_role_embedded(self):
        token = create_access_token(subject="admin_user", role="ADMIN")
        payload = decode_access_token(token)
        assert payload["role"] == "ADMIN"

    def test_analyst_role_embedded(self):
        token = create_access_token(subject="analyst_user", role="ANALYST")
        payload = decode_access_token(token)
        assert payload["role"] == "ANALYST"

    def test_agent_role_embedded(self):
        token = create_access_token(subject="agent_svc", role="AGENT")
        payload = decode_access_token(token)
        assert payload["role"] == "AGENT"

    def test_user_id_propagated_in_extra(self):
        token = create_access_token(subject="bob", role="ANALYST", extra={"user_id": "u-999"})
        payload = decode_access_token(token)
        assert payload["user_id"] == "u-999"
        assert payload["sub"] == "bob"

    def test_payload_manipulation_by_header_swap_raises(self):
        """Swapping in a different JOSE header must invalidate the signature."""
        import base64
        import json

        token = create_access_token(subject="user", role="ANALYST")
        header_b64, payload_b64, sig = token.split(".")

        # Decode and re-encode the payload claiming ADMIN role
        # (pad to multiple of 4 before decoding)
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        original = json.loads(base64.urlsafe_b64decode(padded))
        original["role"] = "ADMIN"
        new_payload = base64.urlsafe_b64encode(
            json.dumps(original).encode()
        ).rstrip(b"=").decode()

        tampered = f"{header_b64}.{new_payload}.{sig}"
        with pytest.raises(JWTError):
            decode_access_token(tampered)

    def test_signature_truncation_raises(self):
        token = create_access_token(subject="user", role="ANALYST")
        truncated = token[:-8]
        with pytest.raises(JWTError):
            decode_access_token(truncated)

    def test_empty_string_raises(self):
        with pytest.raises(JWTError):
            decode_access_token("")

    def test_none_alg_attack_raises(self):
        """Tokens signed with 'none' algorithm must be rejected."""
        import base64
        import json

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload_data = {"sub": "attacker", "role": "ADMIN"}
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload_data).encode()
        ).rstrip(b"=").decode()
        none_token = f"{header}.{payload_b64}."
        with pytest.raises(JWTError):
            decode_access_token(none_token)


class TestTokenExpiry:
    """Expired tokens must be rejected by the decoder."""

    def test_expired_token_raises(self):
        from datetime import timedelta

        from jose import jwt

        from intriqo.config import get_settings

        settings = get_settings()
        import datetime as _dt

        past = _dt.datetime.now(_dt.timezone.utc) - timedelta(seconds=1)
        payload = {"sub": "user", "role": "ANALYST", "exp": past, "iat": past}
        expired_token = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
        with pytest.raises(JWTError):
            decode_access_token(expired_token)

    def test_wrong_secret_raises(self):
        from jose import jwt

        token = jwt.encode(
            {"sub": "user", "role": "ANALYST"},
            "WRONG_SECRET",
            algorithm="HS256",
        )
        with pytest.raises(JWTError):
            decode_access_token(token)
