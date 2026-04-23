"""Tests for JWT token creation and verification."""

from __future__ import annotations

import time

import jwt as pyjwt
import pytest

from bgpeek.config import settings
from bgpeek.core.jwt import create_token, decode_token


def test_create_and_decode_roundtrip() -> None:
    token = create_token(42, "alice", "admin")
    payload = decode_token(token)
    assert payload["sub"] == "42"
    assert payload["username"] == "alice"
    assert payload["role"] == "admin"
    assert "exp" in payload
    assert "iat" in payload


def test_decode_expired_token_raises() -> None:
    payload = {
        "sub": "1",
        "username": "bob",
        "role": "public",
        "iat": 1000000,
        "exp": 1000001,
    }
    token = pyjwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    with pytest.raises(pyjwt.ExpiredSignatureError):
        decode_token(token)


def test_decode_invalid_signature_raises() -> None:
    token = create_token(1, "bob", "public")
    # Tamper with the token
    parts = token.split(".")
    parts[2] = parts[2][::-1]
    tampered = ".".join(parts)
    with pytest.raises(pyjwt.InvalidTokenError):
        decode_token(tampered)


def test_decode_garbage_token_raises() -> None:
    with pytest.raises(pyjwt.InvalidTokenError):
        decode_token("not.a.jwt")


def test_token_contains_exp_claim() -> None:
    token = create_token(1, "alice", "noc")
    payload = decode_token(token)
    assert isinstance(payload["exp"], int)
    assert payload["exp"] > time.time()


def test_token_contains_unique_jti() -> None:
    """Each mint carries its own ``jti`` so server-side revocation can target
    one session without kicking out other concurrent sessions."""
    t1 = create_token(1, "alice", "noc")
    t2 = create_token(1, "alice", "noc")
    p1 = decode_token(t1)
    p2 = decode_token(t2)
    assert isinstance(p1["jti"], str)
    assert len(p1["jti"]) >= 16
    assert p1["jti"] != p2["jti"]
