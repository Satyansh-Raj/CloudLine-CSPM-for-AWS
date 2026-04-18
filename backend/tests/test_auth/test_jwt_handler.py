"""Tests for JWT encode/decode utilities."""

from datetime import timedelta

import pytest

from app.auth.jwt_handler import (
    InvalidTokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.auth.models import UserRole

SECRET = "test-secret-key-that-is-long-enough-32c"


class TestCreateAccessToken:
    def test_returns_string(self):
        token = create_access_token(
            "user1",
            UserRole.ADMIN,
            SECRET,
            timedelta(minutes=60),
        )
        assert isinstance(token, str)
        assert len(token) > 0

    def test_has_three_parts(self):
        token = create_access_token(
            "user1",
            UserRole.VIEWER,
            SECRET,
            timedelta(minutes=60),
        )
        assert len(token.split(".")) == 3

    def test_payload_sub_and_role(self):
        token = create_access_token(
            "user-abc",
            UserRole.OPERATOR,
            SECRET,
            timedelta(minutes=60),
        )
        payload = decode_token(
            token, SECRET, expected_type="access"
        )
        assert payload.sub == "user-abc"
        assert payload.role == UserRole.OPERATOR

    def test_payload_type_is_access(self):
        token = create_access_token(
            "u1",
            UserRole.ADMIN,
            SECRET,
            timedelta(minutes=60),
        )
        payload = decode_token(
            token, SECRET, expected_type="access"
        )
        assert payload.type == "access"

    def test_jti_is_non_empty(self):
        token = create_access_token(
            "u1",
            UserRole.ADMIN,
            SECRET,
            timedelta(minutes=60),
        )
        payload = decode_token(
            token, SECRET, expected_type="access"
        )
        assert payload.jti
        assert len(payload.jti) > 0

    def test_different_tokens_have_different_jti(self):
        t1 = create_access_token(
            "u1",
            UserRole.ADMIN,
            SECRET,
            timedelta(minutes=60),
        )
        t2 = create_access_token(
            "u1",
            UserRole.ADMIN,
            SECRET,
            timedelta(minutes=60),
        )
        p1 = decode_token(t1, SECRET, expected_type="access")
        p2 = decode_token(t2, SECRET, expected_type="access")
        assert p1.jti != p2.jti


class TestCreateRefreshToken:
    def test_returns_string(self):
        token = create_refresh_token(
            "user1", SECRET, timedelta(days=7)
        )
        assert isinstance(token, str)

    def test_payload_type_is_refresh(self):
        token = create_refresh_token(
            "user1", SECRET, timedelta(days=7)
        )
        payload = decode_token(
            token, SECRET, expected_type="refresh"
        )
        assert payload.type == "refresh"
        assert payload.sub == "user1"

    def test_no_role_in_refresh_token(self):
        token = create_refresh_token(
            "user1", SECRET, timedelta(days=7)
        )
        payload = decode_token(
            token, SECRET, expected_type="refresh"
        )
        assert payload.role is None


class TestDecodeToken:
    def test_expired_token_raises(self):
        token = create_access_token(
            "user1",
            UserRole.ADMIN,
            SECRET,
            timedelta(seconds=-1),
        )
        with pytest.raises(
            InvalidTokenError, match="expired"
        ):
            decode_token(
                token, SECRET, expected_type="access"
            )

    def test_wrong_secret_raises(self):
        token = create_access_token(
            "user1",
            UserRole.ADMIN,
            SECRET,
            timedelta(hours=1),
        )
        with pytest.raises(InvalidTokenError):
            decode_token(
                token,
                "wrong-secret",
                expected_type="access",
            )

    def test_refresh_rejected_as_access(self):
        token = create_refresh_token(
            "user1", SECRET, timedelta(days=7)
        )
        with pytest.raises(
            InvalidTokenError, match="type"
        ):
            decode_token(
                token, SECRET, expected_type="access"
            )

    def test_access_rejected_as_refresh(self):
        token = create_access_token(
            "user1",
            UserRole.ADMIN,
            SECRET,
            timedelta(hours=1),
        )
        with pytest.raises(
            InvalidTokenError, match="type"
        ):
            decode_token(
                token, SECRET, expected_type="refresh"
            )

    def test_malformed_token_raises(self):
        with pytest.raises(InvalidTokenError):
            decode_token(
                "not.a.token",
                SECRET,
                expected_type="access",
            )

    def test_empty_token_raises(self):
        with pytest.raises(InvalidTokenError):
            decode_token(
                "", SECRET, expected_type="access"
            )
