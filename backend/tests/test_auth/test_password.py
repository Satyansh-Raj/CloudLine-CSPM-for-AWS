"""Tests for password hashing utilities."""

import pytest

from app.auth.password import (
    MIN_PASSWORD_LENGTH,
    hash_password,
    verify_password,
)


class TestHashPassword:
    def test_returns_string(self):
        h = hash_password("mypassword123!")
        assert isinstance(h, str)

    def test_not_plaintext(self):
        pw = "mypassword123!"
        assert hash_password(pw) != pw

    def test_salted(self):
        pw = "mypassword123!"
        h1 = hash_password(pw)
        h2 = hash_password(pw)
        assert h1 != h2

    def test_starts_with_bcrypt_prefix(self):
        h = hash_password("mypassword123!")
        assert h.startswith("$2b$") or h.startswith("$2a$")

    def test_min_length_enforced(self):
        short = "x" * (MIN_PASSWORD_LENGTH - 1)
        with pytest.raises(ValueError, match="too short"):
            hash_password(short)

    def test_exact_min_length_ok(self):
        pw = "x" * MIN_PASSWORD_LENGTH
        h = hash_password(pw)
        assert h  # no exception raised


class TestVerifyPassword:
    def test_correct_password(self):
        pw = "mypassword123!"
        h = hash_password(pw)
        assert verify_password(pw, h) is True

    def test_wrong_password(self):
        h = hash_password("mypassword123!")
        assert verify_password("wrongpassword!!", h) is False

    def test_empty_password(self):
        h = hash_password("mypassword123!")
        assert verify_password("", h) is False

    def test_case_sensitive(self):
        pw = "MyPassword123!"
        h = hash_password(pw)
        assert verify_password("mypassword123!", h) is False

    def test_hash_is_not_reusable_as_password(self):
        pw = "mypassword123!"
        h = hash_password(pw)
        # verifying the hash against itself should fail
        assert verify_password(h, h) is False
