"""Tests for RBAC user models."""

import pytest

from app.auth.models import (
    ChangePasswordRequest,
    LoginRequest,
    ResetRequestCreate,
    TokenPair,
    TokenPayload,
    User,
    UserRole,
)


class TestUserRole:
    def test_values(self):
        assert UserRole.ADMIN == "admin"
        assert UserRole.OPERATOR == "operator"
        assert UserRole.VIEWER == "viewer"

    def test_all_roles_present(self):
        roles = {r.value for r in UserRole}
        assert roles == {"admin", "operator", "viewer"}

    def test_is_string_enum(self):
        assert isinstance(UserRole.ADMIN, str)


class TestUser:
    def _make_user(self, role=UserRole.VIEWER):
        return User(
            sk="user-1",
            email="test@example.com",
            full_name="Test User",
            password_hash="$2b$12$abc",
            role=role,
        )

    def test_pk_default(self):
        user = self._make_user()
        assert user.pk == "USERS"

    def test_is_active_default(self):
        assert self._make_user().is_active is True

    def test_reset_allowed_default(self):
        assert self._make_user().reset_allowed is False

    def test_optional_fields_default_none(self):
        user = self._make_user()
        assert user.reset_requested_at is None
        assert user.reset_approved_by is None
        assert user.last_login is None

    def test_created_by_default(self):
        assert self._make_user().created_by == ""

    def test_all_roles_accepted(self):
        for role in UserRole:
            user = User(
                sk="u1",
                email="a@b.com",
                full_name="A",
                password_hash="hash",
                role=role,
            )
            assert user.role == role

    def test_missing_required_fields(self):
        with pytest.raises(Exception):
            User()

    def test_explicit_optional_fields(self):
        user = User(
            sk="u2",
            email="b@c.com",
            full_name="B",
            password_hash="hash",
            role=UserRole.ADMIN,
            last_login="2026-04-09T10:00:00Z",
            reset_requested_at="2026-04-09T09:00:00Z",
            reset_approved_by="admin-1",
            reset_allowed=True,
        )
        assert user.last_login == "2026-04-09T10:00:00Z"
        assert user.reset_allowed is True
        assert user.reset_approved_by == "admin-1"


class TestLoginRequest:
    def test_valid(self):
        req = LoginRequest(
            email="a@b.com", password="secret"
        )
        assert req.email == "a@b.com"
        assert req.password == "secret"

    def test_missing_fields(self):
        with pytest.raises(Exception):
            LoginRequest()


class TestTokenPair:
    def test_fields(self):
        tp = TokenPair(
            access_token="a",
            refresh_token="r",
        )
        assert tp.token_type == "bearer"
        assert tp.access_token == "a"
        assert tp.refresh_token == "r"


class TestTokenPayload:
    def test_access_token_fields(self):
        p = TokenPayload(
            sub="u1",
            role=UserRole.ADMIN,
            type="access",
            jti="jti-1",
            exp=9_999_999_999,
            iat=0,
        )
        assert p.sub == "u1"
        assert p.role == UserRole.ADMIN
        assert p.type == "access"
        assert p.jti == "jti-1"

    def test_role_optional(self):
        p = TokenPayload(
            sub="u1",
            role=None,
            type="refresh",
            jti="jti-2",
            exp=9_999_999_999,
            iat=0,
        )
        assert p.role is None


class TestChangePasswordRequest:
    def test_valid(self):
        req = ChangePasswordRequest(
            current_password="oldpass",
            new_password="newpassword123!",
        )
        assert req.current_password == "oldpass"
        assert req.new_password == "newpassword123!"

    def test_missing_fields(self):
        with pytest.raises(Exception):
            ChangePasswordRequest()


class TestResetRequestCreate:
    def test_valid(self):
        req = ResetRequestCreate(email="a@b.com")
        assert req.email == "a@b.com"

    def test_missing_email(self):
        with pytest.raises(Exception):
            ResetRequestCreate()
