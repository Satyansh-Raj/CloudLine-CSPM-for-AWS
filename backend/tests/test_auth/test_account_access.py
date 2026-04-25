"""Tests for account_access enforcement helpers."""

import pytest
from fastapi import HTTPException

from app.auth.account_access import (
    assert_account_allowed,
    filter_accounts,
    resolve_allowed_accounts,
)
from app.auth.models import User, UserRole
from app.models.account import TargetAccount


def _user(
    role=UserRole.VIEWER,
    allowed=None,
    all_access=True,
) -> User:
    return User(
        sk="user-1",
        email="test@example.com",
        full_name="Test",
        password_hash="x",
        role=role,
        all_accounts_access=all_access,
        allowed_account_ids=allowed or [],
    )


def _acct(account_id: str) -> TargetAccount:
    return TargetAccount(
        sk=account_id,
        account_id=account_id,
        account_name=f"Acct {account_id}",
        role_arn=f"arn:aws:iam::{account_id}:role/S",
    )


class TestResolveAllowedAccounts:
    def test_admin_sees_all(self):
        u = _user(role=UserRole.ADMIN, all_access=False)
        result = resolve_allowed_accounts(
            u, ["111", "222", "333"]
        )
        assert result == ["111", "222", "333"]

    def test_all_accounts_access_sees_all(self):
        u = _user(role=UserRole.VIEWER, all_access=True)
        result = resolve_allowed_accounts(
            u, ["111", "222"]
        )
        assert result == ["111", "222"]

    def test_operator_all_access_sees_all(self):
        u = _user(
            role=UserRole.OPERATOR, all_access=True
        )
        result = resolve_allowed_accounts(
            u, ["111", "222"]
        )
        assert result == ["111", "222"]

    def test_restricted_viewer_intersection(self):
        u = _user(
            role=UserRole.VIEWER,
            allowed=["111", "333"],
            all_access=False,
        )
        result = resolve_allowed_accounts(
            u, ["111", "222", "333"]
        )
        assert set(result) == {"111", "333"}

    def test_restricted_no_match(self):
        u = _user(
            role=UserRole.VIEWER,
            allowed=["999"],
            all_access=False,
        )
        result = resolve_allowed_accounts(
            u, ["111", "222"]
        )
        assert result == []

    def test_empty_all_accounts(self):
        u = _user(role=UserRole.ADMIN)
        result = resolve_allowed_accounts(u, [])
        assert result == []

    def test_restricted_empty_allowlist(self):
        u = _user(
            role=UserRole.VIEWER,
            allowed=[],
            all_access=False,
        )
        result = resolve_allowed_accounts(
            u, ["111", "222"]
        )
        assert result == []


class TestAssertAccountAllowed:
    def test_admin_always_allowed(self):
        u = _user(
            role=UserRole.ADMIN,
            allowed=[],
            all_access=False,
        )
        assert_account_allowed(u, "any-account")

    def test_all_accounts_access_allowed(self):
        u = _user(role=UserRole.VIEWER, all_access=True)
        assert_account_allowed(u, "any-account")

    def test_operator_all_access_allowed(self):
        u = _user(
            role=UserRole.OPERATOR, all_access=True
        )
        assert_account_allowed(u, "any-account")

    def test_restricted_allowed_account_passes(self):
        u = _user(
            role=UserRole.VIEWER,
            allowed=["111"],
            all_access=False,
        )
        assert_account_allowed(u, "111")

    def test_restricted_forbidden_account_raises(self):
        u = _user(
            role=UserRole.VIEWER,
            allowed=["111"],
            all_access=False,
        )
        with pytest.raises(HTTPException) as exc_info:
            assert_account_allowed(u, "222")
        assert exc_info.value.status_code == 403

    def test_operator_restricted_raises_403(self):
        u = _user(
            role=UserRole.OPERATOR,
            allowed=["111"],
            all_access=False,
        )
        with pytest.raises(HTTPException) as exc_info:
            assert_account_allowed(u, "999")
        assert exc_info.value.status_code == 403

    def test_forbidden_detail_contains_account_id(self):
        u = _user(
            role=UserRole.VIEWER,
            allowed=[],
            all_access=False,
        )
        with pytest.raises(HTTPException) as exc_info:
            assert_account_allowed(u, "123456789012")
        assert "123456789012" in exc_info.value.detail

    def test_empty_allowlist_any_account_forbidden(self):
        u = _user(
            role=UserRole.VIEWER,
            allowed=[],
            all_access=False,
        )
        with pytest.raises(HTTPException) as exc_info:
            assert_account_allowed(u, "111")
        assert exc_info.value.status_code == 403


class TestFilterAccounts:
    def test_admin_sees_all(self):
        u = _user(
            role=UserRole.ADMIN,
            allowed=[],
            all_access=False,
        )
        accts = [_acct("111"), _acct("222")]
        result = filter_accounts(u, accts)
        assert result == accts

    def test_all_access_sees_all(self):
        u = _user(role=UserRole.VIEWER, all_access=True)
        accts = [_acct("111"), _acct("222")]
        result = filter_accounts(u, accts)
        assert result == accts

    def test_restricted_filters_correctly(self):
        u = _user(
            role=UserRole.VIEWER,
            allowed=["111"],
            all_access=False,
        )
        accts = [_acct("111"), _acct("222")]
        result = filter_accounts(u, accts)
        assert len(result) == 1
        assert result[0].account_id == "111"

    def test_restricted_no_match_empty(self):
        u = _user(
            role=UserRole.VIEWER,
            allowed=["999"],
            all_access=False,
        )
        accts = [_acct("111"), _acct("222")]
        result = filter_accounts(u, accts)
        assert result == []

    def test_empty_account_list(self):
        u = _user(role=UserRole.ADMIN)
        result = filter_accounts(u, [])
        assert result == []

    def test_restricted_multiple_allowed(self):
        u = _user(
            role=UserRole.VIEWER,
            allowed=["111", "333"],
            all_access=False,
        )
        accts = [_acct("111"), _acct("222"), _acct("333")]
        result = filter_accounts(u, accts)
        ids = {a.account_id for a in result}
        assert ids == {"111", "333"}
