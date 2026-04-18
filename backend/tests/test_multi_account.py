"""Tests for multi-account scanning support (F4 Batch 9).

TDD: Written BEFORE implementation — tests MUST fail
until implementation is complete.

Coverage:
  - TargetAccount model validation
  - AccountStore DynamoDB CRUD operations
  - AWSSessionFactory STS AssumeRole behavior
  - _run_scan() multi-account iteration + fallback
  - Accounts CRUD REST API endpoints
"""

from unittest.mock import MagicMock, patch, call
from datetime import UTC, datetime

import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from app.config import Settings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_settings(**kwargs) -> Settings:
    """Return a Settings instance with test defaults."""
    defaults = dict(
        aws_account_id="123456789012",
        api_key="test-key",
        app_env="testing",
        dynamodb_endpoint="http://localhost:9730",
    )
    defaults.update(kwargs)
    return Settings(_env_file=None, **defaults)


def _make_account_item(
    account_id="111111111111",
    account_name="Dev Account",
    role_arn="arn:aws:iam::111111111111:role/CloudLineScanner",
    external_id="",
    regions=None,
    is_active=True,
    added_at="2026-03-18T00:00:00Z",
    last_scanned=None,
):
    """Return a raw DynamoDB item for an account."""
    item = {
        "pk": "ACCOUNTS",
        "sk": account_id,
        "account_id": account_id,
        "account_name": account_name,
        "role_arn": role_arn,
        "external_id": external_id,
        "regions": regions or ["us-east-1"],
        "is_active": is_active,
        "added_at": added_at,
    }
    if last_scanned is not None:
        item["last_scanned"] = last_scanned
    return item


# ---------------------------------------------------------------------------
# 1. TestTargetAccountModel
# ---------------------------------------------------------------------------

class TestTargetAccountModel:
    """TargetAccount pydantic model validation."""

    def test_default_values(self):
        """pk defaults to ACCOUNTS, is_active defaults True."""
        from app.models.account import TargetAccount

        acc = TargetAccount(
            sk="222222222222",
            account_id="222222222222",
            account_name="Test",
            role_arn=(
                "arn:aws:iam::222222222222"
                ":role/CloudLineScanner"
            ),
        )
        assert acc.pk == "ACCOUNTS"
        assert acc.is_active is True
        assert acc.external_id == ""
        assert acc.regions == ["us-east-1"]

    def test_full_model(self):
        """All fields populated correctly."""
        from app.models.account import TargetAccount

        acc = TargetAccount(
            pk="ACCOUNTS",
            sk="333333333333",
            account_id="333333333333",
            account_name="Prod Account",
            role_arn=(
                "arn:aws:iam::333333333333"
                ":role/CloudLineScanner"
            ),
            external_id="secret-ext-id",
            regions=["us-east-1", "eu-west-1"],
            is_active=True,
            added_at="2026-03-18T00:00:00Z",
            last_scanned="2026-03-18T01:00:00Z",
        )
        assert acc.account_name == "Prod Account"
        assert acc.external_id == "secret-ext-id"
        assert acc.regions == ["us-east-1", "eu-west-1"]
        assert acc.last_scanned == "2026-03-18T01:00:00Z"

    def test_sk_is_account_id(self):
        """sk should equal the account_id."""
        from app.models.account import TargetAccount

        acc = TargetAccount(
            sk="444444444444",
            account_id="444444444444",
            account_name="Other",
            role_arn=(
                "arn:aws:iam::444444444444"
                ":role/CloudLineScanner"
            ),
        )
        assert acc.sk == acc.account_id


# ---------------------------------------------------------------------------
# 2. TestAccountStore
# ---------------------------------------------------------------------------

class TestAccountStore:
    """AccountStore DynamoDB CRUD operations."""

    def _make_store(self):
        """Build an AccountStore with a mocked table."""
        from app.pipeline.account_store import (
            AccountStore,
        )
        mock_session = MagicMock()
        mock_table = MagicMock()
        mock_dynamodb = MagicMock()
        mock_dynamodb.Table.return_value = mock_table
        mock_session.resource.return_value = mock_dynamodb

        store = AccountStore(
            session=mock_session,
            table_name="target-accounts",
        )
        store.table = mock_table
        return store, mock_table

    def test_put_and_get_account(self):
        """Round-trip: put then get returns same account."""
        from app.models.account import TargetAccount
        from app.pipeline.account_store import (
            AccountStore,
        )

        store, mock_table = self._make_store()
        account_id = "111111111111"

        acc = TargetAccount(
            sk=account_id,
            account_id=account_id,
            account_name="Dev",
            role_arn=(
                f"arn:aws:iam::{account_id}"
                ":role/CloudLineScanner"
            ),
        )

        # Setup mock for get_item
        item = _make_account_item(account_id=account_id)
        mock_table.get_item.return_value = {"Item": item}

        # put_account must call put_item
        result = store.put_account(acc)
        assert result is True
        mock_table.put_item.assert_called_once()

        # get_account returns a TargetAccount
        fetched = store.get_account(account_id)
        assert fetched is not None
        assert fetched.account_id == account_id
        mock_table.get_item.assert_called_once_with(
            Key={"pk": "ACCOUNTS", "sk": account_id}
        )

    def test_list_active_returns_only_active(self):
        """list_active filters out is_active=False accounts."""
        from app.pipeline.account_store import (
            AccountStore,
        )

        store, mock_table = self._make_store()

        active_item = _make_account_item(
            account_id="111111111111", is_active=True
        )
        inactive_item = _make_account_item(
            account_id="222222222222", is_active=False
        )

        mock_table.query.return_value = {
            "Items": [active_item, inactive_item]
        }

        accounts = store.list_active()

        # Should only return active accounts
        assert len(accounts) == 1
        assert accounts[0].account_id == "111111111111"

    def test_deactivate_account(self):
        """deactivate sets is_active=False via update_item."""
        from app.pipeline.account_store import (
            AccountStore,
        )

        store, mock_table = self._make_store()
        account_id = "111111111111"

        result = store.deactivate(account_id)

        assert result is True
        mock_table.update_item.assert_called_once()
        call_kwargs = mock_table.update_item.call_args[1]
        assert call_kwargs["Key"] == {
            "pk": "ACCOUNTS",
            "sk": account_id,
        }
        # Expression must set is_active to False
        assert "is_active" in call_kwargs.get(
            "UpdateExpression", ""
        )

    def test_get_nonexistent_returns_none(self):
        """get_account returns None for missing account."""
        from app.pipeline.account_store import (
            AccountStore,
        )

        store, mock_table = self._make_store()
        mock_table.get_item.return_value = {}

        result = store.get_account("999999999999")

        assert result is None

    def test_update_last_scanned(self):
        """update_last_scanned writes timestamp via update_item."""
        from app.pipeline.account_store import (
            AccountStore,
        )

        store, mock_table = self._make_store()
        account_id = "111111111111"
        ts = "2026-03-18T12:00:00Z"

        result = store.update_last_scanned(
            account_id, ts
        )

        assert result is True
        mock_table.update_item.assert_called_once()
        call_kwargs = mock_table.update_item.call_args[1]
        assert call_kwargs["Key"] == {
            "pk": "ACCOUNTS",
            "sk": account_id,
        }

    def test_list_active_empty(self):
        """list_active returns empty list when no accounts."""
        from app.pipeline.account_store import (
            AccountStore,
        )

        store, mock_table = self._make_store()
        mock_table.query.return_value = {"Items": []}

        accounts = store.list_active()

        assert accounts == []

    def test_list_active_pagination(self):
        """list_active handles DynamoDB pagination."""
        from app.pipeline.account_store import (
            AccountStore,
        )

        store, mock_table = self._make_store()

        page1_item = _make_account_item(
            account_id="111111111111"
        )
        page2_item = _make_account_item(
            account_id="222222222222"
        )

        # First page has LastEvaluatedKey
        mock_table.query.side_effect = [
            {
                "Items": [page1_item],
                "LastEvaluatedKey": {
                    "pk": "ACCOUNTS",
                    "sk": "111111111111",
                },
            },
            {"Items": [page2_item]},
        ]

        accounts = store.list_active()

        assert len(accounts) == 2
        assert mock_table.query.call_count == 2

    def test_put_account_error_returns_false(self):
        """put_account returns False when DynamoDB raises."""
        from app.pipeline.account_store import (
            AccountStore,
        )
        from app.models.account import TargetAccount

        store, mock_table = self._make_store()
        mock_table.put_item.side_effect = Exception(
            "DynamoDB error"
        )

        acc = TargetAccount(
            sk="111111111111",
            account_id="111111111111",
            account_name="Dev",
            role_arn=(
                "arn:aws:iam::111111111111"
                ":role/CloudLineScanner"
            ),
        )

        result = store.put_account(acc)
        assert result is False

    def test_get_account_error_returns_none(self):
        """get_account returns None when DynamoDB raises."""
        from app.pipeline.account_store import (
            AccountStore,
        )

        store, mock_table = self._make_store()
        mock_table.get_item.side_effect = Exception(
            "DynamoDB error"
        )

        result = store.get_account("111111111111")
        assert result is None

    def test_list_active_error_returns_empty(self):
        """list_active returns [] when DynamoDB raises."""
        from app.pipeline.account_store import (
            AccountStore,
        )

        store, mock_table = self._make_store()
        mock_table.query.side_effect = Exception(
            "DynamoDB error"
        )

        accounts = store.list_active()
        assert accounts == []

    def test_deactivate_error_returns_false(self):
        """deactivate returns False when DynamoDB raises."""
        from app.pipeline.account_store import (
            AccountStore,
        )

        store, mock_table = self._make_store()
        mock_table.update_item.side_effect = Exception(
            "DynamoDB error"
        )

        result = store.deactivate("111111111111")
        assert result is False

    def test_update_last_scanned_error_returns_false(
        self,
    ):
        """update_last_scanned returns False on error."""
        from app.pipeline.account_store import (
            AccountStore,
        )

        store, mock_table = self._make_store()
        mock_table.update_item.side_effect = Exception(
            "DynamoDB error"
        )

        result = store.update_last_scanned(
            "111111111111", "2026-03-18T00:00:00Z"
        )
        assert result is False


# ---------------------------------------------------------------------------
# 3. TestAWSSessionFactory
# ---------------------------------------------------------------------------

class TestAWSSessionFactory:
    """AWSSessionFactory STS AssumeRole behavior."""

    def _make_factory(self):
        """Build AWSSessionFactory with a mocked STS."""
        from app.pipeline.session_factory import (
            AWSSessionFactory,
        )
        mock_base = MagicMock()
        mock_sts = MagicMock()
        mock_base.client.return_value = mock_sts

        factory = AWSSessionFactory(
            base_session=mock_base
        )
        return factory, mock_sts

    def _make_account(
        self,
        account_id="111111111111",
        external_id="",
    ):
        """Build a TargetAccount for testing."""
        from app.models.account import TargetAccount

        return TargetAccount(
            sk=account_id,
            account_id=account_id,
            account_name="Test",
            role_arn=(
                f"arn:aws:iam::{account_id}"
                ":role/CloudLineScanner"
            ),
            external_id=external_id,
        )

    def _assume_role_response(self, account_id):
        """Fake STS AssumeRole response."""
        return {
            "Credentials": {
                "AccessKeyId": "AKIA_FAKE",
                "SecretAccessKey": "fake-secret",
                "SessionToken": "fake-token",
                "Expiration": "2099-01-01T00:00:00Z",
            },
            "AssumedRoleUser": {
                "AssumedRoleId": (
                    f"AROA:{account_id}"
                ),
                "Arn": (
                    f"arn:aws:sts::{account_id}"
                    ":assumed-role/CloudLineScanner"
                    f"/CloudLineScan-{account_id}"
                ),
            },
        }

    def test_get_session_calls_assume_role(self):
        """AssumeRole is called with correct role_arn + session_name."""
        import boto3
        from app.pipeline.session_factory import (
            AWSSessionFactory,
        )

        factory, mock_sts = self._make_factory()
        account = self._make_account("111111111111")

        mock_sts.assume_role.return_value = (
            self._assume_role_response("111111111111")
        )

        with patch("boto3.Session") as mock_session_cls:
            factory.get_session(account)

        mock_sts.assume_role.assert_called_once()
        call_kwargs = mock_sts.assume_role.call_args[1]
        assert (
            call_kwargs["RoleArn"] == account.role_arn
        )
        assert call_kwargs["RoleSessionName"] == (
            "CloudLineScan-111111111111"
        )

    def test_get_session_with_external_id(self):
        """ExternalId is passed to AssumeRole when non-empty."""
        from app.pipeline.session_factory import (
            AWSSessionFactory,
        )

        factory, mock_sts = self._make_factory()
        account = self._make_account(
            "111111111111", external_id="my-ext-id"
        )

        mock_sts.assume_role.return_value = (
            self._assume_role_response("111111111111")
        )

        with patch("boto3.Session"):
            factory.get_session(account)

        call_kwargs = mock_sts.assume_role.call_args[1]
        assert call_kwargs.get("ExternalId") == (
            "my-ext-id"
        )

    def test_get_session_returns_boto3_session(self):
        """get_session returns a boto3.Session instance."""
        import boto3
        from app.pipeline.session_factory import (
            AWSSessionFactory,
        )

        factory, mock_sts = self._make_factory()
        account = self._make_account("111111111111")

        mock_sts.assume_role.return_value = (
            self._assume_role_response("111111111111")
        )

        result = factory.get_session(account)

        # Result must be a boto3.Session (real or mock)
        # We just verify it's not None and was created
        assert result is not None

    def test_get_session_failure_raises_runtime_error(
        self,
    ):
        """ClientError from AssumeRole raises RuntimeError."""
        from app.pipeline.session_factory import (
            AWSSessionFactory,
        )

        factory, mock_sts = self._make_factory()
        account = self._make_account("111111111111")

        mock_sts.assume_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied",
                       "Message": "Access denied"}},
            "AssumeRole",
        )

        with pytest.raises(RuntimeError) as exc_info:
            factory.get_session(account)

        assert "111111111111" in str(exc_info.value)

    def test_get_caller_identity(self):
        """get_caller_identity returns identity dict."""
        from app.pipeline.session_factory import (
            AWSSessionFactory,
        )

        factory, mock_sts = self._make_factory()
        expected = {
            "Account": "123456789012",
            "UserId": "AIDAEXAMPLE",
            "Arn": (
                "arn:aws:iam::123456789012"
                ":user/test"
            ),
        }
        mock_sts.get_caller_identity.return_value = (
            expected
        )

        result = factory.get_caller_identity()

        assert result == expected
        mock_sts.get_caller_identity.assert_called_once()


# ---------------------------------------------------------------------------
# 4. TestMultiAccountScan
# ---------------------------------------------------------------------------

class TestMultiAccountScan:
    """_run_scan multi-account iteration and fallback."""

    def _make_mock_account(
        self,
        account_id,
        regions=None,
    ):
        """Build a MagicMock TargetAccount."""
        from app.models.account import TargetAccount

        return TargetAccount(
            sk=account_id,
            account_id=account_id,
            account_name=f"Account {account_id}",
            role_arn=(
                f"arn:aws:iam::{account_id}"
                ":role/CloudLineScanner"
            ),
            regions=regions or ["us-east-1"],
        )

    def test_scan_with_no_accounts_uses_default(self):
        """When AccountStore returns empty, scan uses settings.aws_account_id."""
        from app.routers.scans import _run_scan

        settings = _make_settings(
            aws_account_id="123456789012",
            aws_regions=["us-east-1"],
        )

        mock_evaluator = MagicMock()
        mock_evaluator.evaluate_all.return_value = []
        mock_state_manager = MagicMock()
        mock_state_manager.query_by_account.return_value = []
        mock_resource_store = MagicMock()
        mock_resource_store.query_by_account.return_value = []
        mock_account_store = MagicMock()
        mock_account_store.list_active.return_value = []
        mock_session = MagicMock()

        with patch(
            "app.routers.scans.CollectionOrchestrator"
        ) as mock_orch_cls:
            mock_orch = MagicMock()
            mock_orch.collect_iam.return_value = {}
            mock_orch.collect_regional.return_value = {}
            mock_orch_cls.return_value = mock_orch

            with patch(
                "app.routers.scans.get_account_store",
                return_value=mock_account_store,
            ):
                _run_scan(
                    scan_id="test-scan",
                    session=mock_session,
                    settings=settings,
                    evaluator=mock_evaluator,
                    state_manager=mock_state_manager,
                    resource_store=mock_resource_store,
                )

        # Orchestrator must have been called with the
        # default account from settings
        calls = mock_orch_cls.call_args_list
        account_ids = [
            c[1].get("account_id") or c[0][1]
            if len(c[0]) > 1
            else c[1].get("account_id", "")
            for c in calls
        ]
        assert any(
            "123456789012" in str(c) for c in calls
        )

    def test_scan_iterates_over_accounts(self):
        """With 2 active accounts, both get scanned."""
        from app.routers.scans import _run_scan

        settings = _make_settings(
            aws_account_id="123456789012",
            aws_regions=["us-east-1"],
        )

        account_a = self._make_mock_account(
            "111111111111"
        )
        account_b = self._make_mock_account(
            "222222222222"
        )

        mock_evaluator = MagicMock()
        mock_evaluator.evaluate_all.return_value = []
        mock_state_manager = MagicMock()
        mock_state_manager.query_by_account.return_value = []
        mock_resource_store = MagicMock()
        mock_resource_store.query_by_account.return_value = []
        mock_account_store = MagicMock()
        mock_account_store.list_active.return_value = [
            account_a, account_b
        ]
        mock_session_factory = MagicMock()
        mock_assumed_session = MagicMock()
        mock_session_factory.get_session.return_value = (
            mock_assumed_session
        )

        scanned_accounts = []

        def mock_orch_factory(*args, **kwargs):
            acc_id = kwargs.get("account_id", "")
            scanned_accounts.append(acc_id)
            mock_orch = MagicMock()
            mock_orch.collect_iam.return_value = {}
            mock_orch.collect_regional.return_value = {}
            return mock_orch

        with patch(
            "app.routers.scans.CollectionOrchestrator",
            side_effect=mock_orch_factory,
        ):
            with patch(
                "app.routers.scans.get_account_store",
                return_value=mock_account_store,
            ):
                with patch(
                    "app.routers.scans"
                    ".get_session_factory",
                    return_value=mock_session_factory,
                ):
                    _run_scan(
                        scan_id="test-scan",
                        session=MagicMock(),
                        settings=settings,
                        evaluator=mock_evaluator,
                        state_manager=mock_state_manager,
                        resource_store=mock_resource_store,
                    )

        # Both accounts must appear in scanned set
        assert "111111111111" in scanned_accounts
        assert "222222222222" in scanned_accounts

    def test_scan_uses_assumed_session_per_account(self):
        """SessionFactory.get_session called for each account."""
        from app.routers.scans import _run_scan

        settings = _make_settings(
            aws_account_id="123456789012",
            aws_regions=["us-east-1"],
        )

        account_a = self._make_mock_account(
            "111111111111"
        )
        account_b = self._make_mock_account(
            "222222222222"
        )

        mock_evaluator = MagicMock()
        mock_evaluator.evaluate_all.return_value = []
        mock_state_manager = MagicMock()
        mock_state_manager.query_by_account.return_value = []
        mock_resource_store = MagicMock()
        mock_resource_store.query_by_account.return_value = []
        mock_account_store = MagicMock()
        mock_account_store.list_active.return_value = [
            account_a, account_b
        ]
        mock_session_factory = MagicMock()
        mock_session_factory.get_session.return_value = (
            MagicMock()
        )

        with patch(
            "app.routers.scans.CollectionOrchestrator"
        ) as mock_orch_cls:
            mock_orch = MagicMock()
            mock_orch.collect_iam.return_value = {}
            mock_orch.collect_regional.return_value = {}
            mock_orch_cls.return_value = mock_orch

            with patch(
                "app.routers.scans.get_account_store",
                return_value=mock_account_store,
            ):
                with patch(
                    "app.routers.scans"
                    ".get_session_factory",
                    return_value=mock_session_factory,
                ):
                    _run_scan(
                        scan_id="test-scan",
                        session=MagicMock(),
                        settings=settings,
                        evaluator=mock_evaluator,
                        state_manager=mock_state_manager,
                        resource_store=mock_resource_store,
                    )

        # get_session must be called once per account
        assert (
            mock_session_factory.get_session.call_count
            == 2
        )

    def test_scan_updates_last_scanned(self):
        """After scan, each account's last_scanned is updated."""
        from app.routers.scans import _run_scan

        settings = _make_settings(
            aws_account_id="123456789012",
            aws_regions=["us-east-1"],
        )

        account_a = self._make_mock_account(
            "111111111111"
        )

        mock_evaluator = MagicMock()
        mock_evaluator.evaluate_all.return_value = []
        mock_state_manager = MagicMock()
        mock_state_manager.query_by_account.return_value = []
        mock_resource_store = MagicMock()
        mock_resource_store.query_by_account.return_value = []
        mock_account_store = MagicMock()
        mock_account_store.list_active.return_value = [
            account_a
        ]
        mock_session_factory = MagicMock()
        mock_session_factory.get_session.return_value = (
            MagicMock()
        )

        with patch(
            "app.routers.scans.CollectionOrchestrator"
        ) as mock_orch_cls:
            mock_orch = MagicMock()
            mock_orch.collect_iam.return_value = {}
            mock_orch.collect_regional.return_value = {}
            mock_orch_cls.return_value = mock_orch

            with patch(
                "app.routers.scans.get_account_store",
                return_value=mock_account_store,
            ):
                with patch(
                    "app.routers.scans"
                    ".get_session_factory",
                    return_value=mock_session_factory,
                ):
                    _run_scan(
                        scan_id="test-scan",
                        session=MagicMock(),
                        settings=settings,
                        evaluator=mock_evaluator,
                        state_manager=mock_state_manager,
                        resource_store=mock_resource_store,
                    )

        # update_last_scanned must have been called
        mock_account_store.update_last_scanned.assert_called()
        call_args = (
            mock_account_store
            .update_last_scanned
            .call_args_list[0]
        )
        # First arg should be the account_id
        assert (
            call_args[0][0] == "111111111111"
            or call_args[1].get("account_id")
            == "111111111111"
        )

    def test_scan_continues_on_account_failure(self):
        """Error in one account does not abort remaining accounts."""
        from app.routers.scans import _run_scan

        settings = _make_settings(
            aws_account_id="123456789012",
            aws_regions=["us-east-1"],
        )

        account_ok = self._make_mock_account(
            "222222222222"
        )
        account_bad = self._make_mock_account(
            "111111111111"
        )

        mock_evaluator = MagicMock()
        mock_evaluator.evaluate_all.return_value = []
        mock_state_manager = MagicMock()
        mock_state_manager.query_by_account.return_value = []
        mock_resource_store = MagicMock()
        mock_resource_store.query_by_account.return_value = []
        mock_account_store = MagicMock()
        mock_account_store.list_active.return_value = [
            account_bad, account_ok
        ]

        def _get_session_side_effect(account, **kw):
            if account.account_id == "111111111111":
                raise RuntimeError(
                    "AssumeRole failed for 111111111111"
                )
            return MagicMock()

        mock_session_factory = MagicMock()
        mock_session_factory.get_session.side_effect = (
            _get_session_side_effect
        )

        scanned = []

        def mock_orch_factory(*args, **kwargs):
            acc_id = kwargs.get("account_id", "")
            scanned.append(acc_id)
            mock_orch = MagicMock()
            mock_orch.collect_iam.return_value = {}
            mock_orch.collect_regional.return_value = {}
            return mock_orch

        with patch(
            "app.routers.scans.CollectionOrchestrator",
            side_effect=mock_orch_factory,
        ):
            with patch(
                "app.routers.scans.get_account_store",
                return_value=mock_account_store,
            ):
                with patch(
                    "app.routers.scans"
                    ".get_session_factory",
                    return_value=mock_session_factory,
                ):
                    # Must NOT raise — failure is caught internally
                    _run_scan(
                        scan_id="test-scan",
                        session=MagicMock(),
                        settings=settings,
                        evaluator=mock_evaluator,
                        state_manager=mock_state_manager,
                        resource_store=mock_resource_store,
                    )

        # account_ok must still have been scanned
        assert "222222222222" in scanned


# ---------------------------------------------------------------------------
# 5. TestAccountsAPI
# ---------------------------------------------------------------------------

class TestAccountsAPI:
    """Accounts CRUD REST API endpoints."""

    def _client(self, mock_store):
        """Build TestClient with mocked AccountStore."""
        from app.main import app
        from app.dependencies import get_account_store

        app.dependency_overrides[get_account_store] = (
            lambda: mock_store
        )
        client = TestClient(app)
        yield client
        app.dependency_overrides.clear()

    def test_create_account(self):
        """POST /api/v1/accounts returns 201 and account data."""
        from app.main import app
        from app.dependencies import (
            get_account_store,
            get_session_factory,
        )

        mock_store = MagicMock()
        mock_store.put_account.return_value = True
        mock_store.get_account.return_value = None
        mock_factory = MagicMock()
        mock_factory.get_session.return_value = (
            MagicMock()
        )

        app.dependency_overrides[get_account_store] = (
            lambda: mock_store
        )
        app.dependency_overrides[
            get_session_factory
        ] = lambda: mock_factory
        try:
            client = TestClient(app)
            payload = {
                "account_id": "111111111111",
                "account_name": "Dev Account",
                "role_arn": (
                    "arn:aws:iam::111111111111"
                    ":role/CloudLineScanner"
                ),
                "regions": ["us-east-1"],
            }
            resp = client.post(
                "/api/v1/accounts", json=payload
            )
            assert resp.status_code == 201
            data = resp.json()
            assert data["account_id"] == "111111111111"
        finally:
            app.dependency_overrides.clear()

    def test_list_accounts(self):
        """GET /api/v1/accounts returns list of accounts."""
        from app.main import app
        from app.dependencies import get_account_store
        from app.models.account import TargetAccount

        mock_store = MagicMock()
        acc = TargetAccount(
            sk="111111111111",
            account_id="111111111111",
            account_name="Dev",
            role_arn=(
                "arn:aws:iam::111111111111"
                ":role/CloudLineScanner"
            ),
        )
        mock_store.list_active.return_value = [acc]

        app.dependency_overrides[get_account_store] = (
            lambda: mock_store
        )
        try:
            client = TestClient(app)
            resp = client.get("/api/v1/accounts")
            assert resp.status_code == 200
            data = resp.json()
            assert isinstance(data, list)
            assert len(data) == 1
            assert data[0]["account_id"] == "111111111111"
        finally:
            app.dependency_overrides.clear()

    def test_get_account(self):
        """GET /api/v1/accounts/{id} returns single account."""
        from app.main import app
        from app.dependencies import get_account_store
        from app.models.account import TargetAccount

        mock_store = MagicMock()
        acc = TargetAccount(
            sk="111111111111",
            account_id="111111111111",
            account_name="Dev",
            role_arn=(
                "arn:aws:iam::111111111111"
                ":role/CloudLineScanner"
            ),
        )
        mock_store.get_account.return_value = acc

        app.dependency_overrides[get_account_store] = (
            lambda: mock_store
        )
        try:
            client = TestClient(app)
            resp = client.get(
                "/api/v1/accounts/111111111111"
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["account_id"] == "111111111111"
            assert data["account_name"] == "Dev"
        finally:
            app.dependency_overrides.clear()

    def test_delete_account(self):
        """DELETE /api/v1/accounts/{id} deactivates account."""
        from app.main import app
        from app.dependencies import get_account_store

        mock_store = MagicMock()
        mock_store.deactivate.return_value = True

        app.dependency_overrides[get_account_store] = (
            lambda: mock_store
        )
        try:
            client = TestClient(app)
            resp = client.delete(
                "/api/v1/accounts/111111111111"
            )
            assert resp.status_code == 200
            mock_store.deactivate.assert_called_once_with(
                "111111111111"
            )
        finally:
            app.dependency_overrides.clear()

    def test_get_account_not_found(self):
        """GET /api/v1/accounts/{id} returns 404 when missing."""
        from app.main import app
        from app.dependencies import get_account_store

        mock_store = MagicMock()
        mock_store.get_account.return_value = None

        app.dependency_overrides[get_account_store] = (
            lambda: mock_store
        )
        try:
            client = TestClient(app)
            resp = client.get(
                "/api/v1/accounts/999999999999"
            )
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.clear()

    def test_delete_account_store_failure(self):
        """DELETE /api/v1/accounts returns 500 on store error."""
        from app.main import app
        from app.dependencies import get_account_store

        mock_store = MagicMock()
        mock_store.deactivate.return_value = False

        app.dependency_overrides[get_account_store] = (
            lambda: mock_store
        )
        try:
            client = TestClient(app)
            resp = client.delete(
                "/api/v1/accounts/111111111111"
            )
            assert resp.status_code == 500
        finally:
            app.dependency_overrides.clear()

    # ------------------------------------------------------------------
    # POST enhancements: external_id generation + STS validation
    # ------------------------------------------------------------------

    def test_create_account_generates_external_id(self):
        """POST /api/v1/accounts auto-generates a UUID external_id."""
        from app.main import app
        from app.dependencies import (
            get_account_store,
            get_session_factory,
        )

        mock_store = MagicMock()
        mock_store.put_account.return_value = True
        mock_factory = MagicMock()
        mock_factory.get_session.return_value = (
            MagicMock()
        )

        app.dependency_overrides[get_account_store] = (
            lambda: mock_store
        )
        app.dependency_overrides[
            get_session_factory
        ] = lambda: mock_factory
        try:
            client = TestClient(app)
            # Do NOT send external_id — server must
            # generate one
            payload = {
                "account_id": "111111111111",
                "account_name": "Dev Account",
                "role_arn": (
                    "arn:aws:iam::111111111111"
                    ":role/CloudLineScanner"
                ),
            }
            resp = client.post(
                "/api/v1/accounts", json=payload
            )
            assert resp.status_code == 201
            data = resp.json()
            ext_id = data.get("external_id", "")
            # Must be a non-empty UUID (36 chars)
            assert len(ext_id) == 36
            assert ext_id.count("-") == 4
        finally:
            app.dependency_overrides.clear()

    def test_create_account_sts_validation(self):
        """POST /api/v1/accounts calls STS assume-role."""
        from app.main import app
        from app.dependencies import (
            get_account_store,
            get_session_factory,
        )

        mock_store = MagicMock()
        mock_store.put_account.return_value = True
        mock_factory = MagicMock()
        mock_factory.get_session.return_value = (
            MagicMock()
        )

        app.dependency_overrides[get_account_store] = (
            lambda: mock_store
        )
        app.dependency_overrides[
            get_session_factory
        ] = lambda: mock_factory
        try:
            client = TestClient(app)
            payload = {
                "account_id": "111111111111",
                "account_name": "Dev Account",
                "role_arn": (
                    "arn:aws:iam::111111111111"
                    ":role/CloudLineScanner"
                ),
            }
            client.post(
                "/api/v1/accounts", json=payload
            )
            # STS validation must have been called once
            mock_factory.get_session.assert_called_once()
        finally:
            app.dependency_overrides.clear()

    def test_create_account_bad_role_returns_400(self):
        """POST returns 400 when assume-role fails."""
        from app.main import app
        from app.dependencies import (
            get_account_store,
            get_session_factory,
        )

        mock_store = MagicMock()
        mock_factory = MagicMock()
        mock_factory.get_session.side_effect = (
            RuntimeError(
                "AssumeRole failed for 111111111111"
            )
        )

        app.dependency_overrides[get_account_store] = (
            lambda: mock_store
        )
        app.dependency_overrides[
            get_session_factory
        ] = lambda: mock_factory
        try:
            client = TestClient(app)
            payload = {
                "account_id": "111111111111",
                "account_name": "Bad Role",
                "role_arn": (
                    "arn:aws:iam::111111111111"
                    ":role/DoesNotExist"
                ),
            }
            resp = client.post(
                "/api/v1/accounts", json=payload
            )
            assert resp.status_code == 400
            # Account must NOT have been saved
            mock_store.put_account.assert_not_called()
        finally:
            app.dependency_overrides.clear()

    # ------------------------------------------------------------------
    # PUT endpoint: update alias/regions
    # ------------------------------------------------------------------

    def test_update_account(self):
        """PUT /api/v1/accounts/{id} updates name and regions."""
        from app.main import app
        from app.dependencies import get_account_store
        from app.models.account import TargetAccount

        mock_store = MagicMock()
        mock_store.get_account.return_value = (
            TargetAccount(
                sk="111111111111",
                account_id="111111111111",
                account_name="Dev",
                role_arn=(
                    "arn:aws:iam::111111111111"
                    ":role/CloudLineScanner"
                ),
                regions=["us-east-1"],
            )
        )
        mock_store.update_account.return_value = True
        # After update, return updated account
        updated = TargetAccount(
            sk="111111111111",
            account_id="111111111111",
            account_name="Production",
            role_arn=(
                "arn:aws:iam::111111111111"
                ":role/CloudLineScanner"
            ),
            regions=["us-east-1", "eu-west-1"],
        )
        mock_store.get_account.side_effect = [
            mock_store.get_account.return_value,
            updated,
        ]

        app.dependency_overrides[get_account_store] = (
            lambda: mock_store
        )
        try:
            client = TestClient(app)
            resp = client.put(
                "/api/v1/accounts/111111111111",
                json={
                    "account_name": "Production",
                    "regions": [
                        "us-east-1", "eu-west-1"
                    ],
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["account_name"] == "Production"
            assert "eu-west-1" in data["regions"]
            mock_store.update_account.assert_called_once()
        finally:
            app.dependency_overrides.clear()

    def test_update_account_not_found(self):
        """PUT /api/v1/accounts/{id} returns 404 for missing account."""
        from app.main import app
        from app.dependencies import get_account_store

        mock_store = MagicMock()
        mock_store.get_account.return_value = None

        app.dependency_overrides[get_account_store] = (
            lambda: mock_store
        )
        try:
            client = TestClient(app)
            resp = client.put(
                "/api/v1/accounts/999999999999",
                json={"account_name": "New Name"},
            )
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.clear()

    def test_update_account_store_failure(self):
        """PUT /api/v1/accounts returns 500 on store error."""
        from app.main import app
        from app.dependencies import get_account_store
        from app.models.account import TargetAccount

        mock_store = MagicMock()
        mock_store.get_account.return_value = (
            TargetAccount(
                sk="111111111111",
                account_id="111111111111",
                account_name="Dev",
                role_arn=(
                    "arn:aws:iam::111111111111"
                    ":role/CloudLineScanner"
                ),
            )
        )
        mock_store.update_account.return_value = False

        app.dependency_overrides[get_account_store] = (
            lambda: mock_store
        )
        try:
            client = TestClient(app)
            resp = client.put(
                "/api/v1/accounts/111111111111",
                json={"account_name": "New Name"},
            )
            assert resp.status_code == 500
        finally:
            app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 6. TestAccountStoreUpdate
# ---------------------------------------------------------------------------

class TestAccountStoreUpdate:
    """AccountStore.update_account CRUD."""

    def _make_store(self):
        from app.pipeline.account_store import (
            AccountStore,
        )
        mock_session = MagicMock()
        mock_table = MagicMock()
        mock_dynamodb = MagicMock()
        mock_dynamodb.Table.return_value = mock_table
        mock_session.resource.return_value = (
            mock_dynamodb
        )
        store = AccountStore(
            session=mock_session,
            table_name="target-accounts",
        )
        store.table = mock_table
        return store, mock_table

    def test_update_account_name(self):
        """update_account updates account_name via update_item."""
        from app.pipeline.account_store import (
            AccountStore,
        )

        store, mock_table = self._make_store()
        result = store.update_account(
            "111111111111",
            account_name="New Name",
        )
        assert result is True
        mock_table.update_item.assert_called_once()
        call_kwargs = (
            mock_table.update_item.call_args[1]
        )
        assert call_kwargs["Key"] == {
            "pk": "ACCOUNTS",
            "sk": "111111111111",
        }
        assert "account_name" in call_kwargs.get(
            "UpdateExpression", ""
        )

    def test_update_account_regions(self):
        """update_account updates regions via update_item."""
        from app.pipeline.account_store import (
            AccountStore,
        )

        store, mock_table = self._make_store()
        result = store.update_account(
            "111111111111",
            regions=["eu-west-1"],
        )
        assert result is True
        call_kwargs = (
            mock_table.update_item.call_args[1]
        )
        assert "regions" in call_kwargs.get(
            "UpdateExpression", ""
        )

    def test_update_account_both_fields(self):
        """update_account sets both name and regions."""
        from app.pipeline.account_store import (
            AccountStore,
        )

        store, mock_table = self._make_store()
        result = store.update_account(
            "111111111111",
            account_name="Prod",
            regions=["us-east-1", "eu-west-1"],
        )
        assert result is True
        call_kwargs = (
            mock_table.update_item.call_args[1]
        )
        expr = call_kwargs.get("UpdateExpression", "")
        assert "account_name" in expr
        assert "regions" in expr

    def test_update_account_noop(self):
        """update_account with no fields returns True without DynamoDB call."""
        from app.pipeline.account_store import (
            AccountStore,
        )

        store, mock_table = self._make_store()
        result = store.update_account("111111111111")
        assert result is True
        mock_table.update_item.assert_not_called()

    def test_update_account_error_returns_false(self):
        """update_account returns False on DynamoDB error."""
        from app.pipeline.account_store import (
            AccountStore,
        )

        store, mock_table = self._make_store()
        mock_table.update_item.side_effect = (
            Exception("DynamoDB error")
        )
        result = store.update_account(
            "111111111111",
            account_name="New Name",
        )
        assert result is False


# ---------------------------------------------------------------------------
# 7. TestPreflightEndpoint
# ---------------------------------------------------------------------------

class TestPreflightEndpoint:
    """POST /accounts/preflight generates setup artifacts."""

    def _post_preflight(self, payload=None):
        from app.main import app

        if payload is None:
            payload = {
                "account_id": "111111111111",
                "account_name": "Dev Account",
            }
        client = TestClient(app)
        return client.post(
            "/api/v1/accounts/preflight",
            json=payload,
        )

    def test_preflight_returns_200(self):
        """POST /accounts/preflight returns HTTP 200."""
        resp = self._post_preflight()
        assert resp.status_code == 200

    def test_preflight_returns_external_id(self):
        """Response contains external_id field."""
        resp = self._post_preflight()
        data = resp.json()
        assert "external_id" in data

    def test_preflight_external_id_is_uuid(self):
        """external_id is a valid UUID (36 chars, 4 dashes)."""
        resp = self._post_preflight()
        ext_id = resp.json()["external_id"]
        assert len(ext_id) == 36
        assert ext_id.count("-") == 4

    def test_preflight_external_id_unique_per_call(self):
        """Each preflight call returns a different external_id."""
        r1 = self._post_preflight()
        r2 = self._post_preflight()
        assert (
            r1.json()["external_id"]
            != r2.json()["external_id"]
        )

    def test_preflight_returns_bash_script(self):
        """Response contains bash_script field."""
        resp = self._post_preflight()
        data = resp.json()
        assert "bash_script" in data
        assert len(data["bash_script"]) > 0

    def test_preflight_bash_script_contains_external_id(
        self,
    ):
        """bash_script embeds the generated external_id."""
        resp = self._post_preflight()
        data = resp.json()
        assert (
            data["external_id"] in data["bash_script"]
        )

    def test_preflight_bash_script_contains_account_id(
        self,
    ):
        """bash_script references the target account_id."""
        resp = self._post_preflight(
            {
                "account_id": "999888777666",
                "account_name": "Prod",
            }
        )
        data = resp.json()
        assert "999888777666" in data["bash_script"]

    def test_preflight_returns_cf_template(self):
        """Response contains cloudformation_template field."""
        resp = self._post_preflight()
        data = resp.json()
        assert "cloudformation_template" in data
        assert len(data["cloudformation_template"]) > 0

    def test_preflight_cf_template_contains_external_id(
        self,
    ):
        """cloudformation_template embeds the external_id."""
        resp = self._post_preflight()
        data = resp.json()
        assert (
            data["external_id"]
            in data["cloudformation_template"]
        )

    def test_preflight_cf_template_is_yaml(self):
        """cloudformation_template starts with AWSTemplateFormatVersion."""
        resp = self._post_preflight()
        cf = resp.json()["cloudformation_template"]
        assert "AWSTemplateFormatVersion" in cf

    def test_preflight_does_not_require_role_arn(self):
        """Preflight only needs account_id + account_name."""
        resp = self._post_preflight(
            {
                "account_id": "111111111111",
                "account_name": "Dev",
            }
        )
        assert resp.status_code == 200

    def test_create_account_uses_provided_external_id(
        self,
    ):
        """POST /accounts with external_id uses it, not a new UUID."""
        from app.main import app
        from app.dependencies import (
            get_account_store,
            get_session_factory,
        )

        mock_store = MagicMock()
        saved = []

        def _put(acc):
            saved.append(acc)
            return True

        mock_store.put_account.side_effect = _put
        mock_factory = MagicMock()
        mock_factory.get_session.return_value = (
            MagicMock()
        )

        app.dependency_overrides[get_account_store] = (
            lambda: mock_store
        )
        app.dependency_overrides[
            get_session_factory
        ] = lambda: mock_factory
        try:
            client = TestClient(app)
            payload = {
                "account_id": "111111111111",
                "account_name": "Dev Account",
                "role_arn": (
                    "arn:aws:iam::111111111111"
                    ":role/CloudLineScanner"
                ),
                "external_id": "my-preflight-ext-id",
            }
            resp = client.post(
                "/api/v1/accounts", json=payload
            )
            assert resp.status_code == 201
            assert len(saved) == 1
            assert (
                saved[0].external_id
                == "my-preflight-ext-id"
            )
        finally:
            app.dependency_overrides.clear()

    def test_create_account_generates_external_id_if_not_provided(
        self,
    ):
        """POST /accounts without external_id generates a UUID."""
        from app.main import app
        from app.dependencies import (
            get_account_store,
            get_session_factory,
        )

        mock_store = MagicMock()
        saved = []

        def _put(acc):
            saved.append(acc)
            return True

        mock_store.put_account.side_effect = _put
        mock_factory = MagicMock()
        mock_factory.get_session.return_value = (
            MagicMock()
        )

        app.dependency_overrides[get_account_store] = (
            lambda: mock_store
        )
        app.dependency_overrides[
            get_session_factory
        ] = lambda: mock_factory
        try:
            client = TestClient(app)
            payload = {
                "account_id": "111111111111",
                "account_name": "Dev Account",
                "role_arn": (
                    "arn:aws:iam::111111111111"
                    ":role/CloudLineScanner"
                ),
            }
            resp = client.post(
                "/api/v1/accounts", json=payload
            )
            assert resp.status_code == 201
            assert len(saved) == 1
            ext = saved[0].external_id
            assert len(ext) == 36
            assert ext.count("-") == 4
        finally:
            app.dependency_overrides.clear()


class TestScanAccountScope:
    """POST /scans?account_id= scopes scan to one account."""

    def _make_mock_account(self, account_id):
        from app.models.account import TargetAccount
        return TargetAccount(
            sk=account_id,
            account_id=account_id,
            account_name=f"Account {account_id}",
            role_arn=(
                f"arn:aws:iam::{account_id}"
                ":role/CloudLineScanner"
            ),
            regions=["us-east-1"],
        )

    def test_scan_endpoint_accepts_account_id_param(self):
        """POST /scans?account_id=... returns 202."""
        from app.main import app
        from app.dependencies import (
            get_state_manager,
            get_evaluator,
            get_resource_store,
            get_macie_store,
        )
        from app.auth.dependencies import (
            require_admin_or_operator,
        )

        mock_state = MagicMock()
        mock_evaluator = MagicMock()
        mock_resource = MagicMock()
        mock_macie = MagicMock()
        mock_user = MagicMock()

        app.dependency_overrides[get_state_manager] = (
            lambda: mock_state
        )
        app.dependency_overrides[get_evaluator] = (
            lambda: mock_evaluator
        )
        app.dependency_overrides[get_resource_store] = (
            lambda: mock_resource
        )
        app.dependency_overrides[get_macie_store] = (
            lambda: mock_macie
        )
        app.dependency_overrides[
            require_admin_or_operator
        ] = lambda: mock_user

        try:
            client = TestClient(app)
            resp = client.post(
                "/api/v1/scans?account_id=111111111111"
            )
            assert resp.status_code == 202
        finally:
            app.dependency_overrides.clear()

    def test_run_scan_with_account_id_skips_other_accounts(
        self,
    ):
        """_run_scan(account_id=X) only processes account X."""
        from app.routers.scans import _run_scan

        settings = _make_settings(
            aws_account_id="123456789012",
            aws_regions=["us-east-1"],
        )

        acct_a = self._make_mock_account("111111111111")
        acct_b = self._make_mock_account("222222222222")

        mock_evaluator = MagicMock()
        mock_evaluator.evaluate_all.return_value = []
        mock_state_manager = MagicMock()
        mock_state_manager.query_by_account.return_value = []
        mock_resource_store = MagicMock()
        mock_resource_store.query_by_account.return_value = []
        mock_account_store = MagicMock()
        # Both accounts active, but only A should be scanned
        mock_account_store.list_active.return_value = [
            acct_a, acct_b
        ]
        mock_session_factory = MagicMock()
        mock_session_factory.get_session.return_value = (
            MagicMock()
        )

        scanned_accounts: list[str] = []

        with patch(
            "app.routers.scans.CollectionOrchestrator"
        ) as mock_orch_cls:
            mock_orch = MagicMock()
            mock_orch.collect_iam.return_value = {}
            mock_orch.collect_regional.return_value = {}
            mock_orch_cls.return_value = mock_orch

            with patch(
                "app.routers.scans.get_account_store",
                return_value=mock_account_store,
            ):
                with patch(
                    "app.routers.scans.get_session_factory",
                    return_value=mock_session_factory,
                ):
                    _run_scan(
                        scan_id="test-scope",
                        session=MagicMock(),
                        settings=settings,
                        evaluator=mock_evaluator,
                        state_manager=mock_state_manager,
                        resource_store=mock_resource_store,
                        account_id="111111111111",
                    )

        # Only account A's session should be requested
        calls = mock_session_factory.get_session.call_args_list
        for c in calls:
            acct_arg = c[0][0]
            assert acct_arg.account_id == "111111111111"

    def test_run_scan_without_account_id_scans_all(self):
        """_run_scan without account_id processes all accounts."""
        from app.routers.scans import _run_scan

        settings = _make_settings(
            aws_account_id="123456789012",
            aws_regions=["us-east-1"],
        )

        acct_a = self._make_mock_account("111111111111")
        acct_b = self._make_mock_account("222222222222")

        mock_evaluator = MagicMock()
        mock_evaluator.evaluate_all.return_value = []
        mock_state_manager = MagicMock()
        mock_state_manager.query_by_account.return_value = []
        mock_resource_store = MagicMock()
        mock_resource_store.query_by_account.return_value = []
        mock_account_store = MagicMock()
        mock_account_store.list_active.return_value = [
            acct_a, acct_b
        ]
        mock_session_factory = MagicMock()
        mock_session_factory.get_session.return_value = (
            MagicMock()
        )

        with patch(
            "app.routers.scans.CollectionOrchestrator"
        ) as mock_orch_cls:
            mock_orch = MagicMock()
            mock_orch.collect_iam.return_value = {}
            mock_orch.collect_regional.return_value = {}
            mock_orch_cls.return_value = mock_orch

            with patch(
                "app.routers.scans.get_account_store",
                return_value=mock_account_store,
            ):
                with patch(
                    "app.routers.scans.get_session_factory",
                    return_value=mock_session_factory,
                ):
                    _run_scan(
                        scan_id="test-all",
                        session=MagicMock(),
                        settings=settings,
                        evaluator=mock_evaluator,
                        state_manager=mock_state_manager,
                        resource_store=mock_resource_store,
                    )

        # Both accounts should have had sessions requested
        assert (
            mock_session_factory.get_session.call_count == 2
        )
