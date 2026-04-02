"""Tests for multi-region scanning support (F3 Batch 7).

TDD: Written BEFORE implementation — these tests MUST fail
until the implementation is in place.

Coverage:
  - Settings.aws_regions field and backward compat
  - Orchestrator collect_iam() / collect_regional() split
  - _run_scan() IAM-once + per-region ThreadPoolExecutor
"""

import concurrent.futures
from unittest.mock import MagicMock, patch

import pytest

from app.config import Settings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_settings(**kwargs) -> Settings:
    """Return a Settings instance with test defaults.

    Bypasses .env file so tests are not affected by the
    local developer environment.
    """
    defaults = dict(
        aws_account_id="123456789012",
        api_key="test-key",
        app_env="testing",
        dynamodb_endpoint="http://localhost:9730",
    )
    defaults.update(kwargs)
    return Settings(_env_file=None, **defaults)


# ---------------------------------------------------------------------------
# 1. TestConfigRegions
# ---------------------------------------------------------------------------

class TestConfigRegions:
    """Settings.aws_regions field + backward compat."""

    def test_default_regions(self):
        """aws_regions defaults to ['us-east-1']."""
        s = _make_settings()
        assert s.aws_regions == ["us-east-1"]

    def test_custom_regions_list(self):
        """Can set multiple regions directly."""
        s = _make_settings(
            aws_regions=["us-east-1", "eu-west-1", "ap-south-1"]
        )
        assert s.aws_regions == [
            "us-east-1",
            "eu-west-1",
            "ap-south-1",
        ]

    def test_aws_region_backward_compat(self):
        """aws_region property returns first region."""
        s = _make_settings(
            aws_regions=["eu-central-1", "us-west-2"]
        )
        assert s.aws_region == "eu-central-1"

    def test_aws_region_single_region(self):
        """aws_region backward compat with single region."""
        s = _make_settings(aws_regions=["ap-south-1"])
        assert s.aws_region == "ap-south-1"

    def test_aws_regions_env_var_comma_separated(
        self, monkeypatch
    ):
        """AWS_REGIONS env var parses comma-separated string."""
        monkeypatch.setenv(
            "AWS_REGIONS",
            "us-east-1,eu-west-1,ap-south-1",
        )
        # Clear any stale AWS_REGION env var
        monkeypatch.delenv("AWS_REGION", raising=False)
        s = Settings(
            _env_file=None,
            aws_account_id="123456789012",
            api_key="test-key",
            app_env="testing",
        )
        assert s.aws_regions == [
            "us-east-1",
            "eu-west-1",
            "ap-south-1",
        ]

    def test_aws_regions_single_value_env_var(
        self, monkeypatch
    ):
        """Single region in AWS_REGIONS env var works."""
        monkeypatch.setenv("AWS_REGIONS", "eu-west-2")
        monkeypatch.delenv("AWS_REGION", raising=False)
        s = Settings(
            _env_file=None,
            aws_account_id="123456789012",
            api_key="test-key",
            app_env="testing",
        )
        assert s.aws_regions == ["eu-west-2"]
        assert s.aws_region == "eu-west-2"

    def test_aws_region_singular_env_var_fallback(
        self, monkeypatch
    ):
        """AWS_REGION (singular) env var falls back to
        aws_regions when AWS_REGIONS is not set."""
        monkeypatch.setenv("AWS_REGION", "ap-south-1")
        monkeypatch.delenv(
            "AWS_REGIONS", raising=False
        )
        s = Settings(
            _env_file=None,
            aws_account_id="123456789012",
            api_key="test-key",
            app_env="testing",
        )
        assert s.aws_regions == ["ap-south-1"]
        assert s.aws_region == "ap-south-1"

    def test_aws_regions_plural_takes_precedence(
        self, monkeypatch
    ):
        """AWS_REGIONS takes precedence over AWS_REGION
        when both are set."""
        monkeypatch.setenv(
            "AWS_REGIONS", "eu-west-1,us-west-2"
        )
        monkeypatch.setenv("AWS_REGION", "ap-south-1")
        s = Settings(
            _env_file=None,
            aws_account_id="123456789012",
            api_key="test-key",
            app_env="testing",
        )
        assert s.aws_regions == [
            "eu-west-1",
            "us-west-2",
        ]


# ---------------------------------------------------------------------------
# 2. TestOrchestratorSplit
# ---------------------------------------------------------------------------

class TestOrchestratorSplit:
    """collect_iam() and collect_regional() split."""

    @pytest.fixture
    def mock_session(self):
        return MagicMock()

    @pytest.fixture
    def orch(self, mock_session):
        from app.collectors.orchestrator import (
            CollectionOrchestrator,
        )
        return CollectionOrchestrator(
            session=mock_session,
            account_id="123456789012",
            region="us-east-1",
        )

    def _patch_collector(self, orch, collector_cls):
        """Patch a collector's collect() to return
        (key, {}) without calling AWS."""
        from app.collectors.kms import KMSCollector
        for col in orch.collectors:
            if isinstance(col, collector_cls):
                cls_name = col.__class__.__name__
                if isinstance(col, KMSCollector):
                    col.collect_full = MagicMock(
                        return_value={
                            "kms": {"keys": []},
                            "secrets_manager": {
                                "secrets": []
                            },
                            "backup": {
                                "plans": [],
                                "protected_resources": [],
                            },
                        }
                    )
                else:
                    key = self._COLLECTOR_KEY.get(
                        cls_name, cls_name.lower()
                    )
                    col.collect = MagicMock(
                        return_value=(key, {})
                    )

    # Map collector class name → key returned by
    # its collect() method.
    _COLLECTOR_KEY = {
        "IAMCollector": "iam",
        "S3Collector": "s3",
        "EC2Collector": "ec2",
        "VPCCollector": "vpc",
        "RDSCollector": "rds",
        "LambdaCollector": "lambda_functions",
        "LoggingCollector": "logging",
    }

    def _stub_all_collectors(self, orch):
        """Stub every collector so no real AWS call
        is made."""
        from app.collectors.kms import KMSCollector
        from app.collectors.logging_collector import (
            LoggingCollector,
        )
        for col in orch.collectors:
            cls_name = col.__class__.__name__
            if isinstance(col, KMSCollector):
                col.collect_full = MagicMock(
                    return_value={
                        "kms": {"keys": []},
                        "secrets_manager": {
                            "secrets": []
                        },
                        "backup": {
                            "plans": [],
                            "protected_resources": [],
                        },
                    }
                )
            elif isinstance(col, LoggingCollector):
                col.collect_full = MagicMock(
                    return_value={
                        "cloudtrail": {"trails": []},
                        "cloudwatch": {
                            "alarms": [],
                            "log_groups": [],
                        },
                        "aws_config": {
                            "recorders": []
                        },
                        "guardduty": {
                            "detectors": []
                        },
                    }
                )
            else:
                key = self._COLLECTOR_KEY.get(
                    cls_name, cls_name.lower()
                )
                col.collect = MagicMock(
                    return_value=(key, {})
                )

    def test_collect_iam_only_returns_iam_key(
        self, orch
    ):
        """collect_iam() result contains 'iam' key."""
        self._stub_all_collectors(orch)
        result = orch.collect_iam()
        assert "iam" in result

    def test_collect_iam_excludes_regional_services(
        self, orch
    ):
        """collect_iam() does NOT include s3/ec2/rds etc."""
        self._stub_all_collectors(orch)
        result = orch.collect_iam()
        regional_keys = {
            "s3", "ec2", "vpc", "rds",
            "lambda_functions", "logging", "kms",
            "secrets_manager", "backup",
        }
        for key in regional_keys:
            assert key not in result, (
                f"collect_iam() should not include {key}"
            )

    def test_collect_regional_excludes_iam(
        self, orch
    ):
        """collect_regional() does NOT include 'iam'."""
        self._stub_all_collectors(orch)
        result = orch.collect_regional()
        assert "iam" not in result

    def test_collect_regional_includes_all_regional(
        self, orch
    ):
        """collect_regional() includes S3, EC2, VPC, RDS,
        Lambda, Logging, KMS."""
        self._stub_all_collectors(orch)
        result = orch.collect_regional()
        # KMS expands to kms/secrets_manager/backup
        # LoggingCollector expands to cloudtrail/cloudwatch/aws_config/guardduty
        expected = {
            "s3", "ec2", "vpc", "rds",
            "cloudtrail", "kms",
        }
        for key in expected:
            assert key in result, (
                f"collect_regional() missing {key}"
            )

    def test_collect_full_still_works(self, orch):
        """collect_full() backward compat: returns
        both IAM and regional data."""
        self._stub_all_collectors(orch)
        result = orch.collect_full()
        assert "iam" in result
        # At least one regional key present
        assert "s3" in result or "ec2" in result

    def test_collect_full_has_metadata(self, orch):
        """collect_full() still sets account_id/region."""
        self._stub_all_collectors(orch)
        result = orch.collect_full()
        assert result["account_id"] == "123456789012"
        assert result["region"] == "us-east-1"
        assert result["collection_mode"] == "full"

    def test_collect_regional_has_metadata(self, orch):
        """collect_regional() also sets region metadata."""
        self._stub_all_collectors(orch)
        result = orch.collect_regional()
        assert result["account_id"] == "123456789012"
        assert result["region"] == "us-east-1"

    def test_collect_iam_has_metadata(self, orch):
        """collect_iam() also sets account_id metadata."""
        self._stub_all_collectors(orch)
        result = orch.collect_iam()
        assert result["account_id"] == "123456789012"


# ---------------------------------------------------------------------------
# 3. TestGlobalRegionalConstants
# ---------------------------------------------------------------------------

class TestGlobalRegionalConstants:
    """GLOBAL_COLLECTORS and REGIONAL_COLLECTORS dicts."""

    def test_global_collectors_contains_iam(self):
        from app.collectors.iam import IAMCollector
        from app.collectors.orchestrator import (
            GLOBAL_COLLECTORS,
        )
        assert "iam" in GLOBAL_COLLECTORS
        assert GLOBAL_COLLECTORS["iam"] is IAMCollector

    def test_regional_collectors_excludes_iam(self):
        from app.collectors.orchestrator import (
            REGIONAL_COLLECTORS,
        )
        assert "iam" not in REGIONAL_COLLECTORS

    def test_regional_collectors_has_all_services(self):
        from app.collectors.orchestrator import (
            REGIONAL_COLLECTORS,
        )
        expected = {
            "s3", "ec2", "vpc", "rds",
            "lambda", "logging", "kms",
            "elb", "cdn", "dynamodb",
            "apigateway", "containers",
        }
        assert set(REGIONAL_COLLECTORS.keys()) == expected

    def test_collector_map_has_all_thirteen(self):
        """COLLECTOR_MAP has all 13 collectors."""
        from app.collectors.orchestrator import (
            COLLECTOR_MAP,
        )
        expected = {
            "iam", "s3", "ec2", "vpc",
            "rds", "lambda", "logging", "kms",
            "elb", "cdn", "dynamodb",
            "apigateway", "containers",
        }
        assert set(COLLECTOR_MAP.keys()) == expected


# ---------------------------------------------------------------------------
# 4. TestMultiRegionScan
# ---------------------------------------------------------------------------

class TestMultiRegionScan:
    """_run_scan() multi-region orchestration."""

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _build_mock_violation(
        self,
        check_id: str = "CHK-001",
        resource: str = "arn:aws:s3:::bucket",
        status: str = "alarm",
        severity: str = "HIGH",
        domain: str = "s3",
    ):
        v = MagicMock()
        v.check_id = check_id
        v.resource = resource
        v.status = status
        v.severity = severity
        v.domain = domain
        v.reason = "test reason"
        return v

    def _make_scan_deps(self, regions: list[str]):
        """Return a minimal set of mocked scan dependencies."""
        settings = _make_settings(
            aws_regions=regions,
            sns_alert_topic_arn="",
        )
        session = MagicMock()
        evaluator = MagicMock()
        evaluator.evaluate_all.return_value = []
        state_manager = MagicMock()
        state_manager.get_state.return_value = None
        state_manager.put_state.return_value = True
        state_manager.query_by_account.return_value = []
        state_manager.update_status.return_value = True
        resource_store = None
        return (
            settings,
            session,
            evaluator,
            state_manager,
            resource_store,
        )

    # ------------------------------------------------------------------
    # IAM collected once
    # ------------------------------------------------------------------

    def test_iam_collected_once_across_regions(self):
        """IAMCollector.collect() is called ONCE regardless
        of how many regions are scanned."""
        from app.routers.scans import _run_scan

        regions = ["us-east-1", "eu-west-1", "ap-south-1"]
        (
            settings,
            session,
            evaluator,
            state_manager,
            resource_store,
        ) = self._make_scan_deps(regions)

        iam_collect_calls = []

        def fake_collect_iam_side_effect(self_inner):
            iam_collect_calls.append(1)
            return {
                "account_id": "123456789012",
                "iam": {"users": [], "roles": []},
            }

        def fake_collect_regional_side_effect(
            self_inner,
        ):
            return {
                "account_id": "123456789012",
                "region": self_inner.region,
                "s3": {"buckets": []},
                "ec2": {"instances": []},
            }

        with patch(
            "app.collectors.orchestrator"
            ".CollectionOrchestrator.collect_iam",
            fake_collect_iam_side_effect,
        ), patch(
            "app.collectors.orchestrator"
            ".CollectionOrchestrator.collect_regional",
            fake_collect_regional_side_effect,
        ):
            _run_scan(
                "scan-001",
                session,
                settings,
                evaluator,
                state_manager,
                resource_store,
            )

        assert len(iam_collect_calls) == 1, (
            f"Expected IAM collected once, "
            f"got {len(iam_collect_calls)}"
        )

    # ------------------------------------------------------------------
    # Regional collectors called per-region
    # ------------------------------------------------------------------

    def test_regional_collectors_called_per_region(self):
        """collect_regional() is called once per region."""
        from app.routers.scans import _run_scan

        regions = ["us-east-1", "eu-west-1", "ap-south-1"]
        (
            settings,
            session,
            evaluator,
            state_manager,
            resource_store,
        ) = self._make_scan_deps(regions)

        regional_call_regions = []

        def fake_collect_iam(self_inner):
            return {
                "account_id": "123456789012",
                "iam": {"users": []},
            }

        def fake_collect_regional(self_inner):
            regional_call_regions.append(
                self_inner.region
            )
            return {
                "account_id": "123456789012",
                "region": self_inner.region,
                "s3": {"buckets": []},
            }

        with patch(
            "app.collectors.orchestrator"
            ".CollectionOrchestrator.collect_iam",
            fake_collect_iam,
        ), patch(
            "app.collectors.orchestrator"
            ".CollectionOrchestrator.collect_regional",
            fake_collect_regional,
        ):
            _run_scan(
                "scan-002",
                session,
                settings,
                evaluator,
                state_manager,
                resource_store,
            )

        assert sorted(regional_call_regions) == sorted(
            regions
        ), (
            f"Expected one collect_regional per region. "
            f"Got: {regional_call_regions}"
        )

    # ------------------------------------------------------------------
    # ThreadPoolExecutor is used
    # ------------------------------------------------------------------

    def test_thread_pool_used(self):
        """ThreadPoolExecutor.submit() is called for
        per-region parallel collection."""
        from app.routers.scans import _run_scan

        regions = ["us-east-1", "eu-west-1"]
        (
            settings,
            session,
            evaluator,
            state_manager,
            resource_store,
        ) = self._make_scan_deps(regions)

        submit_calls = []
        real_tpe = concurrent.futures.ThreadPoolExecutor

        class CapturingExecutor:
            def __init__(self, max_workers=None):
                self._real = real_tpe(
                    max_workers=max_workers
                )

            def submit(self, fn, *args, **kwargs):
                submit_calls.append((fn, args, kwargs))
                return self._real.submit(
                    fn, *args, **kwargs
                )

            def __enter__(self):
                self._real.__enter__()
                return self

            def __exit__(self, *args):
                return self._real.__exit__(*args)

        def fake_collect_iam(self_inner):
            return {
                "account_id": "123456789012",
                "iam": {"users": []},
            }

        def fake_collect_regional(self_inner):
            return {
                "account_id": "123456789012",
                "region": self_inner.region,
                "s3": {"buckets": []},
            }

        with patch(
            "concurrent.futures.ThreadPoolExecutor",
            CapturingExecutor,
        ), patch(
            "app.collectors.orchestrator"
            ".CollectionOrchestrator.collect_iam",
            fake_collect_iam,
        ), patch(
            "app.collectors.orchestrator"
            ".CollectionOrchestrator.collect_regional",
            fake_collect_regional,
        ):
            _run_scan(
                "scan-003",
                session,
                settings,
                evaluator,
                state_manager,
                resource_store,
            )

        assert len(submit_calls) == len(regions), (
            f"Expected {len(regions)} submit() calls, "
            f"got {len(submit_calls)}"
        )

    # ------------------------------------------------------------------
    # IAM data merged into each region's input_data
    # ------------------------------------------------------------------

    def test_iam_data_merged_into_each_region(self):
        """Each region's input_data passed to evaluate_all()
        contains the global IAM data."""
        from app.routers.scans import _run_scan

        regions = ["us-east-1", "eu-west-1"]
        (
            settings,
            session,
            evaluator,
            state_manager,
            resource_store,
        ) = self._make_scan_deps(regions)

        iam_payload = {
            "account_id": "123456789012",
            "iam": {
                "users": [{"name": "alice"}],
                "roles": [],
            },
        }

        def fake_collect_iam(self_inner):
            return iam_payload

        def fake_collect_regional(self_inner):
            return {
                "account_id": "123456789012",
                "region": self_inner.region,
                "s3": {"buckets": []},
            }

        with patch(
            "app.collectors.orchestrator"
            ".CollectionOrchestrator.collect_iam",
            fake_collect_iam,
        ), patch(
            "app.collectors.orchestrator"
            ".CollectionOrchestrator.collect_regional",
            fake_collect_regional,
        ):
            _run_scan(
                "scan-004",
                session,
                settings,
                evaluator,
                state_manager,
                resource_store,
            )

        # evaluate_all() was called once per region
        assert evaluator.evaluate_all.call_count == len(
            regions
        )
        for c in evaluator.evaluate_all.call_args_list:
            input_data = c[0][0]
            assert "iam" in input_data, (
                "IAM data must be merged into each "
                "region's input_data"
            )
            assert input_data["iam"] == iam_payload["iam"]

    # ------------------------------------------------------------------
    # Single-region backward compat
    # ------------------------------------------------------------------

    def test_single_region_backward_compat(self):
        """Single-region config produces valid scan result."""
        from app.routers.scans import _run_scan, _scan_results

        regions = ["us-east-1"]
        (
            settings,
            session,
            evaluator,
            state_manager,
            resource_store,
        ) = self._make_scan_deps(regions)

        def fake_collect_iam(self_inner):
            return {
                "account_id": "123456789012",
                "iam": {"users": []},
            }

        def fake_collect_regional(self_inner):
            return {
                "account_id": "123456789012",
                "region": self_inner.region,
                "s3": {"buckets": []},
            }

        scan_id = "scan-compat-001"
        with patch(
            "app.collectors.orchestrator"
            ".CollectionOrchestrator.collect_iam",
            fake_collect_iam,
        ), patch(
            "app.collectors.orchestrator"
            ".CollectionOrchestrator.collect_regional",
            fake_collect_regional,
        ):
            _run_scan(
                scan_id,
                session,
                settings,
                evaluator,
                state_manager,
                resource_store,
            )

        result = _scan_results.get(scan_id)
        assert result is not None
        assert result["status"] == "completed"
        assert "total_evaluated" in result
        assert "violations" in result

    # ------------------------------------------------------------------
    # Aggregated result includes per-region info
    # ------------------------------------------------------------------

    def test_scan_result_aggregates_regions(self):
        """Final scan result includes regions scanned."""
        from app.routers.scans import _run_scan, _scan_results

        regions = ["us-east-1", "eu-west-1", "ap-south-1"]
        (
            settings,
            session,
            evaluator,
            state_manager,
            resource_store,
        ) = self._make_scan_deps(regions)

        evaluator.evaluate_all.return_value = [
            self._build_mock_violation()
        ]

        def fake_collect_iam(self_inner):
            return {
                "account_id": "123456789012",
                "iam": {"users": []},
            }

        def fake_collect_regional(self_inner):
            return {
                "account_id": "123456789012",
                "region": self_inner.region,
                "s3": {"buckets": []},
            }

        scan_id = "scan-agg-001"
        with patch(
            "app.collectors.orchestrator"
            ".CollectionOrchestrator.collect_iam",
            fake_collect_iam,
        ), patch(
            "app.collectors.orchestrator"
            ".CollectionOrchestrator.collect_regional",
            fake_collect_regional,
        ):
            _run_scan(
                scan_id,
                session,
                settings,
                evaluator,
                state_manager,
                resource_store,
            )

        result = _scan_results.get(scan_id)
        assert result["status"] == "completed"
        assert "regions_scanned" in result
        assert sorted(result["regions_scanned"]) == sorted(
            regions
        )
        # violations are aggregated across regions
        assert result["violations"] >= 0
        assert result["total_evaluated"] >= 0

    # ------------------------------------------------------------------
    # Max workers capped
    # ------------------------------------------------------------------

    def test_max_workers_capped_at_five(self):
        """ThreadPoolExecutor max_workers <= 5."""
        from app.routers.scans import _run_scan

        regions = [
            "us-east-1", "eu-west-1", "ap-south-1",
            "us-west-2", "eu-central-1", "ap-northeast-1",
            "ca-central-1",
        ]
        (
            settings,
            session,
            evaluator,
            state_manager,
            resource_store,
        ) = self._make_scan_deps(regions)

        captured_max_workers = []
        real_tpe = concurrent.futures.ThreadPoolExecutor

        class CapturingExecutor:
            def __init__(self, max_workers=None):
                captured_max_workers.append(max_workers)
                self._real = real_tpe(
                    max_workers=max_workers
                )

            def submit(self, fn, *args, **kwargs):
                return self._real.submit(
                    fn, *args, **kwargs
                )

            def __enter__(self):
                self._real.__enter__()
                return self

            def __exit__(self, *args):
                return self._real.__exit__(*args)

        def fake_collect_iam(self_inner):
            return {
                "account_id": "123456789012",
                "iam": {"users": []},
            }

        def fake_collect_regional(self_inner):
            return {
                "account_id": "123456789012",
                "region": self_inner.region,
                "s3": {"buckets": []},
            }

        with patch(
            "concurrent.futures.ThreadPoolExecutor",
            CapturingExecutor,
        ), patch(
            "app.collectors.orchestrator"
            ".CollectionOrchestrator.collect_iam",
            fake_collect_iam,
        ), patch(
            "app.collectors.orchestrator"
            ".CollectionOrchestrator.collect_regional",
            fake_collect_regional,
        ):
            _run_scan(
                "scan-cap",
                session,
                settings,
                evaluator,
                state_manager,
                resource_store,
            )

        assert len(captured_max_workers) >= 1
        assert captured_max_workers[0] <= 5, (
            f"Expected max_workers <= 5, "
            f"got {captured_max_workers[0]}"
        )

    # ------------------------------------------------------------------
    # Region error isolation
    # ------------------------------------------------------------------

    def test_region_error_does_not_abort_other_regions(
        self,
    ):
        """If one region's collect_regional() raises,
        other regions still complete."""
        from app.routers.scans import _run_scan, _scan_results

        regions = ["us-east-1", "eu-west-1", "ap-south-1"]
        (
            settings,
            session,
            evaluator,
            state_manager,
            resource_store,
        ) = self._make_scan_deps(regions)

        call_count = {"n": 0}

        def fake_collect_iam(self_inner):
            return {
                "account_id": "123456789012",
                "iam": {"users": []},
            }

        def fake_collect_regional(self_inner):
            call_count["n"] += 1
            if self_inner.region == "eu-west-1":
                raise RuntimeError(
                    "Simulated AWS throttle"
                )
            return {
                "account_id": "123456789012",
                "region": self_inner.region,
                "s3": {"buckets": []},
            }

        scan_id = "scan-err-001"
        with patch(
            "app.collectors.orchestrator"
            ".CollectionOrchestrator.collect_iam",
            fake_collect_iam,
        ), patch(
            "app.collectors.orchestrator"
            ".CollectionOrchestrator.collect_regional",
            fake_collect_regional,
        ):
            _run_scan(
                scan_id,
                session,
                settings,
                evaluator,
                state_manager,
                resource_store,
            )

        result = _scan_results.get(scan_id)
        # Scan must NOT fail entirely just because one
        # region errored
        assert result["status"] == "completed"
        # All 3 regions were attempted
        assert call_count["n"] == len(regions)


# ---------------------------------------------------------------------------
# 6. TestRegionScopedSession
# ---------------------------------------------------------------------------

class TestRegionScopedSession:
    """_collect_region creates a session pinned to the
    target region so collectors call the correct AWS
    region API."""

    def test_collect_region_creates_regional_session(self):
        """The orchestrator receives a session whose
        region matches the target scan region."""
        from app.routers.scans import _collect_region

        captured_sessions = []

        class _CapturingOrch:
            def __init__(self, session, account_id, region):
                captured_sessions.append(
                    session.region_name
                )
                self.region = region

            def collect_regional(self):
                return {
                    "account_id": "123",
                    "region": self.region,
                }

        base_session = MagicMock()
        creds = MagicMock()
        frozen = MagicMock()
        frozen.access_key = "AK"
        frozen.secret_key = "SK"
        frozen.token = None
        creds.get_frozen_credentials.return_value = (
            frozen
        )
        base_session.get_credentials.return_value = (
            creds
        )

        with patch(
            "app.routers.scans.CollectionOrchestrator",
            _CapturingOrch,
        ), patch(
            "app.routers.scans.boto3.Session",
        ) as mock_sess_cls:
            # Make the mocked Session return an
            # object whose region_name matches
            mock_sess_cls.return_value = MagicMock(
                region_name="eu-west-1",
            )
            _collect_region(
                "eu-west-1",
                base_session,
                "123",
                {},
            )

        mock_sess_cls.assert_called_once_with(
            aws_access_key_id="AK",
            aws_secret_access_key="SK",
            aws_session_token=None,
            region_name="eu-west-1",
        )
        assert captured_sessions == ["eu-west-1"]

    def test_collect_region_two_different_regions(self):
        """Two calls with different regions produce
        sessions with the matching region_name."""
        from app.routers.scans import _collect_region

        base_session = MagicMock()
        creds = MagicMock()
        frozen = MagicMock()
        frozen.access_key = "AK"
        frozen.secret_key = "SK"
        frozen.token = None
        creds.get_frozen_credentials.return_value = (
            frozen
        )
        base_session.get_credentials.return_value = (
            creds
        )

        created_regions = []

        class _TrackingOrch:
            def __init__(self, session, account_id, region):
                self.region = region

            def collect_regional(self):
                return {
                    "account_id": "123",
                    "region": self.region,
                }

        with patch(
            "app.routers.scans.CollectionOrchestrator",
            _TrackingOrch,
        ), patch(
            "app.routers.scans.boto3.Session",
        ) as mock_sess_cls:
            def make_session(**kwargs):
                s = MagicMock()
                s.region_name = kwargs.get(
                    "region_name", ""
                )
                created_regions.append(s.region_name)
                return s

            mock_sess_cls.side_effect = make_session

            _collect_region(
                "us-east-1", base_session, "123", {},
            )
            _collect_region(
                "ap-south-1", base_session, "123", {},
            )

        assert created_regions == [
            "us-east-1",
            "ap-south-1",
        ]
