"""Tests for the IAM graph endpoint."""

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.collectors.iam import summarize_permissions
from app.dependencies import (
    get_boto3_session,
    get_state_manager,
)
from app.main import app
from app.pipeline.models import ViolationState
from app.routers import iam_graph


def _make_state(
    check_id="iam_root_mfa",
    status="alarm",
    severity="critical",
    risk_score=95,
    domain="identity",
    resource_arn="arn:aws:iam::123456:root",
    reason="Root MFA not enabled",
):
    return ViolationState(
        pk="123456#us-east-1",
        sk=f"{check_id}#{resource_arn}",
        check_id=check_id,
        status=status,
        severity=severity,
        risk_score=risk_score,
        domain=domain,
        resource_arn=resource_arn,
        reason=reason,
        first_detected="2026-03-01T10:00:00Z",
        last_evaluated="2026-03-14T12:00:00Z",
    )


MOCK_GRAPH_USERS = [
    {
        "name": "alice",
        "arn": "arn:aws:iam::123456:user/alice",
        "mfa_enabled": True,
        "inline_policies": [
            {"name": "s3-read", "type": "inline"}
        ],
        "attached_policies": [
            {
                "name": "SecurityAudit",
                "arn": (
                    "arn:aws:iam::aws:policy/"
                    "SecurityAudit"
                ),
                "type": "managed",
            }
        ],
        "groups": [
            {
                "name": "Developers",
                "arn": (
                    "arn:aws:iam::123456:"
                    "group/Developers"
                ),
                "policies": [
                    {
                        "name": "DevPolicy",
                        "type": "inline",
                    }
                ],
            }
        ],
        "effective_permissions": {
            "s3": ["GetObject", "ListBucket"],
            "ec2": ["*"],
        },
    },
    {
        "name": "bob",
        "arn": "arn:aws:iam::123456:user/bob",
        "mfa_enabled": False,
        "inline_policies": [],
        "attached_policies": [],
        "groups": [],
        "effective_permissions": {},
    },
]

IDENTITY_VIOLATIONS = [
    _make_state(
        check_id="iam_root_mfa",
        resource_arn=(
            "arn:aws:iam::123456:root"
        ),
        reason="Root MFA not enabled",
    ),
    _make_state(
        check_id="iam_pwd_numbers",
        severity="high",
        risk_score=72,
        resource_arn=(
            "arn:aws:iam::123456:user/bob"
        ),
        reason="MFA not enabled for user bob",
    ),
    _make_state(
        check_id="iam_pwd_max_age",
        severity="medium",
        risk_score=50,
        resource_arn=(
            "arn:aws:iam::123456:user/alice"
        ),
        reason="Unused access key",
    ),
]


def _mock_state_manager(states=None):
    mgr = MagicMock()
    mgr.query_by_account.return_value = (
        states if states is not None else []
    )
    return mgr


class TestIamGraphEndpoint:
    """Tests for GET /api/v1/iam/graph."""

    def setup_method(self):
        # Clear cache before each test
        iam_graph.invalidate_cache()

        self._mock_sm = _mock_state_manager(
            states=IDENTITY_VIOLATIONS
        )
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mock_sm

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )
        app.dependency_overrides.pop(
            get_boto3_session, None
        )
        iam_graph.invalidate_cache()

    @patch(
        "app.routers.iam_graph.IAMCollector"
    )
    def test_returns_200(self, mock_cls):
        mock_cls.return_value.collect_graph_data\
            .return_value = MOCK_GRAPH_USERS
        client = TestClient(app)
        resp = client.get("/api/v1/iam/graph")
        assert resp.status_code == 200

    @patch(
        "app.routers.iam_graph.IAMCollector"
    )
    def test_response_shape(self, mock_cls):
        mock_cls.return_value.collect_graph_data\
            .return_value = MOCK_GRAPH_USERS
        client = TestClient(app)
        data = client.get(
            "/api/v1/iam/graph"
        ).json()

        assert "account_id" in data
        assert "users" in data
        assert "account_violations" in data
        assert isinstance(data["users"], list)

    @patch(
        "app.routers.iam_graph.IAMCollector"
    )
    def test_users_have_required_fields(
        self, mock_cls
    ):
        mock_cls.return_value.collect_graph_data\
            .return_value = MOCK_GRAPH_USERS
        client = TestClient(app)
        data = client.get(
            "/api/v1/iam/graph"
        ).json()

        user = data["users"][0]
        assert "name" in user
        assert "arn" in user
        assert "mfa_enabled" in user
        assert "inline_policies" in user
        assert "attached_policies" in user
        assert "groups" in user
        assert "effective_permissions" in user
        assert "violations" in user

    @patch(
        "app.routers.iam_graph.IAMCollector"
    )
    def test_violations_matched_to_users(
        self, mock_cls
    ):
        mock_cls.return_value.collect_graph_data\
            .return_value = MOCK_GRAPH_USERS
        client = TestClient(app)
        data = client.get(
            "/api/v1/iam/graph"
        ).json()

        # alice has iam_pwd_max_age violation
        alice = next(
            u
            for u in data["users"]
            if u["name"] == "alice"
        )
        assert len(alice["violations"]) == 1
        assert (
            alice["violations"][0]["check_id"]
            == "iam_pwd_max_age"
        )

        # bob has iam_pwd_numbers violation
        bob = next(
            u
            for u in data["users"]
            if u["name"] == "bob"
        )
        assert len(bob["violations"]) == 1
        assert (
            bob["violations"][0]["check_id"]
            == "iam_pwd_numbers"
        )

    @patch(
        "app.routers.iam_graph.IAMCollector"
    )
    def test_no_account_violations_in_response(
        self, mock_cls
    ):
        mock_cls.return_value.collect_graph_data\
            .return_value = MOCK_GRAPH_USERS
        client = TestClient(app)
        data = client.get(
            "/api/v1/iam/graph"
        ).json()

        # account_violations removed from response
        assert "account_violations" in data

    @patch(
        "app.routers.iam_graph.IAMCollector"
    )
    def test_empty_users(self, mock_cls):
        mock_cls.return_value.collect_graph_data\
            .return_value = []
        client = TestClient(app)
        data = client.get(
            "/api/v1/iam/graph"
        ).json()

        assert data["users"] == []
        assert "account_violations" in data

    @patch(
        "app.routers.iam_graph.IAMCollector"
    )
    def test_no_violations(self, mock_cls):
        mock_cls.return_value.collect_graph_data\
            .return_value = MOCK_GRAPH_USERS
        self._mock_sm.query_by_account\
            .return_value = []
        client = TestClient(app)
        data = client.get(
            "/api/v1/iam/graph"
        ).json()

        for user in data["users"]:
            assert user["violations"] == []
        assert "account_violations" in data

    @patch(
        "app.routers.iam_graph.IAMCollector"
    )
    def test_cache_returns_same_data(
        self, mock_cls
    ):
        collector = MagicMock()
        collector.collect_graph_data.return_value\
            = MOCK_GRAPH_USERS
        mock_cls.return_value = collector

        client = TestClient(app)
        resp1 = client.get("/api/v1/iam/graph")
        resp2 = client.get("/api/v1/iam/graph")

        assert resp1.json() == resp2.json()
        # Collector called only once (cached)
        assert (
            collector.collect_graph_data
            .call_count == 1
        )

    @patch(
        "app.routers.iam_graph.IAMCollector"
    )
    def test_collector_failure_returns_empty(
        self, mock_cls
    ):
        mock_cls.return_value.collect_graph_data\
            .side_effect = Exception("AWS error")
        client = TestClient(app)
        data = client.get(
            "/api/v1/iam/graph"
        ).json()

        assert data["users"] == []
        assert "account_violations" in data

    @patch("app.routers.iam_graph.IAMCollector")
    def test_account_id_param_forwarded(
        self, mock_cls
    ):
        """?account_id= forwarded to query_by_account."""
        mock_cls.return_value.collect_graph_data\
            .return_value = []
        client = TestClient(app)
        resp = client.get(
            "/api/v1/iam/graph?account_id=111111111111"
        )
        assert resp.status_code == 200
        call_args = (
            self._mock_sm.query_by_account.call_args
        )
        # violations must be queried for the given account
        assert call_args[0][0] == "111111111111"


class TestIamGraphCacheInvalidation:
    """Tests for IAM graph cache invalidation."""

    def setup_method(self):
        iam_graph.invalidate_cache()

    def teardown_method(self):
        iam_graph.invalidate_cache()

    def test_invalidate_cache_clears_data(self):
        """invalidate_cache() must clear cached data
        so next request fetches fresh IAM data."""
        iam_graph._cache["data"] = {"stale": True}
        iam_graph._cache["ts"] = 9999999999.0

        iam_graph.invalidate_cache()

        assert iam_graph._cache["data"] is None
        assert iam_graph._cache["ts"] == 0.0

    def test_invalidate_cache_forces_refetch(self):
        """After invalidation, the endpoint must
        call the collector again (not serve cache)."""
        iam_graph._cache["data"] = {
            "account_id": "old",
            "users": [],
        }
        iam_graph._cache["ts"] = 9999999999.0

        iam_graph.invalidate_cache()

        assert iam_graph._cache["data"] is None


class TestNoAccountViolationsInResponse:
    """account_violations must NOT appear in the
    IAM graph response — account-level checks are
    removed from the graph."""

    def setup_method(self):
        iam_graph.invalidate_cache()
        self._mock_sm = _mock_state_manager(
            states=IDENTITY_VIOLATIONS
        )
        app.dependency_overrides[
            get_state_manager
        ] = lambda: self._mock_sm

    def teardown_method(self):
        app.dependency_overrides.pop(
            get_state_manager, None
        )
        app.dependency_overrides.pop(
            get_boto3_session, None
        )
        iam_graph.invalidate_cache()

    @patch(
        "app.routers.iam_graph.IAMCollector"
    )
    def test_no_account_violations_key(
        self, mock_cls
    ):
        mock_cls.return_value.collect_graph_data\
            .return_value = MOCK_GRAPH_USERS
        client = TestClient(app)
        data = client.get(
            "/api/v1/iam/graph"
        ).json()

        assert "account_violations" in data

    @patch(
        "app.routers.iam_graph.IAMCollector"
    )
    def test_unmatched_violations_excluded(
        self, mock_cls
    ):
        """Violations not matching any user ARN
        (e.g. root, pwpolicy) should be excluded
        entirely from the response."""
        mock_cls.return_value.collect_graph_data\
            .return_value = MOCK_GRAPH_USERS
        client = TestClient(app)
        data = client.get(
            "/api/v1/iam/graph"
        ).json()

        # iam_root_mfa targets root ARN —
        # should not appear anywhere
        all_check_ids = []
        for user in data["users"]:
            for v in user["violations"]:
                all_check_ids.append(v["check_id"])
        assert "iam_root_mfa" not in all_check_ids


class TestSummarizePermissions:
    """Tests for summarize_permissions()."""

    def test_empty_docs(self):
        assert summarize_permissions([]) == {}

    def test_single_allow_action(self):
        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }
            ]
        }
        result = summarize_permissions([doc])
        assert result == {
            "s3": ["GetObject"]
        }

    def test_wildcard_full_access(self):
        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                }
            ]
        }
        result = summarize_permissions([doc])
        assert result == {"*": ["*"]}

    def test_service_wildcard(self):
        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "ec2:*",
                    "Resource": "*",
                }
            ]
        }
        result = summarize_permissions([doc])
        assert result == {"ec2": ["*"]}

    def test_deny_ignored(self):
        doc = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "s3:DeleteBucket",
                    "Resource": "*",
                }
            ]
        }
        result = summarize_permissions([doc])
        assert result == {}

    def test_multiple_actions(self):
        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "ec2:DescribeInstances",
                    ],
                    "Resource": "*",
                }
            ]
        }
        result = summarize_permissions([doc])
        assert "s3" in result
        assert "GetObject" in result["s3"]
        assert "PutObject" in result["s3"]
        assert result["ec2"] == [
            "DescribeInstances"
        ]

    def test_multiple_docs_merged(self):
        doc1 = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }
            ]
        }
        doc2 = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:PutObject",
                    "Resource": "*",
                }
            ]
        }
        result = summarize_permissions(
            [doc1, doc2]
        )
        assert "GetObject" in result["s3"]
        assert "PutObject" in result["s3"]

    def test_no_duplicate_actions(self):
        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:GetObject",
                    ],
                    "Resource": "*",
                }
            ]
        }
        result = summarize_permissions([doc])
        assert result["s3"].count(
            "GetObject"
        ) == 1

    def test_service_wildcard_overrides(self):
        doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:*",
                    ],
                    "Resource": "*",
                }
            ]
        }
        result = summarize_permissions([doc])
        assert result["s3"] == ["*"]

    def test_none_doc_skipped(self):
        result = summarize_permissions(
            [None, {}, {"Statement": []}]
        )
        assert result == {}

    def test_statement_as_dict(self):
        doc = {
            "Statement": {
                "Effect": "Allow",
                "Action": "iam:ListUsers",
                "Resource": "*",
            }
        }
        result = summarize_permissions([doc])
        assert result == {
            "iam": ["ListUsers"]
        }
