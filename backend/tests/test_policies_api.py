"""Tests for policy management endpoints."""

import textwrap
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

VALID_REGO = textwrap.dedent("""\
    package aws.identity.custom_test

    import future.keywords.if
    import future.keywords.in

    violations contains result if {
        some user in input.iam.users
        user.mfa_enabled == false
        result := {
            "check_id": "custom_test_01",
            "status": "alarm",
            "severity": "high",
            "reason": "User has no MFA",
            "resource": user.arn,
            "domain": "identity",
            "service": "iam",
            "compliance": {},
            "remediation_id": "REM_custom_01",
        }
    }
""")


@pytest.fixture
def policies_dir(tmp_path):
    """Create a temp policies directory with one
    sample policy."""
    identity = tmp_path / "identity"
    identity.mkdir()
    sample = identity / "iam.rego"
    sample.write_text(textwrap.dedent("""\
        package aws.identity.iam

        import future.keywords.if
        import future.keywords.in

        violations contains result if {
            some user in input.iam.users
            user.mfa_enabled == false
            result := {
                "check_id": "iam_01",
                "status": "alarm",
                "severity": "critical",
                "reason": sprintf(
                    "User '%s' has no MFA",
                    [user.name],
                ),
                "resource": user.arn,
                "domain": "identity",
                "service": "iam",
                "compliance": {
                    "cis_aws": ["1.5"],
                    "nist_800_53": ["IA-2(1)"],
                    "pci_dss": ["8.3.1"],
                },
                "remediation_id": "REM_01",
            }
        }

        violations contains result if {
            some user in input.iam.users
            user.access_key_age > 90
            result := {
                "check_id": "iam_02",
                "status": "alarm",
                "severity": "high",
                "reason": "Access key too old",
                "resource": user.arn,
                "domain": "identity",
                "service": "iam",
                "compliance": {},
                "remediation_id": "REM_02",
            }
        }
    """))
    # Create other domain dirs
    for d in [
        "compute",
        "data_protection",
        "network",
        "logging",
        "detection",
    ]:
        (tmp_path / d).mkdir()
    # Dirs to skip
    (tmp_path / "tests").mkdir()
    (tmp_path / "risk_scoring").mkdir()
    (tmp_path / "cross_resource").mkdir()
    return tmp_path


@pytest.fixture
def override_policy_dir(policies_dir):
    """Override settings to use temp policies dir."""
    from app.config import Settings
    from app.dependencies import get_settings

    def _override():
        return Settings(
            opa_policy_dir=str(policies_dir),
            aws_region="us-east-1",
            aws_account_id="123456789012",
            api_key="test",
            app_env="testing",
        )

    app.dependency_overrides[get_settings] = (
        _override
    )
    yield policies_dir
    app.dependency_overrides.pop(
        get_settings, None
    )


# ---- GET /policies ----


class TestListPolicies:
    def test_list_returns_policies(
        self, override_policy_dir
    ):
        resp = client.get("/api/v1/policies")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        p = data["policies"][0]
        assert p["check_id"] == "iam_01"
        assert p["domain"] == "identity"
        assert p["service"] == "iam"

    def test_list_includes_rule_count(
        self, override_policy_dir
    ):
        resp = client.get("/api/v1/policies")
        data = resp.json()
        p = data["policies"][0]
        assert p["rule_count"] == 2

    def test_list_includes_description(
        self, override_policy_dir
    ):
        resp = client.get("/api/v1/policies")
        data = resp.json()
        p = data["policies"][0]
        assert "MFA" in p["description"]

    def test_list_skips_test_files(
        self, override_policy_dir
    ):
        test_file = (
            override_policy_dir
            / "tests"
            / "iam_test.rego"
        )
        test_file.write_text(
            'package test\n"check_id": "test_99"'
        )
        resp = client.get("/api/v1/policies")
        data = resp.json()
        ids = [
            p["check_id"] for p in data["policies"]
        ]
        assert "test_99" not in ids


# ---- GET /policies/{check_id}/source ----


class TestGetPolicySource:
    def test_get_source_found(
        self, override_policy_dir
    ):
        resp = client.get(
            "/api/v1/policies/iam_01/source"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["check_id"] == "iam_01"
        assert data["filename"] == "iam.rego"
        assert "violations contains" in (
            data["rego_code"]
        )

    def test_get_source_not_found(
        self, override_policy_dir
    ):
        resp = client.get(
            "/api/v1/policies/nonexistent_99/source"
        )
        assert resp.status_code == 404

    def test_get_source_invalid_check_id(
        self, override_policy_dir
    ):
        resp = client.get(
            "/api/v1/policies/123-bad!/source"
        )
        assert resp.status_code == 400


# ---- POST /policies/raw ----


class TestCreateRawPolicy:
    def test_create_raw_success(
        self, override_policy_dir
    ):
        with patch(
            "app.routers.policies.subprocess.run"
        ) as mock_run:
            mock_run.return_value = (
                type(
                    "Result",
                    (),
                    {
                        "returncode": 0,
                        "stderr": "",
                        "stdout": "",
                    },
                )()
            )
            resp = client.post(
                "/api/v1/policies/raw",
                json={
                    "rego_code": VALID_REGO,
                    "domain": "identity",
                    "filename": "custom_test.rego",
                },
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "created"
        assert "custom_test_01" in data["check_ids"]
        assert data["filename"] == "custom_test.rego"
        # Verify file was written
        written = (
            override_policy_dir
            / "identity"
            / "custom_test.rego"
        )
        assert written.exists()
        content = written.read_text()
        assert "custom_test_01" in content

    def test_create_raw_no_package(
        self, override_policy_dir
    ):
        rego = textwrap.dedent("""\
            violations contains result if {
                result := {
                    "check_id": "bad_01",
                    "status": "alarm",
                }
            }
        """)
        resp = client.post(
            "/api/v1/policies/raw",
            json={
                "rego_code": rego,
                "domain": "identity",
                "filename": "bad.rego",
            },
        )
        assert resp.status_code == 400
        assert "package" in resp.json()["detail"].lower()

    def test_create_raw_no_violations(
        self, override_policy_dir
    ):
        rego = textwrap.dedent("""\
            package aws.identity.empty

            allow = true
        """)
        resp = client.post(
            "/api/v1/policies/raw",
            json={
                "rego_code": rego,
                "domain": "identity",
                "filename": "empty.rego",
            },
        )
        assert resp.status_code == 400
        assert "violations" in resp.json()["detail"]

    def test_create_raw_no_check_id(
        self, override_policy_dir
    ):
        rego = textwrap.dedent("""\
            package aws.identity.noid

            violations contains result if {
                result := {
                    "status": "alarm",
                }
            }
        """)
        resp = client.post(
            "/api/v1/policies/raw",
            json={
                "rego_code": rego,
                "domain": "identity",
                "filename": "noid.rego",
            },
        )
        assert resp.status_code == 400
        assert "check_id" in resp.json()["detail"]

    def test_create_raw_duplicate_check_id(
        self, override_policy_dir
    ):
        rego = VALID_REGO.replace(
            "custom_test_01", "iam_01"
        )
        with patch(
            "app.routers.policies.subprocess.run"
        ) as mock_run:
            mock_run.return_value = type(
                "Result",
                (),
                {
                    "returncode": 0,
                    "stderr": "",
                    "stdout": "",
                },
            )()
            resp = client.post(
                "/api/v1/policies/raw",
                json={
                    "rego_code": rego,
                    "domain": "identity",
                    "filename": "dup.rego",
                },
            )
        assert resp.status_code == 409
        assert "iam_01" in resp.json()["detail"]

    def test_create_raw_file_exists(
        self, override_policy_dir
    ):
        # Pre-create file
        existing = (
            override_policy_dir
            / "identity"
            / "existing.rego"
        )
        existing.write_text("placeholder")
        with patch(
            "app.routers.policies.subprocess.run"
        ) as mock_run:
            mock_run.return_value = type(
                "Result",
                (),
                {
                    "returncode": 0,
                    "stderr": "",
                    "stdout": "",
                },
            )()
            resp = client.post(
                "/api/v1/policies/raw",
                json={
                    "rego_code": VALID_REGO,
                    "domain": "identity",
                    "filename": "existing.rego",
                },
            )
        assert resp.status_code == 409

    def test_create_raw_invalid_filename(
        self, override_policy_dir
    ):
        resp = client.post(
            "/api/v1/policies/raw",
            json={
                "rego_code": VALID_REGO,
                "domain": "identity",
                "filename": "../evil.rego",
            },
        )
        assert resp.status_code == 422

    def test_create_raw_opa_syntax_error(
        self, override_policy_dir
    ):
        rego = textwrap.dedent("""\
            package aws.identity.bad_syntax

            violations contains result if {
                result := {
                    "check_id": "syntax_err_01",
                    "status": "alarm",
                }
            }
        """)
        with patch(
            "app.routers.policies.subprocess.run"
        ) as mock_run:
            mock_run.return_value = type(
                "Result",
                (),
                {
                    "returncode": 1,
                    "stderr": "1 error occurred",
                    "stdout": "",
                },
            )()
            resp = client.post(
                "/api/v1/policies/raw",
                json={
                    "rego_code": rego,
                    "domain": "identity",
                    "filename": "bad_syntax.rego",
                },
            )
        assert resp.status_code == 400
        assert "error" in resp.json()[
            "detail"
        ].lower()

    def test_create_raw_opa_not_found_skips(
        self, override_policy_dir
    ):
        """When OPA binary is missing, validation
        passes (skips opa check)."""
        with patch(
            "app.routers.policies.subprocess.run",
            side_effect=FileNotFoundError,
        ):
            resp = client.post(
                "/api/v1/policies/raw",
                json={
                    "rego_code": VALID_REGO,
                    "domain": "identity",
                    "filename": "no_opa.rego",
                },
            )
        assert resp.status_code == 201


# ---- DELETE /policies/{check_id} ----


class TestDeletePolicy:
    def test_delete_existing(
        self, override_policy_dir
    ):
        # Create a disposable policy first
        disposable = (
            override_policy_dir
            / "identity"
            / "disposable.rego"
        )
        disposable.write_text(textwrap.dedent("""\
            package aws.identity.disposable

            violations contains result if {
                result := {
                    "check_id": "disp_01",
                    "status": "alarm",
                    "severity": "low",
                    "reason": "test",
                    "resource": "",
                    "domain": "identity",
                }
            }
        """))
        resp = client.delete(
            "/api/v1/policies/disp_01"
        )
        assert resp.status_code == 200
        assert not disposable.exists()

    def test_delete_not_found(
        self, override_policy_dir
    ):
        resp = client.delete(
            "/api/v1/policies/nope_99"
        )
        assert resp.status_code == 404
