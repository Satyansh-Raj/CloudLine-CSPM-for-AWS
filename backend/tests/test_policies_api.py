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
                "check_id": "iam_root_mfa",
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
                "check_id": "iam_pwd_min_length",
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
        assert p["check_id"] == "iam_root_mfa"
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
            "/api/v1/policies/iam_root_mfa/source"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["check_id"] == "iam_root_mfa"
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
        assert data["is_custom"] is True
        # File must be in custom subtree
        written = (
            override_policy_dir
            / "custom"
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
            "custom_test_01", "iam_root_mfa"
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
        assert "iam_root_mfa" in resp.json()["detail"]

    def test_create_raw_file_exists(
        self, override_policy_dir
    ):
        # Pre-create file in the custom subtree
        # (where new policies are now written)
        custom_id = (
            override_policy_dir
            / "custom"
            / "identity"
        )
        custom_id.mkdir(parents=True, exist_ok=True)
        existing = custom_id / "existing.rego"
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
        # Create a disposable policy in custom/ subtree
        custom_id = (
            override_policy_dir / "custom" / "identity"
        )
        custom_id.mkdir(parents=True, exist_ok=True)
        disposable = custom_id / "disposable.rego"
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


# ---- Batch 1: Storage Classifier Foundation ----


class TestStorageClassifier:
    def test_is_custom_path_returns_true_for_custom_subtree(
        self,
    ):
        from app.routers.policies import _is_custom_path

        assert _is_custom_path(
            "custom/identity/foo.rego"
        ) is True

    def test_is_custom_path_returns_false_for_builtin_subtree(
        self,
    ):
        from app.routers.policies import _is_custom_path

        assert _is_custom_path("identity/iam.rego") is False

    def test_is_custom_path_handles_relative_and_absolute_paths(
        self,
    ):
        from pathlib import Path

        from app.routers.policies import _is_custom_path

        assert (
            _is_custom_path(
                Path("custom/identity/foo.rego")
            )
            is True
        )
        assert (
            _is_custom_path(
                Path("/policies/custom/identity/foo.rego")
            )
            is True
        )
        assert (
            _is_custom_path(
                Path("/policies/identity/iam.rego")
            )
            is False
        )

    def test_target_dir_routes_custom_writes_to_custom_subdir(
        self, tmp_path
    ):
        from app.routers.policies import _target_dir

        result = _target_dir(
            tmp_path, "identity", is_custom=True
        )
        assert result == tmp_path / "custom" / "identity"

    def test_target_dir_routes_builtin_to_domain_root(
        self, tmp_path
    ):
        from app.routers.policies import _target_dir

        result = _target_dir(
            tmp_path, "identity", is_custom=False
        )
        assert result == tmp_path / "identity"

    def test_policy_info_includes_is_custom_field_default_false(
        self,
    ):
        from app.routers.policies import PolicyInfo

        info = PolicyInfo(
            filename="test.rego",
            package_name="aws.test",
            check_id="test_01",
            domain="identity",
            service="iam",
            severity="high",
            path="identity/test.rego",
        )
        assert info.is_custom is False

    def test_extract_metadata_sets_is_custom_true_for_custom_path(
        self, tmp_path
    ):
        from app.routers.policies import _extract_metadata

        custom_dir = tmp_path / "custom" / "identity"
        custom_dir.mkdir(parents=True)
        rego = custom_dir / "my_check.rego"
        rego.write_text(
            textwrap.dedent("""\
            package aws.custom.identity.my_check

            violations contains result if {
                result := {
                    "check_id": "custom_check_01",
                    "status": "alarm",
                    "severity": "high",
                    "reason": "Custom check",
                    "resource": "",
                    "domain": "identity",
                    "service": "iam",
                }
            }
        """)
        )
        info = _extract_metadata(rego, tmp_path)
        assert info is not None
        assert info.is_custom is True

    def test_list_policies_returns_is_custom_in_response(
        self, override_policy_dir
    ):
        resp = client.get("/api/v1/policies")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["policies"]) > 0
        p = data["policies"][0]
        assert "is_custom" in p
        assert p["is_custom"] is False


# ---- Batch 2: Write-path routing + delete guard ----

_MOCK_OPA_OK = type(
    "Result",
    (),
    {"returncode": 0, "stderr": "", "stdout": ""},
)()

_CREATE_POLICY_BODY = {
    "check_id": "test_b2_custom",
    "domain": "identity",
    "severity": "high",
    "description": "Batch two write path test",
    "input_field": "iam",
    "resource_pattern": "input.iam.users[_]",
    "remediation_id": "REM_b2_01",
}

_CUSTOM_REGO = textwrap.dedent("""\
    package aws.custom.identity.custom_del

    violations contains result if {
        result := {
            "check_id": "custom_del_01",
            "status": "alarm",
            "severity": "low",
            "reason": "Custom delete test",
            "resource": "",
            "domain": "identity",
            "service": "iam",
        }
    }
""")


class TestWritePathAndDeleteGuard:
    def test_create_policy_writes_to_custom_subdir(
        self, override_policy_dir
    ):
        resp = client.post(
            "/api/v1/policies",
            json=_CREATE_POLICY_BODY,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["path"].startswith("custom/")
        assert (override_policy_dir / data["path"]).exists()

    def test_create_raw_policy_writes_to_custom_subdir(
        self, override_policy_dir
    ):
        with patch(
            "app.routers.policies.subprocess.run",
            return_value=_MOCK_OPA_OK,
        ):
            resp = client.post(
                "/api/v1/policies/raw",
                json={
                    "rego_code": VALID_REGO,
                    "domain": "identity",
                    "filename": "raw_b2_test.rego",
                },
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["path"].startswith("custom/")
        assert (override_policy_dir / data["path"]).exists()

    def test_create_policy_returns_is_custom_true(
        self, override_policy_dir
    ):
        body = dict(_CREATE_POLICY_BODY)
        body["check_id"] = "test_b2_flag"
        resp = client.post(
            "/api/v1/policies",
            json=body,
        )
        assert resp.status_code == 201
        assert resp.json()["is_custom"] is True

    def test_create_policy_rejects_duplicate_across_trees(
        self, override_policy_dir
    ):
        # iam_root_mfa lives in identity/ (built-in)
        resp = client.post(
            "/api/v1/policies",
            json={
                "check_id": "iam_root_mfa",
                "domain": "identity",
                "severity": "critical",
                "description": "Duplicate of builtin policy",
                "input_field": "iam",
                "resource_pattern": "input.iam.users[_]",
                "remediation_id": "REM_dup_01",
            },
        )
        assert resp.status_code == 409
        assert "iam_root_mfa" in resp.json()["detail"]

    def test_delete_builtin_policy_returns_403(
        self, override_policy_dir
    ):
        resp = client.delete(
            "/api/v1/policies/iam_root_mfa"
        )
        assert resp.status_code == 403

    def test_delete_custom_policy_succeeds(
        self, override_policy_dir
    ):
        custom_dir = (
            override_policy_dir / "custom" / "identity"
        )
        custom_dir.mkdir(parents=True, exist_ok=True)
        custom_file = custom_dir / "custom_del.rego"
        custom_file.write_text(_CUSTOM_REGO)
        resp = client.delete(
            "/api/v1/policies/custom_del_01"
        )
        assert resp.status_code == 200
        assert not custom_file.exists()

    def test_delete_403_message_does_not_leak_filesystem_path(
        self, override_policy_dir
    ):
        resp = client.delete(
            "/api/v1/policies/iam_root_mfa"
        )
        assert resp.status_code == 403
        detail = resp.json()["detail"]
        assert str(override_policy_dir) not in detail
        # Must not expose raw filesystem separators
        assert "/" not in detail

    def test_opa_loads_policies_from_both_trees(
        self, override_policy_dir
    ):
        custom_dir = (
            override_policy_dir / "custom" / "identity"
        )
        custom_dir.mkdir(parents=True, exist_ok=True)
        (custom_dir / "custom_policy.rego").write_text(
            textwrap.dedent("""\
            package aws.custom.identity.custom_policy

            violations contains result if {
                result := {
                    "check_id": "custom_policy_01",
                    "status": "alarm",
                    "severity": "medium",
                    "reason": "Custom policy",
                    "resource": "",
                    "domain": "identity",
                    "service": "iam",
                }
            }
        """)
        )
        resp = client.get("/api/v1/policies")
        assert resp.status_code == 200
        ids = [
            p["check_id"]
            for p in resp.json()["policies"]
        ]
        assert "iam_root_mfa" in ids
        assert "custom_policy_01" in ids


# ---- Batch 3: Listing API filter surface ----

_CUSTOM_POLICY_REGO = textwrap.dedent("""\
    package aws.custom.identity.b3_custom

    violations contains result if {
        result := {
            "check_id": "b3_custom_01",
            "status": "alarm",
            "severity": "medium",
            "reason": "Batch 3 custom policy",
            "resource": "",
            "domain": "identity",
            "service": "iam",
        }
    }
""")


@pytest.fixture
def dual_tree_dir(policies_dir):
    """Add a custom policy alongside the builtin one."""
    custom_id = policies_dir / "custom" / "identity"
    custom_id.mkdir(parents=True, exist_ok=True)
    (custom_id / "b3_custom.rego").write_text(
        _CUSTOM_POLICY_REGO
    )
    return policies_dir


@pytest.fixture
def override_dual_tree(dual_tree_dir):
    """Settings override pointing at dual-tree dir."""
    from app.config import Settings
    from app.dependencies import get_settings

    def _override():
        return Settings(
            opa_policy_dir=str(dual_tree_dir),
            aws_region="us-east-1",
            aws_account_id="123456789012",
            api_key="test",
            app_env="testing",
        )

    app.dependency_overrides[get_settings] = _override
    yield dual_tree_dir
    app.dependency_overrides.pop(get_settings, None)


class TestListFilter:
    def test_list_policies_no_filter_returns_both_trees(
        self, override_dual_tree
    ):
        resp = client.get("/api/v1/policies")
        assert resp.status_code == 200
        ids = [
            p["check_id"]
            for p in resp.json()["policies"]
        ]
        assert "iam_root_mfa" in ids
        assert "b3_custom_01" in ids

    def test_list_policies_custom_true_returns_only_custom(
        self, override_dual_tree
    ):
        resp = client.get(
            "/api/v1/policies?custom=true"
        )
        assert resp.status_code == 200
        policies = resp.json()["policies"]
        assert all(p["is_custom"] for p in policies)
        ids = [p["check_id"] for p in policies]
        assert "b3_custom_01" in ids
        assert "iam_root_mfa" not in ids

    def test_list_policies_custom_false_returns_only_builtin(
        self, override_dual_tree
    ):
        resp = client.get(
            "/api/v1/policies?custom=false"
        )
        assert resp.status_code == 200
        policies = resp.json()["policies"]
        assert all(not p["is_custom"] for p in policies)
        ids = [p["check_id"] for p in policies]
        assert "iam_root_mfa" in ids
        assert "b3_custom_01" not in ids

    def test_list_policies_invalid_custom_value_returns_422(
        self, override_dual_tree
    ):
        resp = client.get(
            "/api/v1/policies?custom=notabool"
        )
        assert resp.status_code == 422

    def test_get_policy_source_includes_is_custom_field(
        self, override_dual_tree
    ):
        resp = client.get(
            "/api/v1/policies/iam_root_mfa/source"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "is_custom" in data
        assert data["is_custom"] is False

    def test_get_policy_source_is_custom_true_for_custom_policy(
        self, override_dual_tree
    ):
        resp = client.get(
            "/api/v1/policies/b3_custom_01/source"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_custom"] is True
