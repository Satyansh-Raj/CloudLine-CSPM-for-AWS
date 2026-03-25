"""Tests for the dynamic compliance mapping registry."""

import json
import os
import tempfile

import pytest

from app.compliance.mappings import (
    ComplianceMappingRegistry,
    get_registry,
)
from app.models.violation import ComplianceMapping


# ── Registry loading ──────────────────────────────


class TestRegistryLoading:
    """Test loading mappings from JSON config."""

    def _write_config(self, data, path):
        with open(path, "w") as f:
            json.dump(data, f)

    def test_loads_from_json_file(self, tmp_path):
        cfg = tmp_path / "mappings.json"
        self._write_config(
            {
                "version": "1.0.0",
                "frameworks": ["cis_aws"],
                "mappings": {
                    "iam_root_mfa": {
                        "cis_aws": ["1.5"],
                        "nist_800_53": [],
                        "pci_dss": [],
                        "hipaa": [],
                        "soc2": [],
                        "owasp": [],
                    },
                },
            },
            str(cfg),
        )
        reg = ComplianceMappingRegistry(str(cfg))
        assert reg.get("iam_root_mfa") is not None

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            ComplianceMappingRegistry(
                "/nonexistent/path.json"
            )

    def test_invalid_json_raises(self, tmp_path):
        cfg = tmp_path / "bad.json"
        cfg.write_text("{invalid")
        with pytest.raises(json.JSONDecodeError):
            ComplianceMappingRegistry(str(cfg))


# ── Mapping lookup ────────────────────────────────


class TestMappingLookup:
    """Test check_id → ComplianceMapping lookups."""

    @pytest.fixture()
    def registry(self, tmp_path):
        cfg = tmp_path / "mappings.json"
        data = {
            "version": "1.0.0",
            "frameworks": [
                "cis_aws",
                "nist_800_53",
                "pci_dss",
                "hipaa",
                "soc2",
                "owasp",
            ],
            "mappings": {
                "iam_root_mfa": {
                    "cis_aws": ["1.5"],
                    "nist_800_53": ["IA-2(1)"],
                    "pci_dss": ["8.3.1"],
                    "hipaa": [],
                    "soc2": [],
                    "owasp": [],
                },
                "s3_encryption": {
                    "cis_aws": ["2.1.1"],
                    "nist_800_53": ["SC-28"],
                    "pci_dss": ["3.5.1"],
                    "hipaa": [
                        "164.312(a)(2)(iv)"
                    ],
                    "soc2": [],
                    "owasp": [],
                },
            },
        }
        with open(str(cfg), "w") as f:
            json.dump(data, f)
        return ComplianceMappingRegistry(str(cfg))

    def test_get_returns_compliance_mapping(
        self, registry
    ):
        mapping = registry.get("iam_root_mfa")
        assert isinstance(mapping, ComplianceMapping)
        assert mapping.cis_aws == ["1.5"]
        assert mapping.nist_800_53 == ["IA-2(1)"]
        assert mapping.pci_dss == ["8.3.1"]

    def test_get_unknown_returns_empty(self, registry):
        mapping = registry.get("nonexistent_99")
        assert isinstance(mapping, ComplianceMapping)
        assert mapping.cis_aws == []
        assert mapping.nist_800_53 == []

    def test_hipaa_mapping(self, registry):
        mapping = registry.get("s3_encryption")
        assert mapping.hipaa == [
            "164.312(a)(2)(iv)"
        ]

    def test_contains(self, registry):
        assert registry.contains("iam_root_mfa") is True
        assert (
            registry.contains("fake_99") is False
        )

    def test_check_ids_list(self, registry):
        ids = registry.check_ids()
        assert "iam_root_mfa" in ids
        assert "s3_encryption" in ids
        assert len(ids) == 2

    def test_frameworks_list(self, registry):
        fws = registry.frameworks()
        assert "cis_aws" in fws


# ── Production config ─────────────────────────────


class TestProductionConfig:
    """Test the real mapping file loads correctly."""

    def test_production_file_loads(self):
        config_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "config",
            "check_compliance_mapping.json",
        )
        if not os.path.exists(config_path):
            pytest.skip(
                "Production config not yet created"
            )
        reg = ComplianceMappingRegistry(config_path)
        # Should have 280+ check_ids
        assert len(reg.check_ids()) >= 280

    def test_get_registry_singleton(self):
        config_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "config",
            "check_compliance_mapping.json",
        )
        if not os.path.exists(config_path):
            pytest.skip(
                "Production config not yet created"
            )
        r1 = get_registry()
        r2 = get_registry()
        assert r1 is r2
