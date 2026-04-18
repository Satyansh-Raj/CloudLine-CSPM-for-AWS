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


# ── SOC2 mapping coverage ────────────────────────

# Valid SOC2 Trust Service Criteria prefixes
_VALID_SOC2_PREFIXES = (
    "CC",  # Common Criteria (Security)
    "A",  # Availability
    "C",  # Confidentiality
    "PI",  # Processing Integrity
    "P",  # Privacy
)


class TestSOC2MappingCoverage:
    """Every check_id must have at least one SOC2
    Trust Service Criteria mapping."""

    @pytest.fixture()
    def config(self):
        config_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "config",
            "check_compliance_mapping.json",
        )
        with open(config_path) as f:
            return json.load(f)

    def test_every_check_has_soc2(self, config):
        """No check_id should have an empty soc2
        array."""
        missing = [
            cid
            for cid, m in config["mappings"].items()
            if not m.get("soc2")
        ]
        assert missing == [], (
            f"{len(missing)} checks lack SOC2 "
            f"mappings: {missing[:10]}..."
        )

    def test_soc2_criteria_format(self, config):
        """SOC2 values must match TSC format
        (e.g. CC6.1, A1.2, C1.1)."""
        bad = {}
        for cid, m in config["mappings"].items():
            for val in m.get("soc2", []):
                if not any(
                    val.startswith(p)
                    for p in _VALID_SOC2_PREFIXES
                ):
                    bad.setdefault(cid, []).append(val)
        assert bad == {}, f"Invalid SOC2 format: {bad}"

    def test_soc2_no_duplicates(self, config):
        """No duplicate SOC2 criteria per check."""
        dupes = {}
        for cid, m in config["mappings"].items():
            vals = m.get("soc2", [])
            if len(vals) != len(set(vals)):
                dupes[cid] = vals
        assert dupes == {}, (
            f"Duplicate SOC2 entries: {dupes}"
        )

    def test_soc2_criteria_sorted(self, config):
        """SOC2 criteria should be sorted."""
        unsorted = {}
        for cid, m in config["mappings"].items():
            vals = m.get("soc2", [])
            if vals != sorted(vals):
                unsorted[cid] = vals
        assert unsorted == {}, (
            f"Unsorted SOC2 entries: "
            f"{list(unsorted.keys())[:10]}"
        )

    def test_iam_checks_have_cc6_1(self, config):
        """IAM checks must map to CC6.1
        (Logical Access)."""
        missing = []
        for cid, m in config["mappings"].items():
            if cid.startswith("iam_"):
                if "CC6.1" not in m.get("soc2", []):
                    missing.append(cid)
        assert missing == [], (
            f"IAM checks without CC6.1: {missing}"
        )

    def test_encryption_checks_have_cc6_8(
        self, config
    ):
        """Encryption checks must map to CC6.8."""
        keywords = (
            "encryption",
            "kms_encryption",
            "tls_12",
            "https",
            "deny_http",
        )
        missing = []
        for cid, m in config["mappings"].items():
            if any(k in cid for k in keywords):
                if "CC6.8" not in m.get("soc2", []):
                    missing.append(cid)
        assert missing == [], (
            f"Encryption checks without CC6.8: "
            f"{missing}"
        )

    def test_logging_checks_have_cc7_2(self, config):
        """Logging / monitoring checks must map to
        CC7.2 (Monitor System Components)."""
        prefixes = ("cloudtrail_", "cloudwatch_")
        missing = []
        for cid, m in config["mappings"].items():
            if any(cid.startswith(p) for p in prefixes):
                if "CC7.2" not in m.get("soc2", []):
                    missing.append(cid)
        assert missing == [], (
            f"Logging checks without CC7.2: {missing}"
        )

    def test_network_checks_have_cc6_6(self, config):
        """VPC / WAF checks must map to CC6.6
        (Boundary Protection)."""
        prefixes = ("vpc_", "waf_")
        missing = []
        for cid, m in config["mappings"].items():
            if any(cid.startswith(p) for p in prefixes):
                if "CC6.6" not in m.get("soc2", []):
                    missing.append(cid)
        assert missing == [], (
            f"Network checks without CC6.6: {missing}"
        )


# ── Framework version labels ──────────────────────


class TestFrameworkVersionLabels:
    """Framework display names must include version
    strings so the compliance page shows them correctly.

    Expected values:
      cis_aws  → 'CIS AWS Foundations Benchmark v1.5.0'
      pci_dss  → 'PCI DSS v4.0'
    """

    @pytest.fixture()
    def inventory_config(self):
        config_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "config",
            "compliance_mapping.json",
        )
        with open(config_path) as f:
            return json.load(f)

    def test_pci_dss_label_includes_version(
        self, inventory_config
    ):
        """framework_names.pci_dss must be
        'PCI DSS v4.0'."""
        names = inventory_config.get(
            "framework_names", {}
        )
        assert names.get("pci_dss") == "PCI DSS v4.0", (
            f"Expected 'PCI DSS v4.0', "
            f"got '{names.get('pci_dss')}'"
        )

    def test_cis_aws_label_includes_version(
        self, inventory_config
    ):
        """framework_names.cis_aws must be
        'CIS AWS Foundations Benchmark v1.5.0'."""
        names = inventory_config.get(
            "framework_names", {}
        )
        expected = (
            "CIS AWS Foundations Benchmark v1.5.0"
        )
        assert names.get("cis_aws") == expected, (
            f"Expected '{expected}', "
            f"got '{names.get('cis_aws')}'"
        )

    def test_other_labels_unchanged(
        self, inventory_config
    ):
        """NIST, HIPAA, SOC 2 labels must stay as-is."""
        names = inventory_config.get(
            "framework_names", {}
        )
        assert names.get("nist_800_53") == "NIST 800-53"
        assert names.get("hipaa") == "HIPAA"
        assert names.get("soc2") == "SOC 2"
