"""Tests for OPA result parser."""

from app.engine.result_parser import ResultParser


class TestResultParser:
    def setup_method(self):
        self.parser = ResultParser()

    def test_parse_valid_violation(self):
        raw = {
            "check_id": "iam_root_mfa",
            "status": "alarm",
            "severity": "critical",
            "reason": "Root MFA not enabled",
            "resource": "arn:aws:iam::123:root",
            "domain": "identity",
            "compliance": {
                "cis_aws": ["1.5"],
                "nist_800_53": ["IA-2(1)"],
            },
            "remediation_id": "REM_01",
        }
        result = self.parser.parse(raw)
        assert result is not None
        assert result.check_id == "iam_root_mfa"
        assert result.status == "alarm"
        assert result.severity == "critical"
        assert result.reason == "Root MFA not enabled"
        assert result.domain == "identity"
        assert result.remediation_id == "REM_01"
        assert "1.5" in result.compliance.cis_aws

    def test_parse_minimal_result(self):
        raw = {
            "check_id": "iam_pwd_min_length",
            "status": "ok",
        }
        result = self.parser.parse(raw)
        assert result is not None
        assert result.check_id == "iam_pwd_min_length"
        assert result.status == "ok"
        assert result.severity == ""
        assert result.compliance.cis_aws == []

    def test_parse_missing_check_id(self):
        raw = {"status": "alarm", "reason": "bad"}
        result = self.parser.parse(raw)
        assert result is None

    def test_parse_empty_check_id(self):
        raw = {"check_id": "", "status": "alarm"}
        result = self.parser.parse(raw)
        assert result is None

    def test_parse_non_dict(self):
        result = self.parser.parse("not a dict")
        assert result is None

    def test_parse_none(self):
        result = self.parser.parse(None)
        assert result is None

    def test_parse_compliance_all_fields(self):
        raw = {
            "check_id": "storage_ebs_encryption",
            "status": "alarm",
            "compliance": {
                "cis_aws": ["2.2.1"],
                "nist_800_53": ["SC-28"],
                "pci_dss": ["3.4"],
                "hipaa": ["164.312"],
                "soc2": ["CC6.1"],
            },
        }
        result = self.parser.parse(raw)
        assert result is not None
        c = result.compliance
        assert c.cis_aws == ["2.2.1"]
        assert c.nist_800_53 == ["SC-28"]
        assert c.pci_dss == ["3.4"]
        assert c.hipaa == ["164.312"]
        assert c.soc2 == ["CC6.1"]

    def test_parse_defaults_status_to_error(self):
        raw = {"check_id": "unknown_99"}
        result = self.parser.parse(raw)
        assert result is not None
        assert result.status == "error"
