"""Tests for RiskScorer contextual risk scoring."""

from app.models.violation import (
    ComplianceMapping,
    Violation,
)
from app.pipeline.risk_scorer import (
    DEFAULT_BLAST_RADIUS,
    DEFAULT_DATA_SENSITIVITY,
    DEFAULT_EXPLOITABILITY,
    FRAMEWORK_WEIGHTS,
    SEVERITY_MAP,
    WEIGHTS,
    RiskDimensions,
    RiskScorer,
    _extract_tags,
)


def _make_violation(
    severity="high",
    check_id="ec2_no_open_ssh",
    status="alarm",
    domain="network",
    compliance=None,
):
    """Build a test Violation."""
    return Violation(
        check_id=check_id,
        status=status,
        severity=severity,
        domain=domain,
        reason="Test reason",
        compliance=(
            compliance or ComplianceMapping()
        ),
    )


scorer = RiskScorer()


class TestComputeSeverity:
    """Test severity dimension scoring."""

    def test_critical(self):
        assert scorer.compute_severity("critical") == 100

    def test_high(self):
        assert scorer.compute_severity("high") == 80

    def test_medium(self):
        assert scorer.compute_severity("medium") == 50

    def test_low(self):
        assert scorer.compute_severity("low") == 20

    def test_unknown(self):
        assert scorer.compute_severity("unknown") == 0

    def test_empty(self):
        assert scorer.compute_severity("") == 0

    def test_case_insensitive(self):
        assert scorer.compute_severity("CRITICAL") == 100
        assert scorer.compute_severity("High") == 80


class TestComputeComplianceImpact:
    """Test compliance impact dimension."""

    def test_no_compliance(self):
        assert (
            scorer.compute_compliance_impact(None) == 0
        )

    def test_empty_compliance(self):
        c = ComplianceMapping()
        assert (
            scorer.compute_compliance_impact(c) == 0
        )

    def test_single_framework(self):
        c = ComplianceMapping(cis_aws=["2.1.1"])
        assert (
            scorer.compute_compliance_impact(c) == 25
        )

    def test_two_frameworks(self):
        c = ComplianceMapping(
            cis_aws=["2.1.1"],
            pci_dss=["3.4"],
        )
        assert (
            scorer.compute_compliance_impact(c) == 45
        )

    def test_all_frameworks(self):
        c = ComplianceMapping(
            cis_aws=["2.1.1"],
            nist_800_53=["AC-1"],
            pci_dss=["3.4"],
            hipaa=["164.312"],
            soc2=["CC6.1"],
        )
        assert (
            scorer.compute_compliance_impact(c)
            == 100
        )

    def test_partial_controls(self):
        """Only frameworks with controls count."""
        c = ComplianceMapping(
            cis_aws=["2.1.1", "2.1.2"],
            nist_800_53=[],
            hipaa=["164.312"],
        )
        # cis_aws=25 + hipaa=20 = 45
        assert (
            scorer.compute_compliance_impact(c) == 45
        )


class TestComputeComposite:
    """Test weighted composite calculation."""

    def test_all_zeros(self):
        dims = RiskDimensions()
        assert scorer._compute_composite(dims) == 0

    def test_all_100(self):
        dims = RiskDimensions(
            severity=100,
            exploitability=100,
            blast_radius=100,
            data_sensitivity=100,
            compliance_impact=100,
        )
        assert scorer._compute_composite(dims) == 100

    def test_known_values(self):
        dims = RiskDimensions(
            severity=80,
            exploitability=60,
            blast_radius=40,
            data_sensitivity=20,
            compliance_impact=10,
        )
        # 80*0.30 + 60*0.25 + 40*0.20 + 20*0.15
        # + 10*0.10
        # = 24 + 15 + 8 + 3 + 1 = 51
        assert scorer._compute_composite(dims) == 51

    def test_rounding(self):
        dims = RiskDimensions(
            severity=33,
            exploitability=33,
            blast_radius=33,
            data_sensitivity=33,
            compliance_impact=33,
        )
        # 33*(0.30+0.25+0.20+0.15+0.10) = 33*1.0
        assert scorer._compute_composite(dims) == 33


class TestCategorize:
    """Test score to category mapping."""

    def test_zero(self):
        assert scorer.categorize(0) == "low"

    def test_low_boundary(self):
        assert scorer.categorize(39) == "low"

    def test_medium_low(self):
        assert scorer.categorize(40) == "medium"

    def test_medium_high(self):
        assert scorer.categorize(69) == "medium"

    def test_high_low(self):
        assert scorer.categorize(70) == "high"

    def test_high_high(self):
        assert scorer.categorize(89) == "high"

    def test_critical_low(self):
        assert scorer.categorize(90) == "critical"

    def test_critical_100(self):
        assert scorer.categorize(100) == "critical"


class TestScoreEntryPoint:
    """Test the main score() method."""

    def test_none_violation(self):
        dims = scorer.score(
            violation=None,
            resource_data={},
            service="s3",
        )
        assert dims.composite == 0
        assert dims.category == "low"

    def test_full_score(self):
        compliance = ComplianceMapping(
            cis_aws=["2.1.1"],
            nist_800_53=["AC-1"],
            pci_dss=["3.4"],
        )
        v = _make_violation(
            severity="critical",
            compliance=compliance,
        )
        dims = scorer.score(
            violation=v,
            resource_data={},
            service="ec2",
        )
        assert dims.severity == 100
        assert dims.compliance_impact == 70
        assert dims.composite > 0
        assert dims.category in (
            "low",
            "medium",
            "high",
            "critical",
        )

    def test_composite_matches_manual(self):
        """Verify composite matches the formula."""
        compliance = ComplianceMapping(
            cis_aws=["2.1.1"],
        )
        v = _make_violation(
            severity="high",
            compliance=compliance,
        )
        dims = scorer.score(
            violation=v,
            resource_data={},
            service="unknown",
        )
        expected = round(
            dims.severity * WEIGHTS["severity"]
            + dims.exploitability
            * WEIGHTS["exploitability"]
            + dims.blast_radius
            * WEIGHTS["blast_radius"]
            + dims.data_sensitivity
            * WEIGHTS["data_sensitivity"]
            + dims.compliance_impact
            * WEIGHTS["compliance_impact"]
        )
        assert dims.composite == expected

    def test_score_with_resource_data(self):
        """Score with actual resource data."""
        v = _make_violation(severity="medium")
        data = {
            "Tags": [
                {
                    "Key": "data-classification",
                    "Value": "pii",
                }
            ]
        }
        dims = scorer.score(
            violation=v,
            resource_data=data,
            service="s3",
        )
        assert dims.data_sensitivity == 100
        assert dims.severity == 50


class TestExtractTags:
    """Test tag extraction helper."""

    def test_standard_tags(self):
        data = {
            "Tags": [
                {"Key": "env", "Value": "prod"},
                {"Key": "team", "Value": "sec"},
            ]
        }
        tags = _extract_tags(data)
        assert tags["env"] == "prod"
        assert tags["team"] == "sec"

    def test_nested_tags(self):
        data = {
            "Instance": {
                "Tags": [
                    {
                        "Key": "Name",
                        "Value": "web-1",
                    }
                ]
            }
        }
        tags = _extract_tags(data)
        assert tags["Name"] == "web-1"

    def test_no_tags(self):
        data = {"BucketName": "test"}
        tags = _extract_tags(data)
        assert tags == {}

    def test_empty_data(self):
        tags = _extract_tags({})
        assert tags == {}

    def test_lowercase_tags(self):
        data = {
            "tags": [
                {"key": "env", "value": "dev"}
            ]
        }
        tags = _extract_tags(data)
        assert tags["env"] == "dev"


class TestExploitabilityS3:
    """Test S3 exploitability scoring."""

    def test_full_public_access(self):
        data = {
            "public_access_block": {
                "block_public_acls": False,
                "ignore_public_acls": False,
                "block_public_policy": False,
                "restrict_public_buckets": False,
            }
        }
        assert (
            scorer.compute_exploitability(data, "s3")
            == 100
        )

    def test_wildcard_principal(self):
        data = {
            "Policy": {
                "Statement": [
                    {"Principal": "*"}
                ]
            }
        }
        assert (
            scorer.compute_exploitability(data, "s3")
            == 90
        )

    def test_partial_public(self):
        data = {
            "public_access_block": {
                "block_public_acls": True,
                "ignore_public_acls": False,
                "block_public_policy": True,
                "restrict_public_buckets": True,
            }
        }
        assert (
            scorer.compute_exploitability(data, "s3")
            == 50
        )

    def test_no_conditions(self):
        data = {"bucket_name": "test"}
        assert (
            scorer.compute_exploitability(data, "s3")
            == DEFAULT_EXPLOITABILITY
        )


class TestExploitabilityEC2:
    """Test EC2 exploitability scoring."""

    def test_open_cidr(self):
        data = {
            "ingress_rules": [
                {"cidr": "0.0.0.0/0"}
            ]
        }
        assert (
            scorer.compute_exploitability(
                data, "ec2"
            )
            == 100
        )

    def test_public_ip(self):
        data = {
            "public_ip": "1.2.3.4",
        }
        assert (
            scorer.compute_exploitability(
                data, "ec2"
            )
            == 80
        )

    def test_imdsv1(self):
        data = {
            "metadata_options": {
                "http_tokens": "optional",
            }
        }
        assert (
            scorer.compute_exploitability(
                data, "ec2"
            )
            == 60
        )

    def test_default_ec2(self):
        data = {"instance_id": "i-123"}
        assert (
            scorer.compute_exploitability(
                data, "ec2"
            )
            == DEFAULT_EXPLOITABILITY
        )


class TestExploitabilityIAM:
    """Test IAM exploitability scoring."""

    def test_unused_access_key(self):
        data = {
            "access_keys": [
                {
                    "status": "Active",
                    "last_used_days_ago": None,
                }
            ]
        }
        assert (
            scorer.compute_exploitability(
                data, "iam"
            )
            == 70
        )

    def test_no_mfa(self):
        data = {
            "name": "admin",
            "mfa_enabled": False,
        }
        assert (
            scorer.compute_exploitability(
                data, "iam"
            )
            == 60
        )

    def test_default_iam(self):
        data = {
            "name": "admin",
            "mfa_enabled": True,
        }
        assert (
            scorer.compute_exploitability(
                data, "iam"
            )
            == DEFAULT_EXPLOITABILITY
        )


class TestExploitabilityRDS:
    """Test RDS exploitability scoring."""

    def test_publicly_accessible(self):
        data = {"publicly_accessible": True}
        assert (
            scorer.compute_exploitability(
                data, "rds"
            )
            == 100
        )

    def test_no_encryption(self):
        data = {"storage_encrypted": False}
        assert (
            scorer.compute_exploitability(
                data, "rds"
            )
            == 60
        )

    def test_default_rds(self):
        data = {
            "storage_encrypted": True,
            "publicly_accessible": False,
        }
        assert (
            scorer.compute_exploitability(
                data, "rds"
            )
            == DEFAULT_EXPLOITABILITY
        )


class TestExploitabilityLambda:
    """Test Lambda exploitability scoring."""

    def test_public_policy(self):
        data = {
            "Policy": {
                "Statement": [
                    {"Principal": "*"}
                ]
            }
        }
        assert (
            scorer.compute_exploitability(
                data, "lambda"
            )
            == 80
        )

    def test_default_lambda(self):
        data = {"FunctionName": "my-func"}
        assert (
            scorer.compute_exploitability(
                data, "lambda"
            )
            == DEFAULT_EXPLOITABILITY
        )


class TestExploitabilityGeneral:
    """Test exploitability edge cases."""

    def test_empty_data(self):
        assert (
            scorer.compute_exploitability({}, "s3")
            == DEFAULT_EXPLOITABILITY
        )

    def test_unknown_service(self):
        assert (
            scorer.compute_exploitability(
                {"key": "val"}, "unknown"
            )
            == DEFAULT_EXPLOITABILITY
        )


class TestBlastRadius:
    """Test blast radius dimension scoring."""

    def test_iam_admin_policy(self):
        data = {
            "AttachedPolicies": [
                {
                    "PolicyName":
                    "AdministratorAccess",
                }
            ]
        }
        assert (
            scorer.compute_blast_radius(data, "iam")
            == 100
        )

    def test_iam_many_entities(self):
        data = {"AttachmentCount": 15}
        assert (
            scorer.compute_blast_radius(data, "iam")
            == 80
        )

    def test_iam_some_entities(self):
        data = {"AttachmentCount": 7}
        assert (
            scorer.compute_blast_radius(data, "iam")
            == 60
        )

    def test_iam_few_entities(self):
        data = {"AttachmentCount": 2}
        assert (
            scorer.compute_blast_radius(data, "iam")
            == DEFAULT_BLAST_RADIUS
        )

    def test_ec2_many_instances(self):
        data = {"InstanceCount": 10}
        assert (
            scorer.compute_blast_radius(data, "ec2")
            == 80
        )

    def test_ec2_some_instances(self):
        data = {"InstanceCount": 3}
        assert (
            scorer.compute_blast_radius(data, "ec2")
            == 40
        )

    def test_ec2_no_instances(self):
        data = {"InstanceCount": 0}
        assert (
            scorer.compute_blast_radius(data, "ec2")
            == DEFAULT_BLAST_RADIUS
        )

    def test_s3_bucket(self):
        data = {"BucketName": "test"}
        assert (
            scorer.compute_blast_radius(data, "s3")
            == 50
        )

    def test_rds_multi_az(self):
        data = {"MultiAZ": True}
        assert (
            scorer.compute_blast_radius(data, "rds")
            == 60
        )

    def test_rds_single(self):
        data = {"MultiAZ": False}
        assert (
            scorer.compute_blast_radius(data, "rds")
            == 30
        )

    def test_lambda_isolated(self):
        data = {"FunctionName": "my-func"}
        assert (
            scorer.compute_blast_radius(
                data, "lambda"
            )
            == 20
        )

    def test_logging_service(self):
        data = {"TrailName": "main"}
        assert (
            scorer.compute_blast_radius(
                data, "cloudtrail"
            )
            == 90
        )

    def test_default_service(self):
        data = {"key": "val"}
        assert (
            scorer.compute_blast_radius(
                data, "unknown"
            )
            == DEFAULT_BLAST_RADIUS
        )

    def test_empty_data(self):
        assert (
            scorer.compute_blast_radius({}, "ec2")
            == DEFAULT_BLAST_RADIUS
        )


class TestDataSensitivity:
    """Test data sensitivity dimension scoring."""

    def test_pii_tag(self):
        data = {
            "Tags": [
                {
                    "Key": "data-classification",
                    "Value": "pii",
                }
            ]
        }
        assert (
            scorer.compute_data_sensitivity(data)
            == 100
        )

    def test_phi_tag(self):
        data = {
            "Tags": [
                {
                    "Key": "DataClassification",
                    "Value": "phi",
                }
            ]
        }
        assert (
            scorer.compute_data_sensitivity(data)
            == 90
        )

    def test_financial_tag(self):
        data = {
            "Tags": [
                {
                    "Key": "sensitivity",
                    "Value": "financial",
                }
            ]
        }
        assert (
            scorer.compute_data_sensitivity(data)
            == 80
        )

    def test_confidential_tag(self):
        data = {
            "Tags": [
                {
                    "Key": "data_classification",
                    "Value": "confidential",
                }
            ]
        }
        assert (
            scorer.compute_data_sensitivity(data)
            == 70
        )

    def test_internal_tag(self):
        data = {
            "Tags": [
                {
                    "Key": "data-classification",
                    "Value": "internal",
                }
            ]
        }
        assert (
            scorer.compute_data_sensitivity(data)
            == 40
        )

    def test_public_tag(self):
        data = {
            "Tags": [
                {
                    "Key": "data-classification",
                    "Value": "public",
                }
            ]
        }
        assert (
            scorer.compute_data_sensitivity(data)
            == 10
        )

    def test_no_tags(self):
        data = {"BucketName": "test"}
        assert (
            scorer.compute_data_sensitivity(data)
            == DEFAULT_DATA_SENSITIVITY
        )

    def test_case_insensitive_value(self):
        data = {
            "Tags": [
                {
                    "Key": "data-classification",
                    "Value": "PII",
                }
            ]
        }
        assert (
            scorer.compute_data_sensitivity(data)
            == 100
        )

    def test_nested_tags(self):
        data = {
            "DBInstance": {
                "Tags": [
                    {
                        "Key": "sensitivity",
                        "Value": "payment",
                    }
                ]
            }
        }
        assert (
            scorer.compute_data_sensitivity(data)
            == 80
        )

    def test_empty_data(self):
        assert (
            scorer.compute_data_sensitivity({})
            == DEFAULT_DATA_SENSITIVITY
        )


class TestFullScoreEndToEnd:
    """End-to-end scoring with all real dimensions."""

    def test_critical_s3_exposure(self):
        """S3 bucket fully public + PII data."""
        v = _make_violation(
            severity="critical",
            compliance=ComplianceMapping(
                cis_aws=["2.1.1"],
                pci_dss=["3.4"],
                hipaa=["164.312"],
            ),
        )
        data = {
            "public_access_block": {
                "block_public_acls": False,
                "ignore_public_acls": False,
                "block_public_policy": False,
                "restrict_public_buckets": False,
            },
            "Tags": [
                {
                    "Key": "data-classification",
                    "Value": "pii",
                }
            ],
        }
        dims = scorer.score(
            violation=v,
            resource_data=data,
            service="s3",
        )
        assert dims.severity == 100
        assert dims.exploitability == 100
        assert dims.blast_radius == 50
        assert dims.data_sensitivity == 100
        assert dims.compliance_impact == 65
        # 100*0.3+100*0.25+50*0.2+100*0.15+65*0.1
        # = 30+25+10+15+6.5 = 86.5 -> 86
        assert dims.composite == 86
        assert dims.category == "high"

    def test_low_risk_lambda(self):
        """Low severity lambda with no exposure."""
        v = _make_violation(severity="low")
        data = {"FunctionName": "my-func"}
        dims = scorer.score(
            violation=v,
            resource_data=data,
            service="lambda",
        )
        assert dims.severity == 20
        assert dims.blast_radius == 20
        assert dims.composite < 40
        assert dims.category == "low"

    def test_iam_admin_high_risk(self):
        """IAM admin with all frameworks."""
        v = _make_violation(
            severity="critical",
            compliance=ComplianceMapping(
                cis_aws=["1.1"],
                nist_800_53=["AC-1"],
                pci_dss=["8.1"],
                hipaa=["164.312"],
                soc2=["CC6.1"],
            ),
        )
        data = {
            "AttachedPolicies": [
                {"PolicyName": "AdministratorAccess"}
            ],
            "UserName": "root",
            "MFADevices": [],
        }
        dims = scorer.score(
            violation=v,
            resource_data=data,
            service="iam",
        )
        assert dims.severity == 100
        assert dims.exploitability == 60
        assert dims.blast_radius == 100
        assert dims.compliance_impact == 100
        # 100*0.3+60*0.25+100*0.2+20*0.15+100*0.1
        # = 30+15+20+3+10 = 78
        assert dims.composite == 78
        assert dims.category == "high"
