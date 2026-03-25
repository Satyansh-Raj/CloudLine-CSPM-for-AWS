"""Tests for the ResourceClassifier orchestrator."""

import pytest

from app.inventory.classifier import (
    ResourceClassifier,
    extract_env_owner,
)
from app.models.aws_input import (
    EC2Data,
    EC2Instance,
    EBSVolume,
    InstanceRole,
    KMSData,
    KMSKey,
    LambdaData,
    LambdaFunction,
    LambdaVPCConfig,
    PublicAccessBlock,
    RDSData,
    RDSInstance,
    S3Bucket,
    S3Data,
    Secret,
    SecretsManagerData,
    SecurityGroup,
    UnifiedAWSInput,
    VPC,
    VPCData,
)
from app.models.resource import ResourceRecord

ACCOUNT = "123456789012"
REGION = "us-east-1"


def _make_input(**kwargs):
    """Build a minimal UnifiedAWSInput."""
    defaults = {
        "account_id": ACCOUNT,
        "region": REGION,
        "collection_timestamp": "2026-03-18T00:00:00Z",
    }
    defaults.update(kwargs)
    return UnifiedAWSInput(**defaults)


# ── Tag extraction ─────────────────────────────────


class TestExtractEnvOwner:
    """Test tag-based environment and owner."""

    def test_env_from_environment_tag(self):
        env, _ = extract_env_owner(
            {"Environment": "production"}
        )
        assert env == "prod"

    def test_env_from_env_tag(self):
        env, _ = extract_env_owner({"env": "staging"})
        assert env == "staging"

    def test_env_normalizes_production(self):
        env, _ = extract_env_owner(
            {"Environment": "Production"}
        )
        assert env == "prod"

    def test_env_normalizes_development(self):
        env, _ = extract_env_owner(
            {"Environment": "development"}
        )
        assert env == "dev"

    def test_owner_from_owner_tag(self):
        _, owner = extract_env_owner(
            {"Owner": "team-security"}
        )
        assert owner == "team-security"

    def test_owner_from_team_tag(self):
        _, owner = extract_env_owner(
            {"Team": "platform"}
        )
        assert owner == "platform"

    def test_empty_tags(self):
        env, owner = extract_env_owner({})
        assert env == "unknown"
        assert owner == ""

    def test_no_matching_tags(self):
        env, owner = extract_env_owner(
            {"Name": "res", "Version": "1"}
        )
        assert env == "unknown"
        assert owner == ""


# ── EC2 classification ─────────────────────────────


class TestClassifyEC2:
    """Test EC2 instance classification."""

    def test_basic_ec2(self):
        data = _make_input(
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-abc",
                        arn=(
                            f"arn:aws:ec2:{REGION}"
                            f":{ACCOUNT}:instance/i-abc"
                        ),
                        tags={
                            "Environment": "prod",
                            "Owner": "devops",
                        },
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        ec2 = [
            r for r in recs
            if r.resource_type == "ec2_instance"
        ]
        assert len(ec2) == 1
        r = ec2[0]
        assert r.technology_category == "compute"
        assert r.service == "ec2"
        assert r.account_id == ACCOUNT
        assert r.region == REGION
        assert r.is_active is True
        assert r.environment == "prod"
        assert r.owner == "devops"
        assert r.tags == {
            "Environment": "prod",
            "Owner": "devops",
        }

    def test_ec2_relationships(self):
        data = _make_input(
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-1",
                        arn=(
                            f"arn:aws:ec2:{REGION}"
                            f":{ACCOUNT}:instance/i-1"
                        ),
                        vpc_id="vpc-1",
                        security_groups=["sg-1", "sg-2"],
                        iam_role=InstanceRole(
                            role_name="WebRole",
                            role_arn=(
                                "arn:aws:iam::123:role"
                                "/WebRole"
                            ),
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        ec2 = [
            r for r in recs
            if r.resource_type == "ec2_instance"
        ]
        r = ec2[0]
        assert r.belongs_to == "vpc-1"
        assert r.connected_to == ["sg-1", "sg-2"]
        assert r.managed_by == (
            "arn:aws:iam::123:role/WebRole"
        )


# ── S3 classification ──────────────────────────────


class TestClassifyS3:
    """Test S3 bucket classification."""

    def test_private_bucket(self):
        data = _make_input(
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="secure-bkt",
                        arn="arn:aws:s3:::secure-bkt",
                        public_access_block=(
                            PublicAccessBlock(
                                block_public_acls=True,
                                block_public_policy=True,
                                ignore_public_acls=True,
                                restrict_public_buckets=True,
                            )
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        s3 = [
            r for r in recs
            if r.resource_type == "s3_bucket"
        ]
        assert s3[0].exposure == "private"

    def test_public_bucket(self):
        data = _make_input(
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="pub-bkt",
                        arn="arn:aws:s3:::pub-bkt",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        s3 = [
            r for r in recs
            if r.resource_type == "s3_bucket"
        ]
        assert s3[0].exposure == "internet"
        assert s3[0].technology_category == "storage"

    def test_s3_uses_bucket_region_not_scanner_region(self):
        """S3 buckets are global — record must use the
        bucket's true region, not the scanner loop region."""
        data = _make_input(
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="eu-bkt",
                        arn="arn:aws:s3:::eu-bkt",
                        region="eu-north-1",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        s3 = [
            r for r in recs
            if r.resource_type == "s3_bucket"
        ]
        assert s3[0].region == "eu-north-1"
        assert s3[0].pk == f"{ACCOUNT}#eu-north-1"

    def test_s3_falls_back_to_scanner_region(self):
        """When bucket has no region (empty string),
        fall back to the scanner's loop region."""
        data = _make_input(
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="legacy-bkt",
                        arn="arn:aws:s3:::legacy-bkt",
                        region="",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        s3 = [
            r for r in recs
            if r.resource_type == "s3_bucket"
        ]
        assert s3[0].region == REGION

    def test_s3_name_is_bucket_name(self):
        data = _make_input(
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="my-data",
                        arn="arn:aws:s3:::my-data",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        s3 = [
            r for r in recs
            if r.resource_type == "s3_bucket"
        ]
        assert s3[0].resource_name == "my-data"


# ── RDS classification ─────────────────────────────


class TestClassifyRDS:
    """Test RDS instance classification."""

    def test_public_rds(self):
        data = _make_input(
            rds=RDSData(
                db_instances=[
                    RDSInstance(
                        db_instance_id="mydb",
                        arn=(
                            f"arn:aws:rds:{REGION}"
                            f":{ACCOUNT}:db:mydb"
                        ),
                        publicly_accessible=True,
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        rds = [
            r for r in recs
            if r.resource_type == "rds_instance"
        ]
        assert rds[0].exposure == "internet"
        assert rds[0].technology_category == "database"

    def test_private_rds(self):
        data = _make_input(
            rds=RDSData(
                db_instances=[
                    RDSInstance(
                        db_instance_id="priv-db",
                        arn=(
                            f"arn:aws:rds:{REGION}"
                            f":{ACCOUNT}:db:priv-db"
                        ),
                        publicly_accessible=False,
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        rds = [
            r for r in recs
            if r.resource_type == "rds_instance"
        ]
        assert rds[0].exposure == "private"


# ── Lambda classification ──────────────────────────


class TestClassifyLambda:
    """Test Lambda function classification."""

    def test_no_vpc_is_internet(self):
        data = _make_input(
            lambda_functions=LambdaData(
                functions=[
                    LambdaFunction(
                        function_name="api-fn",
                        arn=(
                            f"arn:aws:lambda:{REGION}"
                            f":{ACCOUNT}:function:api-fn"
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        fn = [
            r for r in recs
            if r.resource_type == "lambda_function"
        ]
        assert fn[0].exposure == "internet"
        assert fn[0].technology_category == "serverless"

    def test_vpc_is_private(self):
        data = _make_input(
            lambda_functions=LambdaData(
                functions=[
                    LambdaFunction(
                        function_name="internal-fn",
                        arn=(
                            f"arn:aws:lambda:{REGION}"
                            f":{ACCOUNT}"
                            ":function:internal-fn"
                        ),
                        vpc_config=LambdaVPCConfig(
                            subnet_ids=["subnet-1"],
                            security_group_ids=["sg-1"],
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        fn = [
            r for r in recs
            if r.resource_type == "lambda_function"
        ]
        assert fn[0].exposure == "private"

    def test_lambda_managed_by_role(self):
        data = _make_input(
            lambda_functions=LambdaData(
                functions=[
                    LambdaFunction(
                        function_name="fn",
                        arn=(
                            f"arn:aws:lambda:{REGION}"
                            f":{ACCOUNT}:function:fn"
                        ),
                        role=(
                            "arn:aws:iam::123"
                            ":role/LambdaExec"
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        fn = [
            r for r in recs
            if r.resource_type == "lambda_function"
        ]
        assert fn[0].managed_by == (
            "arn:aws:iam::123:role/LambdaExec"
        )


# ── EBS classification ─────────────────────────────


class TestClassifyEBS:
    """Test EBS volume classification."""

    def test_ebs_volume(self):
        data = _make_input(
            ec2=EC2Data(
                ebs_volumes=[
                    EBSVolume(
                        volume_id="vol-abc",
                        arn=(
                            f"arn:aws:ec2:{REGION}"
                            f":{ACCOUNT}:volume/vol-abc"
                        ),
                        attached_instance="i-123",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        ebs = [
            r for r in recs
            if r.resource_type == "ebs_volume"
        ]
        assert len(ebs) == 1
        assert ebs[0].technology_category == "storage"
        assert ebs[0].service == "ec2"
        assert ebs[0].exposure == "private"
        assert ebs[0].belongs_to == "i-123"


# ── Security Group classification ──────────────────


class TestClassifySG:
    """Test security group classification."""

    def test_sg(self):
        data = _make_input(
            ec2=EC2Data(
                security_groups=[
                    SecurityGroup(
                        group_id="sg-abc",
                        group_name="web-sg",
                        arn=(
                            f"arn:aws:ec2:{REGION}"
                            f":{ACCOUNT}"
                            ":security-group/sg-abc"
                        ),
                        vpc_id="vpc-1",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        sg = [
            r for r in recs
            if r.resource_type == "security_group"
        ]
        assert len(sg) == 1
        assert sg[0].technology_category == "network"
        assert sg[0].belongs_to == "vpc-1"
        assert sg[0].resource_name == "web-sg"


# ── VPC classification ─────────────────────────────


class TestClassifyVPC:
    """Test VPC classification."""

    def test_vpc(self):
        data = _make_input(
            vpc=VPCData(
                vpcs=[
                    VPC(
                        vpc_id="vpc-abc",
                        cidr_block="10.0.0.0/16",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        vpcs = [
            r for r in recs
            if r.resource_type == "vpc"
        ]
        assert len(vpcs) == 1
        assert vpcs[0].technology_category == "network"
        assert vpcs[0].resource_name == "vpc-abc"


# ── KMS / Secrets classification ───────────────────


class TestClassifyKMS:
    """Test KMS key classification."""

    def test_kms_key(self):
        data = _make_input(
            kms=KMSData(
                keys=[
                    KMSKey(
                        key_id="k-123",
                        arn=(
                            f"arn:aws:kms:{REGION}"
                            f":{ACCOUNT}:key/k-123"
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        kms = [
            r for r in recs
            if r.resource_type == "kms_key"
        ]
        assert len(kms) == 1
        assert kms[0].technology_category == "encryption"
        assert kms[0].service == "kms"


class TestClassifySecret:
    """Test Secrets Manager classification."""

    def test_secret(self):
        data = _make_input(
            secrets_manager=SecretsManagerData(
                secrets=[
                    Secret(
                        name="prod/db-pass",
                        arn=(
                            f"arn:aws:secretsmanager"
                            f":{REGION}:{ACCOUNT}"
                            ":secret:prod/db-pass"
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        sec = [
            r for r in recs
            if r.resource_type == "secret"
        ]
        assert len(sec) == 1
        assert sec[0].technology_category == "encryption"
        assert sec[0].service == "secretsmanager"


# ── Mixed resources ────────────────────────────────


class TestClassifyAllMixed:
    """Test classifying multiple resource types."""

    def test_multiple_types(self):
        data = _make_input(
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-1",
                        arn=(
                            f"arn:aws:ec2:{REGION}"
                            f":{ACCOUNT}:instance/i-1"
                        ),
                    ),
                ],
                ebs_volumes=[
                    EBSVolume(
                        volume_id="vol-1",
                        arn=(
                            f"arn:aws:ec2:{REGION}"
                            f":{ACCOUNT}:volume/vol-1"
                        ),
                    ),
                ],
            ),
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="bkt-1",
                        arn="arn:aws:s3:::bkt-1",
                    ),
                ],
            ),
            rds=RDSData(
                db_instances=[
                    RDSInstance(
                        db_instance_id="db-1",
                        arn=(
                            f"arn:aws:rds:{REGION}"
                            f":{ACCOUNT}:db:db-1"
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        types = {r.resource_type for r in recs}
        assert "ec2_instance" in types
        assert "ebs_volume" in types
        assert "s3_bucket" in types
        assert "rds_instance" in types

    def test_all_records_have_pk_sk(self):
        data = _make_input(
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-1",
                        arn=(
                            f"arn:aws:ec2:{REGION}"
                            f":{ACCOUNT}:instance/i-1"
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        for rec in recs:
            assert rec.pk == f"{ACCOUNT}#{REGION}"
            assert rec.sk.startswith(
                rec.resource_type + "#"
            )

    def test_empty_input(self):
        data = _make_input()
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        assert recs == []


# ── Violation enrichment ───────────────────────────


class _FakeViolation:
    """Minimal violation stub for enrichment tests."""

    def __init__(
        self, resource, severity, status="alarm"
    ):
        self.resource = resource
        self.severity = severity
        self.status = status
        self.check_id = "test_01"


class TestEnrichWithViolations:
    """Test violation count enrichment."""

    def test_counts_by_severity(self):
        data = _make_input(
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="bkt",
                        arn="arn:aws:s3:::bkt",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        violations = [
            _FakeViolation(
                "arn:aws:s3:::bkt", "critical"
            ),
            _FakeViolation(
                "arn:aws:s3:::bkt", "high"
            ),
            _FakeViolation(
                "arn:aws:s3:::bkt", "medium"
            ),
        ]
        clf.enrich_with_violations(recs, violations)

        rec = recs[0]
        assert rec.violation_count == 3
        assert rec.critical_violations == 1
        assert rec.high_violations == 1

    def test_only_alarm_status_counted(self):
        data = _make_input(
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="b",
                        arn="arn:aws:s3:::b",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        violations = [
            _FakeViolation(
                "arn:aws:s3:::b", "critical",
                status="alarm",
            ),
            _FakeViolation(
                "arn:aws:s3:::b", "critical",
                status="ok",
            ),
        ]
        clf.enrich_with_violations(recs, violations)
        assert recs[0].violation_count == 1

    def test_no_matching_violations(self):
        data = _make_input(
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="clean",
                        arn="arn:aws:s3:::clean",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        clf.enrich_with_violations(recs, [])
        assert recs[0].violation_count == 0
        assert recs[0].critical_violations == 0

    def test_violations_for_different_resources(self):
        data = _make_input(
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="a",
                        arn="arn:aws:s3:::a",
                    ),
                    S3Bucket(
                        name="b",
                        arn="arn:aws:s3:::b",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        violations = [
            _FakeViolation(
                "arn:aws:s3:::a", "critical"
            ),
            _FakeViolation(
                "arn:aws:s3:::b", "high"
            ),
            _FakeViolation(
                "arn:aws:s3:::b", "high"
            ),
        ]
        clf.enrich_with_violations(recs, violations)

        by_name = {r.resource_name: r for r in recs}
        assert by_name["a"].violation_count == 1
        assert by_name["a"].critical_violations == 1
        assert by_name["b"].violation_count == 2
        assert by_name["b"].high_violations == 2

    def test_risk_score_computed_from_severities(self):
        """risk_score must be > 0 when violations exist."""
        data = _make_input(
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="risky",
                        arn="arn:aws:s3:::risky",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        violations = [
            _FakeViolation(
                "arn:aws:s3:::risky", "critical"
            ),
            _FakeViolation(
                "arn:aws:s3:::risky", "high"
            ),
        ]
        clf.enrich_with_violations(recs, violations)
        assert recs[0].risk_score > 0

    def test_risk_score_capped_at_100(self):
        """risk_score must never exceed 100."""
        data = _make_input(
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="overloaded",
                        arn="arn:aws:s3:::overloaded",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        violations = [
            _FakeViolation(
                "arn:aws:s3:::overloaded", "critical"
            )
            for _ in range(10)
        ]
        clf.enrich_with_violations(recs, violations)
        assert recs[0].risk_score <= 100

    def test_risk_score_zero_when_no_violations(self):
        """risk_score stays 0 for clean resources."""
        data = _make_input(
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="clean",
                        arn="arn:aws:s3:::clean-rs",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        clf.enrich_with_violations(recs, [])
        assert recs[0].risk_score == 0

    def test_risk_score_scales_with_severity(self):
        """Critical violations score higher than medium."""
        data = _make_input(
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="a",
                        arn="arn:aws:s3:::crit-a",
                    ),
                    S3Bucket(
                        name="b",
                        arn="arn:aws:s3:::med-b",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        clf.enrich_with_violations(
            recs,
            [
                _FakeViolation(
                    "arn:aws:s3:::crit-a", "critical"
                ),
                _FakeViolation(
                    "arn:aws:s3:::med-b", "medium"
                ),
            ],
        )
        by_name = {r.resource_name: r for r in recs}
        assert (
            by_name["a"].risk_score
            > by_name["b"].risk_score
        )
