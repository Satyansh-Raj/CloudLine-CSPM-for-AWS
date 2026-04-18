"""Tests for the ResourceClassifier orchestrator."""

import pytest

from app.inventory.classifier import (
    ResourceClassifier,
    extract_env_owner,
)
from app.models.aws_input import (
    APIGateway,
    APIGatewayAPI,
    APIGatewayData,
    EndpointConfiguration,
    AuroraCluster,
    AutoScalingGroup,
    CDNData,
    CloudFrontDistribution,
    CloudTrailData,
    CloudTrailTrail,
    CloudWatchAlarm,
    CloudWatchData,
    EC2Data,
    EC2Instance,
    ECRData,
    ECRRepository,
    ECSCluster,
    ECSData,
    ECSTaskDefinition,
    EBSSnapshot,
    EBSVolume,
    DynamoDBData,
    DynamoDBTable,
    EKSCluster,
    EKSData,
    ResourcesVpcConfig,
    ELBData,
    GuardDutyData,
    GuardDutyDetector,
    IAMData,
    IAMGroup,
    IAMPolicy,
    IAMRole,
    IAMUser,
    InstanceRole,
    InternetGateway,
    KMSData,
    KMSKey,
    LambdaFunction,
    LambdaVPCConfig,
    LoadBalancer,
    NACL,
    NATGateway,
    NetworkFirewall,
    PublicAccessBlock,
    RDSData,
    RDSInstance,
    RDSSnapshot,
    Route53HostedZone,
    S3Bucket,
    S3Data,
    Secret,
    SecretsManagerData,
    SecurityGroup,
    Subnet,
    UnifiedAWSInput,
    VPC,
    VPCData,
    WAFWebACL,
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
                        security_groups=[
                            {"group_id": "sg-1"},
                            {"group_id": "sg-2"},
                        ],
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
            lambda_functions=[
                LambdaFunction(
                    function_name="api-fn",
                    arn=(
                        f"arn:aws:lambda:{REGION}"
                        f":{ACCOUNT}:function:api-fn"
                    ),
                ),
            ],
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
            lambda_functions=[
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
            lambda_functions=[
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


# ── IAM User classification (Batch 1) ────────────


class TestClassifyIAMUser:
    """Test IAM user classification."""

    def test_iam_user_basic(self):
        data = _make_input(
            iam=IAMData(
                users=[
                    IAMUser(
                        name="admin",
                        arn=(
                            f"arn:aws:iam::{ACCOUNT}"
                            ":user/admin"
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        iam = [
            r for r in recs
            if r.resource_type == "iam_user"
        ]
        assert len(iam) == 1
        assert iam[0].technology_category == "identity"
        assert iam[0].service == "iam"
        assert iam[0].resource_name == "admin"
        assert iam[0].exposure == "private"

    def test_iam_user_uses_arn_as_id(self):
        arn = f"arn:aws:iam::{ACCOUNT}:user/dev"
        data = _make_input(
            iam=IAMData(
                users=[
                    IAMUser(name="dev", arn=arn),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        iam = [
            r for r in recs
            if r.resource_type == "iam_user"
        ]
        assert iam[0].resource_id == arn


# ── CloudTrail classification (Batch 1) ──────────


class TestClassifyCloudTrail:
    """Test CloudTrail trail classification."""

    def test_cloudtrail_basic(self):
        data = _make_input(
            cloudtrail=CloudTrailData(
                trails=[
                    CloudTrailTrail(
                        name="main-trail",
                        arn=(
                            f"arn:aws:cloudtrail"
                            f":{REGION}:{ACCOUNT}"
                            ":trail/main-trail"
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        ct = [
            r for r in recs
            if r.resource_type == "cloudtrail"
        ]
        assert len(ct) == 1
        assert ct[0].technology_category == "monitoring"
        assert ct[0].service == "cloudtrail"
        assert ct[0].resource_name == "main-trail"
        assert ct[0].exposure == "private"


# ── GuardDuty classification (Batch 1) ───────────


class TestClassifyGuardDuty:
    """Test GuardDuty detector classification."""

    def test_guardduty_basic(self):
        data = _make_input(
            guardduty=GuardDutyData(
                detectors=[
                    GuardDutyDetector(
                        detector_id="abc123def",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        gd = [
            r for r in recs
            if r.resource_type == "guardduty"
        ]
        assert len(gd) == 1
        assert gd[0].technology_category == "monitoring"
        assert gd[0].service == "guardduty"
        assert gd[0].resource_name == "abc123def"
        assert gd[0].exposure == "private"

    def test_guardduty_constructs_arn(self):
        data = _make_input(
            guardduty=GuardDutyData(
                detectors=[
                    GuardDutyDetector(
                        detector_id="det1",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        gd = [
            r for r in recs
            if r.resource_type == "guardduty"
        ]
        assert "guardduty" in gd[0].resource_id
        assert "det1" in gd[0].resource_id


# ── CloudWatch Alarm classification (Batch 1) ────


class TestClassifyCloudWatchAlarm:
    """Test CloudWatch alarm classification."""

    def test_cloudwatch_alarm_basic(self):
        data = _make_input(
            cloudwatch=CloudWatchData(
                alarms=[
                    CloudWatchAlarm(
                        alarm_name="high-cpu",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        cw = [
            r for r in recs
            if r.resource_type == "cloudwatch_alarm"
        ]
        assert len(cw) == 1
        assert cw[0].technology_category == "monitoring"
        assert cw[0].service == "cloudwatch"
        assert cw[0].resource_name == "high-cpu"
        assert cw[0].exposure == "private"

    def test_cloudwatch_alarm_constructs_arn(self):
        data = _make_input(
            cloudwatch=CloudWatchData(
                alarms=[
                    CloudWatchAlarm(
                        alarm_name="low-disk",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        cw = [
            r for r in recs
            if r.resource_type == "cloudwatch_alarm"
        ]
        assert "cloudwatch" in cw[0].resource_id
        assert "low-disk" in cw[0].resource_id


# ── Network ACL classification (Batch 1) ─────────


class TestClassifyNetworkACL:
    """Test Network ACL classification."""

    def test_nacl_basic(self):
        data = _make_input(
            vpc=VPCData(
                nacls=[
                    NACL(
                        nacl_id="acl-abc123",
                        vpc_id="vpc-1",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        nacl = [
            r for r in recs
            if r.resource_type == "network_acl"
        ]
        assert len(nacl) == 1
        assert nacl[0].technology_category == "network"
        assert nacl[0].service == "vpc"
        assert nacl[0].resource_name == "acl-abc123"
        assert nacl[0].exposure == "private"
        assert nacl[0].belongs_to == "vpc-1"

    def test_nacl_constructs_arn(self):
        data = _make_input(
            vpc=VPCData(
                nacls=[
                    NACL(
                        nacl_id="acl-xyz",
                        vpc_id="vpc-2",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        nacl = [
            r for r in recs
            if r.resource_type == "network_acl"
        ]
        assert "acl-xyz" in nacl[0].resource_id


# ── IAM Group classification (Batch 2) ───────────


class TestClassifyIAMGroup:
    """Test IAM group classification."""

    def test_iam_group_basic(self):
        data = _make_input(
            iam=IAMData(
                groups=[
                    IAMGroup(
                        group_name="admins",
                        arn=(
                            f"arn:aws:iam::{ACCOUNT}"
                            ":group/admins"
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        grp = [
            r for r in recs
            if r.resource_type == "iam_group"
        ]
        assert len(grp) == 1
        assert grp[0].technology_category == "identity"
        assert grp[0].service == "iam"
        assert grp[0].resource_name == "admins"
        assert grp[0].exposure == "private"

    def test_iam_group_uses_arn_as_id(self):
        arn = f"arn:aws:iam::{ACCOUNT}:group/devs"
        data = _make_input(
            iam=IAMData(
                groups=[
                    IAMGroup(
                        group_name="devs", arn=arn
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        grp = [
            r for r in recs
            if r.resource_type == "iam_group"
        ]
        assert grp[0].resource_id == arn


# ── IAM Role classification (Batch 2) ────────────


class TestClassifyIAMRole:
    """Test IAM role classification."""

    def test_iam_role_basic(self):
        data = _make_input(
            iam=IAMData(
                roles=[
                    IAMRole(
                        role_name="LambdaExec",
                        arn=(
                            f"arn:aws:iam::{ACCOUNT}"
                            ":role/LambdaExec"
                        ),
                        tags={"Environment": "prod"},
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        role = [
            r for r in recs
            if r.resource_type == "iam_role"
        ]
        assert len(role) == 1
        assert role[0].technology_category == "identity"
        assert role[0].service == "iam"
        assert role[0].resource_name == "LambdaExec"
        assert role[0].exposure == "private"
        assert role[0].environment == "prod"

    def test_iam_role_uses_arn_as_id(self):
        arn = f"arn:aws:iam::{ACCOUNT}:role/WebRole"
        data = _make_input(
            iam=IAMData(
                roles=[
                    IAMRole(
                        role_name="WebRole", arn=arn
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        role = [
            r for r in recs
            if r.resource_type == "iam_role"
        ]
        assert role[0].resource_id == arn


# ── IAM Policy classification (Batch 2) ──────────


class TestClassifyIAMPolicy:
    """Test IAM policy classification."""

    def test_iam_policy_basic(self):
        data = _make_input(
            iam=IAMData(
                customer_managed_policies=[
                    IAMPolicy(
                        policy_name="AdminAccess",
                        arn=(
                            f"arn:aws:iam::{ACCOUNT}"
                            ":policy/AdminAccess"
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        pol = [
            r for r in recs
            if r.resource_type == "iam_policy"
        ]
        assert len(pol) == 1
        assert pol[0].technology_category == "identity"
        assert pol[0].service == "iam"
        assert pol[0].resource_name == "AdminAccess"
        assert pol[0].exposure == "private"

    def test_iam_policy_uses_arn_as_id(self):
        arn = (
            f"arn:aws:iam::{ACCOUNT}"
            ":policy/ReadOnly"
        )
        data = _make_input(
            iam=IAMData(
                customer_managed_policies=[
                    IAMPolicy(
                        policy_name="ReadOnly",
                        arn=arn,
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        pol = [
            r for r in recs
            if r.resource_type == "iam_policy"
        ]
        assert pol[0].resource_id == arn


# ── Subnet classification (Batch 3) ──────────────


class TestClassifySubnet:
    """Test Subnet classification."""

    def test_subnet_basic(self):
        arn = (
            f"arn:aws:ec2:{REGION}:{ACCOUNT}"
            ":subnet/subnet-abc"
        )
        data = _make_input(
            vpc=VPCData(
                subnets=[
                    Subnet(
                        subnet_id="subnet-abc",
                        arn=arn,
                        vpc_id="vpc-1",
                        tags={"Environment": "dev"},
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        sub = [
            r for r in recs
            if r.resource_type == "subnet"
        ]
        assert len(sub) == 1
        assert sub[0].technology_category == "network"
        assert sub[0].service == "vpc"
        assert sub[0].resource_name == "subnet-abc"
        assert sub[0].belongs_to == "vpc-1"
        assert sub[0].environment == "dev"

    def test_subnet_public_exposure(self):
        """Subnet with map_public_ip_on_launch has
        internet exposure."""
        data = _make_input(
            vpc=VPCData(
                subnets=[
                    Subnet(
                        subnet_id="subnet-pub",
                        arn=(
                            f"arn:aws:ec2:{REGION}"
                            f":{ACCOUNT}"
                            ":subnet/subnet-pub"
                        ),
                        map_public_ip_on_launch=True,
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        sub = [
            r for r in recs
            if r.resource_type == "subnet"
        ]
        assert sub[0].exposure == "internet"

    def test_subnet_private_exposure(self):
        data = _make_input(
            vpc=VPCData(
                subnets=[
                    Subnet(
                        subnet_id="subnet-priv",
                        arn=(
                            f"arn:aws:ec2:{REGION}"
                            f":{ACCOUNT}"
                            ":subnet/subnet-priv"
                        ),
                        map_public_ip_on_launch=False,
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        sub = [
            r for r in recs
            if r.resource_type == "subnet"
        ]
        assert sub[0].exposure == "private"


# ── Internet Gateway classification (Batch 3) ────


class TestClassifyInternetGateway:
    """Test Internet Gateway classification."""

    def test_igw_basic(self):
        arn = (
            f"arn:aws:ec2:{REGION}:{ACCOUNT}"
            ":internet-gateway/igw-abc"
        )
        data = _make_input(
            vpc=VPCData(
                internet_gateways=[
                    InternetGateway(
                        igw_id="igw-abc",
                        arn=arn,
                        attached_vpcs=["vpc-1"],
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        igw = [
            r for r in recs
            if r.resource_type == "internet_gateway"
        ]
        assert len(igw) == 1
        assert igw[0].technology_category == "network"
        assert igw[0].service == "vpc"
        assert igw[0].resource_name == "igw-abc"
        assert igw[0].exposure == "internet"

    def test_igw_connected_to_vpcs(self):
        data = _make_input(
            vpc=VPCData(
                internet_gateways=[
                    InternetGateway(
                        igw_id="igw-1",
                        arn=(
                            f"arn:aws:ec2:{REGION}"
                            f":{ACCOUNT}"
                            ":internet-gateway/igw-1"
                        ),
                        attached_vpcs=[
                            "vpc-a", "vpc-b"
                        ],
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        igw = [
            r for r in recs
            if r.resource_type == "internet_gateway"
        ]
        assert igw[0].connected_to == [
            "vpc-a", "vpc-b"
        ]


# ── NAT Gateway classification (Batch 3) ─────────


class TestClassifyNATGateway:
    """Test NAT Gateway classification."""

    def test_natgw_basic(self):
        arn = (
            f"arn:aws:ec2:{REGION}:{ACCOUNT}"
            ":natgateway/nat-abc"
        )
        data = _make_input(
            vpc=VPCData(
                nat_gateways=[
                    NATGateway(
                        nat_gateway_id="nat-abc",
                        arn=arn,
                        vpc_id="vpc-1",
                        subnet_id="subnet-1",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        nat = [
            r for r in recs
            if r.resource_type == "nat_gateway"
        ]
        assert len(nat) == 1
        assert nat[0].technology_category == "network"
        assert nat[0].service == "vpc"
        assert nat[0].resource_name == "nat-abc"
        assert nat[0].exposure == "private"
        assert nat[0].belongs_to == "vpc-1"


# ── Network Firewall classification (Batch 3) ────


class TestClassifyNetworkFirewall:
    """Test Network Firewall classification."""

    def test_network_firewall_basic(self):
        arn = (
            f"arn:aws:network-firewall"
            f":{REGION}:{ACCOUNT}"
            ":firewall/prod-fw"
        )
        data = _make_input(
            vpc=VPCData(
                network_firewalls=[
                    NetworkFirewall(
                        firewall_name="prod-fw",
                        arn=arn,
                        vpc_id="vpc-1",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        nf = [
            r for r in recs
            if r.resource_type == "network_firewall"
        ]
        assert len(nf) == 1
        assert nf[0].technology_category == "network"
        assert nf[0].service == "vpc"
        assert nf[0].resource_name == "prod-fw"
        assert nf[0].exposure == "private"
        assert nf[0].belongs_to == "vpc-1"


# ── WAF Web ACL classification (Batch 3) ─────────


class TestClassifyWAFWebACL:
    """Test WAF Web ACL classification."""

    def test_waf_web_acl_basic(self):
        arn = (
            f"arn:aws:wafv2:{REGION}:{ACCOUNT}"
            ":regional/webacl/my-acl/123"
        )
        data = _make_input(
            vpc=VPCData(
                waf_web_acls=[
                    WAFWebACL(
                        name="my-acl",
                        arn=arn,
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        waf = [
            r for r in recs
            if r.resource_type == "waf_web_acl"
        ]
        assert len(waf) == 1
        assert waf[0].technology_category == "network"
        assert waf[0].service == "waf"
        assert waf[0].resource_name == "my-acl"
        assert waf[0].exposure == "private"


# ── Load Balancer classification (Batch 4) ────────


class TestClassifyLoadBalancer:
    """Test Load Balancer classification."""

    def test_internet_facing_lb(self):
        arn = (
            f"arn:aws:elasticloadbalancing"
            f":{REGION}:{ACCOUNT}"
            ":loadbalancer/app/web-lb/abc"
        )
        data = _make_input(
            elb=ELBData(
                load_balancers=[
                    LoadBalancer(
                        lb_name="web-lb",
                        arn=arn,
                        scheme="internet-facing",
                        vpc_id="vpc-1",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        lb = [
            r for r in recs
            if r.resource_type == "load_balancer"
        ]
        assert len(lb) == 1
        assert lb[0].technology_category == "network"
        assert lb[0].service == "elb"
        assert lb[0].resource_name == "web-lb"
        assert lb[0].exposure == "internet"
        assert lb[0].belongs_to == "vpc-1"

    def test_internal_lb(self):
        data = _make_input(
            elb=ELBData(
                load_balancers=[
                    LoadBalancer(
                        lb_name="internal-lb",
                        arn=(
                            f"arn:aws:elb:{REGION}"
                            f":{ACCOUNT}:lb/internal"
                        ),
                        scheme="internal",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        lb = [
            r for r in recs
            if r.resource_type == "load_balancer"
        ]
        assert lb[0].exposure == "private"


# ── CloudFront classification (Batch 4) ──────────


class TestClassifyCloudFront:
    """Test CloudFront distribution classification."""

    def test_cloudfront_basic(self):
        arn = (
            f"arn:aws:cloudfront::{ACCOUNT}"
            ":distribution/E123"
        )
        data = _make_input(
            cdn=CDNData(
                distributions=[
                    CloudFrontDistribution(
                        distribution_id="E123",
                        arn=arn,
                        domain_name="d123.cf.net",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        cf = [
            r for r in recs
            if r.resource_type == (
                "cloudfront_distribution"
            )
        ]
        assert len(cf) == 1
        assert cf[0].technology_category == "network"
        assert cf[0].service == "cloudfront"
        assert cf[0].resource_name == "E123"
        assert cf[0].exposure == "internet"


# ── Route53 classification (Batch 4) ─────────────


class TestClassifyRoute53:
    """Test Route53 hosted zone classification."""

    def test_public_zone(self):
        data = _make_input(
            cdn=CDNData(
                hosted_zones=[
                    Route53HostedZone(
                        hosted_zone_id="Z123",
                        name="example.com",
                        is_private=False,
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        r53 = [
            r for r in recs
            if r.resource_type == (
                "route53_hosted_zone"
            )
        ]
        assert len(r53) == 1
        assert r53[0].technology_category == "network"
        assert r53[0].service == "route53"
        assert r53[0].resource_name == "example.com"
        assert r53[0].exposure == "internet"

    def test_private_zone(self):
        data = _make_input(
            cdn=CDNData(
                hosted_zones=[
                    Route53HostedZone(
                        hosted_zone_id="Z456",
                        name="internal.corp",
                        is_private=True,
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        r53 = [
            r for r in recs
            if r.resource_type == (
                "route53_hosted_zone"
            )
        ]
        assert r53[0].exposure == "private"

    def test_route53_constructs_arn(self):
        data = _make_input(
            cdn=CDNData(
                hosted_zones=[
                    Route53HostedZone(
                        hosted_zone_id="Z789",
                        name="test.com",
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        r53 = [
            r for r in recs
            if r.resource_type == (
                "route53_hosted_zone"
            )
        ]
        assert "route53" in r53[0].resource_id
        assert "Z789" in r53[0].resource_id


# ── Aurora Cluster classification (Batch 5) ──────


class TestClassifyAuroraCluster:
    """Test Aurora cluster classification."""

    def test_aurora_basic(self):
        arn = (
            f"arn:aws:rds:{REGION}:{ACCOUNT}"
            ":cluster:my-aurora"
        )
        data = _make_input(
            rds=RDSData(
                aurora_clusters=[
                    AuroraCluster(
                        cluster_id="my-aurora",
                        arn=arn,
                        engine="aurora-mysql",
                        tags={
                            "Environment": "prod"
                        },
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        ac = [
            r for r in recs
            if r.resource_type == "aurora_cluster"
        ]
        assert len(ac) == 1
        assert ac[0].technology_category == "database"
        assert ac[0].service == "rds"
        assert ac[0].resource_name == "my-aurora"
        assert ac[0].exposure == "private"
        assert ac[0].environment == "prod"


# ── DynamoDB Table classification (Batch 5) ──────


class TestClassifyDynamoDBTable:
    """Test DynamoDB table classification."""

    def test_dynamodb_basic(self):
        arn = (
            f"arn:aws:dynamodb:{REGION}:{ACCOUNT}"
            ":table/users"
        )
        data = _make_input(
            dynamodb=DynamoDBData(
                tables=[
                    DynamoDBTable(
                        table_name="users",
                        arn=arn,
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        ddb = [
            r for r in recs
            if r.resource_type == "dynamodb_table"
        ]
        assert len(ddb) == 1
        assert ddb[0].technology_category == "database"
        assert ddb[0].service == "dynamodb"
        assert ddb[0].resource_name == "users"
        assert ddb[0].exposure == "private"


# ── RDS Snapshot classification (Batch 5) ────────


class TestClassifyRDSSnapshot:
    """Test RDS snapshot classification."""

    def test_private_snapshot(self):
        arn = (
            f"arn:aws:rds:{REGION}:{ACCOUNT}"
            ":snapshot:snap-1"
        )
        data = _make_input(
            rds=RDSData(
                snapshots=[
                    RDSSnapshot(
                        db_snapshot_identifier=(
                            "snap-1"
                        ),
                        db_snapshot_arn=arn,
                        attributes={"restore": []},
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        snap = [
            r for r in recs
            if r.resource_type == "rds_snapshot"
        ]
        assert len(snap) == 1
        assert snap[0].technology_category == "backup"
        assert snap[0].service == "rds"
        assert snap[0].exposure == "private"

    def test_public_snapshot(self):
        arn = (
            f"arn:aws:rds:{REGION}:{ACCOUNT}"
            ":snapshot:snap-pub"
        )
        data = _make_input(
            rds=RDSData(
                snapshots=[
                    RDSSnapshot(
                        db_snapshot_identifier=(
                            "snap-pub"
                        ),
                        db_snapshot_arn=arn,
                        attributes={
                            "restore": ["all"]
                        },
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        snap = [
            r for r in recs
            if r.resource_type == "rds_snapshot"
        ]
        assert snap[0].exposure == "internet"


# ── Auto Scaling Group classification (Batch 6) ──


class TestClassifyAutoScalingGroup:
    """Test Auto Scaling Group classification."""

    def test_asg_basic(self):
        arn = (
            f"arn:aws:autoscaling:{REGION}"
            f":{ACCOUNT}"
            ":autoScalingGroup:123:asg/web-asg"
        )
        data = _make_input(
            ec2=EC2Data(
                auto_scaling_groups=[
                    AutoScalingGroup(
                        asg_name="web-asg",
                        arn=arn,
                        tags={
                            "Environment": "prod"
                        },
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        asg = [
            r for r in recs
            if r.resource_type == (
                "auto_scaling_group"
            )
        ]
        assert len(asg) == 1
        assert asg[0].technology_category == "compute"
        assert asg[0].service == "ec2"
        assert asg[0].resource_name == "web-asg"
        assert asg[0].exposure == "private"
        assert asg[0].environment == "prod"

    def test_asg_uses_arn_as_id(self):
        arn = (
            f"arn:aws:autoscaling:{REGION}"
            f":{ACCOUNT}"
            ":autoScalingGroup:456:asg/api-asg"
        )
        data = _make_input(
            ec2=EC2Data(
                auto_scaling_groups=[
                    AutoScalingGroup(
                        asg_name="api-asg",
                        arn=arn,
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        asg = [
            r for r in recs
            if r.resource_type == (
                "auto_scaling_group"
            )
        ]
        assert asg[0].resource_id == arn


# ── EBS Snapshot classification (Batch 6) ────────


class TestClassifyEBSSnapshot:
    """Test EBS snapshot classification."""

    def test_private_snapshot(self):
        arn = (
            f"arn:aws:ec2:{REGION}:{ACCOUNT}"
            ":snapshot/snap-abc"
        )
        data = _make_input(
            ec2=EC2Data(
                ebs_snapshots=[
                    EBSSnapshot(
                        snapshot_id="snap-abc",
                        arn=arn,
                        is_public=False,
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        snap = [
            r for r in recs
            if r.resource_type == "ebs_snapshot"
        ]
        assert len(snap) == 1
        assert snap[0].technology_category == "backup"
        assert snap[0].service == "ec2"
        assert snap[0].resource_name == "snap-abc"
        assert snap[0].exposure == "private"

    def test_public_snapshot(self):
        arn = (
            f"arn:aws:ec2:{REGION}:{ACCOUNT}"
            ":snapshot/snap-pub"
        )
        data = _make_input(
            ec2=EC2Data(
                ebs_snapshots=[
                    EBSSnapshot(
                        snapshot_id="snap-pub",
                        arn=arn,
                        is_public=True,
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        snap = [
            r for r in recs
            if r.resource_type == "ebs_snapshot"
        ]
        assert snap[0].exposure == "internet"


# ── API Gateway classification (Batch 6) ─────────


class TestClassifyAPIGateway:
    """Test API Gateway classification."""

    def test_regional_api(self):
        arn = (
            f"arn:aws:apigateway:{REGION}"
            "::/restapis/abc123"
        )
        data = _make_input(
            apigateway=APIGatewayData(
                rest_apis=[
                    APIGatewayAPI(
                        id="abc123",
                        name="my-api",
                        arn=arn,
                        endpoint_configuration=(
                            EndpointConfiguration(
                                types=["REGIONAL"]
                            )
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        api = [
            r for r in recs
            if r.resource_type == "api_gateway"
        ]
        assert len(api) == 1
        assert api[0].technology_category == "serverless"
        assert api[0].service == "apigateway"
        assert api[0].resource_name == "my-api"
        assert api[0].exposure == "internet"

    def test_edge_api(self):
        data = _make_input(
            apigateway=APIGatewayData(
                rest_apis=[
                    APIGatewayAPI(
                        id="def456",
                        name="edge-api",
                        arn=(
                            f"arn:aws:apigateway"
                            f":{REGION}"
                            "::/restapis/def456"
                        ),
                        endpoint_configuration=(
                            EndpointConfiguration(
                                types=["EDGE"]
                            )
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        api = [
            r for r in recs
            if r.resource_type == "api_gateway"
        ]
        assert api[0].exposure == "internet"

    def test_private_api(self):
        data = _make_input(
            apigateway=APIGatewayData(
                rest_apis=[
                    APIGatewayAPI(
                        id="priv789",
                        name="internal-api",
                        arn=(
                            f"arn:aws:apigateway"
                            f":{REGION}"
                            "::/restapis/priv789"
                        ),
                        endpoint_configuration=(
                            EndpointConfiguration(
                                types=["PRIVATE"]
                            )
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        api = [
            r for r in recs
            if r.resource_type == "api_gateway"
        ]
        assert api[0].exposure == "private"


# ── ECR Repository classification (Batch 7) ──────


class TestClassifyECRRepository:
    """Test ECR repository classification."""

    def test_ecr_basic(self):
        arn = (
            f"arn:aws:ecr:{REGION}:{ACCOUNT}"
            ":repository/my-app"
        )
        data = _make_input(
            ecr=ECRData(
                repositories=[
                    ECRRepository(
                        repository_name="my-app",
                        arn=arn,
                        tags={
                            "Environment": "prod"
                        },
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        ecr = [
            r for r in recs
            if r.resource_type == "ecr_repository"
        ]
        assert len(ecr) == 1
        assert ecr[0].technology_category == (
            "containers"
        )
        assert ecr[0].service == "ecr"
        assert ecr[0].resource_name == "my-app"
        assert ecr[0].exposure == "private"
        assert ecr[0].environment == "prod"

    def test_ecr_uses_arn_as_id(self):
        arn = (
            f"arn:aws:ecr:{REGION}:{ACCOUNT}"
            ":repository/backend"
        )
        data = _make_input(
            ecr=ECRData(
                repositories=[
                    ECRRepository(
                        repository_name="backend",
                        repository_arn=arn,
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        ecr = [
            r for r in recs
            if r.resource_type == "ecr_repository"
        ]
        assert ecr[0].resource_id == arn


# ── ECS Cluster classification (Batch 7) ─────────


class TestClassifyECSCluster:
    """Test ECS cluster classification."""

    def test_ecs_cluster_basic(self):
        arn = (
            f"arn:aws:ecs:{REGION}:{ACCOUNT}"
            ":cluster/prod-cluster"
        )
        data = _make_input(
            ecs=ECSData(
                clusters=[
                    ECSCluster(
                        cluster_name="prod-cluster",
                        cluster_arn=arn,
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        ecs = [
            r for r in recs
            if r.resource_type == "ecs_cluster"
        ]
        assert len(ecs) == 1
        assert ecs[0].technology_category == (
            "containers"
        )
        assert ecs[0].service == "ecs"
        assert ecs[0].resource_name == (
            "prod-cluster"
        )
        assert ecs[0].exposure == "private"


# ── ECS Task Definition classification (Batch 7) ─


class TestClassifyECSTaskDefinition:
    """Test ECS task definition classification."""

    def test_task_def_basic(self):
        arn = (
            f"arn:aws:ecs:{REGION}:{ACCOUNT}"
            ":task-definition/web-app:3"
        )
        data = _make_input(
            ecs=ECSData(
                task_definitions=[
                    ECSTaskDefinition(
                        family="web-app",
                        arn=arn,
                        revision=3,
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        td = [
            r for r in recs
            if r.resource_type == (
                "ecs_task_definition"
            )
        ]
        assert len(td) == 1
        assert td[0].technology_category == (
            "containers"
        )
        assert td[0].service == "ecs"
        assert td[0].resource_name == "web-app"
        assert td[0].exposure == "private"


# ── EKS Cluster classification (Batch 7) ─────────


class TestClassifyEKSCluster:
    """Test EKS cluster classification."""

    def test_eks_public_basic(self):
        arn = (
            f"arn:aws:eks:{REGION}:{ACCOUNT}"
            ":cluster/k8s-prod"
        )
        data = _make_input(
            eks=EKSData(
                clusters=[
                    EKSCluster(
                        name="k8s-prod",
                        arn=arn,
                        resources_vpc_config=(
                            ResourcesVpcConfig(
                                endpoint_public_access=True
                            )
                        ),
                        tags={
                            "Environment": "prod"
                        },
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        eks = [
            r for r in recs
            if r.resource_type == "eks_cluster"
        ]
        assert len(eks) == 1
        assert eks[0].technology_category == (
            "containers"
        )
        assert eks[0].service == "eks"
        assert eks[0].resource_name == "k8s-prod"
        assert eks[0].exposure == "internet"
        assert eks[0].environment == "prod"

    def test_eks_private(self):
        arn = (
            f"arn:aws:eks:{REGION}:{ACCOUNT}"
            ":cluster/k8s-internal"
        )
        data = _make_input(
            eks=EKSData(
                clusters=[
                    EKSCluster(
                        name="k8s-internal",
                        arn=arn,
                        resources_vpc_config=(
                            ResourcesVpcConfig(
                                endpoint_public_access=False
                            )
                        ),
                    ),
                ],
            ),
        )
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        eks = [
            r for r in recs
            if r.resource_type == "eks_cluster"
        ]
        assert eks[0].exposure == "private"


# ── Batch 8: Full integration — classify_all 35 types ─


class TestClassifyAll35Types:
    """Verify classify_all handles all 35 resource types
    in a single pass and produces correct records."""

    @staticmethod
    def _full_input():
        """Build a UnifiedAWSInput with one resource
        per each of the 35 taxonomy types."""
        return UnifiedAWSInput(
            account_id=ACCOUNT,
            region=REGION,
            collection_timestamp="2026-03-25T00:00:00Z",
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-full",
                        arn=(
                            f"arn:aws:ec2:{REGION}"
                            f":{ACCOUNT}:instance/i-full"
                        ),
                    ),
                ],
                security_groups=[
                    SecurityGroup(group_id="sg-full"),
                ],
                ebs_volumes=[
                    EBSVolume(
                        volume_id="vol-full",
                        arn=(
                            f"arn:aws:ec2:{REGION}"
                            f":{ACCOUNT}:volume/vol-full"
                        ),
                    ),
                ],
                auto_scaling_groups=[
                    AutoScalingGroup(
                        asg_name="asg-full",
                        arn=(
                            f"arn:aws:autoscaling:{REGION}"
                            f":{ACCOUNT}:autoScalingGroup"
                            ":id:asg-full"
                        ),
                    ),
                ],
                ebs_snapshots=[
                    EBSSnapshot(
                        snapshot_id="snap-ebs",
                        arn=(
                            f"arn:aws:ec2:{REGION}"
                            f":{ACCOUNT}:snapshot"
                            "/snap-ebs"
                        ),
                    ),
                ],
            ),
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="full-bkt",
                        arn="arn:aws:s3:::full-bkt",
                    ),
                ],
            ),
            rds=RDSData(
                db_instances=[
                    RDSInstance(
                        db_instance_id="db-full",
                        db_instance_arn=(
                            f"arn:aws:rds:{REGION}"
                            f":{ACCOUNT}:db:db-full"
                        ),
                    ),
                ],
                aurora_clusters=[
                    AuroraCluster(
                        cluster_id="aurora-full",
                        arn=(
                            f"arn:aws:rds:{REGION}"
                            f":{ACCOUNT}:cluster"
                            ":aurora-full"
                        ),
                    ),
                ],
                snapshots=[
                    RDSSnapshot(
                        db_snapshot_identifier=(
                            "snap-rds"
                        ),
                        db_snapshot_arn=(
                            f"arn:aws:rds:{REGION}"
                            f":{ACCOUNT}:snapshot"
                            ":snap-rds"
                        ),
                    ),
                ],
            ),
            dynamodb=DynamoDBData(
                tables=[
                    DynamoDBTable(
                        table_name="tbl-full",
                        table_arn=(
                            f"arn:aws:dynamodb:{REGION}"
                            f":{ACCOUNT}:table/tbl-full"
                        ),
                    ),
                ],
            ),
            vpc=VPCData(
                vpcs=[VPC(vpc_id="vpc-full")],
                nacls=[
                    NACL(
                        nacl_id="acl-full",
                        vpc_id="vpc-full",
                    ),
                ],
                subnets=[
                    Subnet(
                        subnet_id="sub-full",
                        arn=(
                            f"arn:aws:ec2:{REGION}"
                            f":{ACCOUNT}:subnet/sub-full"
                        ),
                    ),
                ],
                internet_gateways=[
                    InternetGateway(
                        igw_id="igw-full",
                        arn=(
                            f"arn:aws:ec2:{REGION}"
                            f":{ACCOUNT}:internet-gateway"
                            "/igw-full"
                        ),
                    ),
                ],
                nat_gateways=[
                    NATGateway(
                        nat_gateway_id="nat-full",
                        arn=(
                            f"arn:aws:ec2:{REGION}"
                            f":{ACCOUNT}:natgateway"
                            "/nat-full"
                        ),
                    ),
                ],
                network_firewalls=[
                    NetworkFirewall(
                        firewall_name="nfw-full",
                        arn=(
                            f"arn:aws:network-firewall"
                            f":{REGION}:{ACCOUNT}"
                            ":firewall/nfw-full"
                        ),
                    ),
                ],
                waf_web_acls=[
                    WAFWebACL(
                        name="waf-full",
                        arn=(
                            f"arn:aws:wafv2:{REGION}"
                            f":{ACCOUNT}:regional"
                            "/webacl/waf-full"
                        ),
                    ),
                ],
            ),
            elb=ELBData(
                load_balancers=[
                    LoadBalancer(
                        lb_name="lb-full",
                        load_balancer_arn=(
                            f"arn:aws:elasticloadbalancing"
                            f":{REGION}:{ACCOUNT}"
                            ":loadbalancer/app/lb-full"
                        ),
                    ),
                ],
            ),
            cdn=CDNData(
                distributions=[
                    CloudFrontDistribution(
                        distribution_id="E1FULL",
                        arn=(
                            "arn:aws:cloudfront"
                            f"::{ACCOUNT}:distribution"
                            "/E1FULL"
                        ),
                    ),
                ],
                hosted_zones=[
                    Route53HostedZone(
                        hosted_zone_id="Z1FULL",
                        name="example.com",
                    ),
                ],
            ),
            lambda_functions=[
                LambdaFunction(
                    function_name="fn-full",
                    function_arn=(
                        f"arn:aws:lambda:{REGION}"
                        f":{ACCOUNT}:function:fn-full"
                    ),
                ),
            ],
            apigateway=APIGatewayData(
                rest_apis=[
                    APIGatewayAPI(
                        id="api-full",
                        name="api-full",
                        arn=(
                            f"arn:aws:apigateway:{REGION}"
                            "::/restapis/api-full"
                        ),
                        endpoint_configuration=(
                            EndpointConfiguration(
                                types=["REGIONAL"]
                            )
                        ),
                    ),
                ],
            ),
            cloudtrail=CloudTrailData(
                trails=[
                    CloudTrailTrail(
                        name="trail-full",
                        arn=(
                            f"arn:aws:cloudtrail:{REGION}"
                            f":{ACCOUNT}:trail/trail-full"
                        ),
                    ),
                ],
            ),
            guardduty=GuardDutyData(
                detectors=[
                    GuardDutyDetector(
                        detector_id="det-full",
                    ),
                ],
            ),
            cloudwatch=CloudWatchData(
                alarms=[
                    CloudWatchAlarm(
                        alarm_name="alarm-full",
                    ),
                ],
            ),
            iam=IAMData(
                users=[
                    IAMUser(
                        name="user-full",
                        arn=(
                            f"arn:aws:iam::{ACCOUNT}"
                            ":user/user-full"
                        ),
                    ),
                ],
                groups=[
                    IAMGroup(
                        group_name="grp-full",
                        arn=(
                            f"arn:aws:iam::{ACCOUNT}"
                            ":group/grp-full"
                        ),
                    ),
                ],
                roles=[
                    IAMRole(
                        role_name="role-full",
                        arn=(
                            f"arn:aws:iam::{ACCOUNT}"
                            ":role/role-full"
                        ),
                    ),
                ],
                customer_managed_policies=[
                    IAMPolicy(
                        policy_name="pol-full",
                        arn=(
                            f"arn:aws:iam::{ACCOUNT}"
                            ":policy/pol-full"
                        ),
                    ),
                ],
            ),
            kms=KMSData(
                keys=[
                    KMSKey(
                        key_id="key-full",
                        arn=(
                            f"arn:aws:kms:{REGION}"
                            f":{ACCOUNT}:key/key-full"
                        ),
                    ),
                ],
            ),
            secrets_manager=SecretsManagerData(
                secrets=[
                    Secret(
                        name="sec-full",
                        arn=(
                            f"arn:aws:secretsmanager"
                            f":{REGION}:{ACCOUNT}"
                            ":secret:sec-full"
                        ),
                    ),
                ],
            ),
            ecr=ECRData(
                repositories=[
                    ECRRepository(
                        repository_name="ecr-full",
                        repository_arn=(
                            f"arn:aws:ecr:{REGION}"
                            f":{ACCOUNT}:repository"
                            "/ecr-full"
                        ),
                    ),
                ],
            ),
            ecs=ECSData(
                clusters=[
                    ECSCluster(
                        cluster_name="ecs-full",
                        cluster_arn=(
                            f"arn:aws:ecs:{REGION}"
                            f":{ACCOUNT}:cluster/ecs-full"
                        ),
                    ),
                ],
                task_definitions=[
                    ECSTaskDefinition(
                        family="td-full",
                        task_definition_arn=(
                            f"arn:aws:ecs:{REGION}"
                            f":{ACCOUNT}:task-definition"
                            "/td-full:1"
                        ),
                    ),
                ],
            ),
            eks=EKSData(
                clusters=[
                    EKSCluster(
                        name="eks-full",
                        arn=(
                            f"arn:aws:eks:{REGION}"
                            f":{ACCOUNT}:cluster/eks-full"
                        ),
                    ),
                ],
            ),
        )

    def test_returns_exactly_35_records(self):
        """classify_all with all 35 types populated
        returns exactly 35 ResourceRecords."""
        data = self._full_input()
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)
        assert len(recs) == 35

    def test_all_35_types_present(self):
        """Every taxonomy type appears in the results."""
        from app.inventory.taxonomy import (
            RESOURCE_TAXONOMY,
        )

        data = self._full_input()
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        result_types = {r.resource_type for r in recs}
        expected_types = set(RESOURCE_TAXONOMY.keys())
        assert result_types == expected_types

    def test_all_records_have_correct_pk_sk(self):
        """Every record has valid pk and sk format."""
        data = self._full_input()
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        for r in recs:
            assert "#" in r.pk
            assert r.pk.startswith(ACCOUNT)
            assert "#" in r.sk
            assert r.sk.startswith(r.resource_type)

    def test_all_records_have_valid_category(self):
        """Every record's category matches taxonomy."""
        from app.inventory.taxonomy import (
            RESOURCE_TAXONOMY,
        )

        data = self._full_input()
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        for r in recs:
            expected_cat, expected_svc = (
                RESOURCE_TAXONOMY[r.resource_type]
            )
            assert r.technology_category == expected_cat, (
                f"{r.resource_type}: "
                f"got {r.technology_category}, "
                f"expected {expected_cat}"
            )
            assert r.service == expected_svc, (
                f"{r.resource_type}: "
                f"got {r.service}, "
                f"expected {expected_svc}"
            )

    def test_all_records_are_active(self):
        """All freshly classified records are active."""
        data = self._full_input()
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        for r in recs:
            assert r.is_active is True

    def test_all_records_have_last_seen(self):
        """All records have a last_seen timestamp."""
        data = self._full_input()
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        for r in recs:
            assert r.last_seen is not None
            assert "T" in r.last_seen

    def test_exposure_values_are_valid(self):
        """All exposure values are in the valid set."""
        valid = {"internet", "private", "unknown"}
        data = self._full_input()
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        for r in recs:
            assert r.exposure in valid, (
                f"{r.resource_type}: "
                f"invalid exposure '{r.exposure}'"
            )

    def test_internet_exposed_types(self):
        """Types with known internet exposure logic."""
        data = self._full_input()
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        by_type = {r.resource_type: r for r in recs}

        # Internet gateway is always internet
        assert by_type[
            "internet_gateway"
        ].exposure == "internet"
        # CloudFront is always internet
        assert by_type[
            "cloudfront_distribution"
        ].exposure == "internet"
        # Route53 public zone is internet
        assert by_type[
            "route53_hosted_zone"
        ].exposure == "internet"
        # Lambda without VPC is internet
        assert by_type[
            "lambda_function"
        ].exposure == "internet"
        # API Gateway REGIONAL is internet
        assert by_type[
            "api_gateway"
        ].exposure == "internet"
        # EKS default public access is internet
        assert by_type[
            "eks_cluster"
        ].exposure == "internet"

    def test_private_types(self):
        """Types that default to private."""
        data = self._full_input()
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        by_type = {r.resource_type: r for r in recs}

        private_types = [
            "ebs_volume", "security_group", "vpc",
            "kms_key", "secret", "iam_user",
            "iam_group", "iam_role", "iam_policy",
            "cloudtrail", "guardduty",
            "cloudwatch_alarm", "network_acl",
            "nat_gateway", "network_firewall",
            "waf_web_acl", "aurora_cluster",
            "dynamodb_table", "ecr_repository",
            "ecs_cluster", "ecs_task_definition",
            "auto_scaling_group",
        ]
        for t in private_types:
            assert by_type[t].exposure == "private", (
                f"{t}: expected private, "
                f"got {by_type[t].exposure}"
            )

    def test_no_duplicate_resource_ids(self):
        """All resource_ids in the output are unique."""
        data = self._full_input()
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        ids = [r.resource_id for r in recs]
        assert len(ids) == len(set(ids))

    def test_enrich_violations_across_types(self):
        """Enriching violations works across multiple
        resource types in a single batch."""
        data = self._full_input()
        clf = ResourceClassifier(ACCOUNT, REGION)
        recs = clf.classify_all(data)

        class FakeViolation:
            def __init__(self, res, sev):
                self.resource = res
                self.severity = sev
                self.status = "alarm"
                self.check_id = "test_check"

        violations = [
            FakeViolation(
                "arn:aws:s3:::full-bkt", "critical"
            ),
            FakeViolation(
                "arn:aws:s3:::full-bkt", "high"
            ),
            FakeViolation(
                f"arn:aws:ec2:{REGION}:{ACCOUNT}"
                ":instance/i-full",
                "medium",
            ),
        ]

        clf.enrich_with_violations(recs, violations)

        by_type = {r.resource_type: r for r in recs}
        s3 = by_type["s3_bucket"]
        assert s3.violation_count == 2
        assert s3.critical_violations == 1
        assert s3.high_violations == 1
        assert s3.risk_score == 40  # 25 + 15

        ec2 = by_type["ec2_instance"]
        assert ec2.violation_count == 1
        assert ec2.risk_score == 8  # medium=8

        # Unenriched types have zero
        kms = by_type["kms_key"]
        assert kms.violation_count == 0
        assert kms.risk_score == 0
