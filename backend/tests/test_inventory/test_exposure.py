"""Tests for ExposureClassifier — graph-path network
exposure analysis.

Tests walk the network path per resource type:
  EC2: public_ip → SG ingress → NACL inbound
  S3:  public_access_block flags
  RDS: publicly_accessible flag
  Lambda: VPC config presence
"""

from app.inventory.exposure import ExposureClassifier
from app.models.aws_input import (
    EC2Data,
    EC2Instance,
    IngressRule,
    LambdaData,
    LambdaFunction,
    LambdaVPCConfig,
    NACL,
    NACLEntry,
    PublicAccessBlock,
    RDSData,
    RDSInstance,
    S3Bucket,
    S3Data,
    SecurityGroup,
    UnifiedAWSInput,
    VPC,
    VPCData,
)

ACCOUNT = "123456789012"
REGION = "us-east-1"
TS = "2026-03-18T10:00:00Z"


def _input(**overrides) -> UnifiedAWSInput:
    """Build a minimal UnifiedAWSInput."""
    defaults = {
        "account_id": ACCOUNT,
        "region": REGION,
        "collection_timestamp": TS,
    }
    defaults.update(overrides)
    return UnifiedAWSInput(**defaults)


def _sg_open(
    group_id="sg-open",
    vpc_id="vpc-1",
    cidr="0.0.0.0/0",
    from_port=0,
    to_port=65535,
    protocol="-1",
) -> SecurityGroup:
    """SG that allows all traffic from cidr."""
    return SecurityGroup(
        group_id=group_id,
        vpc_id=vpc_id,
        ingress_rules=[
            IngressRule(
                from_port=from_port,
                to_port=to_port,
                protocol=protocol,
                cidr=cidr,
            )
        ],
    )


def _sg_restricted(
    group_id="sg-priv",
    vpc_id="vpc-1",
) -> SecurityGroup:
    """SG that only allows internal traffic."""
    return SecurityGroup(
        group_id=group_id,
        vpc_id=vpc_id,
        ingress_rules=[
            IngressRule(
                from_port=443,
                to_port=443,
                protocol="tcp",
                cidr="10.0.0.0/8",
            )
        ],
    )


def _nacl_allow_all(
    vpc_id="vpc-1",
) -> NACL:
    """NACL that allows all inbound from 0.0.0.0/0."""
    return NACL(
        nacl_id="acl-allow",
        vpc_id=vpc_id,
        entries=[
            NACLEntry(
                rule_number=100,
                protocol="-1",
                cidr_block="0.0.0.0/0",
                rule_action="allow",
                egress=False,
            ),
            # Default deny (always present)
            NACLEntry(
                rule_number=32767,
                protocol="-1",
                cidr_block="0.0.0.0/0",
                rule_action="deny",
                egress=False,
            ),
        ],
    )


def _nacl_deny_all(
    vpc_id="vpc-1",
) -> NACL:
    """NACL that denies all inbound (only default deny)."""
    return NACL(
        nacl_id="acl-deny",
        vpc_id=vpc_id,
        entries=[
            NACLEntry(
                rule_number=32767,
                protocol="-1",
                cidr_block="0.0.0.0/0",
                rule_action="deny",
                egress=False,
            ),
        ],
    )


# --------------------------------------------------
# EC2 Exposure Tests
# --------------------------------------------------


class TestEC2Exposure:
    """EC2 exposure = public_ip + SG open + NACL allows."""

    def test_public_ip_open_sg_open_nacl(self):
        """Full open path → internet."""
        data = _input(
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-exposed",
                        public_ip="1.2.3.4",
                        vpc_id="vpc-1",
                        security_groups=["sg-open"],
                    )
                ],
                security_groups=[_sg_open()],
            ),
            vpc=VPCData(
                vpcs=[VPC(vpc_id="vpc-1")],
                nacls=[_nacl_allow_all()],
            ),
        )
        cls = ExposureClassifier(data)
        result = cls.classify_ec2(
            data.ec2.instances[0]
        )
        assert result == "internet"

    def test_no_public_ip(self):
        """No public IP → private regardless of SG."""
        data = _input(
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-priv",
                        public_ip=None,
                        vpc_id="vpc-1",
                        security_groups=["sg-open"],
                    )
                ],
                security_groups=[_sg_open()],
            ),
            vpc=VPCData(
                vpcs=[VPC(vpc_id="vpc-1")],
                nacls=[_nacl_allow_all()],
            ),
        )
        cls = ExposureClassifier(data)
        result = cls.classify_ec2(
            data.ec2.instances[0]
        )
        assert result == "private"

    def test_restricted_sg_blocks(self):
        """Public IP but SG only allows 10.0.0.0/8 → private."""
        data = _input(
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-sg-block",
                        public_ip="1.2.3.4",
                        vpc_id="vpc-1",
                        security_groups=["sg-priv"],
                    )
                ],
                security_groups=[_sg_restricted()],
            ),
            vpc=VPCData(
                vpcs=[VPC(vpc_id="vpc-1")],
                nacls=[_nacl_allow_all()],
            ),
        )
        cls = ExposureClassifier(data)
        result = cls.classify_ec2(
            data.ec2.instances[0]
        )
        assert result == "private"

    def test_nacl_deny_blocks(self):
        """Public IP + open SG but NACL denies → private."""
        data = _input(
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-nacl-block",
                        public_ip="1.2.3.4",
                        vpc_id="vpc-1",
                        security_groups=["sg-open"],
                    )
                ],
                security_groups=[_sg_open()],
            ),
            vpc=VPCData(
                vpcs=[VPC(vpc_id="vpc-1")],
                nacls=[_nacl_deny_all()],
            ),
        )
        cls = ExposureClassifier(data)
        result = cls.classify_ec2(
            data.ec2.instances[0]
        )
        assert result == "private"

    def test_nacl_deny_before_allow(self):
        """NACL deny rule (lower number) overrides allow."""
        nacl = NACL(
            nacl_id="acl-mixed",
            vpc_id="vpc-1",
            entries=[
                NACLEntry(
                    rule_number=50,
                    protocol="-1",
                    cidr_block="0.0.0.0/0",
                    rule_action="deny",
                    egress=False,
                ),
                NACLEntry(
                    rule_number=100,
                    protocol="-1",
                    cidr_block="0.0.0.0/0",
                    rule_action="allow",
                    egress=False,
                ),
            ],
        )
        data = _input(
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-deny-first",
                        public_ip="1.2.3.4",
                        vpc_id="vpc-1",
                        security_groups=["sg-open"],
                    )
                ],
                security_groups=[_sg_open()],
            ),
            vpc=VPCData(
                vpcs=[VPC(vpc_id="vpc-1")],
                nacls=[nacl],
            ),
        )
        cls = ExposureClassifier(data)
        result = cls.classify_ec2(
            data.ec2.instances[0]
        )
        assert result == "private"

    def test_ipv6_open_cidr(self):
        """SG open to ::/0 (IPv6 any) → internet."""
        sg = _sg_open(cidr="::/0")
        data = _input(
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-ipv6",
                        public_ip="1.2.3.4",
                        vpc_id="vpc-1",
                        security_groups=["sg-open"],
                    )
                ],
                security_groups=[sg],
            ),
            vpc=VPCData(
                vpcs=[VPC(vpc_id="vpc-1")],
                nacls=[_nacl_allow_all()],
            ),
        )
        cls = ExposureClassifier(data)
        result = cls.classify_ec2(
            data.ec2.instances[0]
        )
        assert result == "internet"

    def test_multiple_sgs_any_open(self):
        """Multiple SGs — one open is enough."""
        data = _input(
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-multi-sg",
                        public_ip="1.2.3.4",
                        vpc_id="vpc-1",
                        security_groups=[
                            "sg-priv",
                            "sg-open",
                        ],
                    )
                ],
                security_groups=[
                    _sg_restricted(),
                    _sg_open(),
                ],
            ),
            vpc=VPCData(
                vpcs=[VPC(vpc_id="vpc-1")],
                nacls=[_nacl_allow_all()],
            ),
        )
        cls = ExposureClassifier(data)
        result = cls.classify_ec2(
            data.ec2.instances[0]
        )
        assert result == "internet"

    def test_no_vpc_id(self):
        """EC2 without vpc_id → unknown."""
        data = _input(
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-no-vpc",
                        public_ip="1.2.3.4",
                        vpc_id=None,
                        security_groups=["sg-open"],
                    )
                ],
                security_groups=[_sg_open()],
            ),
        )
        cls = ExposureClassifier(data)
        result = cls.classify_ec2(
            data.ec2.instances[0]
        )
        assert result == "unknown"

    def test_missing_sg_data(self):
        """SG referenced but not in data → unknown."""
        data = _input(
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-missing-sg",
                        public_ip="1.2.3.4",
                        vpc_id="vpc-1",
                        security_groups=["sg-ghost"],
                    )
                ],
                security_groups=[],
            ),
            vpc=VPCData(
                vpcs=[VPC(vpc_id="vpc-1")],
                nacls=[_nacl_allow_all()],
            ),
        )
        cls = ExposureClassifier(data)
        result = cls.classify_ec2(
            data.ec2.instances[0]
        )
        assert result == "unknown"

    def test_no_nacl_for_vpc(self):
        """VPC has no NACL → treat as open (AWS default)."""
        data = _input(
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-no-nacl",
                        public_ip="1.2.3.4",
                        vpc_id="vpc-1",
                        security_groups=["sg-open"],
                    )
                ],
                security_groups=[_sg_open()],
            ),
            vpc=VPCData(
                vpcs=[VPC(vpc_id="vpc-1")],
                nacls=[],
            ),
        )
        cls = ExposureClassifier(data)
        result = cls.classify_ec2(
            data.ec2.instances[0]
        )
        assert result == "internet"

    def test_egress_rules_ignored(self):
        """NACL egress rules are not considered for
        inbound exposure."""
        nacl = NACL(
            nacl_id="acl-egress-only",
            vpc_id="vpc-1",
            entries=[
                NACLEntry(
                    rule_number=100,
                    protocol="-1",
                    cidr_block="0.0.0.0/0",
                    rule_action="allow",
                    egress=True,
                ),
                NACLEntry(
                    rule_number=32767,
                    protocol="-1",
                    cidr_block="0.0.0.0/0",
                    rule_action="deny",
                    egress=False,
                ),
            ],
        )
        data = _input(
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-egress",
                        public_ip="1.2.3.4",
                        vpc_id="vpc-1",
                        security_groups=["sg-open"],
                    )
                ],
                security_groups=[_sg_open()],
            ),
            vpc=VPCData(
                vpcs=[VPC(vpc_id="vpc-1")],
                nacls=[nacl],
            ),
        )
        cls = ExposureClassifier(data)
        result = cls.classify_ec2(
            data.ec2.instances[0]
        )
        assert result == "private"


# --------------------------------------------------
# S3 Exposure Tests
# --------------------------------------------------


class TestS3Exposure:
    """S3 exposure = public_access_block flags."""

    def test_all_flags_false_is_internet(self):
        """All public access blocks disabled → internet."""
        bucket = S3Bucket(
            name="open-bucket",
            arn="arn:aws:s3:::open-bucket",
            public_access_block=PublicAccessBlock(
                block_public_acls=False,
                block_public_policy=False,
                ignore_public_acls=False,
                restrict_public_buckets=False,
            ),
        )
        data = _input(
            s3=S3Data(buckets=[bucket])
        )
        cls = ExposureClassifier(data)
        result = cls.classify_s3(bucket)
        assert result == "internet"

    def test_all_flags_true_is_private(self):
        """All blocks enabled → private."""
        bucket = S3Bucket(
            name="locked-bucket",
            arn="arn:aws:s3:::locked-bucket",
            public_access_block=PublicAccessBlock(
                block_public_acls=True,
                block_public_policy=True,
                ignore_public_acls=True,
                restrict_public_buckets=True,
            ),
        )
        data = _input(
            s3=S3Data(buckets=[bucket])
        )
        cls = ExposureClassifier(data)
        result = cls.classify_s3(bucket)
        assert result == "private"

    def test_partial_block_is_internet(self):
        """Any flag False → internet (needs all 4 True)."""
        bucket = S3Bucket(
            name="partial-bucket",
            arn="arn:aws:s3:::partial-bucket",
            public_access_block=PublicAccessBlock(
                block_public_acls=True,
                block_public_policy=True,
                ignore_public_acls=False,
                restrict_public_buckets=True,
            ),
        )
        data = _input(
            s3=S3Data(buckets=[bucket])
        )
        cls = ExposureClassifier(data)
        result = cls.classify_s3(bucket)
        assert result == "internet"


# --------------------------------------------------
# RDS Exposure Tests
# --------------------------------------------------


class TestRDSExposure:
    """RDS exposure = publicly_accessible flag."""

    def test_publicly_accessible_true(self):
        """publicly_accessible=True → internet."""
        db = RDSInstance(
            db_instance_id="db-pub",
            publicly_accessible=True,
        )
        data = _input(
            rds=RDSData(db_instances=[db])
        )
        cls = ExposureClassifier(data)
        result = cls.classify_rds(db)
        assert result == "internet"

    def test_publicly_accessible_false(self):
        """publicly_accessible=False → private."""
        db = RDSInstance(
            db_instance_id="db-priv",
            publicly_accessible=False,
        )
        data = _input(
            rds=RDSData(db_instances=[db])
        )
        cls = ExposureClassifier(data)
        result = cls.classify_rds(db)
        assert result == "private"


# --------------------------------------------------
# Lambda Exposure Tests
# --------------------------------------------------


class TestLambdaExposure:
    """Lambda exposure = VPC config presence."""

    def test_no_vpc_is_internet(self):
        """Lambda not in VPC → internet (default)."""
        fn = LambdaFunction(
            function_name="fn-public",
            vpc_config=LambdaVPCConfig(
                subnet_ids=[],
                security_group_ids=[],
            ),
        )
        data = _input(
            lambda_functions=LambdaData(
                functions=[fn]
            )
        )
        cls = ExposureClassifier(data)
        result = cls.classify_lambda(fn)
        assert result == "internet"

    def test_in_vpc_is_private(self):
        """Lambda in VPC → private (needs NAT for internet)."""
        fn = LambdaFunction(
            function_name="fn-vpc",
            vpc_config=LambdaVPCConfig(
                subnet_ids=["subnet-1"],
                security_group_ids=["sg-1"],
            ),
        )
        data = _input(
            lambda_functions=LambdaData(
                functions=[fn]
            )
        )
        cls = ExposureClassifier(data)
        result = cls.classify_lambda(fn)
        assert result == "private"


# --------------------------------------------------
# Generic classify() Dispatch
# --------------------------------------------------


class TestClassifyDispatch:
    """Test the generic classify() dispatcher."""

    def test_dispatches_ec2(self):
        """classify('ec2_instance', ...) → EC2 path."""
        data = _input(
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-1",
                        public_ip="1.2.3.4",
                        vpc_id="vpc-1",
                        security_groups=["sg-open"],
                    )
                ],
                security_groups=[_sg_open()],
            ),
            vpc=VPCData(
                vpcs=[VPC(vpc_id="vpc-1")],
                nacls=[_nacl_allow_all()],
            ),
        )
        cls = ExposureClassifier(data)
        assert (
            cls.classify("ec2_instance", "i-1")
            == "internet"
        )

    def test_dispatches_s3(self):
        """classify('s3_bucket', ...) → S3 path."""
        bucket = S3Bucket(
            name="bkt",
            arn="arn:aws:s3:::bkt",
            public_access_block=PublicAccessBlock(
                block_public_acls=True,
                block_public_policy=True,
                ignore_public_acls=True,
                restrict_public_buckets=True,
            ),
        )
        data = _input(
            s3=S3Data(buckets=[bucket])
        )
        cls = ExposureClassifier(data)
        assert (
            cls.classify("s3_bucket", "bkt")
            == "private"
        )

    def test_dispatches_rds(self):
        """classify('rds_instance', ...) → RDS path."""
        db = RDSInstance(
            db_instance_id="db-1",
            publicly_accessible=True,
        )
        data = _input(
            rds=RDSData(db_instances=[db])
        )
        cls = ExposureClassifier(data)
        assert (
            cls.classify("rds_instance", "db-1")
            == "internet"
        )

    def test_dispatches_lambda(self):
        """classify('lambda_function', ...) → Lambda path."""
        fn = LambdaFunction(
            function_name="fn-1",
        )
        data = _input(
            lambda_functions=LambdaData(
                functions=[fn]
            )
        )
        cls = ExposureClassifier(data)
        assert (
            cls.classify("lambda_function", "fn-1")
            == "internet"
        )

    def test_unknown_type_returns_unknown(self):
        """Unrecognized resource type → unknown."""
        data = _input()
        cls = ExposureClassifier(data)
        assert (
            cls.classify("cloudtrail", "trail-1")
            == "unknown"
        )

    def test_missing_resource_returns_unknown(self):
        """Resource ID not found → unknown."""
        data = _input()
        cls = ExposureClassifier(data)
        assert (
            cls.classify("ec2_instance", "i-ghost")
            == "unknown"
        )


# --------------------------------------------------
# Batch 8: Exposure dispatch for all new types
# --------------------------------------------------


class TestNewTypeDispatchReturnsUnknown:
    """New resource types added in Batches 1-7 compute
    exposure inline in the classifier, NOT via
    ExposureClassifier.classify(). Verify the dispatch
    returns 'unknown' for all non-dispatched types so
    the inline logic in classifier.py takes effect."""

    _NEW_TYPES = [
        "subnet",
        "internet_gateway",
        "nat_gateway",
        "network_acl",
        "network_firewall",
        "waf_web_acl",
        "load_balancer",
        "cloudfront_distribution",
        "route53_hosted_zone",
        "auto_scaling_group",
        "ebs_snapshot",
        "rds_snapshot",
        "aurora_cluster",
        "dynamodb_table",
        "api_gateway",
        "ecr_repository",
        "ecs_cluster",
        "ecs_task_definition",
        "eks_cluster",
        "iam_user",
        "iam_group",
        "iam_role",
        "iam_policy",
        "cloudtrail",
        "guardduty",
        "cloudwatch_alarm",
        "ebs_volume",
        "security_group",
        "vpc",
        "kms_key",
        "secret",
    ]

    def test_all_non_dispatched_types_return_unknown(
        self,
    ):
        """Types without dedicated classify_TYPE method
        in ExposureClassifier return 'unknown'."""
        data = _input()
        cls = ExposureClassifier(data)
        for rtype in self._NEW_TYPES:
            result = cls.classify(rtype, "fake-id")
            assert result == "unknown", (
                f"{rtype}: expected unknown, "
                f"got {result}"
            )
