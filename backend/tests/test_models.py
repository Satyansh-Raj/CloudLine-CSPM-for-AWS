"""Tests for Pydantic models."""

from app.models.aws_input import (
    NACL,
    VPC,
    AccessKey,
    AccountSummary,
    AttachedPolicy,
    BackupData,
    BucketEncryption,
    BucketLogging,
    CloudTrailTrail,
    CloudWatchAlarm,
    CollectionMode,
    ConfigRecorder,
    EBSVolume,
    EC2Data,
    EC2Instance,
    FlowLog,
    GuardDutyDetector,
    IAMData,
    IAMUser,
    IngressRule,
    InstanceRole,
    KMSKey,
    LambdaFunction,
    LambdaVPCConfig,
    MetadataOptions,
    NACLEntry,
    PasswordPolicy,
    PublicAccessBlock,
    RDSInstance,
    S3Bucket,
    S3Data,
    Secret,
    SecurityGroup,
    UnifiedAWSInput,
)


class TestUnifiedAWSInput:
    def test_minimal(self):
        doc = UnifiedAWSInput(
            account_id="123456789012",
            region="us-east-1",
            collection_timestamp="2026-01-01T00:00:00Z",
        )
        assert doc.account_id == "123456789012"
        assert doc.collection_mode == "full"

    def test_full_document(self):
        doc = UnifiedAWSInput(
            account_id="123456789012",
            region="us-east-1",
            collection_timestamp="2026-01-01T00:00:00Z",
            iam=IAMData(
                account_summary=AccountSummary(
                    mfa_enabled=True, users=5
                ),
                password_policy=PasswordPolicy(
                    minimum_length=14,
                    require_symbols=True,
                ),
                users=[
                    IAMUser(
                        name="admin",
                        arn="arn:aws:iam::123:user/admin",
                    )
                ],
            ),
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="bucket",
                        arn="arn:aws:s3:::bucket",
                    )
                ]
            ),
            ec2=EC2Data(
                instances=[
                    EC2Instance(
                        instance_id="i-123"
                    )
                ]
            ),
        )
        assert doc.iam.account_summary.users == 5
        assert len(doc.s3.buckets) == 1
        assert len(doc.ec2.instances) == 1

    def test_serialization(self):
        doc = UnifiedAWSInput(
            account_id="123",
            region="us-east-1",
            collection_timestamp="2026-01-01T00:00:00Z",
        )
        d = doc.model_dump()
        assert d["account_id"] == "123"
        assert "iam" in d
        assert "s3" in d


class TestIAMModels:
    def test_access_key(self):
        k = AccessKey(
            key_id="AKIA123",
            status="Active",
            created_date="2026-01-01",
        )
        assert k.key_id == "AKIA123"
        assert k.last_used_days_ago is None

    def test_attached_policy(self):
        p = AttachedPolicy(
            policy_name="Admin",
            policy_arn="arn:aws:iam::aws:policy/Admin",
        )
        assert p.policy_name == "Admin"

    def test_iam_user(self):
        u = IAMUser(
            name="user1",
            arn="arn:aws:iam::123:user/user1",
            mfa_enabled=True,
        )
        assert u.mfa_enabled is True
        assert u.access_keys == []

    def test_password_policy_defaults(self):
        pp = PasswordPolicy()
        assert pp.minimum_length == 8
        assert pp.require_symbols is False


class TestS3Models:
    def test_public_access_block(self):
        pab = PublicAccessBlock(
            block_public_acls=True
        )
        assert pab.block_public_acls is True
        assert pab.block_public_policy is False

    def test_encryption(self):
        e = BucketEncryption(
            enabled=True, type="AES256"
        )
        assert e.enabled is True

    def test_logging(self):
        lg = BucketLogging(
            enabled=True,
            target_bucket="logs",
        )
        assert lg.target_bucket == "logs"

    def test_bucket(self):
        b = S3Bucket(
            name="test",
            arn="arn:aws:s3:::test",
        )
        assert b.versioning is False
        assert b.mfa_delete is False


class TestEC2Models:
    def test_metadata_options(self):
        m = MetadataOptions()
        assert m.http_tokens == "optional"

    def test_instance_role(self):
        r = InstanceRole(
            role_name="role",
            role_arn="arn:aws:iam::123:role/role",
        )
        assert r.attached_policies == []

    def test_ingress_rule(self):
        r = IngressRule(
            from_port=22,
            to_port=22,
            protocol="tcp",
            cidr="0.0.0.0/0",
        )
        assert r.from_port == 22

    def test_security_group(self):
        sg = SecurityGroup(group_id="sg-123")
        assert sg.ingress_rules == []

    def test_ebs_volume(self):
        v = EBSVolume(volume_id="vol-123")
        assert v.encrypted is False

    def test_ec2_instance(self):
        i = EC2Instance(instance_id="i-123")
        assert i.state == "running"
        assert i.iam_role is None


class TestVPCModels:
    def test_vpc(self):
        v = VPC(vpc_id="vpc-123")
        assert v.is_default is False

    def test_flow_log(self):
        f = FlowLog(
            flow_log_id="fl-123",
            resource_id="vpc-123",
        )
        assert f.traffic_type == "ALL"

    def test_nacl_entry(self):
        e = NACLEntry(
            rule_number=100, protocol="-1"
        )
        assert e.rule_action == "allow"

    def test_nacl(self):
        n = NACL(nacl_id="acl-123")
        assert n.entries == []


class TestRDSModels:
    def test_rds_instance(self):
        r = RDSInstance(db_instance_id="db-1")
        assert r.publicly_accessible is False
        assert r.backup_retention_period == 0


class TestLambdaModels:
    def test_vpc_config(self):
        v = LambdaVPCConfig()
        assert v.subnet_ids == []

    def test_function(self):
        f = LambdaFunction(
            function_name="fn1"
        )
        assert f.tracing_config == "PassThrough"
        assert f.environment_encryption is False


class TestLoggingModels:
    def test_trail(self):
        t = CloudTrailTrail(name="trail")
        assert t.is_logging is False

    def test_config_recorder(self):
        r = ConfigRecorder(name="default")
        assert r.recording is False

    def test_alarm(self):
        a = CloudWatchAlarm(
            alarm_name="test"
        )
        assert a.state == "OK"

    def test_guardduty(self):
        d = GuardDutyDetector(
            detector_id="abc"
        )
        assert d.status == "DISABLED"


class TestKMSModels:
    def test_key(self):
        k = KMSKey(key_id="key-1")
        assert k.key_rotation_enabled is False

    def test_secret(self):
        s = Secret(name="secret-1")
        assert s.rotation_enabled is False


class TestBackupModel:
    def test_defaults(self):
        b = BackupData()
        assert b.plans == []
        assert b.protected_resources == []


class TestCollectionMode:
    def test_values(self):
        assert CollectionMode.FULL == "full"
        assert (
            CollectionMode.INCREMENTAL
            == "incremental"
        )
