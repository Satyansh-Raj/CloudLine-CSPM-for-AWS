"""Tests for Pydantic models."""

from app.models.aws_input import (
    NACL,
    VPC,
    AccessKey,
    AccountSummary,
    APIGateway,
    APIGatewayData,
    AttachedPolicy,
    AutoScalingGroup,
    BackupData,
    BucketEncryption,
    BucketLogging,
    CDNData,
    CloudFrontDistribution,
    ContainerData,
    AuroraCluster,
    CloudTrailTrail,
    CloudWatchAlarm,
    CollectionMode,
    ConfigRecorder,
    DynamoDBData,
    DynamoDBTable,
    EBSSnapshot,
    EBSVolume,
    EC2Data,
    EC2Instance,
    ECRRepository,
    ECSCluster,
    ECSTaskDefinition,
    EKSCluster,
    ELBData,
    FlowLog,
    GuardDutyDetector,
    IAMData,
    IAMGroup,
    IAMPolicy,
    IAMRole,
    IAMUser,
    IngressRule,
    InstanceRole,
    InternetGateway,
    KMSKey,
    LambdaFunction,
    LambdaVPCConfig,
    LoadBalancer,
    MetadataOptions,
    NACLEntry,
    NATGateway,
    NetworkFirewall,
    PasswordPolicy,
    PublicAccessBlock,
    RDSData,
    RDSInstance,
    RDSSnapshot,
    Route53HostedZone,
    S3Bucket,
    S3Data,
    Secret,
    SecurityGroup,
    Subnet,
    UnifiedAWSInput,
    VPCData,
    WAFWebACL,
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

    def test_iam_group(self):
        g = IAMGroup(
            group_name="admins",
            arn="arn:aws:iam::123:group/admins",
        )
        assert g.group_name == "admins"
        assert g.attached_policies == []

    def test_iam_role(self):
        r = IAMRole(
            role_name="LambdaExec",
            arn="arn:aws:iam::123:role/LambdaExec",
        )
        assert r.role_name == "LambdaExec"
        assert r.assume_role_policy == {}
        assert r.tags == {}

    def test_iam_policy(self):
        p = IAMPolicy(
            policy_name="Admin",
            arn="arn:aws:iam::123:policy/Admin",
        )
        assert p.attachment_count == 0
        assert p.is_attachable is True

    def test_iam_data_has_groups_roles_policies(self):
        d = IAMData()
        assert d.groups == []
        assert d.roles == []
        assert d.policies == []


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

    def test_subnet(self):
        s = Subnet(subnet_id="subnet-1")
        assert s.map_public_ip_on_launch is False
        assert s.vpc_id == ""
        assert s.tags == {}

    def test_internet_gateway(self):
        igw = InternetGateway(igw_id="igw-1")
        assert igw.attached_vpcs == []
        assert igw.tags == {}

    def test_nat_gateway(self):
        nat = NATGateway(nat_gateway_id="nat-1")
        assert nat.state == "available"
        assert nat.vpc_id == ""

    def test_network_firewall(self):
        nf = NetworkFirewall(
            firewall_name="prod-fw"
        )
        assert nf.vpc_id == ""
        assert nf.firewall_policy_arn == ""

    def test_waf_web_acl(self):
        waf = WAFWebACL(name="my-acl")
        assert waf.scope == "REGIONAL"
        assert waf.web_acl_id == ""

    def test_vpc_data_has_new_fields(self):
        d = VPCData()
        assert d.subnets == []
        assert d.internet_gateways == []
        assert d.nat_gateways == []
        assert d.network_firewalls == []
        assert d.waf_web_acls == []


class TestELBCDNModels:
    def test_load_balancer(self):
        lb = LoadBalancer(lb_name="web-lb")
        assert lb.scheme == "internal"
        assert lb.lb_type == "application"

    def test_cloudfront_distribution(self):
        cf = CloudFrontDistribution(
            distribution_id="E123"
        )
        assert cf.enabled is True

    def test_route53_hosted_zone(self):
        z = Route53HostedZone(
            hosted_zone_id="Z1"
        )
        assert z.is_private is False
        assert z.record_count == 0

    def test_elb_data_defaults(self):
        d = ELBData()
        assert d.load_balancers == []

    def test_cdn_data_defaults(self):
        d = CDNData()
        assert d.distributions == []
        assert d.hosted_zones == []


class TestRDSModels:
    def test_rds_instance(self):
        r = RDSInstance(db_instance_id="db-1")
        assert r.publicly_accessible is False
        assert r.backup_retention_period == 0

    def test_aurora_cluster(self):
        c = AuroraCluster(cluster_id="my-aurora")
        assert c.storage_encrypted is False
        assert c.engine == ""

    def test_rds_snapshot(self):
        s = RDSSnapshot(snapshot_id="snap-1")
        assert s.is_public is False
        assert s.encrypted is False

    def test_rds_data_has_aurora_and_snapshots(self):
        d = RDSData()
        assert d.aurora_clusters == []
        assert d.snapshots == []


class TestDynamoDBModels:
    def test_dynamodb_table(self):
        t = DynamoDBTable(table_name="users")
        assert t.billing_mode == "PROVISIONED"
        assert t.point_in_time_recovery is False

    def test_dynamodb_data_defaults(self):
        d = DynamoDBData()
        assert d.tables == []


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


class TestAutoScalingGroupModel:
    def test_defaults(self):
        a = AutoScalingGroup(asg_name="web-asg")
        assert a.min_size == 0
        assert a.max_size == 0
        assert a.desired_capacity == 0
        assert a.launch_template == ""
        assert a.vpc_zone_ids == []
        assert a.tags == {}

    def test_with_values(self):
        a = AutoScalingGroup(
            asg_name="api-asg",
            arn="arn:aws:autoscaling:us-east-1"
            ":123:autoScalingGroup:456"
            ":asg/api-asg",
            min_size=2,
            max_size=10,
        )
        assert a.asg_name == "api-asg"
        assert a.min_size == 2


class TestEBSSnapshotModel:
    def test_defaults(self):
        s = EBSSnapshot(snapshot_id="snap-abc")
        assert s.encrypted is False
        assert s.is_public is False
        assert s.volume_id == ""
        assert s.tags == {}

    def test_public_snapshot(self):
        s = EBSSnapshot(
            snapshot_id="snap-pub",
            is_public=True,
        )
        assert s.is_public is True


class TestEC2DataExtended:
    def test_ec2_data_has_asg_and_snapshots(self):
        d = EC2Data()
        assert d.auto_scaling_groups == []
        assert d.ebs_snapshots == []


class TestAPIGatewayModel:
    def test_defaults(self):
        a = APIGateway(api_id="abc123")
        assert a.name == ""
        assert a.endpoint_type == "REGIONAL"
        assert a.protocol_type == "REST"
        assert a.tags == {}

    def test_with_values(self):
        a = APIGateway(
            api_id="def456",
            name="my-api",
            endpoint_type="EDGE",
            protocol_type="HTTP",
        )
        assert a.name == "my-api"
        assert a.endpoint_type == "EDGE"

    def test_api_gateway_data_defaults(self):
        d = APIGatewayData()
        assert d.apis == []


class TestContainerModels:
    def test_ecr_repository_defaults(self):
        r = ECRRepository(
            repository_name="my-app"
        )
        assert r.image_tag_mutability == "MUTABLE"
        assert r.scan_on_push is False
        assert r.encryption_type == "AES256"
        assert r.tags == {}

    def test_ecs_cluster_defaults(self):
        c = ECSCluster(cluster_name="prod")
        assert c.status == "ACTIVE"
        assert c.running_tasks_count == 0
        assert c.active_services_count == 0
        assert c.tags == {}

    def test_ecs_task_definition_defaults(self):
        td = ECSTaskDefinition(family="web-app")
        assert td.revision == 0
        assert td.status == "ACTIVE"
        assert td.network_mode == ""
        assert td.requires_compatibilities == []
        assert td.tags == {}

    def test_eks_cluster_defaults(self):
        e = EKSCluster(cluster_name="k8s")
        assert e.status == "ACTIVE"
        assert e.kubernetes_version == ""
        assert e.endpoint_public_access is True
        assert e.endpoint_private_access is False
        assert e.tags == {}

    def test_eks_cluster_private(self):
        e = EKSCluster(
            cluster_name="k8s-priv",
            endpoint_public_access=False,
            endpoint_private_access=True,
        )
        assert e.endpoint_public_access is False
        assert e.endpoint_private_access is True

    def test_container_data_defaults(self):
        d = ContainerData()
        assert d.ecr_repositories == []
        assert d.ecs_clusters == []
        assert d.ecs_task_definitions == []
        assert d.eks_clusters == []


class TestCollectionMode:
    def test_values(self):
        assert CollectionMode.FULL == "full"
        assert (
            CollectionMode.INCREMENTAL
            == "incremental"
        )
