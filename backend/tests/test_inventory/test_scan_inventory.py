"""Tests for scan pipeline inventory integration.

Verifies that _run_scan() builds and persists resource
inventory alongside violation state.
"""

from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from app.models.resource import ResourceRecord
from app.pipeline.resource_store import ResourceStore

ACCOUNT = "123456789012"
REGION = "us-east-1"
TABLE_NAME = "resource-inventory"


def _create_table(session):
    """Create the resource-inventory table."""
    ddb = session.resource("dynamodb", region_name=REGION)
    ddb.create_table(
        TableName=TABLE_NAME,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {
                "AttributeName": "technology_category",
                "AttributeType": "S",
            },
            {
                "AttributeName": "risk_score",
                "AttributeType": "N",
            },
            {
                "AttributeName": "exposure",
                "AttributeType": "S",
            },
            {
                "AttributeName": "violation_count",
                "AttributeType": "N",
            },
            {
                "AttributeName": "service",
                "AttributeType": "S",
            },
            {
                "AttributeName": "last_seen",
                "AttributeType": "S",
            },
            {
                "AttributeName": "region",
                "AttributeType": "S",
            },
            {
                "AttributeName": "account_id",
                "AttributeType": "S",
            },
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "category-index",
                "KeySchema": [
                    {
                        "AttributeName": (
                            "technology_category"
                        ),
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": "risk_score",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "exposure-index",
                "KeySchema": [
                    {
                        "AttributeName": "exposure",
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": "violation_count",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "service-index",
                "KeySchema": [
                    {
                        "AttributeName": "service",
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": "last_seen",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "region-index",
                "KeySchema": [
                    {
                        "AttributeName": "region",
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": (
                            "technology_category"
                        ),
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "account-index",
                "KeySchema": [
                    {
                        "AttributeName": "account_id",
                        "KeyType": "HASH",
                    },
                    {
                        "AttributeName": "last_seen",
                        "KeyType": "RANGE",
                    },
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


class TestPersistInventory:
    """Test classify → persist flow."""

    @mock_aws
    def test_classify_and_persist(self):
        session = boto3.Session(region_name=REGION)
        _create_table(session)
        store = ResourceStore(session, TABLE_NAME)

        from app.inventory.classifier import (
            ResourceClassifier,
        )
        from app.models.aws_input import (
            S3Bucket,
            S3Data,
            UnifiedAWSInput,
        )

        data = UnifiedAWSInput(
            account_id=ACCOUNT,
            region=REGION,
            collection_timestamp="2026-03-18T00:00:00Z",
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="bkt-1",
                        arn="arn:aws:s3:::bkt-1",
                    ),
                ],
            ),
        )

        clf = ResourceClassifier(ACCOUNT, REGION)
        records = clf.classify_all(data)

        for rec in records:
            assert store.put_resource(rec)

        result = store.get_resource(
            ACCOUNT, REGION, "s3_bucket",
            "arn:aws:s3:::bkt-1",
        )
        assert result is not None
        assert result.resource_name == "bkt-1"
        assert result.technology_category == "storage"

    @mock_aws
    def test_enrich_then_persist(self):
        """Violation counts survive DynamoDB round-trip."""
        session = boto3.Session(region_name=REGION)
        _create_table(session)
        store = ResourceStore(session, TABLE_NAME)

        from app.inventory.classifier import (
            ResourceClassifier,
        )
        from app.models.aws_input import (
            S3Bucket,
            S3Data,
            UnifiedAWSInput,
        )

        data = UnifiedAWSInput(
            account_id=ACCOUNT,
            region=REGION,
            collection_timestamp="2026-03-18T00:00:00Z",
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="vbkt",
                        arn="arn:aws:s3:::vbkt",
                    ),
                ],
            ),
        )

        clf = ResourceClassifier(ACCOUNT, REGION)
        records = clf.classify_all(data)

        class FV:
            def __init__(self, res, sev):
                self.resource = res
                self.severity = sev
                self.status = "alarm"
                self.check_id = "s3_block_public_acls"

        clf.enrich_with_violations(records, [
            FV("arn:aws:s3:::vbkt", "critical"),
            FV("arn:aws:s3:::vbkt", "high"),
        ])

        for rec in records:
            store.put_resource(rec)

        result = store.get_resource(
            ACCOUNT, REGION, "s3_bucket",
            "arn:aws:s3:::vbkt",
        )
        assert result.violation_count == 2
        assert result.critical_violations == 1
        assert result.high_violations == 1


class TestPersistAll35Types:
    """Batch 8: classify all 35 types → persist → query."""

    @mock_aws
    def test_all_35_types_persist_and_roundtrip(self):
        """Every one of the 35 resource types survives
        a DynamoDB put → get round-trip."""
        session = boto3.Session(region_name=REGION)
        _create_table(session)
        store = ResourceStore(session, TABLE_NAME)

        from app.inventory.classifier import (
            ResourceClassifier,
        )
        from app.inventory.taxonomy import (
            RESOURCE_TAXONOMY,
        )
        from app.models.aws_input import (
            APIGatewayAPI,
            APIGatewayData,
            AuroraCluster,
            AutoScalingGroup,
            CDNData,
            CloudFrontDistribution,
            CloudTrailData,
            CloudTrailTrail,
            CloudWatchAlarm,
            CloudWatchData,
            DynamoDBData,
            DynamoDBTable,
            EBSSnapshot,
            EBSVolume,
            EC2Data,
            EC2Instance,
            ECRData,
            ECRRepository,
            ECSCluster,
            ECSData,
            ECSTaskDefinition,
            EKSCluster,
            EKSData,
            ELBData,
            EndpointConfiguration,
            GuardDutyData,
            GuardDutyDetector,
            IAMData,
            IAMGroup,
            IAMPolicy,
            IAMRole,
            IAMUser,
            InternetGateway,
            KMSData,
            KMSKey,
            LambdaFunction,
            LoadBalancer,
            NACL,
            NATGateway,
            NetworkFirewall,
            RDSData,
            RDSInstance,
            RDSSnapshot,
            ResourcesVpcConfig,
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

        data = UnifiedAWSInput(
            account_id=ACCOUNT,
            region=REGION,
            collection_timestamp=(
                "2026-03-25T00:00:00Z"
            ),
            ec2=EC2Data(
                instances=[EC2Instance(
                    instance_id="i-rt",
                    arn=f"arn:aws:ec2:{REGION}"
                    f":{ACCOUNT}:instance/i-rt",
                )],
                security_groups=[SecurityGroup(
                    group_id="sg-rt",
                )],
                ebs_volumes=[EBSVolume(
                    volume_id="vol-rt",
                    arn=f"arn:aws:ec2:{REGION}"
                    f":{ACCOUNT}:volume/vol-rt",
                )],
                auto_scaling_groups=[AutoScalingGroup(
                    asg_name="asg-rt",
                    arn=f"arn:aws:autoscaling:{REGION}"
                    f":{ACCOUNT}:autoScalingGroup"
                    ":id:asg-rt",
                )],
                ebs_snapshots=[EBSSnapshot(
                    snapshot_id="snap-ebs-rt",
                    arn=f"arn:aws:ec2:{REGION}"
                    f":{ACCOUNT}:snapshot/snap-ebs-rt",
                )],
            ),
            s3=S3Data(buckets=[S3Bucket(
                name="bkt-rt",
                arn="arn:aws:s3:::bkt-rt",
            )]),
            rds=RDSData(
                db_instances=[RDSInstance(
                    db_instance_id="db-rt",
                    arn=f"arn:aws:rds:{REGION}"
                    f":{ACCOUNT}:db:db-rt",
                )],
                aurora_clusters=[AuroraCluster(
                    cluster_id="aurora-rt",
                    arn=f"arn:aws:rds:{REGION}"
                    f":{ACCOUNT}:cluster:aurora-rt",
                )],
                snapshots=[RDSSnapshot(
                    snapshot_id="snap-rds-rt",
                    arn=f"arn:aws:rds:{REGION}"
                    f":{ACCOUNT}:snapshot:snap-rds-rt",
                )],
            ),
            dynamodb=DynamoDBData(tables=[
                DynamoDBTable(
                    table_name="tbl-rt",
                    arn=f"arn:aws:dynamodb:{REGION}"
                    f":{ACCOUNT}:table/tbl-rt",
                ),
            ]),
            vpc=VPCData(
                vpcs=[VPC(vpc_id="vpc-rt")],
                nacls=[NACL(
                    nacl_id="acl-rt",
                    vpc_id="vpc-rt",
                )],
                subnets=[Subnet(
                    subnet_id="sub-rt",
                    arn=f"arn:aws:ec2:{REGION}"
                    f":{ACCOUNT}:subnet/sub-rt",
                )],
                internet_gateways=[InternetGateway(
                    igw_id="igw-rt",
                    arn=f"arn:aws:ec2:{REGION}"
                    f":{ACCOUNT}:internet-gateway"
                    "/igw-rt",
                )],
                nat_gateways=[NATGateway(
                    nat_gateway_id="nat-rt",
                    arn=f"arn:aws:ec2:{REGION}"
                    f":{ACCOUNT}:natgateway/nat-rt",
                )],
                network_firewalls=[NetworkFirewall(
                    firewall_name="nfw-rt",
                    arn=f"arn:aws:network-firewall"
                    f":{REGION}:{ACCOUNT}"
                    ":firewall/nfw-rt",
                )],
                waf_web_acls=[WAFWebACL(
                    name="waf-rt",
                    arn=f"arn:aws:wafv2:{REGION}"
                    f":{ACCOUNT}:regional"
                    "/webacl/waf-rt",
                )],
            ),
            elb=ELBData(load_balancers=[LoadBalancer(
                lb_name="lb-rt",
                arn=f"arn:aws:elasticloadbalancing"
                f":{REGION}:{ACCOUNT}"
                ":loadbalancer/app/lb-rt",
            )]),
            cdn=CDNData(
                distributions=[
                    CloudFrontDistribution(
                        distribution_id="E1RT",
                        arn=f"arn:aws:cloudfront"
                        f"::{ACCOUNT}"
                        ":distribution/E1RT",
                    ),
                ],
                hosted_zones=[Route53HostedZone(
                    hosted_zone_id="Z1RT",
                    name="rt.example.com",
                )],
            ),
            lambda_functions=[LambdaFunction(
                function_name="fn-rt",
                function_arn=(
                    f"arn:aws:lambda:{REGION}"
                    f":{ACCOUNT}:function:fn-rt"
                ),
            )],
            apigateway=APIGatewayData(rest_apis=[
                APIGatewayAPI(
                    id="api-rt",
                    name="api-rt",
                    arn=f"arn:aws:apigateway:{REGION}"
                    "::/restapis/api-rt",
                    endpoint_configuration=(
                        EndpointConfiguration(
                            types=["REGIONAL"]
                        )
                    ),
                ),
            ]),
            cloudtrail=CloudTrailData(
                trails=[CloudTrailTrail(
                    name="trail-rt",
                    arn=f"arn:aws:cloudtrail:{REGION}"
                    f":{ACCOUNT}:trail/trail-rt",
                )],
            ),
            guardduty=GuardDutyData(
                detectors=[GuardDutyDetector(
                    detector_id="det-rt",
                )],
            ),
            cloudwatch=CloudWatchData(
                alarms=[CloudWatchAlarm(
                    alarm_name="alarm-rt",
                )],
            ),
            iam=IAMData(
                users=[IAMUser(
                    name="user-rt",
                    arn=f"arn:aws:iam::{ACCOUNT}"
                    ":user/user-rt",
                )],
                groups=[IAMGroup(
                    group_name="grp-rt",
                    arn=f"arn:aws:iam::{ACCOUNT}"
                    ":group/grp-rt",
                )],
                roles=[IAMRole(
                    role_name="role-rt",
                    arn=f"arn:aws:iam::{ACCOUNT}"
                    ":role/role-rt",
                )],
                customer_managed_policies=[IAMPolicy(
                    policy_name="pol-rt",
                    arn=f"arn:aws:iam::{ACCOUNT}"
                    ":policy/pol-rt",
                )],
            ),
            kms=KMSData(keys=[KMSKey(
                key_id="key-rt",
                arn=f"arn:aws:kms:{REGION}"
                f":{ACCOUNT}:key/key-rt",
            )]),
            secrets_manager=SecretsManagerData(
                secrets=[Secret(
                    name="sec-rt",
                    arn=f"arn:aws:secretsmanager"
                    f":{REGION}:{ACCOUNT}"
                    ":secret:sec-rt",
                )],
            ),
            ecr=ECRData(
                repositories=[ECRRepository(
                    repository_name="ecr-rt",
                    arn=f"arn:aws:ecr:{REGION}"
                    f":{ACCOUNT}:repository/ecr-rt",
                )],
            ),
            ecs=ECSData(
                clusters=[ECSCluster(
                    cluster_name="ecs-rt",
                    cluster_arn=f"arn:aws:ecs:{REGION}"
                    f":{ACCOUNT}:cluster/ecs-rt",
                )],
                task_definitions=[
                    ECSTaskDefinition(
                        family="td-rt",
                        arn=f"arn:aws:ecs:{REGION}"
                        f":{ACCOUNT}"
                        ":task-definition/td-rt:1",
                    ),
                ],
            ),
            eks=EKSData(
                clusters=[EKSCluster(
                    name="eks-rt",
                    arn=f"arn:aws:eks:{REGION}"
                    f":{ACCOUNT}:cluster/eks-rt",
                )],
            ),
        )

        clf = ResourceClassifier(ACCOUNT, REGION)
        records = clf.classify_all(data)
        assert len(records) == 35

        # Persist all
        for rec in records:
            assert store.put_resource(rec)

        # Round-trip: query back and verify count
        result = store.query_by_account(
            ACCOUNT, REGION, limit=5000,
        )
        assert len(result) == 35

        # Verify all 35 types present
        result_types = {r.resource_type for r in result}
        assert result_types == set(
            RESOURCE_TAXONOMY.keys()
        )

    @mock_aws
    def test_enriched_violations_survive_roundtrip(
        self,
    ):
        """Violation counts and risk_score persist
        through DynamoDB for multiple resource types."""
        session = boto3.Session(region_name=REGION)
        _create_table(session)
        store = ResourceStore(session, TABLE_NAME)

        from app.inventory.classifier import (
            ResourceClassifier,
        )
        from app.models.aws_input import (
            EC2Data,
            EC2Instance,
            S3Bucket,
            S3Data,
            UnifiedAWSInput,
        )

        data = UnifiedAWSInput(
            account_id=ACCOUNT,
            region=REGION,
            collection_timestamp=(
                "2026-03-25T00:00:00Z"
            ),
            ec2=EC2Data(instances=[EC2Instance(
                instance_id="i-v",
                arn=f"arn:aws:ec2:{REGION}"
                f":{ACCOUNT}:instance/i-v",
            )]),
            s3=S3Data(buckets=[S3Bucket(
                name="v-bkt",
                arn="arn:aws:s3:::v-bkt",
            )]),
        )

        clf = ResourceClassifier(ACCOUNT, REGION)
        records = clf.classify_all(data)

        class FV:
            def __init__(self, res, sev):
                self.resource = res
                self.severity = sev
                self.status = "alarm"
                self.check_id = "test"

        clf.enrich_with_violations(records, [
            FV("arn:aws:s3:::v-bkt", "critical"),
            FV("arn:aws:s3:::v-bkt", "medium"),
            FV(
                f"arn:aws:ec2:{REGION}"
                f":{ACCOUNT}:instance/i-v",
                "high",
            ),
        ])

        for rec in records:
            store.put_resource(rec)

        s3 = store.get_resource(
            ACCOUNT, REGION, "s3_bucket",
            "arn:aws:s3:::v-bkt",
        )
        assert s3.violation_count == 2
        assert s3.critical_violations == 1
        assert s3.risk_score == 33  # 25 + 8

        ec2 = store.get_resource(
            ACCOUNT, REGION, "ec2_instance",
            f"arn:aws:ec2:{REGION}"
            f":{ACCOUNT}:instance/i-v",
        )
        assert ec2.violation_count == 1
        assert ec2.high_violations == 1
        assert ec2.risk_score == 15


class TestSoftDeleteUnseen:
    """Test deactivation of resources not seen in scan."""

    @mock_aws
    def test_unseen_resources_deactivated(self):
        session = boto3.Session(region_name=REGION)
        _create_table(session)
        store = ResourceStore(session, TABLE_NAME)

        # Pre-populate with old resource
        old = ResourceRecord(
            pk=f"{ACCOUNT}#{REGION}",
            sk="s3_bucket#arn:aws:s3:::old-bkt",
            resource_id="arn:aws:s3:::old-bkt",
            resource_name="old-bkt",
            resource_type="s3_bucket",
            technology_category="storage",
            service="s3",
            region=REGION,
            account_id=ACCOUNT,
            last_seen="2026-03-17T00:00:00Z",
            is_active=True,
        )
        store.put_resource(old)

        # New scan only sees new-bkt
        from app.inventory.classifier import (
            ResourceClassifier,
        )
        from app.models.aws_input import (
            S3Bucket,
            S3Data,
            UnifiedAWSInput,
        )

        data = UnifiedAWSInput(
            account_id=ACCOUNT,
            region=REGION,
            collection_timestamp="2026-03-18T00:00:00Z",
            s3=S3Data(
                buckets=[
                    S3Bucket(
                        name="new-bkt",
                        arn="arn:aws:s3:::new-bkt",
                    ),
                ],
            ),
        )

        clf = ResourceClassifier(ACCOUNT, REGION)
        new_records = clf.classify_all(data)

        # Persist new records
        for rec in new_records:
            store.put_resource(rec)

        # Mark unseen as inactive
        seen_keys = {
            (r.resource_type, r.resource_id)
            for r in new_records
        }
        existing = store.query_by_account(
            ACCOUNT, REGION, limit=5000
        )
        for ex in existing:
            key = (ex.resource_type, ex.resource_id)
            if ex.is_active and key not in seen_keys:
                store.deactivate_resource(
                    ACCOUNT, REGION,
                    ex.resource_type,
                    ex.resource_id,
                )

        # Verify old-bkt is deactivated
        old_result = store.get_resource(
            ACCOUNT, REGION, "s3_bucket",
            "arn:aws:s3:::old-bkt",
        )
        assert old_result is not None
        assert old_result.is_active is False
        assert old_result.deactivated_at is not None

        # Verify new-bkt is still active
        new_result = store.get_resource(
            ACCOUNT, REGION, "s3_bucket",
            "arn:aws:s3:::new-bkt",
        )
        assert new_result is not None
        assert new_result.is_active is True


class TestSoftDeleteMultiType:
    """Batch 8: soft-delete across multiple types."""

    @mock_aws
    def test_multi_type_deactivation(self):
        """Pre-populate EC2, S3, Lambda — rescan with
        only S3 and Lambda present. EC2 must be
        deactivated while others remain active."""
        session = boto3.Session(region_name=REGION)
        _create_table(session)
        store = ResourceStore(session, TABLE_NAME)

        # Old: EC2 + S3 + Lambda
        for rtype, rid, rname, cat, svc in [
            (
                "ec2_instance",
                f"arn:aws:ec2:{REGION}"
                f":{ACCOUNT}:instance/i-old",
                "i-old", "compute", "ec2",
            ),
            (
                "s3_bucket",
                "arn:aws:s3:::keep-bkt",
                "keep-bkt", "storage", "s3",
            ),
            (
                "lambda_function",
                f"arn:aws:lambda:{REGION}"
                f":{ACCOUNT}:function:fn-keep",
                "fn-keep", "serverless", "lambda",
            ),
        ]:
            store.put_resource(ResourceRecord(
                pk=f"{ACCOUNT}#{REGION}",
                sk=f"{rtype}#{rid}",
                resource_id=rid,
                resource_name=rname,
                resource_type=rtype,
                technology_category=cat,
                service=svc,
                region=REGION,
                account_id=ACCOUNT,
                last_seen="2026-03-24T00:00:00Z",
                is_active=True,
            ))

        # New scan: only S3 + Lambda (EC2 gone)
        from app.inventory.classifier import (
            ResourceClassifier,
        )
        from app.models.aws_input import (
            LambdaFunction,
            S3Bucket,
            S3Data,
            UnifiedAWSInput,
        )

        data = UnifiedAWSInput(
            account_id=ACCOUNT,
            region=REGION,
            collection_timestamp=(
                "2026-03-25T00:00:00Z"
            ),
            s3=S3Data(buckets=[S3Bucket(
                name="keep-bkt",
                arn="arn:aws:s3:::keep-bkt",
            )]),
            lambda_functions=[LambdaFunction(
                function_name="fn-keep",
                function_arn=(
                    f"arn:aws:lambda:{REGION}"
                    f":{ACCOUNT}:function:fn-keep"
                ),
            )],
        )

        clf = ResourceClassifier(ACCOUNT, REGION)
        new_records = clf.classify_all(data)

        for rec in new_records:
            store.put_resource(rec)

        seen_keys = {
            (r.resource_type, r.resource_id)
            for r in new_records
        }
        existing = store.query_by_account(
            ACCOUNT, REGION, limit=5000,
        )
        for ex in existing:
            key = (ex.resource_type, ex.resource_id)
            if ex.is_active and key not in seen_keys:
                store.deactivate_resource(
                    ACCOUNT, REGION,
                    ex.resource_type,
                    ex.resource_id,
                )

        # EC2 gone → deactivated
        ec2 = store.get_resource(
            ACCOUNT, REGION, "ec2_instance",
            f"arn:aws:ec2:{REGION}"
            f":{ACCOUNT}:instance/i-old",
        )
        assert ec2.is_active is False
        assert ec2.deactivated_at is not None

        # S3 still active
        s3 = store.get_resource(
            ACCOUNT, REGION, "s3_bucket",
            "arn:aws:s3:::keep-bkt",
        )
        assert s3.is_active is True

        # Lambda still active
        lam = store.get_resource(
            ACCOUNT, REGION, "lambda_function",
            f"arn:aws:lambda:{REGION}"
            f":{ACCOUNT}:function:fn-keep",
        )
        assert lam.is_active is True


class TestEnrichmentChainNonFatal:
    """Batch 8: data classification failure must not
    block inventory persistence."""

    def test_enrichment_error_skips_one_resource(self):
        """If data_classifier raises for one resource,
        others still get enriched."""
        from app.inventory.classifier import (
            ResourceClassifier,
        )
        from app.models.aws_input import (
            S3Bucket,
            S3Data,
            UnifiedAWSInput,
        )

        data = UnifiedAWSInput(
            account_id=ACCOUNT,
            region=REGION,
            collection_timestamp=(
                "2026-03-25T00:00:00Z"
            ),
            s3=S3Data(buckets=[
                S3Bucket(
                    name="ok-bkt",
                    arn="arn:aws:s3:::ok-bkt",
                ),
                S3Bucket(
                    name="bad-bkt",
                    arn="arn:aws:s3:::bad-bkt",
                ),
            ]),
        )

        clf = ResourceClassifier(ACCOUNT, REGION)
        records = clf.classify_all(data)

        # Mock data classifier that fails for bad-bkt
        class FakeClassification:
            sensitivity = "high"
            data_types = ["pii"]

        class FakeResult:
            compliance_gaps = ["PCI DSS 3.4"]

        call_count = 0

        class FakeDataClassifier:
            def classify_resource(self, **kwargs):
                nonlocal call_count
                call_count += 1
                if kwargs["resource_name"] == "bad-bkt":
                    raise RuntimeError("boom")
                return FakeClassification()

        class FakeMapper:
            def map(self, classification):
                return FakeResult()

        clf.enrich_with_data_classification(
            records,
            FakeDataClassifier(),
            FakeMapper(),
        )

        by_name = {
            r.resource_name: r for r in records
        }

        # ok-bkt enriched successfully
        assert by_name["ok-bkt"].data_sensitivity == (
            "high"
        )
        assert by_name["ok-bkt"].data_types == ["pii"]
        assert by_name["ok-bkt"].compliance_gaps == [
            "PCI DSS 3.4"
        ]

        # bad-bkt still has defaults
        assert by_name["bad-bkt"].data_sensitivity == (
            "unknown"
        )
        assert by_name["bad-bkt"].data_types == []

        # Both were attempted
        assert call_count == 2
