"""Tests for EC2 collector using moto."""

import pytest

from app.collectors.ec2 import EC2Collector


@pytest.fixture
def ec2_setup(mock_session):
    """Set up EC2 resources for testing."""
    ec2 = mock_session.client("ec2")

    # Create VPC and subnet
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.1.0/24"
    )
    subnet_id = subnet["Subnet"]["SubnetId"]

    # Create security group with SSH open
    sg = ec2.create_security_group(
        GroupName="web-sg",
        Description="Web server SG",
        VpcId=vpc_id,
    )
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "FromPort": 22,
                "ToPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0",
                        "Description": (
                            "SSH from anywhere"
                        ),
                    }
                ],
            },
            {
                "FromPort": 443,
                "ToPort": 443,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0",
                        "Description": "HTTPS",
                    }
                ],
            },
        ],
    )

    # Launch instance
    instances = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t2.micro",
        SubnetId=subnet_id,
        SecurityGroupIds=[sg_id],
    )
    instance_id = instances["Instances"][0][
        "InstanceId"
    ]

    # Create EBS volume
    vol = ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=100,
        Encrypted=False,
    )

    return {
        "session": mock_session,
        "vpc_id": vpc_id,
        "sg_id": sg_id,
        "instance_id": instance_id,
        "volume_id": vol["VolumeId"],
    }


class TestEC2Collector:
    def test_collect_returns_ec2_key(
        self, ec2_setup
    ):
        collector = EC2Collector(
            ec2_setup["session"]
        )
        key, data = collector.collect()
        assert key == "ec2"

    def test_collect_has_all_sections(
        self, ec2_setup
    ):
        collector = EC2Collector(
            ec2_setup["session"]
        )
        _, data = collector.collect()
        assert "instances" in data
        assert "security_groups" in data
        assert "ebs_volumes" in data

    def test_instance_collected(self, ec2_setup):
        collector = EC2Collector(
            ec2_setup["session"]
        )
        _, data = collector.collect()
        ids = [
            i["instance_id"]
            for i in data["instances"]
        ]
        assert ec2_setup["instance_id"] in ids

    def test_instance_has_vpc(self, ec2_setup):
        collector = EC2Collector(
            ec2_setup["session"]
        )
        _, data = collector.collect()
        inst = next(
            i
            for i in data["instances"]
            if i["instance_id"]
            == ec2_setup["instance_id"]
        )
        assert (
            inst["vpc_id"] == ec2_setup["vpc_id"]
        )

    def test_security_group_ingress(
        self, ec2_setup
    ):
        collector = EC2Collector(
            ec2_setup["session"]
        )
        _, data = collector.collect()
        sg = next(
            s
            for s in data["security_groups"]
            if s["group_id"] == ec2_setup["sg_id"]
        )
        # Should have SSH and HTTPS rules
        assert len(sg["ingress_rules"]) == 2
        ssh_rule = next(
            r
            for r in sg["ingress_rules"]
            if r["from_port"] == 22
        )
        assert ssh_rule["cidr"] == "0.0.0.0/0"

    def test_ebs_volume_unencrypted(
        self, ec2_setup
    ):
        collector = EC2Collector(
            ec2_setup["session"]
        )
        _, data = collector.collect()
        vol = next(
            v
            for v in data["ebs_volumes"]
            if v["volume_id"]
            == ec2_setup["volume_id"]
        )
        assert vol["encrypted"] is False
        assert vol["size_gb"] == 100

    def test_collect_resource_instance(
        self, ec2_setup
    ):
        collector = EC2Collector(
            ec2_setup["session"]
        )
        result = collector.collect_resource(
            ec2_setup["instance_id"]
        )
        assert (
            result["instance_id"]
            == ec2_setup["instance_id"]
        )

    def test_collect_resource_sg(self, ec2_setup):
        collector = EC2Collector(
            ec2_setup["session"]
        )
        result = collector.collect_resource(
            ec2_setup["sg_id"]
        )
        assert (
            result["group_id"]
            == ec2_setup["sg_id"]
        )

    def test_collect_resource_volume(
        self, ec2_setup
    ):
        collector = EC2Collector(
            ec2_setup["session"]
        )
        result = collector.collect_resource(
            ec2_setup["volume_id"]
        )
        assert (
            result["volume_id"]
            == ec2_setup["volume_id"]
        )

    def test_collect_resource_unknown(
        self, ec2_setup
    ):
        collector = EC2Collector(
            ec2_setup["session"]
        )
        result = collector.collect_resource(
            "unknown-123"
        )
        assert result == {}

    def test_no_instances(self, mock_session):
        collector = EC2Collector(mock_session)
        _, data = collector.collect()
        assert data["instances"] == []
