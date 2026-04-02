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
        assert len(sg["ip_permissions"]) == 2
        ssh_rule = next(
            r
            for r in sg["ip_permissions"]
            if r["from_port"] == 22
        )
        assert (
            ssh_rule["ip_ranges"][0]["cidr_ip"]
            == "0.0.0.0/0"
        )

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


class TestEC2CollectorASGSnapshots:
    """Tests for ASG and EBS snapshot collection."""

    def test_collect_has_asg_key(
        self, mock_session
    ):
        collector = EC2Collector(mock_session)
        _, data = collector.collect()
        assert "auto_scaling_groups" in data

    def test_collect_has_ebs_snapshots_key(
        self, mock_session
    ):
        collector = EC2Collector(mock_session)
        _, data = collector.collect()
        assert "snapshots" in data

    def test_asg_collection(self, mock_session):
        asg = mock_session.client("autoscaling")
        asg.create_launch_configuration(
            LaunchConfigurationName="lc-test",
            ImageId="ami-12345678",
            InstanceType="t2.micro",
        )
        asg.create_auto_scaling_group(
            AutoScalingGroupName="test-asg",
            LaunchConfigurationName="lc-test",
            MinSize=1,
            MaxSize=3,
            DesiredCapacity=2,
            AvailabilityZones=["us-east-1a"],
        )
        collector = EC2Collector(mock_session)
        _, data = collector.collect()
        names = [
            g["asg_name"]
            for g in data["auto_scaling_groups"]
        ]
        assert "test-asg" in names

    def test_asg_fields(self, mock_session):
        asg = mock_session.client("autoscaling")
        asg.create_launch_configuration(
            LaunchConfigurationName="lc-2",
            ImageId="ami-12345678",
            InstanceType="t2.micro",
        )
        asg.create_auto_scaling_group(
            AutoScalingGroupName="api-asg",
            LaunchConfigurationName="lc-2",
            MinSize=2,
            MaxSize=5,
            DesiredCapacity=3,
            AvailabilityZones=["us-east-1a"],
        )
        collector = EC2Collector(mock_session)
        _, data = collector.collect()
        grp = next(
            g
            for g in data["auto_scaling_groups"]
            if g["asg_name"] == "api-asg"
        )
        assert grp["min_size"] == 2
        assert grp["max_size"] == 5
        assert grp["desired_capacity"] == 3
        assert "arn" in grp

    def test_snapshot_collection(
        self, mock_session
    ):
        ec2 = mock_session.client("ec2")
        vol = ec2.create_volume(
            AvailabilityZone="us-east-1a",
            Size=10,
        )
        ec2.create_snapshot(
            VolumeId=vol["VolumeId"],
            Description="test snap",
        )
        collector = EC2Collector(mock_session)
        _, data = collector.collect()
        assert len(data["snapshots"]) >= 1

    def test_snapshot_fields(
        self, mock_session
    ):
        ec2 = mock_session.client("ec2")
        vol = ec2.create_volume(
            AvailabilityZone="us-east-1a",
            Size=10,
        )
        snap = ec2.create_snapshot(
            VolumeId=vol["VolumeId"],
        )
        collector = EC2Collector(mock_session)
        _, data = collector.collect()
        s = next(
            s
            for s in data["snapshots"]
            if s["snapshot_id"]
            == snap["SnapshotId"]
        )
        assert s["volume_id"] == vol["VolumeId"]
        assert "arn" in s
        assert "encrypted" in s
        assert "is_public" in s

    def test_collect_resource_snapshot(
        self, mock_session
    ):
        ec2 = mock_session.client("ec2")
        vol = ec2.create_volume(
            AvailabilityZone="us-east-1a",
            Size=10,
        )
        snap = ec2.create_snapshot(
            VolumeId=vol["VolumeId"],
        )
        collector = EC2Collector(mock_session)
        result = collector.collect_resource(
            snap["SnapshotId"]
        )
        assert result["snapshot_id"] == (
            snap["SnapshotId"]
        )
