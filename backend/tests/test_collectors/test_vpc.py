"""Tests for VPC collector using moto."""

import pytest

from app.collectors.vpc import VPCCollector


@pytest.fixture
def vpc_setup(mock_session):
    """Set up VPC resources for testing."""
    ec2 = mock_session.client("ec2")

    # Create a custom VPC
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]

    # Create flow log
    ec2.create_flow_logs(
        ResourceIds=[vpc_id],
        ResourceType="VPC",
        TrafficType="ALL",
        LogDestinationType="cloud-watch-logs",
        LogGroupName="vpc-flow-logs",
        DeliverLogsPermissionArn=(
            "arn:aws:iam::123456789012:role/flow"
        ),
    )

    return {
        "session": mock_session,
        "vpc_id": vpc_id,
    }


class TestVPCCollector:
    def test_collect_returns_vpc_key(
        self, vpc_setup
    ):
        collector = VPCCollector(
            vpc_setup["session"]
        )
        key, data = collector.collect()
        assert key == "vpc"

    def test_collect_has_all_sections(
        self, vpc_setup
    ):
        collector = VPCCollector(
            vpc_setup["session"]
        )
        _, data = collector.collect()
        assert "vpcs" in data
        assert "flow_logs" in data
        assert "nacls" in data

    def test_vpc_found(self, vpc_setup):
        collector = VPCCollector(
            vpc_setup["session"]
        )
        _, data = collector.collect()
        vpc_ids = [
            v["vpc_id"] for v in data["vpcs"]
        ]
        assert vpc_setup["vpc_id"] in vpc_ids

    def test_vpc_cidr(self, vpc_setup):
        collector = VPCCollector(
            vpc_setup["session"]
        )
        _, data = collector.collect()
        vpc = next(
            v
            for v in data["vpcs"]
            if v["vpc_id"] == vpc_setup["vpc_id"]
        )
        assert vpc["cidr_block"] == "10.0.0.0/16"

    def test_flow_logs_found(self, vpc_setup):
        collector = VPCCollector(
            vpc_setup["session"]
        )
        _, data = collector.collect()
        fl_resources = [
            f["resource_id"]
            for f in data["flow_logs"]
        ]
        assert vpc_setup["vpc_id"] in fl_resources

    def test_nacls_exist(self, vpc_setup):
        """Default NACL should exist for VPC."""
        collector = VPCCollector(
            vpc_setup["session"]
        )
        _, data = collector.collect()
        assert len(data["nacls"]) > 0

    def test_nacl_has_entries(self, vpc_setup):
        collector = VPCCollector(
            vpc_setup["session"]
        )
        _, data = collector.collect()
        # Default NACL should have entries
        nacl = data["nacls"][0]
        assert "entries" in nacl
        assert "nacl_id" in nacl

    def test_collect_resource_vpc(self, vpc_setup):
        collector = VPCCollector(
            vpc_setup["session"]
        )
        result = collector.collect_resource(
            vpc_setup["vpc_id"]
        )
        assert (
            result["vpc_id"]
            == vpc_setup["vpc_id"]
        )

    def test_collect_resource_unknown(
        self, vpc_setup
    ):
        collector = VPCCollector(
            vpc_setup["session"]
        )
        result = collector.collect_resource(
            "unknown-123"
        )
        assert result == {}

    def test_collect_has_subnets(self, vpc_setup):
        collector = VPCCollector(
            vpc_setup["session"]
        )
        _, data = collector.collect()
        assert "subnets" in data
        assert isinstance(data["subnets"], list)

    def test_collect_has_internet_gateways(
        self, vpc_setup
    ):
        collector = VPCCollector(
            vpc_setup["session"]
        )
        _, data = collector.collect()
        assert "internet_gateways" in data
        assert isinstance(
            data["internet_gateways"], list
        )

    def test_collect_has_nat_gateways(
        self, vpc_setup
    ):
        collector = VPCCollector(
            vpc_setup["session"]
        )
        _, data = collector.collect()
        assert "nat_gateways" in data
        assert isinstance(
            data["nat_gateways"], list
        )


class TestVPCCollectorExtended:
    """Test VPC collector with subnets, IGW, NAT GW."""

    @pytest.fixture
    def vpc_extended(self, mock_session):
        ec2 = mock_session.client("ec2")

        # Create VPC
        vpc = ec2.create_vpc(
            CidrBlock="10.0.0.0/16"
        )
        vpc_id = vpc["Vpc"]["VpcId"]

        # Create subnet
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.1.0/24",
        )
        subnet_id = subnet["Subnet"]["SubnetId"]

        # Create IGW and attach
        igw = ec2.create_internet_gateway()
        igw_id = igw["InternetGateway"][
            "InternetGatewayId"
        ]
        ec2.attach_internet_gateway(
            InternetGatewayId=igw_id, VpcId=vpc_id
        )

        return {
            "session": mock_session,
            "vpc_id": vpc_id,
            "subnet_id": subnet_id,
            "igw_id": igw_id,
        }

    def test_subnet_collected(self, vpc_extended):
        collector = VPCCollector(
            vpc_extended["session"]
        )
        _, data = collector.collect()
        subnet_ids = [
            s["subnet_id"]
            for s in data["subnets"]
        ]
        assert (
            vpc_extended["subnet_id"] in subnet_ids
        )

    def test_subnet_has_vpc_id(self, vpc_extended):
        collector = VPCCollector(
            vpc_extended["session"]
        )
        _, data = collector.collect()
        sub = next(
            s
            for s in data["subnets"]
            if s["subnet_id"]
            == vpc_extended["subnet_id"]
        )
        assert sub["vpc_id"] == (
            vpc_extended["vpc_id"]
        )

    def test_igw_collected(self, vpc_extended):
        collector = VPCCollector(
            vpc_extended["session"]
        )
        _, data = collector.collect()
        igw_ids = [
            g["igw_id"]
            for g in data["internet_gateways"]
        ]
        assert vpc_extended["igw_id"] in igw_ids

    def test_igw_attached_vpcs(self, vpc_extended):
        collector = VPCCollector(
            vpc_extended["session"]
        )
        _, data = collector.collect()
        igw = next(
            g
            for g in data["internet_gateways"]
            if g["igw_id"] == vpc_extended["igw_id"]
        )
        assert vpc_extended["vpc_id"] in (
            igw["attached_vpcs"]
        )
