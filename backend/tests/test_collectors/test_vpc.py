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
