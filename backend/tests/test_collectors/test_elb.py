"""Tests for ELB collector using moto."""

import pytest

from app.collectors.elb import ELBCollector


@pytest.fixture
def elb_setup(mock_session):
    """Set up ELB resources for testing."""
    client = mock_session.client("elbv2")
    ec2 = mock_session.client("ec2")

    # Create VPC and subnets for ALB
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    sub1 = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.0.1.0/24",
        AvailabilityZone="us-east-1a",
    )
    sub2 = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.0.2.0/24",
        AvailabilityZone="us-east-1b",
    )

    # Create internet-facing ALB
    lb = client.create_load_balancer(
        Name="web-alb",
        Subnets=[
            sub1["Subnet"]["SubnetId"],
            sub2["Subnet"]["SubnetId"],
        ],
        Scheme="internet-facing",
        Type="application",
    )

    return {
        "session": mock_session,
        "lb_arn": lb["LoadBalancers"][0][
            "LoadBalancerArn"
        ],
        "vpc_id": vpc_id,
    }


class TestELBCollector:
    def test_collect_returns_elb_key(
        self, elb_setup
    ):
        collector = ELBCollector(
            elb_setup["session"]
        )
        key, _ = collector.collect()
        assert key == "elb"

    def test_collect_has_load_balancers(
        self, elb_setup
    ):
        collector = ELBCollector(
            elb_setup["session"]
        )
        _, data = collector.collect()
        assert "load_balancers" in data
        assert len(data["load_balancers"]) >= 1

    def test_lb_name(self, elb_setup):
        collector = ELBCollector(
            elb_setup["session"]
        )
        _, data = collector.collect()
        names = [
            lb["load_balancer_name"]
            for lb in data["load_balancers"]
        ]
        assert "web-alb" in names

    def test_lb_scheme(self, elb_setup):
        collector = ELBCollector(
            elb_setup["session"]
        )
        _, data = collector.collect()
        lb = next(
            lb
            for lb in data["load_balancers"]
            if lb["load_balancer_name"] == "web-alb"
        )
        assert lb["scheme"] == "internet-facing"

    def test_lb_has_arn(self, elb_setup):
        collector = ELBCollector(
            elb_setup["session"]
        )
        _, data = collector.collect()
        lb = next(
            lb
            for lb in data["load_balancers"]
            if lb["load_balancer_name"] == "web-alb"
        )
        assert lb["load_balancer_arn"] != ""

    def test_collect_resource_not_found(
        self, elb_setup
    ):
        collector = ELBCollector(
            elb_setup["session"]
        )
        result = collector.collect_resource(
            "nonexistent"
        )
        assert result == {}
