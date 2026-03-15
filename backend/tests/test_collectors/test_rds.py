"""Tests for RDS collector using moto."""

import pytest

from app.collectors.rds import RDSCollector


@pytest.fixture
def rds_setup(mock_session):
    """Set up RDS resources for testing."""
    client = mock_session.client("rds")
    ec2 = mock_session.client("ec2")

    # Create a DB subnet group (required by moto)
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

    client.create_db_subnet_group(
        DBSubnetGroupName="test-subnet-group",
        DBSubnetGroupDescription="test",
        SubnetIds=[
            sub1["Subnet"]["SubnetId"],
            sub2["Subnet"]["SubnetId"],
        ],
    )

    # Create RDS instance
    client.create_db_instance(
        DBInstanceIdentifier="prod-db",
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="securepassword123",
        StorageEncrypted=True,
        MultiAZ=True,
        BackupRetentionPeriod=7,
        AutoMinorVersionUpgrade=True,
        DBSubnetGroupName="test-subnet-group",
    )

    return mock_session


class TestRDSCollector:
    def test_collect_returns_rds_key(
        self, rds_setup
    ):
        collector = RDSCollector(rds_setup)
        key, data = collector.collect()
        assert key == "rds"

    def test_collect_finds_instance(
        self, rds_setup
    ):
        collector = RDSCollector(rds_setup)
        _, data = collector.collect()
        ids = [
            d["db_instance_id"]
            for d in data["db_instances"]
        ]
        assert "prod-db" in ids

    def test_instance_properties(self, rds_setup):
        collector = RDSCollector(rds_setup)
        _, data = collector.collect()
        db = next(
            d
            for d in data["db_instances"]
            if d["db_instance_id"] == "prod-db"
        )
        assert db["engine"] == "mysql"
        assert db["storage_encrypted"] is True
        assert db["multi_az"] is True
        assert db["backup_retention_period"] == 7

    def test_collect_resource(self, rds_setup):
        collector = RDSCollector(rds_setup)
        result = collector.collect_resource(
            "prod-db"
        )
        assert (
            result["db_instance_id"] == "prod-db"
        )

    def test_collect_resource_not_found(
        self, rds_setup
    ):
        collector = RDSCollector(rds_setup)
        result = collector.collect_resource(
            "nonexistent"
        )
        assert result == {}

    def test_no_instances(self, mock_session):
        collector = RDSCollector(mock_session)
        _, data = collector.collect()
        assert data["db_instances"] == []
