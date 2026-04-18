"""Tests for S3 collector using moto."""

import pytest

from app.collectors.s3 import S3Collector


@pytest.fixture
def s3_setup(mock_session):
    """Set up S3 resources for testing."""
    client = mock_session.client("s3")

    # Create buckets
    client.create_bucket(Bucket="secure-bucket")
    client.create_bucket(Bucket="insecure-bucket")

    # Set public access block on secure bucket
    client.put_public_access_block(
        Bucket="secure-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        },
    )

    # Enable versioning on secure bucket
    client.put_bucket_versioning(
        Bucket="secure-bucket",
        VersioningConfiguration={
            "Status": "Enabled"
        },
    )

    # Enable encryption on secure bucket
    client.put_bucket_encryption(
        Bucket="secure-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }
            ]
        },
    )

    return mock_session


class TestS3Collector:
    def test_collect_returns_s3_key(
        self, s3_setup
    ):
        collector = S3Collector(s3_setup)
        key, data = collector.collect()
        assert key == "s3"

    def test_collect_finds_buckets(self, s3_setup):
        collector = S3Collector(s3_setup)
        _, data = collector.collect()
        names = [
            b["name"] for b in data["buckets"]
        ]
        assert "secure-bucket" in names
        assert "insecure-bucket" in names

    def test_bucket_has_arn(self, s3_setup):
        collector = S3Collector(s3_setup)
        _, data = collector.collect()
        secure = next(
            b
            for b in data["buckets"]
            if b["name"] == "secure-bucket"
        )
        assert (
            secure["arn"]
            == "arn:aws:s3:::secure-bucket"
        )

    def test_public_access_block(self, s3_setup):
        collector = S3Collector(s3_setup)
        _, data = collector.collect()
        secure = next(
            b
            for b in data["buckets"]
            if b["name"] == "secure-bucket"
        )
        pab = secure["public_access_block"]
        assert pab["block_public_acls"] is True
        assert pab["block_public_policy"] is True

    def test_no_public_access_block(
        self, s3_setup
    ):
        collector = S3Collector(s3_setup)
        _, data = collector.collect()
        insecure = next(
            b
            for b in data["buckets"]
            if b["name"] == "insecure-bucket"
        )
        pab = insecure["public_access_block"]
        assert pab["block_public_acls"] is False

    def test_encryption_enabled(self, s3_setup):
        collector = S3Collector(s3_setup)
        _, data = collector.collect()
        secure = next(
            b
            for b in data["buckets"]
            if b["name"] == "secure-bucket"
        )
        assert len(secure["encryption"]["rules"]) > 0
        assert (
            secure["encryption"]["rules"][0]
            ["apply_server_side_encryption_by_default"]
            ["sse_algorithm"] == "AES256"
        )

    def test_versioning_enabled(self, s3_setup):
        collector = S3Collector(s3_setup)
        _, data = collector.collect()
        secure = next(
            b
            for b in data["buckets"]
            if b["name"] == "secure-bucket"
        )
        assert secure["versioning"]["status"] == "Enabled"

    def test_insecure_bucket_defaults(
        self, s3_setup
    ):
        collector = S3Collector(s3_setup)
        _, data = collector.collect()
        insecure = next(
            b
            for b in data["buckets"]
            if b["name"] == "insecure-bucket"
        )
        assert insecure["versioning"]["status"] != "Enabled"
        assert insecure["encryption"]["rules"] == []

    def test_collect_resource(self, s3_setup):
        collector = S3Collector(s3_setup)
        result = collector.collect_resource(
            "secure-bucket"
        )
        assert result["name"] == "secure-bucket"

    def test_collect_resource_not_found(
        self, s3_setup
    ):
        collector = S3Collector(s3_setup)
        result = collector.collect_resource(
            "nonexistent-bucket"
        )
        assert result == {}

    def test_no_buckets(self, mock_session):
        collector = S3Collector(mock_session)
        _, data = collector.collect()
        assert data["buckets"] == []
