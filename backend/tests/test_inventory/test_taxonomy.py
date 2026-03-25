"""Tests for resource taxonomy mapping."""

import pytest

from app.inventory.taxonomy import (
    RESOURCE_TAXONOMY,
    get_taxonomy,
)


class TestResourceTaxonomy:
    """Verify all resource types map correctly."""

    def test_ec2_instance(self):
        cat, svc = RESOURCE_TAXONOMY["ec2_instance"]
        assert cat == "compute"
        assert svc == "ec2"

    def test_s3_bucket(self):
        cat, svc = RESOURCE_TAXONOMY["s3_bucket"]
        assert cat == "storage"
        assert svc == "s3"

    def test_rds_instance(self):
        cat, svc = RESOURCE_TAXONOMY["rds_instance"]
        assert cat == "database"
        assert svc == "rds"

    def test_lambda_function(self):
        cat, svc = RESOURCE_TAXONOMY["lambda_function"]
        assert cat == "serverless"
        assert svc == "lambda"

    def test_security_group(self):
        cat, svc = RESOURCE_TAXONOMY["security_group"]
        assert cat == "network"
        assert svc == "ec2"

    def test_ebs_volume(self):
        cat, svc = RESOURCE_TAXONOMY["ebs_volume"]
        assert cat == "storage"
        assert svc == "ec2"

    def test_vpc(self):
        cat, svc = RESOURCE_TAXONOMY["vpc"]
        assert cat == "network"
        assert svc == "vpc"

    def test_kms_key(self):
        cat, svc = RESOURCE_TAXONOMY["kms_key"]
        assert cat == "encryption"
        assert svc == "kms"

    def test_secret(self):
        cat, svc = RESOURCE_TAXONOMY["secret"]
        assert cat == "encryption"
        assert svc == "secretsmanager"

    def test_iam_user(self):
        cat, svc = RESOURCE_TAXONOMY["iam_user"]
        assert cat == "identity"
        assert svc == "iam"

    def test_cloudtrail(self):
        cat, svc = RESOURCE_TAXONOMY["cloudtrail"]
        assert cat == "monitoring"
        assert svc == "cloudtrail"

    def test_guardduty(self):
        cat, svc = RESOURCE_TAXONOMY["guardduty"]
        assert cat == "monitoring"
        assert svc == "guardduty"


class TestGetTaxonomy:
    """Test the get_taxonomy() lookup helper."""

    def test_known_type(self):
        cat, svc = get_taxonomy("ec2_instance")
        assert cat == "compute"
        assert svc == "ec2"

    def test_unknown_type_returns_default(self):
        cat, svc = get_taxonomy("unknown_thing")
        assert cat == "other"
        assert svc == "unknown"

    def test_all_entries_are_two_tuples(self):
        for key, val in RESOURCE_TAXONOMY.items():
            assert len(val) == 2, (
                f"{key} should map to (category, service)"
            )
