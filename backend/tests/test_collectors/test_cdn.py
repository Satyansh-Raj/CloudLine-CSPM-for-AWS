"""Tests for CDN (CloudFront + Route53) collector
using moto."""

import pytest

from app.collectors.cdn import CDNCollector


@pytest.fixture
def cdn_setup(mock_session):
    """Set up Route53 hosted zone for testing."""
    r53 = mock_session.client("route53")
    zone = r53.create_hosted_zone(
        Name="example.com",
        CallerReference="test-ref-1",
    )
    return {
        "session": mock_session,
        "zone_id": zone["HostedZone"]["Id"]
        .split("/")[-1],
    }


class TestCDNCollector:
    def test_collect_returns_cdn_key(
        self, cdn_setup
    ):
        collector = CDNCollector(
            cdn_setup["session"]
        )
        key, _ = collector.collect()
        assert key == "cdn"

    def test_collect_has_sections(
        self, cdn_setup
    ):
        collector = CDNCollector(
            cdn_setup["session"]
        )
        _, data = collector.collect()
        assert "distributions" in data
        assert "hosted_zones" in data

    def test_hosted_zone_collected(
        self, cdn_setup
    ):
        collector = CDNCollector(
            cdn_setup["session"]
        )
        _, data = collector.collect()
        zone_ids = [
            z["hosted_zone_id"]
            for z in data["hosted_zones"]
        ]
        assert cdn_setup["zone_id"] in zone_ids

    def test_hosted_zone_name(self, cdn_setup):
        collector = CDNCollector(
            cdn_setup["session"]
        )
        _, data = collector.collect()
        zone = next(
            z
            for z in data["hosted_zones"]
            if z["hosted_zone_id"]
            == cdn_setup["zone_id"]
        )
        assert zone["name"] == "example.com"

    def test_hosted_zone_is_public(
        self, cdn_setup
    ):
        collector = CDNCollector(
            cdn_setup["session"]
        )
        _, data = collector.collect()
        zone = next(
            z
            for z in data["hosted_zones"]
            if z["hosted_zone_id"]
            == cdn_setup["zone_id"]
        )
        assert zone["is_private"] is False

    def test_collect_resource_not_found(
        self, cdn_setup
    ):
        collector = CDNCollector(
            cdn_setup["session"]
        )
        result = collector.collect_resource(
            "nonexistent"
        )
        assert result == {}
