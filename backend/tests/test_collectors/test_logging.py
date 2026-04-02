"""Tests for Logging collector using moto."""

import pytest

from app.collectors.logging_collector import (
    LoggingCollector,
)


@pytest.fixture
def logging_setup(mock_session):
    """Set up logging resources for testing."""
    # Create S3 bucket for CloudTrail logs
    s3 = mock_session.client("s3")
    s3.create_bucket(Bucket="trail-logs")

    # Create CloudTrail trail
    ct = mock_session.client("cloudtrail")
    ct.create_trail(
        Name="mgmt-trail",
        S3BucketName="trail-logs",
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True,
    )
    ct.start_logging(Name="mgmt-trail")

    # Create CloudWatch alarm
    cw = mock_session.client("cloudwatch")
    cw.put_metric_alarm(
        AlarmName="UnauthorizedAPICalls",
        MetricName="UnauthorizedAttemptCount",
        Namespace="CISBenchmark",
        Statistic="Sum",
        Period=300,
        EvaluationPeriods=1,
        Threshold=1,
        ComparisonOperator=(
            "GreaterThanOrEqualToThreshold"
        ),
    )

    # Enable GuardDuty
    gd = mock_session.client("guardduty")
    gd.create_detector(Enable=True)

    return mock_session


class TestLoggingCollector:
    def test_collect_returns_logging_key(
        self, logging_setup
    ):
        collector = LoggingCollector(logging_setup)
        key, data = collector.collect()
        assert key == "logging"

    def test_collect_has_all_sections(
        self, logging_setup
    ):
        collector = LoggingCollector(logging_setup)
        _, data = collector.collect()
        assert "cloudtrail_trails" in data
        assert "config_recorders" in data
        assert "cloudwatch_alarms" in data
        assert "guardduty_detectors" in data

    def test_cloudtrail_found(
        self, logging_setup
    ):
        collector = LoggingCollector(logging_setup)
        _, data = collector.collect()
        names = [
            t["name"]
            for t in data["cloudtrail_trails"]
        ]
        assert "mgmt-trail" in names

    def test_cloudtrail_properties(
        self, logging_setup
    ):
        collector = LoggingCollector(logging_setup)
        _, data = collector.collect()
        trail = next(
            t
            for t in data["cloudtrail_trails"]
            if t["name"] == "mgmt-trail"
        )
        assert trail["is_multi_region_trail"] is True
        assert trail["is_logging"] is True
        assert (
            trail["log_file_validation_enabled"]
            is True
        )
        assert (
            trail["s3_bucket_name"]
            == "trail-logs"
        )

    def test_cloudwatch_alarm(
        self, logging_setup
    ):
        collector = LoggingCollector(logging_setup)
        _, data = collector.collect()
        names = [
            a["alarm_name"]
            for a in data["cloudwatch_alarms"]
        ]
        assert "UnauthorizedAPICalls" in names

    def test_guardduty_enabled(
        self, logging_setup
    ):
        collector = LoggingCollector(logging_setup)
        _, data = collector.collect()
        assert (
            len(data["guardduty_detectors"]) > 0
        )
        detector = data["guardduty_detectors"][0]
        assert detector["status"] == "ENABLED"

    def test_collect_resource_trail(
        self, logging_setup
    ):
        collector = LoggingCollector(logging_setup)
        result = collector.collect_resource(
            "mgmt-trail"
        )
        assert result["name"] == "mgmt-trail"

    def test_collect_resource_not_found(
        self, logging_setup
    ):
        collector = LoggingCollector(logging_setup)
        result = collector.collect_resource(
            "nonexistent"
        )
        assert result == {}

    def test_empty_state(self, mock_session):
        collector = LoggingCollector(mock_session)
        _, data = collector.collect()
        assert data["cloudtrail_trails"] == []
        assert data["cloudwatch_alarms"] == []
