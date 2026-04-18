"""Tests for event-to-policy mapper."""

from app.pipeline.event_mapper import (
    COLLECTOR_EVENTS,
    EVENT_POLICY_MAP,
    get_event_mapping,
    get_events_for_collector,
    get_tracked_events,
    is_tracked_event,
)


class TestEventPolicyMap:
    """Verify EVENT_POLICY_MAP structure."""

    def test_all_entries_have_collector(self):
        """Every entry must have a collector."""
        for event, mapping in EVENT_POLICY_MAP.items():
            assert "collector" in mapping, (
                f"{event} missing collector"
            )
            assert mapping["collector"], (
                f"{event} has empty collector"
            )

    def test_all_entries_have_policies(self):
        """Every entry must have at least one policy."""
        for event, mapping in EVENT_POLICY_MAP.items():
            assert "policies" in mapping, (
                f"{event} missing policies"
            )
            assert len(mapping["policies"]) > 0, (
                f"{event} has no policies"
            )

    def test_total_tracked_events(self):
        """Verify we track 40 event types."""
        assert len(EVENT_POLICY_MAP) == 40

    def test_s3_events_mapped(self):
        """S3 events map to s3 collector."""
        s3_events = [
            "CreateBucket",
            "PutBucketPublicAccessBlock",
            "PutBucketPolicy",
            "PutBucketEncryption",
            "DeleteBucketEncryption",
        ]
        for event in s3_events:
            m = EVENT_POLICY_MAP[event]
            assert m["collector"] == "s3"
            assert (
                "data_protection.s3"
                in m["policies"]
            )

    def test_sg_events_mapped(self):
        """Security group events map to ec2."""
        m = EVENT_POLICY_MAP[
            "AuthorizeSecurityGroupIngress"
        ]
        assert m["collector"] == "ec2"
        assert (
            "compute.ec2"
            in m["policies"]
        )
        assert (
            "cross_resource.capital_one"
            in m["policies"]
        )

    def test_iam_events_mapped(self):
        """IAM events map to iam collector."""
        iam_events = [
            "CreateUser",
            "CreateAccessKey",
            "AttachRolePolicy",
            "UpdateAccountPasswordPolicy",
        ]
        for event in iam_events:
            assert (
                EVENT_POLICY_MAP[event]["collector"]
                == "iam"
            )
            assert (
                "identity.iam"
                in EVENT_POLICY_MAP[event]["policies"]
            )

    def test_cloudtrail_events_mapped(self):
        """CloudTrail events map to logging."""
        for event in ("StopLogging", "DeleteTrail"):
            m = EVENT_POLICY_MAP[event]
            assert m["collector"] == "logging"
            assert (
                "logging_monitoring.cloudtrail"
                in m["policies"]
            )

    def test_rds_events_mapped(self):
        """RDS events map to rds collector."""
        for event in (
            "CreateDBInstance",
            "ModifyDBInstance",
        ):
            m = EVENT_POLICY_MAP[event]
            assert m["collector"] == "rds"
            assert (
                "data_protection.database"
                in m["policies"]
            )

    def test_lambda_event_mapped(self):
        """Lambda create maps to lambda collector."""
        m = EVENT_POLICY_MAP[
            "CreateFunction20150331"
        ]
        assert m["collector"] == "lambda"
        assert (
            "compute.serverless"
            in m["policies"]
        )

    def test_ebs_event_mapped(self):
        """EBS create maps to ec2 collector."""
        m = EVENT_POLICY_MAP["CreateVolume"]
        assert m["collector"] == "ec2"
        assert (
            "data_protection.storage"
            in m["policies"]
        )

    def test_guardduty_event_mapped(self):
        """GuardDuty delete maps to logging."""
        m = EVENT_POLICY_MAP["DeleteDetector"]
        assert m["collector"] == "logging"
        assert (
            "detection.aws_security"
            in m["policies"]
        )

    def test_policies_use_package_paths(self):
        """All policy strings are dotted package paths."""
        for event, mapping in EVENT_POLICY_MAP.items():
            for policy in mapping["policies"]:
                assert "." in policy, (
                    f"{event} policy '{policy}' is not "
                    f"a dotted package path"
                )
                assert "check_" not in policy, (
                    f"{event} still uses legacy "
                    f"check_ ID: {policy}"
                )


class TestGetEventMapping:
    """Test get_event_mapping function."""

    def test_known_event_returns_mapping(self):
        """Known event returns EventMapping object."""
        result = get_event_mapping("CreateBucket")
        assert result is not None
        assert result.collector == "s3"
        assert (
            "data_protection.s3"
            in result.policies
        )

    def test_unknown_event_returns_none(self):
        """Unknown event returns None."""
        result = get_event_mapping("DescribeBuckets")
        assert result is None

    def test_multi_policy_event(self):
        """Events with multiple policies."""
        result = get_event_mapping(
            "AuthorizeSecurityGroupIngress"
        )
        assert result is not None
        assert len(result.policies) == 2
        assert (
            "compute.ec2"
            in result.policies
        )
        assert (
            "cross_resource.capital_one"
            in result.policies
        )

    def test_empty_string_returns_none(self):
        """Empty event name returns None."""
        assert get_event_mapping("") is None


class TestIsTrackedEvent:
    """Test is_tracked_event function."""

    def test_tracked_event(self):
        """Tracked events return True."""
        assert is_tracked_event("CreateBucket")
        assert is_tracked_event("RunInstances")

    def test_untracked_event(self):
        """Untracked events return False."""
        assert not is_tracked_event("ListBuckets")
        assert not is_tracked_event("")


class TestGetTrackedEvents:
    """Test get_tracked_events function."""

    def test_returns_sorted_list(self):
        """Returns sorted list of event names."""
        events = get_tracked_events()
        assert events == sorted(events)
        assert len(events) == 40

    def test_contains_all_events(self):
        """Contains all mapped event names."""
        events = get_tracked_events()
        for event in EVENT_POLICY_MAP:
            assert event in events


class TestGetEventsForCollector:
    """Test get_events_for_collector function."""

    def test_s3_collector_events(self):
        """S3 collector has 8 events."""
        events = get_events_for_collector("s3")
        assert len(events) == 8
        assert "CreateBucket" in events

    def test_iam_collector_events(self):
        """IAM collector has 8 events."""
        events = get_events_for_collector("iam")
        assert len(events) == 8

    def test_ec2_collector_events(self):
        """EC2 handles SG + EC2 + EBS events."""
        events = get_events_for_collector("ec2")
        assert (
            "AuthorizeSecurityGroupIngress" in events
        )
        assert "RunInstances" in events
        assert "CreateVolume" in events

    def test_unknown_collector_empty(self):
        """Unknown collector returns empty list."""
        events = get_events_for_collector("unknown")
        assert events == []


class TestCollectorEvents:
    """Test COLLECTOR_EVENTS reverse lookup."""

    def test_all_collectors_present(self):
        """All collectors from map are in lookup."""
        collectors = {
            m["collector"]
            for m in EVENT_POLICY_MAP.values()
        }
        for c in collectors:
            assert c in COLLECTOR_EVENTS

    def test_event_count_matches(self):
        """Total events across collectors == 40."""
        total = sum(
            len(v)
            for v in COLLECTOR_EVENTS.values()
        )
        assert total == 40
