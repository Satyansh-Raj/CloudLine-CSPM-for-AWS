"""Tests for CloudTrail event parser."""

from app.pipeline.event_parser import (
    _extract_resource_arn,
    _extract_resource_id,
    _nested_instance_id,
    get_service_from_source,
    parse_cloudtrail_event,
)


def _make_eventbridge_event(
    event_name="CreateBucket",
    event_source="s3.amazonaws.com",
    event_time="2026-02-27T12:00:00Z",
    region="us-east-1",
    account_id="123456789012",
    actor_arn="arn:aws:iam::root",
    actor_type="IAMUser",
    source_ip="1.2.3.4",
    user_agent="console.amazonaws.com",
    request_params=None,
    response_elements=None,
):
    """Build a minimal EventBridge-wrapped event."""
    return {
        "detail-type": (
            "AWS API Call via CloudTrail"
        ),
        "source": "aws.s3",
        "detail": {
            "eventName": event_name,
            "eventSource": event_source,
            "eventTime": event_time,
            "awsRegion": region,
            "userIdentity": {
                "accountId": account_id,
                "arn": actor_arn,
                "type": actor_type,
            },
            "sourceIPAddress": source_ip,
            "userAgent": user_agent,
            "requestParameters": (
                request_params or {}
            ),
            "responseElements": (
                response_elements or {}
            ),
        },
    }


class TestParseCloudTrailEvent:
    """Test parse_cloudtrail_event function."""

    def test_valid_eventbridge_event(self):
        """Parse a valid EventBridge-wrapped event."""
        raw = _make_eventbridge_event(
            request_params={
                "bucketName": "my-bucket"
            },
        )
        event = parse_cloudtrail_event(raw)
        assert event is not None
        assert event.event_name == "CreateBucket"
        assert (
            event.event_source
            == "s3.amazonaws.com"
        )
        assert event.aws_region == "us-east-1"
        assert (
            event.account_id == "123456789012"
        )
        assert event.resource_id == "my-bucket"
        assert event.actor_type == "IAMUser"
        assert event.source_ip == "1.2.3.4"

    def test_direct_cloudtrail_format(self):
        """Parse direct CloudTrail format (no detail)."""
        raw = {
            "eventName": "DeleteTrail",
            "eventSource": (
                "cloudtrail.amazonaws.com"
            ),
            "eventTime": "2026-02-27T12:00:00Z",
            "awsRegion": "us-west-2",
            "userIdentity": {
                "accountId": "999999999999",
                "arn": "arn:aws:iam::admin",
                "type": "Root",
            },
            "requestParameters": {
                "name": "my-trail"
            },
        }
        event = parse_cloudtrail_event(raw)
        assert event is not None
        assert event.event_name == "DeleteTrail"
        assert event.aws_region == "us-west-2"
        assert event.resource_id == "my-trail"

    def test_missing_event_name_returns_none(self):
        """Missing eventName returns None."""
        raw = {
            "detail": {
                "eventSource": "s3.amazonaws.com",
                "eventTime": "2026-02-27T12:00:00Z",
            }
        }
        assert parse_cloudtrail_event(raw) is None

    def test_missing_event_source_returns_none(self):
        """Missing eventSource returns None."""
        raw = {
            "detail": {
                "eventName": "CreateBucket",
                "eventTime": "2026-02-27T12:00:00Z",
            }
        }
        assert parse_cloudtrail_event(raw) is None

    def test_missing_event_time_returns_none(self):
        """Missing eventTime returns None."""
        raw = {
            "detail": {
                "eventName": "CreateBucket",
                "eventSource": "s3.amazonaws.com",
            }
        }
        assert parse_cloudtrail_event(raw) is None

    def test_empty_dict_returns_none(self):
        """Empty dict returns None."""
        assert parse_cloudtrail_event({}) is None

    def test_missing_user_identity_defaults(self):
        """Missing userIdentity uses defaults."""
        raw = {
            "detail": {
                "eventName": "CreateBucket",
                "eventSource": "s3.amazonaws.com",
                "eventTime": "2026-02-27T12:00:00Z",
            }
        }
        event = parse_cloudtrail_event(raw)
        assert event is not None
        assert event.account_id == ""
        assert event.actor_arn == ""
        assert event.actor_type == ""

    def test_null_request_params(self):
        """Null requestParameters handled."""
        raw = _make_eventbridge_event()
        raw["detail"]["requestParameters"] = None
        event = parse_cloudtrail_event(raw)
        assert event is not None
        assert event.request_params == {}

    def test_null_response_elements(self):
        """Null responseElements handled."""
        raw = _make_eventbridge_event()
        raw["detail"]["responseElements"] = None
        event = parse_cloudtrail_event(raw)
        assert event is not None
        assert event.response_elements == {}


class TestExtractResourceId:
    """Test resource ID extraction per event type."""

    def test_s3_bucket_name(self):
        """S3 events extract bucketName."""
        rid = _extract_resource_id(
            "CreateBucket",
            {"bucketName": "test-bucket"},
            {},
        )
        assert rid == "test-bucket"

    def test_sg_group_id(self):
        """SG events extract groupId."""
        rid = _extract_resource_id(
            "AuthorizeSecurityGroupIngress",
            {"groupId": "sg-12345"},
            {},
        )
        assert rid == "sg-12345"

    def test_iam_user_name(self):
        """IAM CreateUser extracts userName."""
        rid = _extract_resource_id(
            "CreateUser",
            {"userName": "test-user"},
            {},
        )
        assert rid == "test-user"

    def test_iam_role_name(self):
        """AttachRolePolicy extracts roleName."""
        rid = _extract_resource_id(
            "AttachRolePolicy",
            {"roleName": "my-role"},
            {},
        )
        assert rid == "my-role"

    def test_password_policy_static(self):
        """Password policy returns static ID."""
        rid = _extract_resource_id(
            "UpdateAccountPasswordPolicy",
            {},
            {},
        )
        assert rid == "account-password-policy"

    def test_run_instances_from_response(self):
        """RunInstances extracts from response."""
        rid = _extract_resource_id(
            "RunInstances",
            {},
            {
                "instancesSet": {
                    "items": [
                        {"instanceId": "i-abc123"}
                    ]
                }
            },
        )
        assert rid == "i-abc123"

    def test_modify_metadata_options(self):
        """ModifyInstanceMetadataOptions."""
        rid = _extract_resource_id(
            "ModifyInstanceMetadataOptions",
            {"instanceId": "i-xyz789"},
            {},
        )
        assert rid == "i-xyz789"

    def test_cloudtrail_trail_name(self):
        """CloudTrail events extract trail name."""
        rid = _extract_resource_id(
            "StopLogging",
            {"name": "my-trail"},
            {},
        )
        assert rid == "my-trail"

    def test_rds_instance_id(self):
        """RDS events extract dBInstanceIdentifier."""
        rid = _extract_resource_id(
            "CreateDBInstance",
            {"dBInstanceIdentifier": "mydb"},
            {},
        )
        assert rid == "mydb"

    def test_lambda_function_name(self):
        """Lambda create extracts functionName."""
        rid = _extract_resource_id(
            "CreateFunction20150331",
            {"functionName": "my-func"},
            {},
        )
        assert rid == "my-func"

    def test_ebs_volume_from_response(self):
        """CreateVolume extracts from response."""
        rid = _extract_resource_id(
            "CreateVolume",
            {},
            {"volumeId": "vol-123"},
        )
        assert rid == "vol-123"

    def test_guardduty_detector_id(self):
        """DeleteDetector extracts detectorId."""
        rid = _extract_resource_id(
            "DeleteDetector",
            {"detectorId": "abc123"},
            {},
        )
        assert rid == "abc123"

    def test_unknown_event_returns_empty(self):
        """Unknown event returns empty string."""
        rid = _extract_resource_id(
            "ListBuckets", {}, {}
        )
        assert rid == ""

    def test_missing_key_returns_empty(self):
        """Missing expected key returns empty."""
        rid = _extract_resource_id(
            "CreateBucket", {}, {}
        )
        assert rid == ""

    def test_put_bucket_public_access(self):
        """PutBucketPublicAccessBlock extracts."""
        rid = _extract_resource_id(
            "PutBucketPublicAccessBlock",
            {"bucketName": "secure-bucket"},
            {},
        )
        assert rid == "secure-bucket"

    def test_delete_bucket_encryption(self):
        """DeleteBucketEncryption extracts."""
        rid = _extract_resource_id(
            "DeleteBucketEncryption",
            {"bucketName": "enc-bucket"},
            {},
        )
        assert rid == "enc-bucket"

    def test_revoke_sg_ingress(self):
        """RevokeSecurityGroupIngress extracts."""
        rid = _extract_resource_id(
            "RevokeSecurityGroupIngress",
            {"groupId": "sg-99999"},
            {},
        )
        assert rid == "sg-99999"

    def test_create_access_key(self):
        """CreateAccessKey extracts userName."""
        rid = _extract_resource_id(
            "CreateAccessKey",
            {"userName": "key-user"},
            {},
        )
        assert rid == "key-user"


class TestNestedInstanceId:
    """Test _nested_instance_id helper."""

    def test_valid_response(self):
        """Extracts first instanceId."""
        resp = {
            "instancesSet": {
                "items": [
                    {"instanceId": "i-first"},
                    {"instanceId": "i-second"},
                ]
            }
        }
        assert _nested_instance_id(resp) == (
            "i-first"
        )

    def test_empty_items(self):
        """Empty items returns empty string."""
        resp = {"instancesSet": {"items": []}}
        assert _nested_instance_id(resp) == ""

    def test_missing_instances_set(self):
        """Missing instancesSet returns empty."""
        assert _nested_instance_id({}) == ""

    def test_missing_items_key(self):
        """Missing items key returns empty."""
        resp = {"instancesSet": {}}
        assert _nested_instance_id(resp) == ""


class TestExtractResourceArn:
    """Test _extract_resource_arn helper."""

    def test_arn_in_request(self):
        """Extracts arn from request params."""
        arn = _extract_resource_arn(
            {},
            {"arn": "arn:aws:s3:::bucket"},
        )
        assert arn == "arn:aws:s3:::bucket"

    def test_trail_arn_in_request(self):
        """Extracts trailArn from request."""
        arn = _extract_resource_arn(
            {},
            {"trailArn": "arn:aws:cloudtrail:..."},
        )
        assert arn == "arn:aws:cloudtrail:..."

    def test_function_arn_in_response(self):
        """Extracts functionArn from response."""
        arn = _extract_resource_arn(
            {"functionArn": "arn:aws:lambda:..."},
            {},
        )
        assert arn == "arn:aws:lambda:..."

    def test_no_arn_returns_empty(self):
        """No ARN found returns empty string."""
        assert _extract_resource_arn({}, {}) == ""


class TestGetServiceFromSource:
    """Test get_service_from_source function."""

    def test_known_sources(self):
        """Known sources map correctly."""
        cases = {
            "s3.amazonaws.com": "s3",
            "ec2.amazonaws.com": "ec2",
            "iam.amazonaws.com": "iam",
            "rds.amazonaws.com": "rds",
            "lambda.amazonaws.com": "lambda",
            "cloudtrail.amazonaws.com": (
                "cloudtrail"
            ),
            "guardduty.amazonaws.com": "guardduty",
            "kms.amazonaws.com": "kms",
        }
        for source, expected in cases.items():
            assert (
                get_service_from_source(source)
                == expected
            )

    def test_unknown_source_fallback(self):
        """Unknown source uses prefix fallback."""
        result = get_service_from_source(
            "custom.amazonaws.com"
        )
        assert result == "custom"
