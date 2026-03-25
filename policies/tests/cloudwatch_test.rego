package aws.logging_monitoring.cloudwatch_test

import data.aws.logging_monitoring.cloudwatch

# =========================================================================
# Helpers
# =========================================================================
_violations_for(check_id, inp) := count([v |
	some v in cloudwatch.violations with input as inp
	v.check_id == check_id
])

_errors_for(check_id, inp) := count([e |
	some e in cloudwatch.error with input as inp
	e.check_id == check_id
])

# =========================================================================
# Compliant alarm fixture — one alarm per required metric pattern
# =========================================================================
_good_alarm(name, metric) := {
	"alarm_name": name,
	"alarm_arn": concat("", ["arn:aws:cloudwatch:us-east-1:123456789012:alarm:", name]),
	"metric_name": metric,
	"alarm_actions": ["arn:aws:sns:us-east-1:123456789012:alerts"],
	"state_value": "OK",
}

_all_alarms := [
	_good_alarm("root-usage", "root_account_usage"),
	_good_alarm("unauthorized-api", "unauthorized_api_calls"),
	_good_alarm("console-no-mfa", "console_login_no_mfa"),
	_good_alarm("iam-changes", "iam_policy_changes"),
	_good_alarm("cloudtrail-changes", "cloudtrail_config_changes"),
	_good_alarm("s3-policy-changes", "s3_bucket_policy_changes"),
	_good_alarm("vpc-changes", "vpc_changes"),
	_good_alarm("sg-changes", "security_group_changes"),
	_good_alarm("nacl-changes", "nacl_changes"),
	_good_alarm("igw-changes", "internet_gateway_changes"),
	_good_alarm("failed-logins", "failed_console_logins"),
	_good_alarm("kms-key-changes", "kms_key_deletion_disable"),
	_good_alarm("config-changes", "config_changes"),
	_good_alarm("org-changes", "organizations_changes"),
	_good_alarm("route-changes", "route_table_changes"),
]

# Compliant log group fixture
_good_log_group := {
	"log_group_name": "/aws/lambda/my-func",
	"arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/my-func",
	"retention_in_days": 365,
	"kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/abc123",
	"tags": {"data_classification": "sensitive"},
}

# Full compliant input
_good_input := {
	"region": "us-east-1",
	"account_id": "123456789012",
	"cloudwatch": {
		"alarms": _all_alarms,
		"log_groups": [_good_log_group],
	},
}

# Helper: remove a specific alarm by metric_name from the good input
_without_alarm(metric) := inp if {
	filtered := [a | some a in _all_alarms; a.metric_name != metric]
	inp := json.patch(_good_input, [{"op": "replace", "path": "/cloudwatch/alarms", "value": filtered}])
}

# =========================================================================
# cloudwatch_01 — Alarm for root account usage
# =========================================================================
test_cloudwatch_01_alarm if {
	_violations_for("cloudwatch_root_usage_alarm", _without_alarm("root_account_usage")) == 1
}

test_cloudwatch_01_pass if {
	_violations_for("cloudwatch_root_usage_alarm", _good_input) == 0
}

# =========================================================================
# cloudwatch_02 — Alarm for unauthorized API calls
# =========================================================================
test_cloudwatch_02_alarm if {
	_violations_for("cloudwatch_unauthorized_api_alarm", _without_alarm("unauthorized_api_calls")) == 1
}

test_cloudwatch_02_pass if {
	_violations_for("cloudwatch_unauthorized_api_alarm", _good_input) == 0
}

# =========================================================================
# cloudwatch_03 — Alarm for console login without MFA
# =========================================================================
test_cloudwatch_03_alarm if {
	_violations_for("cloudwatch_no_mfa_login_alarm", _without_alarm("console_login_no_mfa")) == 1
}

test_cloudwatch_03_pass if {
	_violations_for("cloudwatch_no_mfa_login_alarm", _good_input) == 0
}

# =========================================================================
# cloudwatch_04 — Alarm for IAM policy changes
# =========================================================================
test_cloudwatch_04_alarm if {
	_violations_for("cloudwatch_iam_policy_alarm", _without_alarm("iam_policy_changes")) == 1
}

test_cloudwatch_04_pass if {
	_violations_for("cloudwatch_iam_policy_alarm", _good_input) == 0
}

# =========================================================================
# cloudwatch_05 — Alarm for CloudTrail configuration changes
# =========================================================================
test_cloudwatch_05_alarm if {
	_violations_for("cloudwatch_cloudtrail_alarm", _without_alarm("cloudtrail_config_changes")) == 1
}

test_cloudwatch_05_pass if {
	_violations_for("cloudwatch_cloudtrail_alarm", _good_input) == 0
}

# =========================================================================
# cloudwatch_06 — Alarm for S3 bucket policy changes
# =========================================================================
test_cloudwatch_06_alarm if {
	_violations_for("cloudwatch_s3_policy_alarm", _without_alarm("s3_bucket_policy_changes")) == 1
}

test_cloudwatch_06_pass if {
	_violations_for("cloudwatch_s3_policy_alarm", _good_input) == 0
}

# =========================================================================
# cloudwatch_07 — Alarm for VPC changes
# =========================================================================
test_cloudwatch_07_alarm if {
	_violations_for("cloudwatch_vpc_changes_alarm", _without_alarm("vpc_changes")) == 1
}

test_cloudwatch_07_pass if {
	_violations_for("cloudwatch_vpc_changes_alarm", _good_input) == 0
}

# =========================================================================
# cloudwatch_08 — Alarm for security group changes
# =========================================================================
test_cloudwatch_08_alarm if {
	_violations_for("cloudwatch_sg_changes_alarm", _without_alarm("security_group_changes")) == 1
}

test_cloudwatch_08_pass if {
	_violations_for("cloudwatch_sg_changes_alarm", _good_input) == 0
}

# =========================================================================
# cloudwatch_09 — Alarm for NACL changes
# =========================================================================
test_cloudwatch_09_alarm if {
	_violations_for("cloudwatch_nacl_changes_alarm", _without_alarm("nacl_changes")) == 1
}

test_cloudwatch_09_pass if {
	_violations_for("cloudwatch_nacl_changes_alarm", _good_input) == 0
}

# =========================================================================
# cloudwatch_10 — Alarm for Internet Gateway changes
# =========================================================================
test_cloudwatch_10_alarm if {
	_violations_for("cloudwatch_igw_changes_alarm", _without_alarm("internet_gateway_changes")) == 1
}

test_cloudwatch_10_pass if {
	_violations_for("cloudwatch_igw_changes_alarm", _good_input) == 0
}

# =========================================================================
# cloudwatch_11 — Log groups must have a retention policy set
# =========================================================================
test_cloudwatch_11_alarm if {
	inp := json.patch(_good_input, [{"op": "remove", "path": "/cloudwatch/log_groups/0/retention_in_days"}])
	_violations_for("cloudwatch_log_retention", inp) == 1
}

test_cloudwatch_11_pass if {
	_violations_for("cloudwatch_log_retention", _good_input) == 0
}

# =========================================================================
# cloudwatch_12 — Sensitive log groups must be encrypted with KMS
# =========================================================================
test_cloudwatch_12_alarm if {
	inp := json.patch(_good_input, [{"op": "remove", "path": "/cloudwatch/log_groups/0/kms_key_id"}])
	_violations_for("cloudwatch_log_kms_encryption", inp) == 1
}

test_cloudwatch_12_pass_has_kms if {
	_violations_for("cloudwatch_log_kms_encryption", _good_input) == 0
}

test_cloudwatch_12_pass_not_sensitive if {
	inp := json.patch(_good_input, [
		{"op": "remove", "path": "/cloudwatch/log_groups/0/kms_key_id"},
		{"op": "replace", "path": "/cloudwatch/log_groups/0/tags/data_classification", "value": "public"},
	])
	_violations_for("cloudwatch_log_kms_encryption", inp) == 0
}

# =========================================================================
# cloudwatch_13 — Alarms must have at least one SNS action
# =========================================================================
test_cloudwatch_13_alarm if {
	bad_alarm := {
		"alarm_name": "no-action-alarm",
		"alarm_arn": "arn:aws:cloudwatch:us-east-1:123456789012:alarm:no-action",
		"metric_name": "custom_metric",
		"alarm_actions": [],
		"state_value": "OK",
	}
	inp := json.patch(_good_input, [{"op": "add", "path": "/cloudwatch/alarms/-", "value": bad_alarm}])
	_violations_for("cloudwatch_alarm_sns_action", inp) == 1
}

test_cloudwatch_13_pass if {
	_violations_for("cloudwatch_alarm_sns_action", _good_input) == 0
}

# =========================================================================
# cloudwatch_14 — No alarms in INSUFFICIENT_DATA state
# =========================================================================
test_cloudwatch_14_alarm if {
	inp := json.patch(_good_input, [{"op": "replace", "path": "/cloudwatch/alarms/0/state_value", "value": "INSUFFICIENT_DATA"}])
	_violations_for("cloudwatch_no_insufficient_data", inp) == 1
}

test_cloudwatch_14_pass if {
	_violations_for("cloudwatch_no_insufficient_data", _good_input) == 0
}

# =========================================================================
# cloudwatch_15 — Alarm for failed console sign-in attempts
# =========================================================================
test_cloudwatch_15_alarm if {
	_violations_for("cloudwatch_failed_login_alarm", _without_alarm("failed_console_logins")) == 1
}

test_cloudwatch_15_pass if {
	_violations_for("cloudwatch_failed_login_alarm", _good_input) == 0
}

# =========================================================================
# cloudwatch_16 — Alarm for CMK deletion or disable events
# =========================================================================
test_cloudwatch_16_alarm if {
	_violations_for("cloudwatch_cmk_deletion_alarm", _without_alarm("kms_key_deletion_disable")) == 1
}

test_cloudwatch_16_pass if {
	_violations_for("cloudwatch_cmk_deletion_alarm", _good_input) == 0
}

# =========================================================================
# cloudwatch_17 — Alarm for AWS Config changes
# =========================================================================
test_cloudwatch_17_alarm if {
	_violations_for("cloudwatch_config_changes_alarm", _without_alarm("config_changes")) == 1
}

test_cloudwatch_17_pass if {
	_violations_for("cloudwatch_config_changes_alarm", _good_input) == 0
}

# =========================================================================
# cloudwatch_18 — Alarm for AWS Organizations changes
# =========================================================================
test_cloudwatch_18_alarm if {
	_violations_for("cloudwatch_org_changes_alarm", _without_alarm("organizations_changes")) == 1
}

test_cloudwatch_18_pass if {
	_violations_for("cloudwatch_org_changes_alarm", _good_input) == 0
}

# =========================================================================
# cloudwatch_19 — Log group retention must be >= 90 days
# =========================================================================
test_cloudwatch_19_alarm if {
	inp := json.patch(_good_input, [{"op": "replace", "path": "/cloudwatch/log_groups/0/retention_in_days", "value": 30}])
	_violations_for("cloudwatch_log_retention_90d", inp) == 1
}

test_cloudwatch_19_pass if {
	_violations_for("cloudwatch_log_retention_90d", _good_input) == 0
}

test_cloudwatch_19_pass_exactly_90 if {
	inp := json.patch(_good_input, [{"op": "replace", "path": "/cloudwatch/log_groups/0/retention_in_days", "value": 90}])
	_violations_for("cloudwatch_log_retention_90d", inp) == 0
}

# =========================================================================
# cloudwatch_20 — Alarm for Route Table changes
# =========================================================================
test_cloudwatch_20_alarm if {
	_violations_for("cloudwatch_route_table_alarm", _without_alarm("route_table_changes")) == 1
}

test_cloudwatch_20_pass if {
	_violations_for("cloudwatch_route_table_alarm", _good_input) == 0
}

# =========================================================================
# Error handler — missing cloudwatch data
# =========================================================================
test_error_missing_cloudwatch if {
	inp := {"region": "us-east-1", "account_id": "123456789012"}
	_errors_for("cloudwatch_error", inp) == 1
}

test_error_not_raised_when_data_present if {
	_errors_for("cloudwatch_error", _good_input) == 0
}

# =========================================================================
# Edge case — alarm with empty actions doesn't satisfy pattern check
# =========================================================================
test_alarm_empty_actions_does_not_satisfy_pattern if {
	bad := json.patch(_good_input, [{"op": "replace", "path": "/cloudwatch/alarms/0/alarm_actions", "value": []}])
	_violations_for("cloudwatch_root_usage_alarm", bad) == 1
}
