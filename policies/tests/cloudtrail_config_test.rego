package aws.logging_monitoring.cloudtrail_config_test

import data.aws.logging_monitoring.cloudtrail
import data.aws.logging_monitoring.config

# =========================================================================
# Helpers
# =========================================================================
_ct_violations_for(check_id, inp) := count([v |
	some v in cloudtrail.violations with input as inp
	v.check_id == check_id
])

_cfg_violations_for(check_id, inp) := count([v |
	some v in config.violations with input as inp
	v.check_id == check_id
])

# =========================================================================
# Compliant CloudTrail fixture
# =========================================================================
_good_trail := {
	"name": "main-trail",
	"trail_arn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/main-trail",
	"is_logging": true,
	"is_multi_region_trail": true,
	"log_file_validation_enabled": true,
	"s3_bucket_public_access": false,
	"cloud_watch_logs_log_group_arn": "arn:aws:logs:us-east-1:123456789012:log-group:cloudtrail",
	"kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/abcdef",
	"sns_topic_arn": "arn:aws:sns:us-east-1:123456789012:cloudtrail-alerts",
	"event_selectors": [{
		"include_management_events": true,
		"read_write_type": "All",
		"data_resources": [
			{"type": "AWS::S3::Object", "values": ["arn:aws:s3"]},
			{"type": "AWS::Lambda::Function", "values": ["arn:aws:lambda"]},
		],
	}],
	"insight_selectors": [{"insight_type": "ApiCallRateInsight"}],
	"include_global_service_events": true,
	"log_retention_days": 365,
	"s3_bucket_mfa_delete_enabled": true,
}

_good_ct_input := {
	"region": "us-east-1",
	"account_id": "123456789012",
	"cloudtrail": {"trails": [_good_trail]},
}

# =========================================================================
# cloudtrail_01 — Trail must be actively logging
# =========================================================================
test_cloudtrail_01_alarm if {
	inp := json.patch(_good_ct_input, [{"op": "replace", "path": "/cloudtrail/trails/0/is_logging", "value": false}])
	_ct_violations_for("cloudtrail_01", inp) == 1
}

test_cloudtrail_01_pass if {
	_ct_violations_for("cloudtrail_01", _good_ct_input) == 0
}

# =========================================================================
# cloudtrail_02 — Multi-region trail must be configured
# =========================================================================
test_cloudtrail_02_alarm if {
	inp := json.patch(_good_ct_input, [{"op": "replace", "path": "/cloudtrail/trails/0/is_multi_region_trail", "value": false}])
	_ct_violations_for("cloudtrail_02", inp) == 1
}

test_cloudtrail_02_pass if {
	_ct_violations_for("cloudtrail_02", _good_ct_input) == 0
}

# =========================================================================
# cloudtrail_03 — Log file validation enabled
# =========================================================================
test_cloudtrail_03_alarm if {
	inp := json.patch(_good_ct_input, [{"op": "replace", "path": "/cloudtrail/trails/0/log_file_validation_enabled", "value": false}])
	_ct_violations_for("cloudtrail_03", inp) == 1
}

test_cloudtrail_03_pass if {
	_ct_violations_for("cloudtrail_03", _good_ct_input) == 0
}

# =========================================================================
# cloudtrail_04 — S3 bucket not publicly accessible
# =========================================================================
test_cloudtrail_04_alarm if {
	inp := json.patch(_good_ct_input, [{"op": "replace", "path": "/cloudtrail/trails/0/s3_bucket_public_access", "value": true}])
	_ct_violations_for("cloudtrail_04", inp) == 1
}

test_cloudtrail_04_pass if {
	_ct_violations_for("cloudtrail_04", _good_ct_input) == 0
}

# =========================================================================
# cloudtrail_05 — CloudWatch Logs integration enabled
# =========================================================================
test_cloudtrail_05_alarm if {
	bad_trail := object.remove(_good_trail, ["cloud_watch_logs_log_group_arn"])
	inp := {"region": "us-east-1", "account_id": "123456789012", "cloudtrail": {"trails": [bad_trail]}}
	_ct_violations_for("cloudtrail_05", inp) == 1
}

test_cloudtrail_05_pass if {
	_ct_violations_for("cloudtrail_05", _good_ct_input) == 0
}

# =========================================================================
# cloudtrail_06 — KMS encryption enabled
# =========================================================================
test_cloudtrail_06_alarm if {
	bad_trail := object.remove(_good_trail, ["kms_key_id"])
	inp := {"region": "us-east-1", "account_id": "123456789012", "cloudtrail": {"trails": [bad_trail]}}
	_ct_violations_for("cloudtrail_06", inp) == 1
}

test_cloudtrail_06_pass if {
	_ct_violations_for("cloudtrail_06", _good_ct_input) == 0
}

# =========================================================================
# cloudtrail_07 — SNS notification configured
# =========================================================================
test_cloudtrail_07_alarm if {
	bad_trail := object.remove(_good_trail, ["sns_topic_arn"])
	inp := {"region": "us-east-1", "account_id": "123456789012", "cloudtrail": {"trails": [bad_trail]}}
	_ct_violations_for("cloudtrail_07", inp) == 1
}

test_cloudtrail_07_pass if {
	_ct_violations_for("cloudtrail_07", _good_ct_input) == 0
}

# =========================================================================
# cloudtrail_08 — Management events logged
# =========================================================================
test_cloudtrail_08_alarm if {
	inp := json.patch(_good_ct_input, [{"op": "replace", "path": "/cloudtrail/trails/0/event_selectors/0/include_management_events", "value": false}])
	_ct_violations_for("cloudtrail_08", inp) == 1
}

test_cloudtrail_08_pass if {
	_ct_violations_for("cloudtrail_08", _good_ct_input) == 0
}

# =========================================================================
# cloudtrail_09 — Both read and write events logged
# =========================================================================
test_cloudtrail_09_alarm if {
	inp := json.patch(_good_ct_input, [{"op": "replace", "path": "/cloudtrail/trails/0/event_selectors/0/read_write_type", "value": "WriteOnly"}])
	_ct_violations_for("cloudtrail_09", inp) == 1
}

test_cloudtrail_09_pass if {
	_ct_violations_for("cloudtrail_09", _good_ct_input) == 0
}

test_cloudtrail_09_pass_readonly if {
	inp := json.patch(_good_ct_input, [{"op": "replace", "path": "/cloudtrail/trails/0/event_selectors/0/read_write_type", "value": "ReadOnly"}])
	_ct_violations_for("cloudtrail_09", inp) == 0
}

# =========================================================================
# cloudtrail_10 — S3 data events logged
# =========================================================================
test_cloudtrail_10_alarm if {
	bad_trail := json.patch(_good_trail, [{"op": "replace", "path": "/event_selectors", "value": [{
		"include_management_events": true,
		"read_write_type": "All",
		"data_resources": [],
	}]}])
	inp := {"region": "us-east-1", "account_id": "123456789012", "cloudtrail": {"trails": [bad_trail]}}
	_ct_violations_for("cloudtrail_10", inp) == 1
}

test_cloudtrail_10_pass if {
	_ct_violations_for("cloudtrail_10", _good_ct_input) == 0
}

# =========================================================================
# cloudtrail_11 — Lambda data events logged
# =========================================================================
test_cloudtrail_11_alarm if {
	bad_trail := json.patch(_good_trail, [{"op": "replace", "path": "/event_selectors", "value": [{
		"include_management_events": true,
		"read_write_type": "All",
		"data_resources": [{"type": "AWS::S3::Object", "values": ["arn:aws:s3"]}],
	}]}])
	inp := {"region": "us-east-1", "account_id": "123456789012", "cloudtrail": {"trails": [bad_trail]}}
	_ct_violations_for("cloudtrail_11", inp) == 1
}

test_cloudtrail_11_pass if {
	_ct_violations_for("cloudtrail_11", _good_ct_input) == 0
}

# =========================================================================
# cloudtrail_12 — Insights enabled
# =========================================================================
test_cloudtrail_12_alarm if {
	inp := json.patch(_good_ct_input, [{"op": "replace", "path": "/cloudtrail/trails/0/insight_selectors", "value": []}])
	_ct_violations_for("cloudtrail_12", inp) == 1
}

test_cloudtrail_12_pass if {
	_ct_violations_for("cloudtrail_12", _good_ct_input) == 0
}

# =========================================================================
# cloudtrail_13 — Global service events in multi-region trail
# =========================================================================
test_cloudtrail_13_alarm if {
	inp := json.patch(_good_ct_input, [{"op": "replace", "path": "/cloudtrail/trails/0/include_global_service_events", "value": false}])
	_ct_violations_for("cloudtrail_13", inp) == 1
}

test_cloudtrail_13_pass if {
	_ct_violations_for("cloudtrail_13", _good_ct_input) == 0
}

test_cloudtrail_13_pass_single_region if {
	inp := json.patch(_good_ct_input, [{
		"op": "replace", "path": "/cloudtrail/trails/0/is_multi_region_trail", "value": false,
	}, {
		"op": "replace", "path": "/cloudtrail/trails/0/include_global_service_events", "value": false,
	}])
	_ct_violations_for("cloudtrail_13", inp) == 0
}

# =========================================================================
# cloudtrail_14 — Log retention >= 365 days
# =========================================================================
test_cloudtrail_14_alarm if {
	inp := json.patch(_good_ct_input, [{"op": "replace", "path": "/cloudtrail/trails/0/log_retention_days", "value": 90}])
	_ct_violations_for("cloudtrail_14", inp) == 1
}

test_cloudtrail_14_pass if {
	_ct_violations_for("cloudtrail_14", _good_ct_input) == 0
}

test_cloudtrail_14_pass_over_365 if {
	inp := json.patch(_good_ct_input, [{"op": "replace", "path": "/cloudtrail/trails/0/log_retention_days", "value": 730}])
	_ct_violations_for("cloudtrail_14", inp) == 0
}

# =========================================================================
# cloudtrail_15 — S3 bucket MFA Delete enabled
# =========================================================================
test_cloudtrail_15_alarm if {
	inp := json.patch(_good_ct_input, [{"op": "replace", "path": "/cloudtrail/trails/0/s3_bucket_mfa_delete_enabled", "value": false}])
	_ct_violations_for("cloudtrail_15", inp) == 1
}

test_cloudtrail_15_pass if {
	_ct_violations_for("cloudtrail_15", _good_ct_input) == 0
}

# =========================================================================
# cloudtrail error handler
# =========================================================================
test_cloudtrail_error_missing_data if {
	errs := cloudtrail.error with input as {"region": "us-east-1"}
	count(errs) == 1
}

test_cloudtrail_error_data_present if {
	errs := cloudtrail.error with input as _good_ct_input
	count(errs) == 0
}

# =========================================================================
# CloudTrail — fully compliant produces zero violations
# =========================================================================
test_cloudtrail_all_compliant if {
	viols := cloudtrail.violations with input as _good_ct_input
	count(viols) == 0
}

# =========================================================================
# =========================================================================
# AWS Config Tests
# =========================================================================
# =========================================================================

# =========================================================================
# Compliant Config fixture
# =========================================================================
_good_recorder := {
	"name": "default",
	"recording_group": {
		"all_supported": true,
		"include_global_resource_types": true,
	},
}

_good_recorder_status := {
	"name": "default",
	"recording": true,
}

_good_channel := {
	"name": "default",
	"s3_bucket_name": "config-bucket-123",
	"s3_bucket_public_access": false,
	"sns_topic_arn": "arn:aws:sns:us-east-1:123456789012:config-topic",
	"config_snapshot_delivery_properties": {
		"delivery_frequency": "One_Hour",
	},
}

_good_rule := {
	"config_rule_name": "s3-bucket-versioning",
	"config_rule_arn": "arn:aws:config:us-east-1:123456789012:config-rule/config-rule-abc",
	"compliance_type": "COMPLIANT",
	"config_rule_state": "ACTIVE",
	"remediation_configuration": {"target_id": "SSM-Doc"},
}

_good_cfg_input := {
	"region": "us-east-1",
	"account_id": "123456789012",
	"aws_config": {
		"recorders": [_good_recorder],
		"recorder_statuses": [_good_recorder_status],
		"delivery_channels": [_good_channel],
		"rules": [_good_rule],
		"aggregators": [{"aggregator_name": "org-aggregator"}],
		"conformance_packs": [{"conformance_pack_name": "cis-pack"}],
	},
}

# =========================================================================
# config_01 — Recorder must record all supported resources
# =========================================================================
test_config_01_alarm if {
	inp := json.patch(_good_cfg_input, [{"op": "replace", "path": "/aws_config/recorders/0/recording_group/all_supported", "value": false}])
	_cfg_violations_for("config_01", inp) == 1
}

test_config_01_pass if {
	_cfg_violations_for("config_01", _good_cfg_input) == 0
}

# =========================================================================
# config_02 — Recorder must be actively recording
# =========================================================================
test_config_02_alarm if {
	inp := json.patch(_good_cfg_input, [{"op": "replace", "path": "/aws_config/recorder_statuses/0/recording", "value": false}])
	_cfg_violations_for("config_02", inp) == 1
}

test_config_02_pass if {
	_cfg_violations_for("config_02", _good_cfg_input) == 0
}

# =========================================================================
# config_03 — Delivery channel must be configured
# =========================================================================
test_config_03_alarm if {
	inp := json.patch(_good_cfg_input, [{"op": "replace", "path": "/aws_config/delivery_channels", "value": []}])
	_cfg_violations_for("config_03", inp) == 1
}

test_config_03_pass if {
	_cfg_violations_for("config_03", _good_cfg_input) == 0
}

# =========================================================================
# config_04 — Delivery S3 bucket not publicly accessible
# =========================================================================
test_config_04_alarm if {
	inp := json.patch(_good_cfg_input, [{"op": "replace", "path": "/aws_config/delivery_channels/0/s3_bucket_public_access", "value": true}])
	_cfg_violations_for("config_04", inp) == 1
}

test_config_04_pass if {
	_cfg_violations_for("config_04", _good_cfg_input) == 0
}

# =========================================================================
# config_05 — Config rules must be deployed
# =========================================================================
test_config_05_alarm if {
	inp := json.patch(_good_cfg_input, [{"op": "replace", "path": "/aws_config/rules", "value": []}])
	_cfg_violations_for("config_05", inp) == 1
}

test_config_05_pass if {
	_cfg_violations_for("config_05", _good_cfg_input) == 0
}

# =========================================================================
# config_06 — SNS notification configured on delivery channel
# =========================================================================
test_config_06_alarm if {
	bad_channel := object.remove(_good_channel, ["sns_topic_arn"])
	inp := json.patch(_good_cfg_input, [{"op": "replace", "path": "/aws_config/delivery_channels", "value": [bad_channel]}])
	_cfg_violations_for("config_06", inp) == 1
}

test_config_06_pass if {
	_cfg_violations_for("config_06", _good_cfg_input) == 0
}

# =========================================================================
# config_07 — Recorder must include global IAM resources
# =========================================================================
test_config_07_alarm if {
	inp := json.patch(_good_cfg_input, [{"op": "replace", "path": "/aws_config/recorders/0/recording_group/include_global_resource_types", "value": false}])
	_cfg_violations_for("config_07", inp) == 1
}

test_config_07_pass if {
	_cfg_violations_for("config_07", _good_cfg_input) == 0
}

# =========================================================================
# config_08 — Multi-account aggregator configured
# =========================================================================
test_config_08_alarm if {
	inp := json.patch(_good_cfg_input, [{"op": "replace", "path": "/aws_config/aggregators", "value": []}])
	_cfg_violations_for("config_08", inp) == 1
}

test_config_08_pass if {
	_cfg_violations_for("config_08", _good_cfg_input) == 0
}

# =========================================================================
# config_09 — Conformance packs deployed
# =========================================================================
test_config_09_alarm if {
	inp := json.patch(_good_cfg_input, [{"op": "replace", "path": "/aws_config/conformance_packs", "value": []}])
	_cfg_violations_for("config_09", inp) == 1
}

test_config_09_pass if {
	_cfg_violations_for("config_09", _good_cfg_input) == 0
}

# =========================================================================
# config_10 — Non-compliant rules must have remediation
# =========================================================================
test_config_10_alarm if {
	bad_rule := object.remove(_good_rule, ["remediation_configuration"])
	bad_rule2 := object.union(bad_rule, {"compliance_type": "NON_COMPLIANT"})
	inp := json.patch(_good_cfg_input, [{"op": "replace", "path": "/aws_config/rules", "value": [bad_rule2]}])
	_cfg_violations_for("config_10", inp) == 1
}

test_config_10_pass_compliant if {
	_cfg_violations_for("config_10", _good_cfg_input) == 0
}

test_config_10_pass_has_remediation if {
	rule_with_remediation := object.union(_good_rule, {
		"compliance_type": "NON_COMPLIANT",
		"remediation_configuration": {"target_id": "SSM-Fix"},
	})
	inp := json.patch(_good_cfg_input, [{"op": "replace", "path": "/aws_config/rules", "value": [rule_with_remediation]}])
	_cfg_violations_for("config_10", inp) == 0
}

# =========================================================================
# config_11 — Snapshot frequency not 24 hours
# =========================================================================
test_config_11_alarm if {
	inp := json.patch(_good_cfg_input, [{"op": "replace", "path": "/aws_config/delivery_channels/0/config_snapshot_delivery_properties/delivery_frequency", "value": "TwentyFour_Hours"}])
	_cfg_violations_for("config_11", inp) == 1
}

test_config_11_pass if {
	_cfg_violations_for("config_11", _good_cfg_input) == 0
}

test_config_11_pass_three_hours if {
	inp := json.patch(_good_cfg_input, [{"op": "replace", "path": "/aws_config/delivery_channels/0/config_snapshot_delivery_properties/delivery_frequency", "value": "Three_Hours"}])
	_cfg_violations_for("config_11", inp) == 0
}

# =========================================================================
# config_12 — Rules must not be stuck in EVALUATING state
# =========================================================================
test_config_12_alarm if {
	inp := json.patch(_good_cfg_input, [{"op": "replace", "path": "/aws_config/rules/0/config_rule_state", "value": "EVALUATING"}])
	_cfg_violations_for("config_12", inp) == 1
}

test_config_12_pass if {
	_cfg_violations_for("config_12", _good_cfg_input) == 0
}

# =========================================================================
# Config error handler
# =========================================================================
test_config_error_missing_data if {
	errs := config.error with input as {"region": "us-east-1"}
	count(errs) == 1
}

test_config_error_data_present if {
	errs := config.error with input as _good_cfg_input
	count(errs) == 0
}

# =========================================================================
# Config — fully compliant produces zero violations
# =========================================================================
test_config_all_compliant if {
	viols := config.violations with input as _good_cfg_input
	count(viols) == 0
}
