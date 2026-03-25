package aws.logging_monitoring.config

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Rule config_recorder_enabled — AWS Config recorder must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some recorder in input.aws_config.recorders
	recorder.recording_group.all_supported == false
	result := {
		"check_id": "config_recorder_enabled",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"AWS Config recorder '%s' is not recording all supported resources",
			[recorder.name],
		),
		"resource": concat("", ["arn:aws:config:", input.region, ":", input.account_id, ":recorder"]),
		"domain": "logging_monitoring",
		"service": "config",
		"remediation_id": "REM_config_01",
	}
}

# ---------------------------------------------------------------------------
# Rule config_recorder_active — AWS Config recorder must be active (not stopped)
# ---------------------------------------------------------------------------
violations contains result if {
	some status in input.aws_config.recorder_statuses
	status.recording == false
	result := {
		"check_id": "config_recorder_active",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"AWS Config recorder '%s' is not actively recording",
			[status.name],
		),
		"resource": concat("", ["arn:aws:config:", input.region, ":", input.account_id, ":recorder"]),
		"domain": "logging_monitoring",
		"service": "config",
		"remediation_id": "REM_config_02",
	}
}

# ---------------------------------------------------------------------------
# Rule config_delivery_channel — Delivery channel must be configured for Config snapshots
# ---------------------------------------------------------------------------
violations contains result if {
	count(input.aws_config.delivery_channels) == 0
	result := {
		"check_id": "config_delivery_channel",
		"status": "alarm",
		"severity": "high",
		"reason": "AWS Config has no delivery channel configured",
		"resource": concat("", ["arn:aws:config:", input.region, ":", input.account_id, ":delivery-channel"]),
		"domain": "logging_monitoring",
		"service": "config",
		"remediation_id": "REM_config_03",
	}
}

# ---------------------------------------------------------------------------
# Rule config_s3_private — Config S3 delivery bucket must not be publicly accessible
# ---------------------------------------------------------------------------
violations contains result if {
	some channel in input.aws_config.delivery_channels
	channel.s3_bucket_public_access == true
	result := {
		"check_id": "config_s3_private",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"AWS Config delivery S3 bucket '%s' is publicly accessible",
			[channel.s3_bucket_name],
		),
		"resource": concat("", ["arn:aws:s3:::", channel.s3_bucket_name]),
		"domain": "logging_monitoring",
		"service": "config",
		"remediation_id": "REM_config_04",
	}
}

# ---------------------------------------------------------------------------
# Rule config_rules_deployed — Config rules must be deployed
# ---------------------------------------------------------------------------
violations contains result if {
	count(input.aws_config.rules) == 0
	result := {
		"check_id": "config_rules_deployed",
		"status": "alarm",
		"severity": "high",
		"reason": "No AWS Config rules are deployed — compliance posture is unmonitored",
		"resource": concat("", ["arn:aws:config:", input.region, ":", input.account_id, ":config-rule/*"]),
		"domain": "logging_monitoring",
		"service": "config",
		"remediation_id": "REM_config_05",
	}
}

# ---------------------------------------------------------------------------
# Rule config_sns_notification — SNS notification must be configured for compliance changes
# ---------------------------------------------------------------------------
violations contains result if {
	some channel in input.aws_config.delivery_channels
	not channel.sns_topic_arn
	result := {
		"check_id": "config_sns_notification",
		"status": "alarm",
		"severity": "medium",
		"reason": "AWS Config delivery channel has no SNS notification configured",
		"resource": concat("", ["arn:aws:config:", input.region, ":", input.account_id, ":delivery-channel"]),
		"domain": "logging_monitoring",
		"service": "config",
		"remediation_id": "REM_config_06",
	}
}

# ---------------------------------------------------------------------------
# Rule config_global_iam_resources — Config recorder must include global IAM resources
# ---------------------------------------------------------------------------
violations contains result if {
	some recorder in input.aws_config.recorders
	recorder.recording_group.include_global_resource_types == false
	result := {
		"check_id": "config_global_iam_resources",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"AWS Config recorder '%s' does not include global IAM resource types",
			[recorder.name],
		),
		"resource": concat("", ["arn:aws:config:", input.region, ":", input.account_id, ":recorder"]),
		"domain": "logging_monitoring",
		"service": "config",
		"remediation_id": "REM_config_07",
	}
}

# ---------------------------------------------------------------------------
# Rule config_multi_account_aggregator — Multi-account aggregator must be configured
# ---------------------------------------------------------------------------
violations contains result if {
	count(input.aws_config.aggregators) == 0
	result := {
		"check_id": "config_multi_account_aggregator",
		"status": "alarm",
		"severity": "medium",
		"reason": "No AWS Config multi-account aggregator configured",
		"resource": concat("", ["arn:aws:config:", input.region, ":", input.account_id, ":config-aggregator/*"]),
		"domain": "logging_monitoring",
		"service": "config",
		"remediation_id": "REM_config_08",
	}
}

# ---------------------------------------------------------------------------
# Rule config_conformance_packs — Conformance packs must be deployed
# ---------------------------------------------------------------------------
violations contains result if {
	count(input.aws_config.conformance_packs) == 0
	result := {
		"check_id": "config_conformance_packs",
		"status": "alarm",
		"severity": "medium",
		"reason": "No AWS Config conformance packs deployed — compliance baselines missing",
		"resource": concat("", ["arn:aws:config:", input.region, ":", input.account_id, ":conformance-pack/*"]),
		"domain": "logging_monitoring",
		"service": "config",
		"remediation_id": "REM_config_09",
	}
}

# ---------------------------------------------------------------------------
# Rule config_remediation_actions — Non-compliant Config rules must have remediation actions
# ---------------------------------------------------------------------------
violations contains result if {
	some rule in input.aws_config.rules
	rule.compliance_type == "NON_COMPLIANT"
	not rule.remediation_configuration
	result := {
		"check_id": "config_remediation_actions",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"AWS Config rule '%s' is non-compliant and has no remediation action configured",
			[rule.config_rule_name],
		),
		"resource": rule.config_rule_arn,
		"domain": "logging_monitoring",
		"service": "config",
		"remediation_id": "REM_config_10",
	}
}

# ---------------------------------------------------------------------------
# Rule config_daily_snapshots — Config delivery channel snapshot frequency must be daily
# ---------------------------------------------------------------------------
violations contains result if {
	some channel in input.aws_config.delivery_channels
	channel.config_snapshot_delivery_properties.delivery_frequency == "TwentyFour_Hours"
	result := {
		"check_id": "config_daily_snapshots",
		"status": "alarm",
		"severity": "low",
		"reason": "AWS Config snapshot delivery frequency is 24 hours — use 1 or 3 hours",
		"resource": concat("", ["arn:aws:config:", input.region, ":", input.account_id, ":delivery-channel"]),
		"domain": "logging_monitoring",
		"service": "config",
		"remediation_id": "REM_config_11",
	}
}

# ---------------------------------------------------------------------------
# Rule config_no_error_rules — Config rules must not have ERROR state
# ---------------------------------------------------------------------------
violations contains result if {
	some rule in input.aws_config.rules
	rule.config_rule_state == "EVALUATING"
	result := {
		"check_id": "config_no_error_rules",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"AWS Config rule '%s' is stuck in EVALUATING state",
			[rule.config_rule_name],
		),
		"resource": rule.config_rule_arn,
		"domain": "logging_monitoring",
		"service": "config",
		"remediation_id": "REM_config_12",
	}
}

# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
error contains result if {
	not input.aws_config
	result := {
		"check_id": "config_error",
		"status": "error",
		"severity": "critical",
		"reason": "AWS Config data missing from input — collector may have failed",
		"resource": "",
		"domain": "logging_monitoring",
		"service": "config",
	}
}
