package aws.logging_monitoring.cloudwatch

import future.keywords.if
import future.keywords.in

# Helper: check if an alarm exists for a given metric filter pattern
alarm_exists_for_pattern(pattern) if {
	some alarm in input.cloudwatch.alarms
	alarm.metric_name == pattern
	alarm.alarm_actions != []
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_root_usage_alarm — Alarm must exist for root account usage
# ---------------------------------------------------------------------------
violations contains result if {
	not alarm_exists_for_pattern("root_account_usage")
	result := {
		"check_id": "cloudwatch_root_usage_alarm",
		"status": "alarm",
		"severity": "critical",
		"reason": "No CloudWatch alarm configured for root account usage",
		"resource": concat("", ["arn:aws:cloudwatch:", input.region, ":", input.account_id, ":alarm:root-usage"]),
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_01",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_unauthorized_api_alarm — Alarm for unauthorized API calls
# ---------------------------------------------------------------------------
violations contains result if {
	not alarm_exists_for_pattern("unauthorized_api_calls")
	result := {
		"check_id": "cloudwatch_unauthorized_api_alarm",
		"status": "alarm",
		"severity": "high",
		"reason": "No CloudWatch alarm configured for unauthorized API calls",
		"resource": concat("", ["arn:aws:cloudwatch:", input.region, ":", input.account_id, ":alarm:unauthorized-api"]),
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_02",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_no_mfa_login_alarm — Alarm for console login without MFA
# ---------------------------------------------------------------------------
violations contains result if {
	not alarm_exists_for_pattern("console_login_no_mfa")
	result := {
		"check_id": "cloudwatch_no_mfa_login_alarm",
		"status": "alarm",
		"severity": "high",
		"reason": "No CloudWatch alarm configured for console login without MFA",
		"resource": concat("", ["arn:aws:cloudwatch:", input.region, ":", input.account_id, ":alarm:console-no-mfa"]),
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_03",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_iam_policy_alarm — Alarm for IAM policy changes
# ---------------------------------------------------------------------------
violations contains result if {
	not alarm_exists_for_pattern("iam_policy_changes")
	result := {
		"check_id": "cloudwatch_iam_policy_alarm",
		"status": "alarm",
		"severity": "high",
		"reason": "No CloudWatch alarm configured for IAM policy changes",
		"resource": concat("", ["arn:aws:cloudwatch:", input.region, ":", input.account_id, ":alarm:iam-changes"]),
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_04",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_cloudtrail_alarm — Alarm for CloudTrail configuration changes
# ---------------------------------------------------------------------------
violations contains result if {
	not alarm_exists_for_pattern("cloudtrail_config_changes")
	result := {
		"check_id": "cloudwatch_cloudtrail_alarm",
		"status": "alarm",
		"severity": "critical",
		"reason": "No CloudWatch alarm configured for CloudTrail configuration changes",
		"resource": concat("", ["arn:aws:cloudwatch:", input.region, ":", input.account_id, ":alarm:cloudtrail-changes"]),
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_05",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_s3_policy_alarm — Alarm for S3 bucket policy changes
# ---------------------------------------------------------------------------
violations contains result if {
	not alarm_exists_for_pattern("s3_bucket_policy_changes")
	result := {
		"check_id": "cloudwatch_s3_policy_alarm",
		"status": "alarm",
		"severity": "high",
		"reason": "No CloudWatch alarm configured for S3 bucket policy changes",
		"resource": concat("", ["arn:aws:cloudwatch:", input.region, ":", input.account_id, ":alarm:s3-policy-changes"]),
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_06",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_vpc_changes_alarm — Alarm for VPC changes
# ---------------------------------------------------------------------------
violations contains result if {
	not alarm_exists_for_pattern("vpc_changes")
	result := {
		"check_id": "cloudwatch_vpc_changes_alarm",
		"status": "alarm",
		"severity": "high",
		"reason": "No CloudWatch alarm configured for VPC changes",
		"resource": concat("", ["arn:aws:cloudwatch:", input.region, ":", input.account_id, ":alarm:vpc-changes"]),
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_07",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_sg_changes_alarm — Alarm for security group changes
# ---------------------------------------------------------------------------
violations contains result if {
	not alarm_exists_for_pattern("security_group_changes")
	result := {
		"check_id": "cloudwatch_sg_changes_alarm",
		"status": "alarm",
		"severity": "high",
		"reason": "No CloudWatch alarm configured for security group changes",
		"resource": concat("", ["arn:aws:cloudwatch:", input.region, ":", input.account_id, ":alarm:sg-changes"]),
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_08",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_nacl_changes_alarm — Alarm for NACL changes
# ---------------------------------------------------------------------------
violations contains result if {
	not alarm_exists_for_pattern("nacl_changes")
	result := {
		"check_id": "cloudwatch_nacl_changes_alarm",
		"status": "alarm",
		"severity": "high",
		"reason": "No CloudWatch alarm configured for NACL changes",
		"resource": concat("", ["arn:aws:cloudwatch:", input.region, ":", input.account_id, ":alarm:nacl-changes"]),
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_09",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_igw_changes_alarm — Alarm for Internet Gateway changes
# ---------------------------------------------------------------------------
violations contains result if {
	not alarm_exists_for_pattern("internet_gateway_changes")
	result := {
		"check_id": "cloudwatch_igw_changes_alarm",
		"status": "alarm",
		"severity": "high",
		"reason": "No CloudWatch alarm configured for Internet Gateway changes",
		"resource": concat("", ["arn:aws:cloudwatch:", input.region, ":", input.account_id, ":alarm:igw-changes"]),
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_10",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_log_retention — Log groups must have a retention policy set
# ---------------------------------------------------------------------------
violations contains result if {
	some lg in input.cloudwatch.log_groups
	not lg.retention_in_days
	result := {
		"check_id": "cloudwatch_log_retention",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"CloudWatch Log Group '%s' has no retention policy (logs never expire)",
			[lg.log_group_name],
		),
		"resource": lg.arn,
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_11",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_log_kms_encryption — Log groups must be encrypted with KMS
# ---------------------------------------------------------------------------
violations contains result if {
	some lg in input.cloudwatch.log_groups
	not lg.kms_key_id
	lg.tags.data_classification == "sensitive"
	result := {
		"check_id": "cloudwatch_log_kms_encryption",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Sensitive CloudWatch Log Group '%s' is not encrypted with KMS",
			[lg.log_group_name],
		),
		"resource": lg.arn,
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_12",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_alarm_sns_action — All alarms must have at least one SNS action configured
# ---------------------------------------------------------------------------
violations contains result if {
	some alarm in input.cloudwatch.alarms
	count(alarm.alarm_actions) == 0
	result := {
		"check_id": "cloudwatch_alarm_sns_action",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"CloudWatch alarm '%s' has no SNS actions configured",
			[alarm.alarm_name],
		),
		"resource": alarm.alarm_arn,
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_13",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_no_insufficient_data — No alarms should be in INSUFFICIENT_DATA state
# ---------------------------------------------------------------------------
violations contains result if {
	some alarm in input.cloudwatch.alarms
	alarm.state_value == "INSUFFICIENT_DATA"
	result := {
		"check_id": "cloudwatch_no_insufficient_data",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"CloudWatch alarm '%s' is in INSUFFICIENT_DATA state",
			[alarm.alarm_name],
		),
		"resource": alarm.alarm_arn,
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_14",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_failed_login_alarm — Alarm for failed console sign-in attempts
# ---------------------------------------------------------------------------
violations contains result if {
	not alarm_exists_for_pattern("failed_console_logins")
	result := {
		"check_id": "cloudwatch_failed_login_alarm",
		"status": "alarm",
		"severity": "high",
		"reason": "No CloudWatch alarm for failed console sign-in attempts",
		"resource": concat("", ["arn:aws:cloudwatch:", input.region, ":", input.account_id, ":alarm:failed-logins"]),
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_15",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_cmk_deletion_alarm — Alarm for CMK deletion or disable events
# ---------------------------------------------------------------------------
violations contains result if {
	not alarm_exists_for_pattern("kms_key_deletion_disable")
	result := {
		"check_id": "cloudwatch_cmk_deletion_alarm",
		"status": "alarm",
		"severity": "high",
		"reason": "No CloudWatch alarm for KMS key deletion or disablement",
		"resource": concat("", ["arn:aws:cloudwatch:", input.region, ":", input.account_id, ":alarm:kms-key-changes"]),
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_16",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_config_changes_alarm — Alarm for AWS Config changes
# ---------------------------------------------------------------------------
violations contains result if {
	not alarm_exists_for_pattern("config_changes")
	result := {
		"check_id": "cloudwatch_config_changes_alarm",
		"status": "alarm",
		"severity": "medium",
		"reason": "No CloudWatch alarm configured for AWS Config configuration changes",
		"resource": concat("", ["arn:aws:cloudwatch:", input.region, ":", input.account_id, ":alarm:config-changes"]),
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_17",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_org_changes_alarm — Alarm for AWS Organizations changes
# ---------------------------------------------------------------------------
violations contains result if {
	not alarm_exists_for_pattern("organizations_changes")
	result := {
		"check_id": "cloudwatch_org_changes_alarm",
		"status": "alarm",
		"severity": "high",
		"reason": "No CloudWatch alarm configured for AWS Organizations changes",
		"resource": concat("", ["arn:aws:cloudwatch:", input.region, ":", input.account_id, ":alarm:org-changes"]),
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_18",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_log_retention_90d — Log group retention must be >= 90 days
# ---------------------------------------------------------------------------
violations contains result if {
	some lg in input.cloudwatch.log_groups
	lg.retention_in_days < 90
	result := {
		"check_id": "cloudwatch_log_retention_90d",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"CloudWatch Log Group '%s' retention is %d days (minimum: 90)",
			[lg.log_group_name, lg.retention_in_days],
		),
		"resource": lg.arn,
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_19",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudwatch_route_table_alarm — Alarm for Route Table changes
# ---------------------------------------------------------------------------
violations contains result if {
	not alarm_exists_for_pattern("route_table_changes")
	result := {
		"check_id": "cloudwatch_route_table_alarm",
		"status": "alarm",
		"severity": "high",
		"reason": "No CloudWatch alarm configured for route table changes",
		"resource": concat("", ["arn:aws:cloudwatch:", input.region, ":", input.account_id, ":alarm:route-changes"]),
		"domain": "logging_monitoring",
		"service": "cloudwatch",
		"remediation_id": "REM_cloudwatch_20",
	}
}

# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
error contains result if {
	not input.cloudwatch
	result := {
		"check_id": "cloudwatch_error",
		"status": "error",
		"severity": "critical",
		"reason": "CloudWatch data missing from input — collector may have failed",
		"resource": "",
		"domain": "logging_monitoring",
		"service": "cloudwatch",
	}
}
