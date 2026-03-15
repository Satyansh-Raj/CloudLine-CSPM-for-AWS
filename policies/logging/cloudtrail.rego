package aws.logging_monitoring.cloudtrail

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Rule cloudtrail_01 — Trail must be enabled and actively logging
# ---------------------------------------------------------------------------
violations contains result if {
	some trail in input.cloudtrail.trails
	trail.is_logging == false
	result := {
		"check_id": "cloudtrail_01",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"CloudTrail trail '%s' is not actively logging",
			[trail.name],
		),
		"resource": trail.trail_arn,
		"domain": "logging_monitoring",
		"service": "cloudtrail",
		"compliance": {
			"cis_aws": ["3.1"],
			"nist_800_53": ["AU-12"],
			"pci_dss": ["10.2"],
		},
		"remediation_id": "REM_cloudtrail_01",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudtrail_02 — Multi-region trail must be configured
# ---------------------------------------------------------------------------
violations contains result if {
	multi_region_trails := [t | some t in input.cloudtrail.trails; t.is_multi_region_trail == true]
	count(multi_region_trails) == 0
	result := {
		"check_id": "cloudtrail_02",
		"status": "alarm",
		"severity": "critical",
		"reason": "No multi-region CloudTrail trail configured — activity in other regions unlogged",
		"resource": concat("", ["arn:aws:cloudtrail:", input.region, ":", input.account_id, ":trail/*"]),
		"domain": "logging_monitoring",
		"service": "cloudtrail",
		"compliance": {
			"cis_aws": ["3.1"],
			"nist_800_53": ["AU-12"],
			"pci_dss": ["10.1"],
		},
		"remediation_id": "REM_cloudtrail_02",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudtrail_03 — Log file validation must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some trail in input.cloudtrail.trails
	trail.log_file_validation_enabled == false
	result := {
		"check_id": "cloudtrail_03",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"CloudTrail trail '%s' does not have log file validation enabled",
			[trail.name],
		),
		"resource": trail.trail_arn,
		"domain": "logging_monitoring",
		"service": "cloudtrail",
		"compliance": {
			"cis_aws": ["3.2"],
			"nist_800_53": ["AU-9"],
			"pci_dss": ["10.5"],
		},
		"remediation_id": "REM_cloudtrail_03",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudtrail_04 — S3 bucket for logs must not be publicly accessible
# ---------------------------------------------------------------------------
violations contains result if {
	some trail in input.cloudtrail.trails
	trail.s3_bucket_public_access == true
	result := {
		"check_id": "cloudtrail_04",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"CloudTrail trail '%s' S3 log bucket is publicly accessible",
			[trail.name],
		),
		"resource": trail.trail_arn,
		"domain": "logging_monitoring",
		"service": "cloudtrail",
		"compliance": {
			"cis_aws": ["3.3"],
			"nist_800_53": ["AU-9"],
			"pci_dss": ["10.5"],
		},
		"remediation_id": "REM_cloudtrail_04",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudtrail_05 — CloudWatch Logs integration must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some trail in input.cloudtrail.trails
	not trail.cloud_watch_logs_log_group_arn
	result := {
		"check_id": "cloudtrail_05",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"CloudTrail trail '%s' is not integrated with CloudWatch Logs",
			[trail.name],
		),
		"resource": trail.trail_arn,
		"domain": "logging_monitoring",
		"service": "cloudtrail",
		"compliance": {
			"cis_aws": ["3.4"],
			"nist_800_53": ["AU-6"],
			"pci_dss": ["10.7"],
		},
		"remediation_id": "REM_cloudtrail_05",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudtrail_06 — KMS encryption for CloudTrail log files must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some trail in input.cloudtrail.trails
	not trail.kms_key_id
	result := {
		"check_id": "cloudtrail_06",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"CloudTrail trail '%s' logs are not encrypted with KMS",
			[trail.name],
		),
		"resource": trail.trail_arn,
		"domain": "logging_monitoring",
		"service": "cloudtrail",
		"compliance": {
			"cis_aws": ["3.5"],
			"nist_800_53": ["AU-9"],
			"pci_dss": ["10.5"],
		},
		"remediation_id": "REM_cloudtrail_06",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudtrail_07 — SNS notification must be configured for trail events
# ---------------------------------------------------------------------------
violations contains result if {
	some trail in input.cloudtrail.trails
	not trail.sns_topic_arn
	result := {
		"check_id": "cloudtrail_07",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"CloudTrail trail '%s' has no SNS notification configured",
			[trail.name],
		),
		"resource": trail.trail_arn,
		"domain": "logging_monitoring",
		"service": "cloudtrail",
		"compliance": {
			"nist_800_53": ["AU-6"],
		},
		"remediation_id": "REM_cloudtrail_07",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudtrail_08 — Management events must be logged (read and write)
# ---------------------------------------------------------------------------
violations contains result if {
	some trail in input.cloudtrail.trails
	some selector in trail.event_selectors
	selector.include_management_events == false
	result := {
		"check_id": "cloudtrail_08",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"CloudTrail trail '%s' does not log management events",
			[trail.name],
		),
		"resource": trail.trail_arn,
		"domain": "logging_monitoring",
		"service": "cloudtrail",
		"compliance": {
			"cis_aws": ["3.1"],
			"nist_800_53": ["AU-12"],
			"pci_dss": ["10.2"],
		},
		"remediation_id": "REM_cloudtrail_08",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudtrail_09 — Read-only and write management events must both be logged
# ---------------------------------------------------------------------------
violations contains result if {
	some trail in input.cloudtrail.trails
	some selector in trail.event_selectors
	selector.include_management_events == true
	selector.read_write_type == "WriteOnly"
	result := {
		"check_id": "cloudtrail_09",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"CloudTrail trail '%s' only logs write events — read events excluded",
			[trail.name],
		),
		"resource": trail.trail_arn,
		"domain": "logging_monitoring",
		"service": "cloudtrail",
		"compliance": {
			"cis_aws": ["3.1"],
			"nist_800_53": ["AU-12"],
		},
		"remediation_id": "REM_cloudtrail_09",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudtrail_10 — S3 data events must be logged
# ---------------------------------------------------------------------------
violations contains result if {
	some trail in input.cloudtrail.trails
	s3_data_selectors := [s |
		some s in trail.event_selectors
		some r in s.data_resources
		r.type == "AWS::S3::Object"
	]
	count(s3_data_selectors) == 0
	result := {
		"check_id": "cloudtrail_10",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"CloudTrail trail '%s' does not log S3 data events",
			[trail.name],
		),
		"resource": trail.trail_arn,
		"domain": "logging_monitoring",
		"service": "cloudtrail",
		"compliance": {
			"cis_aws": ["3.11"],
			"nist_800_53": ["AU-12"],
			"pci_dss": ["10.2"],
		},
		"remediation_id": "REM_cloudtrail_10",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudtrail_11 — Lambda data events must be logged
# ---------------------------------------------------------------------------
violations contains result if {
	some trail in input.cloudtrail.trails
	lambda_selectors := [s |
		some s in trail.event_selectors
		some r in s.data_resources
		r.type == "AWS::Lambda::Function"
	]
	count(lambda_selectors) == 0
	result := {
		"check_id": "cloudtrail_11",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"CloudTrail trail '%s' does not log Lambda data events",
			[trail.name],
		),
		"resource": trail.trail_arn,
		"domain": "logging_monitoring",
		"service": "cloudtrail",
		"compliance": {
			"cis_aws": ["3.12"],
			"nist_800_53": ["AU-12"],
		},
		"remediation_id": "REM_cloudtrail_11",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudtrail_12 — CloudTrail Insights must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some trail in input.cloudtrail.trails
	count(trail.insight_selectors) == 0
	result := {
		"check_id": "cloudtrail_12",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"CloudTrail trail '%s' does not have Insight events enabled",
			[trail.name],
		),
		"resource": trail.trail_arn,
		"domain": "logging_monitoring",
		"service": "cloudtrail",
		"compliance": {
			"nist_800_53": ["AU-6"],
			"pci_dss": ["10.7"],
		},
		"remediation_id": "REM_cloudtrail_12",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudtrail_13 — Global service events must be included in multi-region trail
# ---------------------------------------------------------------------------
violations contains result if {
	some trail in input.cloudtrail.trails
	trail.is_multi_region_trail == true
	trail.include_global_service_events == false
	result := {
		"check_id": "cloudtrail_13",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Multi-region CloudTrail trail '%s' excludes global service events (IAM, STS)",
			[trail.name],
		),
		"resource": trail.trail_arn,
		"domain": "logging_monitoring",
		"service": "cloudtrail",
		"compliance": {
			"cis_aws": ["3.1"],
			"nist_800_53": ["AU-12"],
		},
		"remediation_id": "REM_cloudtrail_13",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudtrail_14 — Log retention must be >= 365 days
# ---------------------------------------------------------------------------
violations contains result if {
	some trail in input.cloudtrail.trails
	trail.log_retention_days < 365
	result := {
		"check_id": "cloudtrail_14",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"CloudTrail trail '%s' log retention is %d days (minimum: 365)",
			[trail.name, trail.log_retention_days],
		),
		"resource": trail.trail_arn,
		"domain": "logging_monitoring",
		"service": "cloudtrail",
		"compliance": {
			"nist_800_53": ["AU-11"],
			"pci_dss": ["10.7"],
			"hipaa": ["164.312(b)"],
		},
		"remediation_id": "REM_cloudtrail_14",
	}
}

# ---------------------------------------------------------------------------
# Rule cloudtrail_15 — S3 bucket for CloudTrail must not allow public access
#                      and must have MFA delete enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some trail in input.cloudtrail.trails
	trail.s3_bucket_mfa_delete_enabled == false
	result := {
		"check_id": "cloudtrail_15",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"CloudTrail trail '%s' S3 log bucket does not have MFA Delete enabled",
			[trail.name],
		),
		"resource": trail.trail_arn,
		"domain": "logging_monitoring",
		"service": "cloudtrail",
		"compliance": {
			"cis_aws": ["3.3"],
			"nist_800_53": ["AU-9"],
		},
		"remediation_id": "REM_cloudtrail_15",
	}
}

# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
error contains result if {
	not input.cloudtrail
	result := {
		"check_id": "cloudtrail_00",
		"status": "error",
		"severity": "critical",
		"reason": "CloudTrail data missing from input — collector may have failed",
		"resource": "",
		"domain": "logging_monitoring",
		"service": "cloudtrail",
	}
}
