package aws.detection.aws_security

import future.keywords.if
import future.keywords.in

# =============================================================================
# AWS SECURITY POLICY — covers GuardDuty, Security Hub, and Inspector
# Rule naming: awssec_01 … awssec_20
# =============================================================================

# ---------------------------------------------------------------------------
# Rule awssec_guardduty_enabled — GuardDuty: detector must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some detector in input.guardduty.detectors
	detector.status != "ENABLED"
	result := {
		"check_id": "awssec_guardduty_enabled",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf("GuardDuty detector '%s' is not enabled", [detector.detector_id]),
		"resource": detector.detector_id,
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_01",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_guardduty_detector — GuardDuty: no detectors found means threat detection is off
# ---------------------------------------------------------------------------
violations contains result if {
	count(input.guardduty.detectors) == 0
	result := {
		"check_id": "awssec_guardduty_detector",
		"status": "alarm",
		"severity": "critical",
		"reason": "No GuardDuty detector found — threat detection is completely disabled",
		"resource": concat("", ["arn:aws:guardduty:", input.region, ":", input.account_id, ":detector/*"]),
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_01",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_guardduty_s3_protection — GuardDuty: S3 protection must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some detector in input.guardduty.detectors
	detector.data_sources.s3_logs.status != "ENABLED"
	result := {
		"check_id": "awssec_guardduty_s3_protection",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"GuardDuty detector '%s' S3 protection is not enabled",
			[detector.detector_id],
		),
		"resource": detector.detector_id,
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_03",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_guardduty_malware_ec2 — GuardDuty: malware protection for EC2 must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some detector in input.guardduty.detectors
	detector.features.malware_protection.status != "ENABLED"
	result := {
		"check_id": "awssec_guardduty_malware_ec2",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"GuardDuty detector '%s' malware protection is not enabled",
			[detector.detector_id],
		),
		"resource": detector.detector_id,
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_04",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_guardduty_no_suppress_crit — GuardDuty: suppression rules must not hide HIGH/CRITICAL findings
# ---------------------------------------------------------------------------
violations contains result if {
	some detector in input.guardduty.detectors
	some filter in detector.filters
	filter.action == "ARCHIVE"
	filter.severity_threshold <= 7
	result := {
		"check_id": "awssec_guardduty_no_suppress_crit",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"GuardDuty filter '%s' suppresses HIGH/CRITICAL severity findings",
			[filter.name],
		),
		"resource": detector.detector_id,
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_05",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_guardduty_publish_frequency — GuardDuty: finding publishing frequency must be <= SIX_HOURS
# ---------------------------------------------------------------------------
violations contains result if {
	some detector in input.guardduty.detectors
	detector.finding_publishing_frequency == "TWENTY_FOUR_HOURS"
	result := {
		"check_id": "awssec_guardduty_publish_frequency",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"GuardDuty detector '%s' publishing frequency is 24h — reduce to 6h or 1h",
			[detector.detector_id],
		),
		"resource": detector.detector_id,
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_06",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_guardduty_sns_high — GuardDuty: SNS notification must be configured for HIGH findings
# ---------------------------------------------------------------------------
violations contains result if {
	some detector in input.guardduty.detectors
	detector.status == "ENABLED"
	not detector.high_severity_sns_arn
	result := {
		"check_id": "awssec_guardduty_sns_high",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"GuardDuty detector '%s' has no SNS notification for HIGH findings",
			[detector.detector_id],
		),
		"resource": detector.detector_id,
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_07",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_securityhub_enabled — Security Hub: must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	input.securityhub.hub_enabled == false
	result := {
		"check_id": "awssec_securityhub_enabled",
		"status": "alarm",
		"severity": "critical",
		"reason": "AWS Security Hub is not enabled in this account/region",
		"resource": concat("", ["arn:aws:securityhub:", input.region, ":", input.account_id, ":hub/default"]),
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_08",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_securityhub_cis_standard — Security Hub: CIS AWS Foundations standard must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	cis_standards := [s |
		some s in input.securityhub.standards
		contains(s.standards_arn, "cis-aws-foundations-benchmark")
	]
	count(cis_standards) == 0
	result := {
		"check_id": "awssec_securityhub_cis_standard",
		"status": "alarm",
		"severity": "high",
		"reason": "CIS AWS Foundations Benchmark standard is not enabled in Security Hub",
		"resource": concat("", ["arn:aws:securityhub:", input.region, ":", input.account_id, ":hub/default"]),
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_09",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_securityhub_fsbp_standard — Security Hub: FSBP standard must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	fsbp := [s |
		some s in input.securityhub.standards
		contains(s.standards_arn, "aws-foundational-security-best-practices")
	]
	count(fsbp) == 0
	result := {
		"check_id": "awssec_securityhub_fsbp_standard",
		"status": "alarm",
		"severity": "high",
		"reason": "AWS Foundational Security Best Practices standard not enabled in Security Hub",
		"resource": concat("", ["arn:aws:securityhub:", input.region, ":", input.account_id, ":hub/default"]),
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_10",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_securityhub_no_suppress_crit — Security Hub: CRITICAL findings must not be suppressed without notes
# ---------------------------------------------------------------------------
violations contains result if {
	some finding in input.securityhub.findings
	finding.workflow.status == "SUPPRESSED"
	finding.severity.label == "CRITICAL"
	not finding.note.text
	result := {
		"check_id": "awssec_securityhub_no_suppress_crit",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Security Hub CRITICAL finding '%s' is suppressed without justification",
			[finding.id],
		),
		"resource": finding.id,
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_11",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_securityhub_delegated_admin — Security Hub: delegated admin must be configured for org
# ---------------------------------------------------------------------------
violations contains result if {
	input.securityhub.is_org_management_account == true
	not input.securityhub.delegated_admin_account_id
	result := {
		"check_id": "awssec_securityhub_delegated_admin",
		"status": "alarm",
		"severity": "high",
		"reason": "Security Hub delegated admin account not configured for the organization",
		"resource": concat("", ["arn:aws:securityhub:", input.region, ":", input.account_id, ":hub/default"]),
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_12",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_securityhub_sns_critical — Security Hub: critical findings must trigger SNS notifications
# ---------------------------------------------------------------------------
violations contains result if {
	input.securityhub.hub_enabled == true
	not input.securityhub.critical_findings_sns_arn
	result := {
		"check_id": "awssec_securityhub_sns_critical",
		"status": "alarm",
		"severity": "high",
		"reason": "Security Hub has no SNS notification for CRITICAL severity findings",
		"resource": concat("", ["arn:aws:securityhub:", input.region, ":", input.account_id, ":hub/default"]),
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_13",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_inspector_ec2_scanning — Inspector: EC2 scanning must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	input.inspector.ec2_scanning_enabled == false
	result := {
		"check_id": "awssec_inspector_ec2_scanning",
		"status": "alarm",
		"severity": "high",
		"reason": "AWS Inspector EC2 instance scanning is not enabled",
		"resource": concat("", ["arn:aws:inspector2:", input.region, ":", input.account_id, ":coverage/ec2"]),
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_14",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_inspector_ecr_scanning — Inspector: ECR container image scanning must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	input.inspector.ecr_scanning_enabled == false
	result := {
		"check_id": "awssec_inspector_ecr_scanning",
		"status": "alarm",
		"severity": "high",
		"reason": "AWS Inspector ECR container image scanning is not enabled",
		"resource": concat("", ["arn:aws:inspector2:", input.region, ":", input.account_id, ":coverage/ecr"]),
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_15",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_inspector_lambda_scanning — Inspector: Lambda function scanning must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	input.inspector.lambda_scanning_enabled == false
	result := {
		"check_id": "awssec_inspector_lambda_scanning",
		"status": "alarm",
		"severity": "high",
		"reason": "AWS Inspector Lambda function scanning is not enabled",
		"resource": concat("", ["arn:aws:inspector2:", input.region, ":", input.account_id, ":coverage/lambda"]),
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_16",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_inspector_critical_cve_30d — Inspector: CRITICAL CVEs must be remediated within 30 days
# ---------------------------------------------------------------------------
violations contains result if {
	some finding in input.inspector.findings
	finding.severity == "CRITICAL"
	finding.status == "ACTIVE"
	finding.age_days > 30
	result := {
		"check_id": "awssec_inspector_critical_cve_30d",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Inspector CRITICAL CVE '%s' on '%s' has been open for %d days (SLA: 30)",
			[finding.finding_arn, finding.resource_id, finding.age_days],
		),
		"resource": finding.resource_id,
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_17",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_inspector_high_cve_90d — Inspector: HIGH CVEs must be remediated within 90 days
# ---------------------------------------------------------------------------
violations contains result if {
	some finding in input.inspector.findings
	finding.severity == "HIGH"
	finding.status == "ACTIVE"
	finding.age_days > 90
	result := {
		"check_id": "awssec_inspector_high_cve_90d",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Inspector HIGH CVE '%s' on '%s' has been open for %d days (SLA: 90)",
			[finding.finding_arn, finding.resource_id, finding.age_days],
		),
		"resource": finding.resource_id,
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_18",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_inspector_securityhub — Inspector: must be integrated with Security Hub
# ---------------------------------------------------------------------------
violations contains result if {
	input.inspector.security_hub_integration_enabled == false
	result := {
		"check_id": "awssec_inspector_securityhub",
		"status": "alarm",
		"severity": "medium",
		"reason": "AWS Inspector is not integrated with Security Hub",
		"resource": concat("", ["arn:aws:inspector2:", input.region, ":", input.account_id, ":integration/security-hub"]),
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_19",
	}
}

# ---------------------------------------------------------------------------
# Rule awssec_inspector_no_suppress_crit — Inspector: suppression filters must not hide CRITICAL findings
# ---------------------------------------------------------------------------
violations contains result if {
	some filter in input.inspector.filters
	filter.action == "SUPPRESS"
	some criterion in filter.filter_criteria
	criterion.field == "severity"
	"CRITICAL" in criterion.values
	result := {
		"check_id": "awssec_inspector_no_suppress_crit",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Inspector suppression filter '%s' suppresses CRITICAL severity findings",
			[filter.name],
		),
		"resource": filter.arn,
		"domain": "detection",
		"service": "aws_security",
		"remediation_id": "REM_awssec_20",
	}
}

# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
error contains result if {
	not input.guardduty
	result := {
		"check_id": "awssec_guardduty_error",
		"status": "error",
		"severity": "critical",
		"reason": "GuardDuty data missing from input — collector may have failed",
		"resource": "",
		"domain": "detection",
		"service": "aws_security",
	}
}

error contains result if {
	not input.securityhub
	result := {
		"check_id": "awssec_securityhub_error",
		"status": "error",
		"severity": "critical",
		"reason": "Security Hub data missing from input — collector may have failed",
		"resource": "",
		"domain": "detection",
		"service": "aws_security",
	}
}

error contains result if {
	not input.inspector
	result := {
		"check_id": "awssec_inspector_error",
		"status": "error",
		"severity": "critical",
		"reason": "Inspector data missing from input — collector may have failed",
		"resource": "",
		"domain": "detection",
		"service": "aws_security",
	}
}
