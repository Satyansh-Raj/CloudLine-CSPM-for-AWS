package aws.detection.aws_security_test

import data.aws.detection.aws_security

# =========================================================================
# Helpers
# =========================================================================
_violations_for(check_id, inp) := count([v |
	some v in aws_security.violations with input as inp
	v.check_id == check_id
])

_errors_for(check_id, inp) := count([e |
	some e in aws_security.error with input as inp
	e.check_id == check_id
])

# =========================================================================
# Compliant fixtures
# =========================================================================
_good_detector := {
	"detector_id": "d-abc123",
	"status": "ENABLED",
	"data_sources": {"s3_logs": {"status": "ENABLED"}},
	"features": {"malware_protection": {"status": "ENABLED"}},
	"filters": [],
	"finding_publishing_frequency": "SIX_HOURS",
	"high_severity_sns_arn": "arn:aws:sns:us-east-1:123456789012:guardduty-high",
}

_good_securityhub := {
	"hub_enabled": true,
	"standards": [
		{"standards_arn": "arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.4.0"},
		{"standards_arn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0"},
	],
	"findings": [],
	"is_org_management_account": false,
	"critical_findings_sns_arn": "arn:aws:sns:us-east-1:123456789012:sechub-critical",
}

_good_inspector := {
	"ec2_scanning_enabled": true,
	"ecr_scanning_enabled": true,
	"lambda_scanning_enabled": true,
	"findings": [],
	"filters": [],
	"security_hub_integration_enabled": true,
}

_good_input := {
	"region": "us-east-1",
	"account_id": "123456789012",
	"guardduty": {"detectors": [_good_detector]},
	"securityhub": _good_securityhub,
	"inspector": _good_inspector,
}

# =========================================================================
# awssec_01 — GuardDuty detector must be enabled
# =========================================================================
test_awssec_01_alarm if {
	inp := json.patch(_good_input, [{"op": "replace", "path": "/guardduty/detectors/0/status", "value": "SUSPENDED"}])
	_violations_for("awssec_guardduty_enabled", inp) == 1
}

test_awssec_01_pass if {
	_violations_for("awssec_guardduty_enabled", _good_input) == 0
}

# =========================================================================
# awssec_02 — No detectors means threat detection is off
# =========================================================================
test_awssec_02_alarm if {
	inp := json.patch(_good_input, [{"op": "replace", "path": "/guardduty/detectors", "value": []}])
	_violations_for("awssec_guardduty_detector", inp) == 1
}

test_awssec_02_pass if {
	_violations_for("awssec_guardduty_detector", _good_input) == 0
}

# =========================================================================
# awssec_03 — GuardDuty S3 protection must be enabled
# =========================================================================
test_awssec_03_alarm if {
	inp := json.patch(_good_input, [{"op": "replace", "path": "/guardduty/detectors/0/data_sources/s3_logs/status", "value": "DISABLED"}])
	_violations_for("awssec_guardduty_s3_protection", inp) == 1
}

test_awssec_03_pass if {
	_violations_for("awssec_guardduty_s3_protection", _good_input) == 0
}

# =========================================================================
# awssec_04 — GuardDuty malware protection must be enabled
# =========================================================================
test_awssec_04_alarm if {
	inp := json.patch(_good_input, [{"op": "replace", "path": "/guardduty/detectors/0/features/malware_protection/status", "value": "DISABLED"}])
	_violations_for("awssec_guardduty_malware_ec2", inp) == 1
}

test_awssec_04_pass if {
	_violations_for("awssec_guardduty_malware_ec2", _good_input) == 0
}

# =========================================================================
# awssec_05 — Suppression rules must not hide HIGH/CRITICAL findings
# =========================================================================
test_awssec_05_alarm if {
	bad_filter := {"name": "hide-high", "action": "ARCHIVE", "severity_threshold": 5}
	inp := json.patch(_good_input, [{"op": "replace", "path": "/guardduty/detectors/0/filters", "value": [bad_filter]}])
	_violations_for("awssec_guardduty_no_suppress_crit", inp) == 1
}

test_awssec_05_pass_no_filters if {
	_violations_for("awssec_guardduty_no_suppress_crit", _good_input) == 0
}

test_awssec_05_pass_high_threshold if {
	ok_filter := {"name": "hide-low", "action": "ARCHIVE", "severity_threshold": 8}
	inp := json.patch(_good_input, [{"op": "replace", "path": "/guardduty/detectors/0/filters", "value": [ok_filter]}])
	_violations_for("awssec_guardduty_no_suppress_crit", inp) == 0
}

# =========================================================================
# awssec_06 — Finding publishing frequency must not be 24h
# =========================================================================
test_awssec_06_alarm if {
	inp := json.patch(_good_input, [{"op": "replace", "path": "/guardduty/detectors/0/finding_publishing_frequency", "value": "TWENTY_FOUR_HOURS"}])
	_violations_for("awssec_guardduty_publish_frequency", inp) == 1
}

test_awssec_06_pass if {
	_violations_for("awssec_guardduty_publish_frequency", _good_input) == 0
}

test_awssec_06_pass_one_hour if {
	inp := json.patch(_good_input, [{"op": "replace", "path": "/guardduty/detectors/0/finding_publishing_frequency", "value": "ONE_HOUR"}])
	_violations_for("awssec_guardduty_publish_frequency", inp) == 0
}

# =========================================================================
# awssec_07 — GuardDuty SNS notification for HIGH findings
# =========================================================================
test_awssec_07_alarm if {
	inp := json.patch(_good_input, [{"op": "remove", "path": "/guardduty/detectors/0/high_severity_sns_arn"}])
	_violations_for("awssec_guardduty_sns_high", inp) == 1
}

test_awssec_07_pass if {
	_violations_for("awssec_guardduty_sns_high", _good_input) == 0
}

test_awssec_07_pass_disabled_detector if {
	inp := json.patch(_good_input, [
		{"op": "replace", "path": "/guardduty/detectors/0/status", "value": "SUSPENDED"},
		{"op": "remove", "path": "/guardduty/detectors/0/high_severity_sns_arn"},
	])
	_violations_for("awssec_guardduty_sns_high", inp) == 0
}

# =========================================================================
# awssec_08 — Security Hub must be enabled
# =========================================================================
test_awssec_08_alarm if {
	inp := json.patch(_good_input, [{"op": "replace", "path": "/securityhub/hub_enabled", "value": false}])
	_violations_for("awssec_securityhub_enabled", inp) == 1
}

test_awssec_08_pass if {
	_violations_for("awssec_securityhub_enabled", _good_input) == 0
}

# =========================================================================
# awssec_09 — CIS AWS Foundations standard must be enabled
# =========================================================================
test_awssec_09_alarm if {
	inp := json.patch(_good_input, [{"op": "replace", "path": "/securityhub/standards", "value": [
		{"standards_arn": "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0"},
	]}])
	_violations_for("awssec_securityhub_cis_standard", inp) == 1
}

test_awssec_09_pass if {
	_violations_for("awssec_securityhub_cis_standard", _good_input) == 0
}

# =========================================================================
# awssec_10 — FSBP standard must be enabled
# =========================================================================
test_awssec_10_alarm if {
	inp := json.patch(_good_input, [{"op": "replace", "path": "/securityhub/standards", "value": [
		{"standards_arn": "arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.4.0"},
	]}])
	_violations_for("awssec_securityhub_fsbp_standard", inp) == 1
}

test_awssec_10_pass if {
	_violations_for("awssec_securityhub_fsbp_standard", _good_input) == 0
}

# =========================================================================
# awssec_11 — CRITICAL findings must not be suppressed without notes
# =========================================================================
test_awssec_11_alarm if {
	bad_finding := {
		"id": "finding-001",
		"workflow": {"status": "SUPPRESSED"},
		"severity": {"label": "CRITICAL"},
	}
	inp := json.patch(_good_input, [{"op": "replace", "path": "/securityhub/findings", "value": [bad_finding]}])
	_violations_for("awssec_securityhub_no_suppress_crit", inp) == 1
}

test_awssec_11_pass_has_note if {
	ok_finding := {
		"id": "finding-001",
		"workflow": {"status": "SUPPRESSED"},
		"severity": {"label": "CRITICAL"},
		"note": {"text": "Accepted risk per CISO approval"},
	}
	inp := json.patch(_good_input, [{"op": "replace", "path": "/securityhub/findings", "value": [ok_finding]}])
	_violations_for("awssec_securityhub_no_suppress_crit", inp) == 0
}

test_awssec_11_pass_not_critical if {
	ok_finding := {
		"id": "finding-002",
		"workflow": {"status": "SUPPRESSED"},
		"severity": {"label": "HIGH"},
	}
	inp := json.patch(_good_input, [{"op": "replace", "path": "/securityhub/findings", "value": [ok_finding]}])
	_violations_for("awssec_securityhub_no_suppress_crit", inp) == 0
}

# =========================================================================
# awssec_12 — Delegated admin must be configured for org
# =========================================================================
test_awssec_12_alarm if {
	inp := json.patch(_good_input, [
		{"op": "replace", "path": "/securityhub/is_org_management_account", "value": true},
	])
	# Good input has no delegated_admin_account_id, and now is_org_management_account is true
	_violations_for("awssec_securityhub_delegated_admin", inp) == 1
}

test_awssec_12_pass_not_management if {
	_violations_for("awssec_securityhub_delegated_admin", _good_input) == 0
}

test_awssec_12_pass_has_delegated_admin if {
	inp := json.patch(_good_input, [
		{"op": "replace", "path": "/securityhub/is_org_management_account", "value": true},
		{"op": "add", "path": "/securityhub/delegated_admin_account_id", "value": "987654321098"},
	])
	_violations_for("awssec_securityhub_delegated_admin", inp) == 0
}

# =========================================================================
# awssec_13 — Security Hub SNS for CRITICAL findings
# =========================================================================
test_awssec_13_alarm if {
	inp := json.patch(_good_input, [{"op": "remove", "path": "/securityhub/critical_findings_sns_arn"}])
	_violations_for("awssec_securityhub_sns_critical", inp) == 1
}

test_awssec_13_pass if {
	_violations_for("awssec_securityhub_sns_critical", _good_input) == 0
}

test_awssec_13_pass_hub_disabled if {
	inp := json.patch(_good_input, [
		{"op": "replace", "path": "/securityhub/hub_enabled", "value": false},
		{"op": "remove", "path": "/securityhub/critical_findings_sns_arn"},
	])
	_violations_for("awssec_securityhub_sns_critical", inp) == 0
}

# =========================================================================
# awssec_14 — Inspector EC2 scanning must be enabled
# =========================================================================
test_awssec_14_alarm if {
	inp := json.patch(_good_input, [{"op": "replace", "path": "/inspector/ec2_scanning_enabled", "value": false}])
	_violations_for("awssec_inspector_ec2_scanning", inp) == 1
}

test_awssec_14_pass if {
	_violations_for("awssec_inspector_ec2_scanning", _good_input) == 0
}

# =========================================================================
# awssec_15 — Inspector ECR scanning must be enabled
# =========================================================================
test_awssec_15_alarm if {
	inp := json.patch(_good_input, [{"op": "replace", "path": "/inspector/ecr_scanning_enabled", "value": false}])
	_violations_for("awssec_inspector_ecr_scanning", inp) == 1
}

test_awssec_15_pass if {
	_violations_for("awssec_inspector_ecr_scanning", _good_input) == 0
}

# =========================================================================
# awssec_16 — Inspector Lambda scanning must be enabled
# =========================================================================
test_awssec_16_alarm if {
	inp := json.patch(_good_input, [{"op": "replace", "path": "/inspector/lambda_scanning_enabled", "value": false}])
	_violations_for("awssec_inspector_lambda_scanning", inp) == 1
}

test_awssec_16_pass if {
	_violations_for("awssec_inspector_lambda_scanning", _good_input) == 0
}

# =========================================================================
# awssec_17 — CRITICAL CVEs must be remediated within 30 days
# =========================================================================
test_awssec_17_alarm if {
	bad_finding := {
		"finding_arn": "arn:aws:inspector2:us-east-1:123456789012:finding/cve-001",
		"resource_id": "i-0abc123",
		"severity": "CRITICAL",
		"status": "ACTIVE",
		"age_days": 45,
	}
	inp := json.patch(_good_input, [{"op": "replace", "path": "/inspector/findings", "value": [bad_finding]}])
	_violations_for("awssec_inspector_critical_cve_30d", inp) == 1
}

test_awssec_17_pass_within_sla if {
	ok_finding := {
		"finding_arn": "arn:aws:inspector2:us-east-1:123456789012:finding/cve-002",
		"resource_id": "i-0abc123",
		"severity": "CRITICAL",
		"status": "ACTIVE",
		"age_days": 15,
	}
	inp := json.patch(_good_input, [{"op": "replace", "path": "/inspector/findings", "value": [ok_finding]}])
	_violations_for("awssec_inspector_critical_cve_30d", inp) == 0
}

test_awssec_17_pass_resolved if {
	ok_finding := {
		"finding_arn": "arn:aws:inspector2:us-east-1:123456789012:finding/cve-003",
		"resource_id": "i-0abc123",
		"severity": "CRITICAL",
		"status": "CLOSED",
		"age_days": 60,
	}
	inp := json.patch(_good_input, [{"op": "replace", "path": "/inspector/findings", "value": [ok_finding]}])
	_violations_for("awssec_inspector_critical_cve_30d", inp) == 0
}

# =========================================================================
# awssec_18 — HIGH CVEs must be remediated within 90 days
# =========================================================================
test_awssec_18_alarm if {
	bad_finding := {
		"finding_arn": "arn:aws:inspector2:us-east-1:123456789012:finding/cve-004",
		"resource_id": "i-0def456",
		"severity": "HIGH",
		"status": "ACTIVE",
		"age_days": 120,
	}
	inp := json.patch(_good_input, [{"op": "replace", "path": "/inspector/findings", "value": [bad_finding]}])
	_violations_for("awssec_inspector_high_cve_90d", inp) == 1
}

test_awssec_18_pass_within_sla if {
	ok_finding := {
		"finding_arn": "arn:aws:inspector2:us-east-1:123456789012:finding/cve-005",
		"resource_id": "i-0def456",
		"severity": "HIGH",
		"status": "ACTIVE",
		"age_days": 60,
	}
	inp := json.patch(_good_input, [{"op": "replace", "path": "/inspector/findings", "value": [ok_finding]}])
	_violations_for("awssec_inspector_high_cve_90d", inp) == 0
}

# =========================================================================
# awssec_19 — Inspector must be integrated with Security Hub
# =========================================================================
test_awssec_19_alarm if {
	inp := json.patch(_good_input, [{"op": "replace", "path": "/inspector/security_hub_integration_enabled", "value": false}])
	_violations_for("awssec_inspector_securityhub", inp) == 1
}

test_awssec_19_pass if {
	_violations_for("awssec_inspector_securityhub", _good_input) == 0
}

# =========================================================================
# awssec_20 — Inspector suppression filters must not hide CRITICAL findings
# =========================================================================
test_awssec_20_alarm if {
	bad_filter := {
		"name": "suppress-critical",
		"arn": "arn:aws:inspector2:us-east-1:123456789012:filter/f-001",
		"action": "SUPPRESS",
		"filter_criteria": [{"field": "severity", "values": ["CRITICAL", "HIGH"]}],
	}
	inp := json.patch(_good_input, [{"op": "replace", "path": "/inspector/filters", "value": [bad_filter]}])
	_violations_for("awssec_inspector_no_suppress_crit", inp) == 1
}

test_awssec_20_pass_no_filters if {
	_violations_for("awssec_inspector_no_suppress_crit", _good_input) == 0
}

test_awssec_20_pass_no_critical_in_filter if {
	ok_filter := {
		"name": "suppress-low",
		"arn": "arn:aws:inspector2:us-east-1:123456789012:filter/f-002",
		"action": "SUPPRESS",
		"filter_criteria": [{"field": "severity", "values": ["LOW", "MEDIUM"]}],
	}
	inp := json.patch(_good_input, [{"op": "replace", "path": "/inspector/filters", "value": [ok_filter]}])
	_violations_for("awssec_inspector_no_suppress_crit", inp) == 0
}

# =========================================================================
# Error handlers
# =========================================================================
test_error_missing_guardduty if {
	inp := {"region": "us-east-1", "account_id": "123456789012", "securityhub": _good_securityhub, "inspector": _good_inspector}
	_errors_for("awssec_guardduty_error", inp) == 1
}

test_error_missing_securityhub if {
	inp := {"region": "us-east-1", "account_id": "123456789012", "guardduty": {"detectors": [_good_detector]}, "inspector": _good_inspector}
	_errors_for("awssec_securityhub_error", inp) == 1
}

test_error_missing_inspector if {
	inp := {"region": "us-east-1", "account_id": "123456789012", "guardduty": {"detectors": [_good_detector]}, "securityhub": _good_securityhub}
	_errors_for("awssec_inspector_error", inp) == 1
}

test_error_not_raised_when_all_present if {
	_errors_for("awssec_guardduty_error", _good_input) == 0
	_errors_for("awssec_securityhub_error", _good_input) == 0
	_errors_for("awssec_inspector_error", _good_input) == 0
}
