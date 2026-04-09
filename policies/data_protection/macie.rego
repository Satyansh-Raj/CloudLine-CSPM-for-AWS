package aws.data_protection.macie

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Rule macie_not_enabled — Macie must be active for data discovery
# ---------------------------------------------------------------------------
violations contains result if {
	input.macie
	input.macie.enabled == false
	result := {
		"check_id": "macie_not_enabled",
		"status": "alarm",
		"severity": "medium",
		"reason": "AWS Macie is not enabled — sensitive data discovery is inactive",
		"resource": "aws:macie",
		"domain": "data_protection",
		"service": "macie",
		"remediation_id": "REM_macie_01",
	}
}

# ---------------------------------------------------------------------------
# Rule macie_sensitive_bucket_public_access
# — Bucket with Macie findings must not have public access enabled
# ---------------------------------------------------------------------------
violations contains result if {
	input.macie.enabled == true
	some bucket in input.s3.buckets
	input.macie.by_bucket[bucket.name]
	not _fully_blocked(bucket)
	result := {
		"check_id": "macie_sensitive_bucket_public_access",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"S3 bucket '%s' has Macie sensitive-data findings but public access is not fully blocked",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "macie",
		"remediation_id": "REM_macie_02",
	}
}

# ---------------------------------------------------------------------------
# Rule macie_sensitive_data_no_kms
# — Buckets with High-severity CLASSIFICATION findings must use KMS
# ---------------------------------------------------------------------------
violations contains result if {
	input.macie.enabled == true
	some finding in input.macie.findings
	finding.severity == "High"
	finding.category == "CLASSIFICATION"
	some bucket in input.s3.buckets
	bucket.name == finding.bucket_name
	not _has_kms(bucket)
	result := {
		"check_id": "macie_sensitive_data_no_kms",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"S3 bucket '%s' has High-severity Macie findings but is not KMS-encrypted",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "macie",
		"remediation_id": "REM_macie_03",
	}
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_fully_blocked(bucket) if {
	bucket.public_access_block.block_public_acls == true
	bucket.public_access_block.ignore_public_acls == true
	bucket.public_access_block.block_public_policy == true
	bucket.public_access_block.restrict_public_buckets == true
}

_has_kms(bucket) if {
	some rule in bucket.encryption.rules
	rule.apply_server_side_encryption_by_default.sse_algorithm == "aws:kms"
}

# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
error contains result if {
	not input.macie
	result := {
		"check_id": "macie_error",
		"status": "error",
		"severity": "critical",
		"reason": "Macie data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
		"service": "macie",
	}
}
