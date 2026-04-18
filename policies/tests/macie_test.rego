package aws.data_protection.macie_test

import data.aws.data_protection.macie

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
_violations_for(check_id, inp) := count([v |
	some v in macie.violations with input as inp
	v.check_id == check_id
])

# ---------------------------------------------------------------------------
# Base fixtures
# ---------------------------------------------------------------------------
_good_finding := {
	"finding_id": "find-001",
	"type": "SensitiveData:S3Object/Personal",
	"bucket_name": "my-data-bucket",
	"severity": "High",
	"category": "CLASSIFICATION",
	"count": 3,
	"first_observed_at": "2026-04-01T00:00:00Z",
	"last_observed_at": "2026-04-02T00:00:00Z",
	"region": "ap-south-1",
	"account_id": "123456789012",
}

_good_macie := {
	"enabled": true,
	"findings": [_good_finding],
	"by_bucket": {"my-data-bucket": ["find-001"]},
	"summary": {"total": 1, "by_severity": {"High": 1}},
}

_good_bucket := {
	"name": "my-data-bucket",
	"public_access_block": {
		"block_public_acls": true,
		"ignore_public_acls": true,
		"block_public_policy": true,
		"restrict_public_buckets": true,
	},
	"encryption": {"rules": [{
		"apply_server_side_encryption_by_default": {
			"sse_algorithm": "aws:kms",
		},
	}]},
}

_full_input := {
	"macie": _good_macie,
	"s3": {"buckets": [_good_bucket]},
	"account_id": "123456789012",
	"region": "ap-south-1",
}

# ===========================================================================
# macie_not_enabled — Macie must be active
# ===========================================================================
test_macie_not_enabled_alarm if {
	inp := {
		"macie": object.union(_good_macie, {"enabled": false}),
		"account_id": "123456789012",
		"region": "ap-south-1",
	}
	r := macie.violations with input as inp
	some v in r
	v.check_id == "macie_not_enabled"
	v.severity == "medium"
}

test_macie_not_enabled_pass if {
	_violations_for("macie_not_enabled", _full_input) == 0
}

# ===========================================================================
# macie_sensitive_bucket_public_access
# — Bucket with findings must have full public access block
# ===========================================================================
test_macie_sensitive_bucket_public_alarm if {
	bucket := object.union(_good_bucket, {
		"public_access_block": object.union(
			_good_bucket.public_access_block,
			{"block_public_acls": false},
		),
	})
	inp := {
		"macie": _good_macie,
		"s3": {"buckets": [bucket]},
	}
	r := macie.violations with input as inp
	some v in r
	v.check_id == "macie_sensitive_bucket_public_access"
	v.severity == "critical"
}

test_macie_sensitive_bucket_public_pass if {
	_violations_for(
		"macie_sensitive_bucket_public_access",
		_full_input,
	) == 0
}

test_macie_sensitive_bucket_public_pass_no_findings if {
	# Bucket with public access block disabled, but no Macie findings
	bucket := object.union(_good_bucket, {
		"name": "other-bucket",
		"public_access_block": object.union(
			_good_bucket.public_access_block,
			{"block_public_acls": false},
		),
	})
	inp := {
		"macie": _good_macie,
		"s3": {"buckets": [bucket]},
	}
	_violations_for(
		"macie_sensitive_bucket_public_access",
		inp,
	) == 0
}

# ===========================================================================
# macie_sensitive_data_no_kms
# — Bucket with High CLASSIFICATION findings must use KMS
# ===========================================================================
test_macie_no_kms_alarm if {
	bucket := object.union(_good_bucket, {
		"encryption": {"rules": [{
			"apply_server_side_encryption_by_default": {
				"sse_algorithm": "AES256",
			},
		}]},
	})
	inp := {
		"macie": _good_macie,
		"s3": {"buckets": [bucket]},
	}
	r := macie.violations with input as inp
	some v in r
	v.check_id == "macie_sensitive_data_no_kms"
	v.severity == "high"
}

test_macie_no_kms_pass if {
	_violations_for("macie_sensitive_data_no_kms", _full_input) == 0
}

test_macie_no_kms_pass_low_severity if {
	# Low severity finding — rule only fires for High
	low_finding := object.union(_good_finding, {"severity": "Low"})
	low_macie := object.union(_good_macie, {"findings": [low_finding]})
	bucket := object.union(_good_bucket, {
		"encryption": {"rules": [{
			"apply_server_side_encryption_by_default": {
				"sse_algorithm": "AES256",
			},
		}]},
	})
	inp := {
		"macie": low_macie,
		"s3": {"buckets": [bucket]},
	}
	_violations_for("macie_sensitive_data_no_kms", inp) == 0
}

test_macie_no_kms_pass_policy_category if {
	# POLICY category finding (not CLASSIFICATION) — rule should not fire
	policy_finding := object.union(_good_finding, {"category": "POLICY"})
	policy_macie := object.union(_good_macie, {"findings": [policy_finding]})
	bucket := object.union(_good_bucket, {
		"encryption": {"rules": [{
			"apply_server_side_encryption_by_default": {
				"sse_algorithm": "AES256",
			},
		}]},
	})
	inp := {
		"macie": policy_macie,
		"s3": {"buckets": [bucket]},
	}
	_violations_for("macie_sensitive_data_no_kms", inp) == 0
}

# ===========================================================================
# Error handler
# ===========================================================================
test_error_macie_missing if {
	r := macie.error with input as {}
	some e in r
	e.check_id == "macie_error"
}
