package aws.data_protection.s3_test

import data.aws.data_protection.s3

# =========================================================================
# Helper
# =========================================================================
_violations_for(check_id, inp) := count([v |
	some v in s3.violations with input as inp
	v.check_id == check_id
])

# =========================================================================
# Minimal compliant bucket
# =========================================================================
_good_bucket := {
	"name": "my-bucket",
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
	"versioning": {"status": "Enabled", "mfa_delete": "Enabled"},
	"tags": {
		"environment": "production",
		"data_classification": "sensitive",
		"compliance_required": "true",
		"security_monitoring": "required",
		"data_criticality": "high",
	},
	"logging": {"target_bucket": "logging-bucket"},
	"policy_denies_http": true,
	"acl": {"grants": []},
	"lifecycle_rules": [{"id": "cleanup", "status": "Enabled"}],
	"object_lock": {"enabled": true},
	"cors_rules": [{"allowed_origins": ["https://example.com"]}],
	"policy": {"Statement": []},
	"replication_configuration": {"rules": [{"status": "Enabled"}]},
	"notification_configuration": {"topic_configurations": [{"events": ["s3:ObjectCreated:*"]}]},
	"size_gb": 50,
	"intelligent_tiering_enabled": true,
}

_full_input := {
	"s3": {"buckets": [_good_bucket]},
	"account_id": "123456789012",
}

# =========================================================================
# s3_01 — BlockPublicAcls
# =========================================================================
test_s3_01_alarm if {
	bucket := object.union(_good_bucket, {
		"public_access_block": object.union(
			_good_bucket.public_access_block,
			{"block_public_acls": false},
		),
	})
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_block_public_acls"
}

test_s3_01_compliant if {
	_violations_for("s3_block_public_acls", _full_input) == 0
}

# =========================================================================
# s3_02 — IgnorePublicAcls
# =========================================================================
test_s3_02_alarm if {
	bucket := object.union(_good_bucket, {
		"public_access_block": object.union(
			_good_bucket.public_access_block,
			{"ignore_public_acls": false},
		),
	})
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_ignore_public_acls"
}

test_s3_02_compliant if {
	_violations_for("s3_ignore_public_acls", _full_input) == 0
}

# =========================================================================
# s3_03 — BlockPublicPolicy
# =========================================================================
test_s3_03_alarm if {
	bucket := object.union(_good_bucket, {
		"public_access_block": object.union(
			_good_bucket.public_access_block,
			{"block_public_policy": false},
		),
	})
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_block_public_policy"
}

test_s3_03_compliant if {
	_violations_for("s3_block_public_policy", _full_input) == 0
}

# =========================================================================
# s3_04 — RestrictPublicBuckets
# =========================================================================
test_s3_04_alarm if {
	bucket := object.union(_good_bucket, {
		"public_access_block": object.union(
			_good_bucket.public_access_block,
			{"restrict_public_buckets": false},
		),
	})
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_restrict_public_buckets"
}

test_s3_04_compliant if {
	_violations_for("s3_restrict_public_buckets", _full_input) == 0
}

# =========================================================================
# s3_05 — Server-side encryption enabled
# =========================================================================
test_s3_05_alarm if {
	bucket := object.remove(_good_bucket, ["encryption"])
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_encryption"
}

test_s3_05_compliant if {
	_violations_for("s3_encryption", _full_input) == 0
}

# =========================================================================
# s3_06 — Versioning on sensitive buckets
# =========================================================================
test_s3_06_alarm if {
	bucket := object.union(_good_bucket, {
		"versioning": {"status": "Suspended", "mfa_delete": "Disabled"},
	})
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_versioning"
}

test_s3_06_compliant if {
	_violations_for("s3_versioning", _full_input) == 0
}

test_s3_06_compliant_not_sensitive if {
	bucket := object.union(_good_bucket, {
		"versioning": {"status": "Suspended", "mfa_delete": "Disabled"},
		"tags": object.union(
			_good_bucket.tags,
			{"data_classification": "public"},
		),
	})
	_violations_for("s3_versioning", {"s3": {"buckets": [bucket]}}) == 0
}

# =========================================================================
# s3_07 — MFA delete on sensitive buckets
# =========================================================================
test_s3_07_alarm if {
	bucket := object.union(_good_bucket, {
		"versioning": {"status": "Enabled", "mfa_delete": "Disabled"},
	})
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_mfa_delete"
}

test_s3_07_compliant if {
	_violations_for("s3_mfa_delete", _full_input) == 0
}

# =========================================================================
# s3_08 — Access logging on production buckets
# =========================================================================
test_s3_08_alarm if {
	bucket := object.remove(_good_bucket, ["logging"])
	bucket2 := object.union(bucket, {"logging": {}})
	r := s3.violations with input as {"s3": {"buckets": [bucket2]}}
	some v in r
	v.check_id == "s3_access_logging"
}

test_s3_08_compliant if {
	_violations_for("s3_access_logging", _full_input) == 0
}

test_s3_08_compliant_non_prod if {
	bucket := object.union(_good_bucket, {
		"tags": object.union(
			_good_bucket.tags,
			{"environment": "development"},
		),
		"logging": {},
	})
	_violations_for("s3_access_logging", {"s3": {"buckets": [bucket]}}) == 0
}

# =========================================================================
# s3_09 — Deny HTTP (require SSL)
# =========================================================================
test_s3_09_alarm if {
	bucket := object.union(_good_bucket, {
		"policy_denies_http": false,
	})
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_deny_http"
}

test_s3_09_compliant if {
	_violations_for("s3_deny_http", _full_input) == 0
}

# =========================================================================
# s3_10 — ACL public READ
# =========================================================================
test_s3_10_alarm if {
	bucket := object.union(_good_bucket, {
		"acl": {"grants": [{
			"grantee": {"uri": "http://acs.amazonaws.com/groups/global/AllUsers"},
			"permission": "READ",
		}]},
	})
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_no_public_read_acl"
}

test_s3_10_compliant if {
	_violations_for("s3_no_public_read_acl", _full_input) == 0
}

# =========================================================================
# s3_11 — ACL public WRITE
# =========================================================================
test_s3_11_alarm if {
	bucket := object.union(_good_bucket, {
		"acl": {"grants": [{
			"grantee": {"uri": "http://acs.amazonaws.com/groups/global/AllUsers"},
			"permission": "WRITE",
		}]},
	})
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_no_public_write_acl"
}

test_s3_11_compliant if {
	_violations_for("s3_no_public_write_acl", _full_input) == 0
}

# =========================================================================
# s3_12 — Lifecycle policy on production buckets
# =========================================================================
test_s3_12_alarm if {
	bucket := object.remove(_good_bucket, ["lifecycle_rules"])
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_lifecycle_policy"
}

test_s3_12_compliant if {
	_violations_for("s3_lifecycle_policy", _full_input) == 0
}

test_s3_12_compliant_non_prod if {
	bucket := object.union(
		object.remove(_good_bucket, ["lifecycle_rules"]),
		{"tags": object.union(
			_good_bucket.tags,
			{"environment": "development"},
		)},
	)
	_violations_for("s3_lifecycle_policy", {"s3": {"buckets": [bucket]}}) == 0
}

# =========================================================================
# s3_13 — Object Lock on compliance buckets
# =========================================================================
test_s3_13_alarm if {
	bucket := object.union(_good_bucket, {
		"object_lock": {"enabled": false},
	})
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_object_lock"
}

test_s3_13_compliant if {
	_violations_for("s3_object_lock", _full_input) == 0
}

test_s3_13_compliant_not_required if {
	bucket := object.union(_good_bucket, {
		"object_lock": {"enabled": false},
		"tags": object.union(
			_good_bucket.tags,
			{"compliance_required": "false"},
		),
	})
	_violations_for("s3_object_lock", {"s3": {"buckets": [bucket]}}) == 0
}

# =========================================================================
# s3_14 — CORS wildcard origin
# =========================================================================
test_s3_14_alarm if {
	bucket := object.union(_good_bucket, {
		"cors_rules": [{"allowed_origins": ["*"]}],
	})
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_cors_wildcard"
}

test_s3_14_compliant if {
	_violations_for("s3_cors_wildcard", _full_input) == 0
}

# =========================================================================
# s3_15 — KMS encryption for sensitive buckets
# =========================================================================
test_s3_15_alarm if {
	bucket := object.union(_good_bucket, {
		"encryption": {"rules": [{
			"apply_server_side_encryption_by_default": {
				"sse_algorithm": "AES256",
			},
		}]},
	})
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_kms_encryption"
}

test_s3_15_compliant if {
	_violations_for("s3_kms_encryption", _full_input) == 0
}

test_s3_15_compliant_not_sensitive if {
	bucket := object.union(_good_bucket, {
		"encryption": {"rules": [{
			"apply_server_side_encryption_by_default": {
				"sse_algorithm": "AES256",
			},
		}]},
		"tags": object.union(
			_good_bucket.tags,
			{"data_classification": "public"},
		),
	})
	_violations_for("s3_kms_encryption", {"s3": {"buckets": [bucket]}}) == 0
}

# =========================================================================
# s3_16 — Bucket policy Principal:* without Condition
# =========================================================================
test_s3_16_alarm if {
	bucket := object.union(_good_bucket, {
		"policy": {"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
		}]},
	})
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_no_public_principal"
}

test_s3_16_compliant if {
	_violations_for("s3_no_public_principal", _full_input) == 0
}

test_s3_16_compliant_with_condition if {
	bucket := object.union(_good_bucket, {
		"policy": {"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
		}]},
	})
	_violations_for("s3_no_public_principal", {"s3": {"buckets": [bucket]}}) == 0
}

# =========================================================================
# s3_17 — Replication on high-criticality buckets
# =========================================================================
test_s3_17_alarm if {
	bucket := object.remove(_good_bucket, ["replication_configuration"])
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_replication"
}

test_s3_17_compliant if {
	_violations_for("s3_replication", _full_input) == 0
}

test_s3_17_compliant_low_criticality if {
	bucket := object.union(
		object.remove(_good_bucket, ["replication_configuration"]),
		{"tags": object.union(
			_good_bucket.tags,
			{"data_criticality": "low"},
		)},
	)
	_violations_for("s3_replication", {"s3": {"buckets": [bucket]}}) == 0
}

# =========================================================================
# s3_18 — Event notifications on security-monitored buckets
# =========================================================================
test_s3_18_alarm if {
	bucket := object.remove(
		_good_bucket,
		["notification_configuration"],
	)
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_event_notifications"
}

test_s3_18_compliant if {
	_violations_for("s3_event_notifications", _full_input) == 0
}

test_s3_18_compliant_not_monitored if {
	bucket := object.union(
		object.remove(_good_bucket, ["notification_configuration"]),
		{"tags": object.union(
			_good_bucket.tags,
			{"security_monitoring": "optional"},
		)},
	)
	_violations_for("s3_event_notifications", {"s3": {"buckets": [bucket]}}) == 0
}

# =========================================================================
# s3_19 — Cross-account access without org ID condition
# =========================================================================
test_s3_19_alarm if {
	bucket := object.union(_good_bucket, {
		"policy": {"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::999888777666:root"},
			"Action": "s3:GetObject",
		}]},
	})
	r := s3.violations with input as {
		"s3": {"buckets": [bucket]},
		"account_id": "123456789012",
	}
	some v in r
	v.check_id == "s3_cross_account_org_id"
}

test_s3_19_compliant if {
	_violations_for("s3_cross_account_org_id", _full_input) == 0
}

test_s3_19_compliant_same_account if {
	bucket := object.union(_good_bucket, {
		"policy": {"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::123456789012:role/my-role"},
			"Action": "s3:GetObject",
		}]},
	})
	_violations_for("s3_cross_account_org_id", {
		"s3": {"buckets": [bucket]},
		"account_id": "123456789012",
	}) == 0
}

# =========================================================================
# s3_20 — Intelligent-Tiering on large buckets
# =========================================================================
test_s3_20_alarm if {
	bucket := object.union(_good_bucket, {
		"size_gb": 200,
		"intelligent_tiering_enabled": false,
	})
	r := s3.violations with input as {"s3": {"buckets": [bucket]}}
	some v in r
	v.check_id == "s3_intelligent_tiering"
}

test_s3_20_compliant if {
	_violations_for("s3_intelligent_tiering", _full_input) == 0
}

test_s3_20_compliant_small_bucket if {
	bucket := object.union(_good_bucket, {
		"size_gb": 50,
		"intelligent_tiering_enabled": false,
	})
	_violations_for("s3_intelligent_tiering", {"s3": {"buckets": [bucket]}}) == 0
}

# =========================================================================
# Error handler
# =========================================================================
test_error_s3_missing if {
	r := s3.error with input as {}
	some e in r
	e.check_id == "s3_error"
}
