package aws.data_protection.kms_secretsmanager_test

import data.aws.data_protection.kms
import data.aws.data_protection.secretsmanager

# =========================================================================
# Helpers
# =========================================================================
_kms_violations_for(check_id, inp) := count([v |
	some v in kms.violations with input as inp
	v.check_id == check_id
])

_sm_violations_for(check_id, inp) := count([v |
	some v in secretsmanager.violations with input as inp
	v.check_id == check_id
])

# =========================================================================
# KMS — Minimal compliant fixtures
# =========================================================================
_good_key := {
	"key_id": "key-abc123",
	"arn": "arn:aws:kms:us-east-1:123456789012:key/key-abc123",
	"description": "My encryption key",
	"key_manager": "CUSTOMER",
	"key_state": "Enabled",
	"key_rotation_enabled": true,
	"key_spec": "SYMMETRIC_DEFAULT",
	"multi_region": false,
	"origin": "AWS_KMS",
	"deletion_alarm_configured": true,
	"tags": {
		"owner": "security-team",
		"used_for": "ebs",
	},
	"policy": {"Statement": [
		{
			"Sid": "KeyAdministration",
			"Effect": "Allow",
			"Principal": {"AWS": ["arn:aws:iam::123456789012:role/admin"]},
			"Action": ["kms:Create*", "kms:Describe*"],
		},
		{
			"Sid": "KeyUsage",
			"Effect": "Allow",
			"Principal": {"AWS": ["arn:aws:iam::123456789012:role/user"]},
			"Action": ["kms:Encrypt", "kms:Decrypt"],
		},
	]},
	"grants": [],
}

_good_alias := {
	"alias_name": "alias/my-key",
	"alias_arn": "arn:aws:kms:us-east-1:123456789012:alias/my-key",
	"target_key_id": "key-abc123",
	"key_manager": "CUSTOMER",
}

_kms_input := {
	"kms": {
		"keys": [_good_key],
		"aliases": [_good_alias],
	},
	"account_id": "123456789012",
}

# =========================================================================
# SecretsManager — Minimal compliant fixtures
# =========================================================================
_good_secret := {
	"name": "prod/db/connection",
	"arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/connection-abc",
	"description": "Production database credentials",
	"rotation_enabled": true,
	"rotation_rules": {"automatically_after_days": 30},
	"rotation_lambda_arn": "arn:aws:lambda:us-east-1:123456789012:function:rotate",
	"rotation_function_exists": true,
	"kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/key-abc123",
	"days_since_last_accessed": 5,
	"deleted_date": null,
	"replication_status": [{"region": "us-west-2", "status": "InSync"}],
	"tags": {
		"owner": "backend-team",
		"data_classification": "sensitive",
		"data_criticality": "high",
	},
	"resource_policy": {"Statement": []},
}

_sm_input := {
	"secrets_manager": {"secrets": [_good_secret]},
	"account_id": "123456789012",
}

# =========================================================================
# kms_01 — Key rotation
# =========================================================================
test_kms_01_alarm if {
	key := object.union(_good_key, {"key_rotation_enabled": false})
	r := kms.violations with input as {"kms": {"keys": [key]}}
	some v in r
	v.check_id == "kms_01"
}

test_kms_01_compliant if {
	_kms_violations_for("kms_01", _kms_input) == 0
}

test_kms_01_skip_aws_managed if {
	key := object.union(_good_key, {
		"key_manager": "AWS",
		"key_rotation_enabled": false,
	})
	_kms_violations_for("kms_01", {"kms": {"keys": [key]}}) == 0
}

# =========================================================================
# kms_02 — Key policy Principal:* without condition
# =========================================================================
test_kms_02_alarm if {
	key := object.union(_good_key, {
		"policy": {"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "kms:Decrypt",
		}]},
	})
	r := kms.violations with input as {"kms": {"keys": [key]}}
	some v in r
	v.check_id == "kms_02"
}

test_kms_02_compliant if {
	_kms_violations_for("kms_02", _kms_input) == 0
}

test_kms_02_compliant_with_condition if {
	key := object.union(_good_key, {
		"policy": {"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "kms:Decrypt",
			"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}},
		}]},
	})
	_kms_violations_for("kms_02", {"kms": {"keys": [key]}}) == 0
}

# =========================================================================
# kms_03 — Pending deletion without approval
# =========================================================================
test_kms_03_alarm if {
	key := object.union(_good_key, {
		"key_state": "PendingDeletion",
		"tags": object.remove(_good_key.tags, ["deletion_approved"]),
	})
	r := kms.violations with input as {"kms": {"keys": [key]}}
	some v in r
	v.check_id == "kms_03"
}

test_kms_03_compliant_not_pending if {
	_kms_violations_for("kms_03", _kms_input) == 0
}

test_kms_03_compliant_approved if {
	key := object.union(_good_key, {
		"key_state": "PendingDeletion",
		"tags": object.union(_good_key.tags, {"deletion_approved": "true"}),
	})
	_kms_violations_for("kms_03", {"kms": {"keys": [key]}}) == 0
}

# =========================================================================
# kms_04 — Separation of admin/user principals
# =========================================================================
test_kms_04_alarm if {
	key := object.union(_good_key, {
		"policy": {"Statement": [
			{
				"Sid": "KeyAdministration",
				"Effect": "Allow",
				"Principal": {"AWS": ["arn:aws:iam::123456789012:role/shared"]},
				"Action": ["kms:Create*"],
			},
			{
				"Sid": "KeyUsage",
				"Effect": "Allow",
				"Principal": {"AWS": ["arn:aws:iam::123456789012:role/shared"]},
				"Action": ["kms:Decrypt"],
			},
		]},
	})
	r := kms.violations with input as {"kms": {"keys": [key]}}
	some v in r
	v.check_id == "kms_04"
}

test_kms_04_compliant if {
	_kms_violations_for("kms_04", _kms_input) == 0
}

# =========================================================================
# kms_05 — Key description empty
# =========================================================================
test_kms_05_alarm if {
	key := object.union(_good_key, {"description": ""})
	r := kms.violations with input as {"kms": {"keys": [key]}}
	some v in r
	v.check_id == "kms_05"
}

test_kms_05_compliant if {
	_kms_violations_for("kms_05", _kms_input) == 0
}

# =========================================================================
# kms_06 — Multi-region without justification
# =========================================================================
test_kms_06_alarm if {
	key := object.union(_good_key, {"multi_region": true})
	r := kms.violations with input as {"kms": {"keys": [key]}}
	some v in r
	v.check_id == "kms_06"
}

test_kms_06_compliant_not_multi if {
	_kms_violations_for("kms_06", _kms_input) == 0
}

test_kms_06_compliant_justified if {
	key := object.union(_good_key, {
		"multi_region": true,
		"tags": object.union(_good_key.tags, {"multi_region_justified": "true"}),
	})
	_kms_violations_for("kms_06", {"kms": {"keys": [key]}}) == 0
}

# =========================================================================
# kms_07 — Cross-account access without org condition
# =========================================================================
test_kms_07_alarm if {
	key := object.union(_good_key, {
		"policy": {"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": ["arn:aws:iam::999888777666:root"]},
			"Action": "kms:Decrypt",
		}]},
	})
	r := kms.violations with input as {
		"kms": {"keys": [key]},
		"account_id": "123456789012",
	}
	some v in r
	v.check_id == "kms_07"
}

test_kms_07_compliant if {
	_kms_violations_for("kms_07", _kms_input) == 0
}

test_kms_07_compliant_approved_tag if {
	key := object.union(_good_key, {
		"policy": {"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": ["arn:aws:iam::999888777666:root"]},
			"Action": "kms:Decrypt",
		}]},
		"tags": object.union(_good_key.tags, {"cross_account_approved": "true"}),
	})
	_kms_violations_for("kms_07", {
		"kms": {"keys": [key]},
		"account_id": "123456789012",
	}) == 0
}

# =========================================================================
# kms_08 — Missing owner tag
# =========================================================================
test_kms_08_alarm if {
	key := object.union(
		object.remove(_good_key, ["tags"]),
		{"tags": {"used_for": "ebs"}},
	)
	r := kms.violations with input as {"kms": {"keys": [key]}}
	some v in r
	v.check_id == "kms_08"
}

test_kms_08_compliant if {
	_kms_violations_for("kms_08", _kms_input) == 0
}

# =========================================================================
# kms_09 — Disabled key > 90 days
# =========================================================================
test_kms_09_alarm if {
	key := object.union(_good_key, {
		"key_state": "Disabled",
		"days_since_disabled": 120,
	})
	r := kms.violations with input as {"kms": {"keys": [key]}}
	some v in r
	v.check_id == "kms_09"
}

test_kms_09_compliant_enabled if {
	_kms_violations_for("kms_09", _kms_input) == 0
}

test_kms_09_compliant_under_90 if {
	key := object.union(_good_key, {
		"key_state": "Disabled",
		"days_since_disabled": 30,
	})
	_kms_violations_for("kms_09", {"kms": {"keys": [key]}}) == 0
}

test_kms_09_compliant_reviewed if {
	key := object.union(_good_key, {
		"key_state": "Disabled",
		"days_since_disabled": 120,
		"tags": object.union(_good_key.tags, {"deletion_reviewed": "true"}),
	})
	_kms_violations_for("kms_09", {"kms": {"keys": [key]}}) == 0
}

# =========================================================================
# kms_10 — Root kms:* without conditions
# =========================================================================
test_kms_10_alarm if {
	key := object.union(_good_key, {
		"policy": {"Statement": [{
			"Effect": "Allow",
			"Action": "kms:*",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
		}]},
	})
	r := kms.violations with input as {
		"kms": {"keys": [key]},
		"account_id": "123456789012",
	}
	some v in r
	v.check_id == "kms_10"
}

test_kms_10_compliant if {
	_kms_violations_for("kms_10", _kms_input) == 0
}

test_kms_10_compliant_with_condition if {
	key := object.union(_good_key, {
		"policy": {"Statement": [{
			"Effect": "Allow",
			"Action": "kms:*",
			"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
			"Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
		}]},
	})
	_kms_violations_for("kms_10", {
		"kms": {"keys": [key]},
		"account_id": "123456789012",
	}) == 0
}

# =========================================================================
# kms_11 — Alias uses aws/ prefix for customer key
# =========================================================================
test_kms_11_alarm if {
	alias := object.union(_good_alias, {
		"alias_name": "alias/aws/my-custom",
	})
	r := kms.violations with input as {
		"kms": {"keys": [], "aliases": [alias]},
	}
	some v in r
	v.check_id == "kms_11"
}

test_kms_11_compliant if {
	_kms_violations_for("kms_11", _kms_input) == 0
}

test_kms_11_compliant_aws_managed if {
	alias := object.union(_good_alias, {
		"alias_name": "alias/aws/s3",
		"key_manager": "AWS",
	})
	_kms_violations_for("kms_11", {
		"kms": {"keys": [], "aliases": [alias]},
	}) == 0
}

# =========================================================================
# kms_12 — Symmetric S3 key without rotation
# =========================================================================
test_kms_12_alarm if {
	key := object.union(_good_key, {
		"key_spec": "SYMMETRIC_DEFAULT",
		"key_rotation_enabled": false,
		"tags": object.union(_good_key.tags, {"used_for": "s3"}),
	})
	r := kms.violations with input as {"kms": {"keys": [key]}}
	some v in r
	v.check_id == "kms_12"
}

test_kms_12_compliant if {
	_kms_violations_for("kms_12", _kms_input) == 0
}

# =========================================================================
# kms_13 — No deletion alarm
# =========================================================================
test_kms_13_alarm if {
	key := object.remove(_good_key, ["deletion_alarm_configured"])
	r := kms.violations with input as {"kms": {"keys": [key]}}
	some v in r
	v.check_id == "kms_13"
}

test_kms_13_compliant if {
	_kms_violations_for("kms_13", _kms_input) == 0
}

# =========================================================================
# kms_14 — External key material without approval
# =========================================================================
test_kms_14_alarm if {
	key := object.union(_good_key, {"origin": "EXTERNAL"})
	r := kms.violations with input as {"kms": {"keys": [key]}}
	some v in r
	v.check_id == "kms_14"
}

test_kms_14_compliant_aws_kms if {
	_kms_violations_for("kms_14", _kms_input) == 0
}

test_kms_14_compliant_approved if {
	key := object.union(_good_key, {
		"origin": "EXTERNAL",
		"tags": object.union(_good_key.tags, {"external_key_approved": "true"}),
	})
	_kms_violations_for("kms_14", {"kms": {"keys": [key]}}) == 0
}

# =========================================================================
# kms_15 — Grant with Decrypt but no retiring principal
# =========================================================================
test_kms_15_alarm if {
	key := object.union(_good_key, {
		"grants": [{
			"operations": ["kms:Decrypt", "kms:Encrypt"],
			"grantee_principal": "arn:aws:iam::123456789012:role/app",
		}],
	})
	r := kms.violations with input as {"kms": {"keys": [key]}}
	some v in r
	v.check_id == "kms_15"
}

test_kms_15_compliant_no_grants if {
	_kms_violations_for("kms_15", _kms_input) == 0
}

test_kms_15_compliant_has_retiring if {
	key := object.union(_good_key, {
		"grants": [{
			"operations": ["kms:Decrypt"],
			"grantee_principal": "arn:aws:iam::123456789012:role/app",
			"retiring_principal": "arn:aws:iam::123456789012:role/admin",
		}],
	})
	_kms_violations_for("kms_15", {"kms": {"keys": [key]}}) == 0
}

# =========================================================================
# KMS error handler
# =========================================================================
test_kms_error_missing if {
	r := kms.error with input as {}
	some e in r
	e.check_id == "kms_00"
}

# =========================================================================
# secretsmanager_01 — Rotation not enabled
# =========================================================================
test_sm_01_alarm if {
	secret := object.union(_good_secret, {"rotation_enabled": false})
	r := secretsmanager.violations with input as {
		"secrets_manager": {"secrets": [secret]},
	}
	some v in r
	v.check_id == "secretsmanager_01"
}

test_sm_01_compliant if {
	_sm_violations_for("secretsmanager_01", _sm_input) == 0
}

# =========================================================================
# secretsmanager_02 — Rotation interval > 90 days
# =========================================================================
test_sm_02_alarm if {
	secret := object.union(_good_secret, {
		"rotation_rules": {"automatically_after_days": 180},
	})
	r := secretsmanager.violations with input as {
		"secrets_manager": {"secrets": [secret]},
	}
	some v in r
	v.check_id == "secretsmanager_02"
}

test_sm_02_compliant if {
	_sm_violations_for("secretsmanager_02", _sm_input) == 0
}

test_sm_02_compliant_boundary if {
	secret := object.union(_good_secret, {
		"rotation_rules": {"automatically_after_days": 90},
	})
	_sm_violations_for("secretsmanager_02", {
		"secrets_manager": {"secrets": [secret]},
	}) == 0
}

# =========================================================================
# secretsmanager_03 — Public access via resource policy
# =========================================================================
test_sm_03_alarm if {
	secret := object.union(_good_secret, {
		"resource_policy": {"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "secretsmanager:GetSecretValue",
		}]},
	})
	r := secretsmanager.violations with input as {
		"secrets_manager": {"secrets": [secret]},
	}
	some v in r
	v.check_id == "secretsmanager_03"
}

test_sm_03_compliant if {
	_sm_violations_for("secretsmanager_03", _sm_input) == 0
}

test_sm_03_compliant_with_condition if {
	secret := object.union(_good_secret, {
		"resource_policy": {"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "secretsmanager:GetSecretValue",
			"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}},
		}]},
	})
	_sm_violations_for("secretsmanager_03", {
		"secrets_manager": {"secrets": [secret]},
	}) == 0
}

# =========================================================================
# secretsmanager_04 — AWS-managed key instead of CMK
# =========================================================================
test_sm_04_alarm if {
	secret := object.union(_good_secret, {
		"kms_key_id": "alias/aws/secretsmanager",
	})
	r := secretsmanager.violations with input as {
		"secrets_manager": {"secrets": [secret]},
	}
	some v in r
	v.check_id == "secretsmanager_04"
}

test_sm_04_compliant if {
	_sm_violations_for("secretsmanager_04", _sm_input) == 0
}

test_sm_04_compliant_not_sensitive if {
	secret := object.union(_good_secret, {
		"kms_key_id": "alias/aws/secretsmanager",
		"tags": object.union(_good_secret.tags, {
			"data_classification": "public",
		}),
	})
	_sm_violations_for("secretsmanager_04", {
		"secrets_manager": {"secrets": [secret]},
	}) == 0
}

# =========================================================================
# secretsmanager_05 — Unused > 90 days
# =========================================================================
test_sm_05_alarm if {
	secret := object.union(_good_secret, {
		"days_since_last_accessed": 120,
	})
	r := secretsmanager.violations with input as {
		"secrets_manager": {"secrets": [secret]},
	}
	some v in r
	v.check_id == "secretsmanager_05"
}

test_sm_05_compliant if {
	_sm_violations_for("secretsmanager_05", _sm_input) == 0
}

# =========================================================================
# secretsmanager_06 — Cross-account without org ID
# =========================================================================
test_sm_06_alarm if {
	secret := object.union(_good_secret, {
		"resource_policy": {"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws:iam::999888777666:root"},
			"Action": "secretsmanager:GetSecretValue",
		}]},
	})
	r := secretsmanager.violations with input as {
		"secrets_manager": {"secrets": [secret]},
		"account_id": "123456789012",
	}
	some v in r
	v.check_id == "secretsmanager_06"
}

test_sm_06_compliant if {
	_sm_violations_for("secretsmanager_06", _sm_input) == 0
}

# =========================================================================
# secretsmanager_07 — Deletion without approval
# =========================================================================
test_sm_07_alarm if {
	secret := object.union(_good_secret, {
		"deleted_date": "2026-03-01T00:00:00Z",
		"tags": object.remove(_good_secret.tags, ["deletion_approved"]),
	})
	r := secretsmanager.violations with input as {
		"secrets_manager": {"secrets": [secret]},
	}
	some v in r
	v.check_id == "secretsmanager_07"
}

test_sm_07_compliant_not_deleted if {
	_sm_violations_for("secretsmanager_07", _sm_input) == 0
}

test_sm_07_compliant_approved if {
	secret := object.union(_good_secret, {
		"deleted_date": "2026-03-01T00:00:00Z",
		"tags": object.union(_good_secret.tags, {"deletion_approved": "true"}),
	})
	_sm_violations_for("secretsmanager_07", {
		"secrets_manager": {"secrets": [secret]},
	}) == 0
}

# =========================================================================
# secretsmanager_08 — Missing owner tag
# =========================================================================
test_sm_08_alarm if {
	secret := object.union(
		object.remove(_good_secret, ["tags"]),
		{"tags": {
			"data_classification": "sensitive",
			"data_criticality": "high",
		}},
	)
	r := secretsmanager.violations with input as {
		"secrets_manager": {"secrets": [secret]},
	}
	some v in r
	v.check_id == "secretsmanager_08"
}

test_sm_08_compliant if {
	_sm_violations_for("secretsmanager_08", _sm_input) == 0
}

# =========================================================================
# secretsmanager_09 — Sensitive name patterns
# =========================================================================
test_sm_09_alarm if {
	secret := object.union(_good_secret, {
		"name": "prod/db_password",
	})
	r := secretsmanager.violations with input as {
		"secrets_manager": {"secrets": [secret]},
	}
	some v in r
	v.check_id == "secretsmanager_09"
}

test_sm_09_alarm_apikey if {
	secret := object.union(_good_secret, {
		"name": "MyApiKey",
	})
	r := secretsmanager.violations with input as {
		"secrets_manager": {"secrets": [secret]},
	}
	some v in r
	v.check_id == "secretsmanager_09"
}

test_sm_09_compliant if {
	_sm_violations_for("secretsmanager_09", _sm_input) == 0
}

# =========================================================================
# secretsmanager_10 — Orphaned rotation Lambda
# =========================================================================
test_sm_10_alarm if {
	secret := object.union(_good_secret, {
		"rotation_function_exists": false,
	})
	r := secretsmanager.violations with input as {
		"secrets_manager": {"secrets": [secret]},
	}
	some v in r
	v.check_id == "secretsmanager_10"
}

test_sm_10_compliant if {
	_sm_violations_for("secretsmanager_10", _sm_input) == 0
}

# =========================================================================
# secretsmanager_11 — Empty description
# =========================================================================
test_sm_11_alarm if {
	secret := object.union(_good_secret, {"description": ""})
	r := secretsmanager.violations with input as {
		"secrets_manager": {"secrets": [secret]},
	}
	some v in r
	v.check_id == "secretsmanager_11"
}

test_sm_11_compliant if {
	_sm_violations_for("secretsmanager_11", _sm_input) == 0
}

# =========================================================================
# secretsmanager_12 — No replication for critical secrets
# =========================================================================
test_sm_12_alarm if {
	secret := object.union(_good_secret, {
		"replication_status": [],
	})
	r := secretsmanager.violations with input as {
		"secrets_manager": {"secrets": [secret]},
	}
	some v in r
	v.check_id == "secretsmanager_12"
}

test_sm_12_compliant if {
	_sm_violations_for("secretsmanager_12", _sm_input) == 0
}

test_sm_12_compliant_low_criticality if {
	secret := object.union(_good_secret, {
		"replication_status": [],
		"tags": object.union(_good_secret.tags, {
			"data_criticality": "low",
		}),
	})
	_sm_violations_for("secretsmanager_12", {
		"secrets_manager": {"secrets": [secret]},
	}) == 0
}

# =========================================================================
# secretsmanager_13 — Wildcard principal (even with condition)
# =========================================================================
test_sm_13_alarm if {
	secret := object.union(_good_secret, {
		"resource_policy": {"Statement": [{
			"Effect": "Allow",
			"Principal": "*",
			"Action": "secretsmanager:GetSecretValue",
			"Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}},
		}]},
	})
	r := secretsmanager.violations with input as {
		"secrets_manager": {"secrets": [secret]},
	}
	some v in r
	v.check_id == "secretsmanager_13"
}

test_sm_13_compliant if {
	_sm_violations_for("secretsmanager_13", _sm_input) == 0
}

# =========================================================================
# SecretsManager error handler
# =========================================================================
test_sm_error_missing if {
	r := secretsmanager.error with input as {}
	some e in r
	e.check_id == "secretsmanager_00"
}
