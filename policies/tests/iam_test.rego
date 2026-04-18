package aws.identity.iam_test

import data.aws.identity.iam

# =========================================================================
# Helper — count violations for a specific check_id
# =========================================================================
_violations_for(check_id, inp) := count([v |
	some v in iam.violations with input as inp
	v.check_id == check_id
])

# =========================================================================
# iam_01 — Root account MFA enabled
# =========================================================================
test_iam_01_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"account_summary": {
			"mfa_enabled": false,
			"account_access_keys_present": 0,
		}},
	}
	some v in r
	v.check_id == "iam_root_mfa"
}

test_iam_01_compliant if {
	_violations_for("iam_root_mfa", {
		"account_id": "123456789012",
		"iam": {"account_summary": {
			"mfa_enabled": true,
			"account_access_keys_present": 0,
		}},
	}) == 0
}

# =========================================================================
# iam_02 — Password policy: minimum length >= 14
# =========================================================================
test_iam_02_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 8,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"password_reuse_prevention": 24,
			"max_password_age": 90,
		}},
	}
	some v in r
	v.check_id == "iam_pwd_min_length"
}

test_iam_02_compliant if {
	_violations_for("iam_pwd_min_length", {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"password_reuse_prevention": 24,
			"max_password_age": 90,
		}},
	}) == 0
}

test_iam_02_boundary if {
	_violations_for("iam_pwd_min_length", {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 13,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"password_reuse_prevention": 24,
			"max_password_age": 90,
		}},
	}) == 1
}

# =========================================================================
# iam_03 — Password policy: requires uppercase
# =========================================================================
test_iam_03_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 14,
			"require_uppercase_characters": false,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"password_reuse_prevention": 24,
			"max_password_age": 90,
		}},
	}
	some v in r
	v.check_id == "iam_pwd_uppercase"
}

test_iam_03_compliant if {
	_violations_for("iam_pwd_uppercase", {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"password_reuse_prevention": 24,
			"max_password_age": 90,
		}},
	}) == 0
}

# =========================================================================
# iam_04 — Password policy: requires lowercase
# =========================================================================
test_iam_04_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_lowercase_characters": false,
			"require_numbers": true,
			"require_symbols": true,
			"password_reuse_prevention": 24,
			"max_password_age": 90,
		}},
	}
	some v in r
	v.check_id == "iam_pwd_lowercase"
}

test_iam_04_compliant if {
	_violations_for("iam_pwd_lowercase", {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"password_reuse_prevention": 24,
			"max_password_age": 90,
		}},
	}) == 0
}

# =========================================================================
# iam_05 — Password policy: requires numbers
# =========================================================================
test_iam_05_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": false,
			"require_symbols": true,
			"password_reuse_prevention": 24,
			"max_password_age": 90,
		}},
	}
	some v in r
	v.check_id == "iam_pwd_numbers"
}

test_iam_05_compliant if {
	_violations_for("iam_pwd_numbers", {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"password_reuse_prevention": 24,
			"max_password_age": 90,
		}},
	}) == 0
}

# =========================================================================
# iam_06 — Password policy: requires symbols
# =========================================================================
test_iam_06_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": false,
			"password_reuse_prevention": 24,
			"max_password_age": 90,
		}},
	}
	some v in r
	v.check_id == "iam_pwd_symbols"
}

test_iam_06_compliant if {
	_violations_for("iam_pwd_symbols", {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"password_reuse_prevention": 24,
			"max_password_age": 90,
		}},
	}) == 0
}

# =========================================================================
# iam_07 — Password policy: reuse prevention >= 24
# =========================================================================
test_iam_07_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"password_reuse_prevention": 12,
			"max_password_age": 90,
		}},
	}
	some v in r
	v.check_id == "iam_pwd_reuse"
}

test_iam_07_compliant if {
	_violations_for("iam_pwd_reuse", {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"password_reuse_prevention": 24,
			"max_password_age": 90,
		}},
	}) == 0
}

test_iam_07_boundary if {
	_violations_for("iam_pwd_reuse", {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"password_reuse_prevention": 23,
			"max_password_age": 90,
		}},
	}) == 1
}

# =========================================================================
# iam_08 — Password policy: max age <= 90 days
# =========================================================================
test_iam_08_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"password_reuse_prevention": 24,
			"max_password_age": 120,
		}},
	}
	some v in r
	v.check_id == "iam_pwd_max_age"
}

test_iam_08_compliant if {
	_violations_for("iam_pwd_max_age", {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"password_reuse_prevention": 24,
			"max_password_age": 90,
		}},
	}) == 0
}

test_iam_08_boundary if {
	_violations_for("iam_pwd_max_age", {
		"account_id": "123456789012",
		"iam": {"password_policy": {
			"minimum_password_length": 14,
			"require_uppercase_characters": true,
			"require_lowercase_characters": true,
			"require_numbers": true,
			"require_symbols": true,
			"password_reuse_prevention": 24,
			"max_password_age": 91,
		}},
	}) == 1
}

# =========================================================================
# iam_09 — IAM users must have MFA (when console access is enabled)
# =========================================================================
test_iam_09_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "alice",
			"arn": "arn:aws:iam::123456789012:user/alice",
			"mfa_enabled": false,
			"password_enabled": true,
			"inline_policies": [],
			"attached_policies": [],
			"access_keys": [],
			"days_since_last_use": 0,
		}]},
	}
	some v in r
	v.check_id == "iam_user_mfa"
}

test_iam_09_compliant_mfa_on if {
	_violations_for("iam_user_mfa", {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "alice",
			"arn": "arn:aws:iam::123456789012:user/alice",
			"mfa_enabled": true,
			"password_enabled": true,
			"inline_policies": [],
			"attached_policies": [],
			"access_keys": [],
			"days_since_last_use": 0,
		}]},
	}) == 0
}

test_iam_09_compliant_no_console if {
	_violations_for("iam_user_mfa", {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "svc-account",
			"arn": "arn:aws:iam::123456789012:user/svc-account",
			"mfa_enabled": false,
			"password_enabled": false,
			"inline_policies": [],
			"attached_policies": [],
			"access_keys": [],
			"days_since_last_use": 0,
		}]},
	}) == 0
}

# =========================================================================
# iam_10 — No active root access keys
# =========================================================================
test_iam_10_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"account_summary": {
			"mfa_enabled": true,
			"account_access_keys_present": 1,
		}},
	}
	some v in r
	v.check_id == "iam_root_access_keys"
}

test_iam_10_compliant if {
	_violations_for("iam_root_access_keys", {
		"account_id": "123456789012",
		"iam": {"account_summary": {
			"mfa_enabled": true,
			"account_access_keys_present": 0,
		}},
	}) == 0
}

# =========================================================================
# iam_11 — No inline policies on users
# =========================================================================
test_iam_11_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "bob",
			"arn": "arn:aws:iam::123456789012:user/bob",
			"mfa_enabled": true,
			"password_enabled": true,
			"inline_policies": ["legacy-policy"],
			"attached_policies": [],
			"access_keys": [],
			"days_since_last_use": 0,
		}]},
	}
	some v in r
	v.check_id == "iam_no_inline_policies"
}

test_iam_11_compliant if {
	_violations_for("iam_no_inline_policies", {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "bob",
			"arn": "arn:aws:iam::123456789012:user/bob",
			"mfa_enabled": true,
			"password_enabled": true,
			"inline_policies": [],
			"attached_policies": [],
			"access_keys": [],
			"days_since_last_use": 0,
		}]},
	}) == 0
}

# =========================================================================
# iam_12 — No user has AdministratorAccess
# =========================================================================
test_iam_12_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "admin-user",
			"arn": "arn:aws:iam::123456789012:user/admin-user",
			"mfa_enabled": true,
			"password_enabled": true,
			"inline_policies": [],
			"attached_policies": [{"policy_name": "AdministratorAccess"}],
			"access_keys": [],
			"days_since_last_use": 0,
		}]},
	}
	some v in r
	v.check_id == "iam_no_admin_access"
}

test_iam_12_compliant if {
	_violations_for("iam_no_admin_access", {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "dev-user",
			"arn": "arn:aws:iam::123456789012:user/dev-user",
			"mfa_enabled": true,
			"password_enabled": true,
			"inline_policies": [],
			"attached_policies": [{"policy_name": "ReadOnlyAccess"}],
			"access_keys": [],
			"days_since_last_use": 0,
		}]},
	}) == 0
}

# =========================================================================
# iam_13 — Access keys rotated within 90 days
# =========================================================================
test_iam_13_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "charlie",
			"arn": "arn:aws:iam::123456789012:user/charlie",
			"mfa_enabled": true,
			"password_enabled": false,
			"inline_policies": [],
			"attached_policies": [],
			"access_keys": [{
				"access_key_id": "AKIAIOSFODNN7EXAMPLE",
				"status": "Active",
				"age_days": 120,
				"last_used_days": 1,
			}],
			"days_since_last_use": 0,
		}]},
	}
	some v in r
	v.check_id == "iam_key_rotation"
}

test_iam_13_compliant if {
	_violations_for("iam_key_rotation", {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "charlie",
			"arn": "arn:aws:iam::123456789012:user/charlie",
			"mfa_enabled": true,
			"password_enabled": false,
			"inline_policies": [],
			"attached_policies": [],
			"access_keys": [{
				"access_key_id": "AKIAIOSFODNN7EXAMPLE",
				"status": "Active",
				"age_days": 30,
				"last_used_days": 1,
			}],
			"days_since_last_use": 0,
		}]},
	}) == 0
}

test_iam_13_inactive_key_ok if {
	_violations_for("iam_key_rotation", {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "charlie",
			"arn": "arn:aws:iam::123456789012:user/charlie",
			"mfa_enabled": true,
			"password_enabled": false,
			"inline_policies": [],
			"attached_policies": [],
			"access_keys": [{
				"access_key_id": "AKIAIOSFODNN7EXAMPLE",
				"status": "Inactive",
				"age_days": 200,
				"last_used_days": 200,
			}],
			"days_since_last_use": 0,
		}]},
	}) == 0
}

# =========================================================================
# iam_14 — Inactive users (> 90 days) must have credentials disabled
# =========================================================================
test_iam_14_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "old-user",
			"arn": "arn:aws:iam::123456789012:user/old-user",
			"mfa_enabled": true,
			"password_enabled": true,
			"inline_policies": [],
			"attached_policies": [],
			"access_keys": [],
			"days_since_last_use": 120,
		}]},
	}
	some v in r
	v.check_id == "iam_inactive_user"
}

test_iam_14_compliant_active if {
	_violations_for("iam_inactive_user", {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "active-user",
			"arn": "arn:aws:iam::123456789012:user/active-user",
			"mfa_enabled": true,
			"password_enabled": true,
			"inline_policies": [],
			"attached_policies": [],
			"access_keys": [],
			"days_since_last_use": 10,
		}]},
	}) == 0
}

test_iam_14_compliant_disabled if {
	_violations_for("iam_inactive_user", {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "old-user",
			"arn": "arn:aws:iam::123456789012:user/old-user",
			"mfa_enabled": false,
			"password_enabled": false,
			"inline_policies": [],
			"attached_policies": [],
			"access_keys": [],
			"days_since_last_use": 120,
		}]},
	}) == 0
}

# =========================================================================
# iam_15 — IAM Access Analyzer must be enabled
# =========================================================================
test_iam_15_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"access_analyzer": {"enabled": false}},
	}
	some v in r
	v.check_id == "iam_access_analyzer"
}

test_iam_15_compliant if {
	_violations_for("iam_access_analyzer", {
		"account_id": "123456789012",
		"iam": {"access_analyzer": {"enabled": true}},
	}) == 0
}

# =========================================================================
# iam_16 — No policy allows Action:* on Resource:*
# =========================================================================
test_iam_16_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"customer_managed_policies": [{
			"policy_name": "OverlyPermissive",
			"arn": "arn:aws:iam::123456789012:policy/OverlyPermissive",
			"document": {"Statement": [{
				"Effect": "Allow",
				"Action": "*",
				"Resource": "*",
			}]},
		}]},
	}
	some v in r
	v.check_id == "iam_no_wildcard_policy"
}

test_iam_16_compliant if {
	_violations_for("iam_no_wildcard_policy", {
		"account_id": "123456789012",
		"iam": {"customer_managed_policies": [{
			"policy_name": "ScopedPolicy",
			"arn": "arn:aws:iam::123456789012:policy/ScopedPolicy",
			"document": {"Statement": [{
				"Effect": "Allow",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::my-bucket/*",
			}]},
		}]},
	}) == 0
}

test_iam_16_deny_star_ok if {
	_violations_for("iam_no_wildcard_policy", {
		"account_id": "123456789012",
		"iam": {"customer_managed_policies": [{
			"policy_name": "DenyAll",
			"arn": "arn:aws:iam::123456789012:policy/DenyAll",
			"document": {"Statement": [{
				"Effect": "Deny",
				"Action": "*",
				"Resource": "*",
			}]},
		}]},
	}) == 0
}

# =========================================================================
# iam_17 — Unused access keys (active but not used in 90 days)
# =========================================================================
test_iam_17_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "dave",
			"arn": "arn:aws:iam::123456789012:user/dave",
			"mfa_enabled": true,
			"password_enabled": false,
			"inline_policies": [],
			"attached_policies": [],
			"access_keys": [{
				"access_key_id": "AKIAIOSFODNN7UNUSED",
				"status": "Active",
				"age_days": 100,
				"last_used_days": 100,
			}],
			"days_since_last_use": 0,
		}]},
	}
	some v in r
	v.check_id == "iam_unused_keys"
}

test_iam_17_compliant if {
	_violations_for("iam_unused_keys", {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "dave",
			"arn": "arn:aws:iam::123456789012:user/dave",
			"mfa_enabled": true,
			"password_enabled": false,
			"inline_policies": [],
			"attached_policies": [],
			"access_keys": [{
				"access_key_id": "AKIAIOSFODNN7RECENT",
				"status": "Active",
				"age_days": 100,
				"last_used_days": 5,
			}],
			"days_since_last_use": 0,
		}]},
	}) == 0
}

# =========================================================================
# iam_18 — Role trust policy must not allow all principals (*)
# =========================================================================
test_iam_18_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"roles": [{
			"role_name": "open-role",
			"arn": "arn:aws:iam::123456789012:role/open-role",
			"trust_policy": {"Statement": [{
				"Effect": "Allow",
				"Principal": "*",
				"Action": "sts:AssumeRole",
			}]},
		}]},
	}
	some v in r
	v.check_id == "iam_role_trust_wildcard"
}

test_iam_18_compliant if {
	_violations_for("iam_role_trust_wildcard", {
		"account_id": "123456789012",
		"iam": {"roles": [{
			"role_name": "scoped-role",
			"arn": "arn:aws:iam::123456789012:role/scoped-role",
			"trust_policy": {"Statement": [{
				"Effect": "Allow",
				"Principal": {"Service": "ec2.amazonaws.com"},
				"Action": "sts:AssumeRole",
			}]},
		}]},
	}) == 0
}

# =========================================================================
# iam_19 — No user has both console AND programmatic access
# =========================================================================
test_iam_19_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "dual-access",
			"arn": "arn:aws:iam::123456789012:user/dual-access",
			"mfa_enabled": true,
			"password_enabled": true,
			"inline_policies": [],
			"attached_policies": [],
			"access_keys": [{
				"access_key_id": "AKIAIOSFODNN7DUAL",
				"status": "Active",
				"age_days": 30,
				"last_used_days": 1,
			}],
			"days_since_last_use": 0,
		}]},
	}
	some v in r
	v.check_id == "iam_dual_access"
}

test_iam_19_compliant_console_only if {
	_violations_for("iam_dual_access", {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "console-user",
			"arn": "arn:aws:iam::123456789012:user/console-user",
			"mfa_enabled": true,
			"password_enabled": true,
			"inline_policies": [],
			"attached_policies": [],
			"access_keys": [],
			"days_since_last_use": 0,
		}]},
	}) == 0
}

test_iam_19_compliant_api_only if {
	_violations_for("iam_dual_access", {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "api-user",
			"arn": "arn:aws:iam::123456789012:user/api-user",
			"mfa_enabled": false,
			"password_enabled": false,
			"inline_policies": [],
			"attached_policies": [],
			"access_keys": [{
				"access_key_id": "AKIAIOSFODNN7API",
				"status": "Active",
				"age_days": 30,
				"last_used_days": 1,
			}],
			"days_since_last_use": 0,
		}]},
	}) == 0
}

test_iam_19_compliant_inactive_key if {
	_violations_for("iam_dual_access", {
		"account_id": "123456789012",
		"iam": {"users": [{
			"username": "mixed-user",
			"arn": "arn:aws:iam::123456789012:user/mixed-user",
			"mfa_enabled": true,
			"password_enabled": true,
			"inline_policies": [],
			"attached_policies": [],
			"access_keys": [{
				"access_key_id": "AKIAIOSFODNN7OLD",
				"status": "Inactive",
				"age_days": 200,
				"last_used_days": 200,
			}],
			"days_since_last_use": 0,
		}]},
	}) == 0
}

# =========================================================================
# iam_20 — Support role must exist
# =========================================================================
test_iam_20_alarm if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"roles": [{
			"role_name": "AdminRole",
			"arn": "arn:aws:iam::123456789012:role/AdminRole",
			"trust_policy": {"Statement": []},
			"attached_policies": [],
		}]},
	}
	some v in r
	v.check_id == "iam_support_role"
}

test_iam_20_alarm_empty_roles if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"roles": []},
	}
	some v in r
	v.check_id == "iam_support_role"
}

# Role named "support" but without AWSSupportAccess policy still alarms
test_iam_20_alarm_name_only if {
	r := iam.violations with input as {
		"account_id": "123456789012",
		"iam": {"roles": [{
			"role_name": "incident-support-team",
			"arn": "arn:aws:iam::123456789012:role/incident-support-team",
			"trust_policy": {"Statement": []},
			"attached_policies": [],
		}]},
	}
	some v in r
	v.check_id == "iam_support_role"
}

# Compliant: role has AWSSupportAccess attached regardless of name
test_iam_20_compliant if {
	_violations_for("iam_support_role", {
		"account_id": "123456789012",
		"iam": {"roles": [{
			"role_name": "IncidentResponseRole",
			"arn": "arn:aws:iam::123456789012:role/IncidentResponseRole",
			"trust_policy": {"Statement": []},
			"attached_policies": [{"PolicyName": "AWSSupportAccess", "PolicyArn": "arn:aws:iam::aws:policy/AWSSupportAccess"}],
		}]},
	}) == 0
}

# Compliant: any role with AWSSupportAccess satisfies the check
test_iam_20_compliant_any_role_name if {
	_violations_for("iam_support_role", {
		"account_id": "123456789012",
		"iam": {"roles": [
			{
				"role_name": "AdminRole",
				"arn": "arn:aws:iam::123456789012:role/AdminRole",
				"trust_policy": {"Statement": []},
				"attached_policies": [],
			},
			{
				"role_name": "SupportAccessRole",
				"arn": "arn:aws:iam::123456789012:role/SupportAccessRole",
				"trust_policy": {"Statement": []},
				"attached_policies": [{"PolicyName": "AWSSupportAccess", "PolicyArn": "arn:aws:iam::aws:policy/AWSSupportAccess"}],
			},
		]},
	}) == 0
}

# =========================================================================
# iam_00 — Error handler (missing IAM input)
# =========================================================================
test_iam_00_error_no_iam if {
	r := iam.error with input as {"account_id": "123456789012"}
	some v in r
	v.check_id == "iam_error"
	v.status == "error"
}

test_iam_00_no_error_when_iam_present if {
	r := iam.error with input as {
		"account_id": "123456789012",
		"iam": {"account_summary": {"mfa_enabled": true}},
	}
	count(r) == 0
}
