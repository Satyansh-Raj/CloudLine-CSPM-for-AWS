package aws.identity.cognito_test

import data.aws.identity.cognito

# =========================================================================
# Helper
# =========================================================================
_violations_for(check_id, inp) := count([v |
	some v in cognito.violations with input as inp
	v.check_id == check_id
])

# Compliant user pool template — triggers NO rules
_compliant_pool := {
	"user_pool_id": "us-east-1_test",
	"arn": "arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_test",
	"mfa_configuration": "ON",
	"policies": {"password_policy": {
		"minimum_length": 12,
		"require_uppercase": true,
		"require_lowercase": true,
		"require_numbers": true,
		"require_symbols": true,
		"temporary_password_validity_days": 7,
	}},
	"user_pool_add_ons": {"advanced_security_mode": "ENFORCED"},
	"auto_verified_attributes": ["email"],
	"device_configuration": {"challenge_required_on_new_device": true},
	"app_clients": [{
		"client_id": "abc123",
		"client_type": "public",
		"client_secret": "",
		"access_token_validity": 60,
		"refresh_token_validity": 30,
		"explicit_auth_flows": ["ALLOW_USER_SRP_AUTH"],
	}],
	"deletion_protection": "ACTIVE",
	"email_configuration": {"email_sending_account": "DEVELOPER"},
}

# =========================================================================
# cognito_01 — MFA required
# =========================================================================
test_cognito_01_alarm_off if {
	r := cognito.violations with input as {"cognito": {"user_pools": [object.union(_compliant_pool, {"mfa_configuration": "OFF"})]}}
	some v in r
	v.check_id == "cognito_01"
}

test_cognito_01_compliant_on if {
	_violations_for("cognito_01", {"cognito": {"user_pools": [_compliant_pool]}}) == 0
}

test_cognito_01_compliant_optional if {
	_violations_for("cognito_01", {"cognito": {"user_pools": [object.union(_compliant_pool, {"mfa_configuration": "OPTIONAL"})]}}) == 0
}

# =========================================================================
# cognito_02 — Password minimum length >= 8
# =========================================================================
_pool_with_pw(overrides) := object.union(_compliant_pool, {"policies": {"password_policy": object.union(
	_compliant_pool.policies.password_policy,
	overrides,
)}})

test_cognito_02_alarm if {
	r := cognito.violations with input as {"cognito": {"user_pools": [_pool_with_pw({"minimum_length": 6})]}}
	some v in r
	v.check_id == "cognito_02"
}

test_cognito_02_compliant if {
	_violations_for("cognito_02", {"cognito": {"user_pools": [_pool_with_pw({"minimum_length": 8})]}}) == 0
}

test_cognito_02_boundary if {
	r := cognito.violations with input as {"cognito": {"user_pools": [_pool_with_pw({"minimum_length": 7})]}}
	some v in r
	v.check_id == "cognito_02"
}

# =========================================================================
# cognito_03 — Requires uppercase
# =========================================================================
test_cognito_03_alarm if {
	r := cognito.violations with input as {"cognito": {"user_pools": [_pool_with_pw({"require_uppercase": false})]}}
	some v in r
	v.check_id == "cognito_03"
}

test_cognito_03_compliant if {
	_violations_for("cognito_03", {"cognito": {"user_pools": [_compliant_pool]}}) == 0
}

# =========================================================================
# cognito_04 — Requires lowercase
# =========================================================================
test_cognito_04_alarm if {
	r := cognito.violations with input as {"cognito": {"user_pools": [_pool_with_pw({"require_lowercase": false})]}}
	some v in r
	v.check_id == "cognito_04"
}

test_cognito_04_compliant if {
	_violations_for("cognito_04", {"cognito": {"user_pools": [_compliant_pool]}}) == 0
}

# =========================================================================
# cognito_05 — Requires numbers
# =========================================================================
test_cognito_05_alarm if {
	r := cognito.violations with input as {"cognito": {"user_pools": [_pool_with_pw({"require_numbers": false})]}}
	some v in r
	v.check_id == "cognito_05"
}

test_cognito_05_compliant if {
	_violations_for("cognito_05", {"cognito": {"user_pools": [_compliant_pool]}}) == 0
}

# =========================================================================
# cognito_06 — Requires symbols
# =========================================================================
test_cognito_06_alarm if {
	r := cognito.violations with input as {"cognito": {"user_pools": [_pool_with_pw({"require_symbols": false})]}}
	some v in r
	v.check_id == "cognito_06"
}

test_cognito_06_compliant if {
	_violations_for("cognito_06", {"cognito": {"user_pools": [_compliant_pool]}}) == 0
}

# =========================================================================
# cognito_07 — Advanced security mode ENFORCED
# =========================================================================
test_cognito_07_alarm if {
	r := cognito.violations with input as {"cognito": {"user_pools": [object.union(_compliant_pool, {"user_pool_add_ons": {"advanced_security_mode": "AUDIT"}})]}}
	some v in r
	v.check_id == "cognito_07"
}

test_cognito_07_compliant if {
	_violations_for("cognito_07", {"cognito": {"user_pools": [_compliant_pool]}}) == 0
}

# =========================================================================
# cognito_08 — Temporary password validity <= 7 days
# =========================================================================
test_cognito_08_alarm if {
	r := cognito.violations with input as {"cognito": {"user_pools": [_pool_with_pw({"temporary_password_validity_days": 14})]}}
	some v in r
	v.check_id == "cognito_08"
}

test_cognito_08_compliant if {
	_violations_for("cognito_08", {"cognito": {"user_pools": [_compliant_pool]}}) == 0
}

test_cognito_08_boundary if {
	_violations_for("cognito_08", {"cognito": {"user_pools": [_pool_with_pw({"temporary_password_validity_days": 7})]}}) == 0
}

# =========================================================================
# cognito_09 — Auto-verified attributes not empty
# =========================================================================
test_cognito_09_alarm if {
	r := cognito.violations with input as {"cognito": {"user_pools": [object.union(_compliant_pool, {"auto_verified_attributes": []})]}}
	some v in r
	v.check_id == "cognito_09"
}

test_cognito_09_compliant if {
	_violations_for("cognito_09", {"cognito": {"user_pools": [_compliant_pool]}}) == 0
}

# =========================================================================
# cognito_10 — Challenge on new device
# =========================================================================
test_cognito_10_alarm if {
	r := cognito.violations with input as {"cognito": {"user_pools": [object.union(_compliant_pool, {"device_configuration": {"challenge_required_on_new_device": false}})]}}
	some v in r
	v.check_id == "cognito_10"
}

test_cognito_10_compliant if {
	_violations_for("cognito_10", {"cognito": {"user_pools": [_compliant_pool]}}) == 0
}

# =========================================================================
# cognito_11 — Access token validity <= 60 min
# =========================================================================
_pool_with_client(overrides) := object.union(_compliant_pool, {"app_clients": [object.union(
	_compliant_pool.app_clients[0],
	overrides,
)]})

test_cognito_11_alarm if {
	r := cognito.violations with input as {"cognito": {"user_pools": [_pool_with_client({"access_token_validity": 120})]}}
	some v in r
	v.check_id == "cognito_11"
}

test_cognito_11_compliant if {
	_violations_for("cognito_11", {"cognito": {"user_pools": [_compliant_pool]}}) == 0
}

test_cognito_11_boundary if {
	_violations_for("cognito_11", {"cognito": {"user_pools": [_pool_with_client({"access_token_validity": 60})]}}) == 0
}

# =========================================================================
# cognito_12 — Refresh token validity <= 30 days
# =========================================================================
test_cognito_12_alarm if {
	r := cognito.violations with input as {"cognito": {"user_pools": [_pool_with_client({"refresh_token_validity": 90})]}}
	some v in r
	v.check_id == "cognito_12"
}

test_cognito_12_compliant if {
	_violations_for("cognito_12", {"cognito": {"user_pools": [_compliant_pool]}}) == 0
}

# =========================================================================
# cognito_13 — No unauthenticated identities
# =========================================================================
test_cognito_13_alarm if {
	r := cognito.violations with input as {"cognito": {"identity_pools": [{
		"identity_pool_id": "us-east-1:abc",
		"allow_unauthenticated_identities": true,
	}]}}
	some v in r
	v.check_id == "cognito_13"
}

test_cognito_13_compliant if {
	_violations_for("cognito_13", {"cognito": {"identity_pools": [{
		"identity_pool_id": "us-east-1:abc",
		"allow_unauthenticated_identities": false,
	}]}}) == 0
}

# =========================================================================
# cognito_14 — No ALLOW_USER_PASSWORD_AUTH
# =========================================================================
test_cognito_14_alarm if {
	r := cognito.violations with input as {"cognito": {"user_pools": [_pool_with_client({"explicit_auth_flows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH"]})]}}
	some v in r
	v.check_id == "cognito_14"
}

test_cognito_14_compliant if {
	_violations_for("cognito_14", {"cognito": {"user_pools": [_compliant_pool]}}) == 0
}

# =========================================================================
# cognito_15 — Server-side clients must have secret
# =========================================================================
test_cognito_15_alarm if {
	r := cognito.violations with input as {"cognito": {"user_pools": [_pool_with_client({
		"client_type": "server",
		"client_secret": "",
	})]}}
	some v in r
	v.check_id == "cognito_15"
}

test_cognito_15_compliant_has_secret if {
	_violations_for("cognito_15", {"cognito": {"user_pools": [_pool_with_client({
		"client_type": "server",
		"client_secret": "supersecret",
	})]}}) == 0
}

test_cognito_15_compliant_public_client if {
	_violations_for("cognito_15", {"cognito": {"user_pools": [_compliant_pool]}}) == 0
}

# =========================================================================
# cognito_16 — Deletion protection ACTIVE
# =========================================================================
test_cognito_16_alarm if {
	r := cognito.violations with input as {"cognito": {"user_pools": [object.union(_compliant_pool, {"deletion_protection": "INACTIVE"})]}}
	some v in r
	v.check_id == "cognito_16"
}

test_cognito_16_compliant if {
	_violations_for("cognito_16", {"cognito": {"user_pools": [_compliant_pool]}}) == 0
}

# =========================================================================
# cognito_17 — Not using default Cognito email
# =========================================================================
test_cognito_17_alarm if {
	r := cognito.violations with input as {"cognito": {"user_pools": [object.union(_compliant_pool, {"email_configuration": {"email_sending_account": "COGNITO_DEFAULT"}})]}}
	some v in r
	v.check_id == "cognito_17"
}

test_cognito_17_compliant if {
	_violations_for("cognito_17", {"cognito": {"user_pools": [_compliant_pool]}}) == 0
}

# =========================================================================
# cognito_00 — Error handler
# =========================================================================
test_cognito_00_error if {
	r := cognito.error with input as {"account_id": "123456789012"}
	some v in r
	v.check_id == "cognito_00"
}

test_cognito_00_no_error if {
	r := cognito.error with input as {"cognito": {"user_pools": []}}
	count(r) == 0
}
