package aws.identity.cognito

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Rule cognito_mfa_required — MFA required for user pool
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.mfa_configuration != "ON"
	pool.mfa_configuration != "OPTIONAL"
	result := {
		"check_id": "cognito_mfa_required",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Cognito user pool '%s' has MFA disabled",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_01",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_pwd_min_length — Password policy: minimum length >= 8
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.policies.password_policy.minimum_length < 8
	result := {
		"check_id": "cognito_pwd_min_length",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Cognito user pool '%s' password minimum length %d < 8",
			[pool.user_pool_id, pool.policies.password_policy.minimum_length],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_02",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_pwd_uppercase — Password policy: requires uppercase letters
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.policies.password_policy.require_uppercase == false
	result := {
		"check_id": "cognito_pwd_uppercase",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Cognito user pool '%s' does not require uppercase characters",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_02",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_pwd_lowercase — Password policy: requires lowercase letters
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.policies.password_policy.require_lowercase == false
	result := {
		"check_id": "cognito_pwd_lowercase",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Cognito user pool '%s' does not require lowercase characters",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_02",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_pwd_numbers — Password policy: requires numbers
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.policies.password_policy.require_numbers == false
	result := {
		"check_id": "cognito_pwd_numbers",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Cognito user pool '%s' does not require numbers in password",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_02",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_pwd_symbols — Password policy: requires symbols
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.policies.password_policy.require_symbols == false
	result := {
		"check_id": "cognito_pwd_symbols",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Cognito user pool '%s' does not require symbols in password",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_02",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_advanced_security — Advanced security mode must be ENFORCED
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.user_pool_add_ons.advanced_security_mode != "ENFORCED"
	result := {
		"check_id": "cognito_advanced_security",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Cognito user pool '%s' advanced security mode is not ENFORCED",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_07",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_temp_pwd_validity — Temporary password validity <= 7 days
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.policies.password_policy.temporary_password_validity_days > 7
	result := {
		"check_id": "cognito_temp_pwd_validity",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Cognito user pool '%s' temporary password validity is %d days (limit: 7)",
			[
				pool.user_pool_id,
				pool.policies.password_policy.temporary_password_validity_days,
			],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_02",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_verification_required — Email or phone verification required
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.auto_verified_attributes == []
	result := {
		"check_id": "cognito_verification_required",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Cognito user pool '%s' has no auto-verified attributes (email/phone)",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_09",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_device_tracking — Device tracking enabled (USER_OPT_IN or ALWAYS)
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.device_configuration.challenge_required_on_new_device == false
	result := {
		"check_id": "cognito_device_tracking",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Cognito user pool '%s' does not challenge on new device",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_10",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_access_token_validity — Access token validity <= 1 hour (3600 seconds)
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	some client in pool.app_clients
	client.access_token_validity > 60
	result := {
		"check_id": "cognito_access_token_validity",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Cognito app client '%s' access token validity %d min exceeds 60 min",
			[client.client_id, client.access_token_validity],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_11",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_refresh_token_validity — Refresh token validity <= 30 days
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	some client in pool.app_clients
	client.refresh_token_validity > 30
	result := {
		"check_id": "cognito_refresh_token_validity",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Cognito app client '%s' refresh token validity %d days exceeds 30",
			[client.client_id, client.refresh_token_validity],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_11",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_no_unauth_identities — No unauthenticated identities in identity pool
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.identity_pools
	pool.allow_unauthenticated_identities == true
	result := {
		"check_id": "cognito_no_unauth_identities",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Cognito identity pool '%s' allows unauthenticated access",
			[pool.identity_pool_id],
		),
		"resource": pool.identity_pool_id,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_13",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_no_user_pwd_auth — App client does not use ALLOW_USER_PASSWORD_AUTH
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	some client in pool.app_clients
	"ALLOW_USER_PASSWORD_AUTH" in client.explicit_auth_flows
	result := {
		"check_id": "cognito_no_user_pwd_auth",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Cognito app client '%s' allows plain USER_PASSWORD_AUTH — use SRP",
			[client.client_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_14",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_app_client_secret — App client secret must be set for server-side clients
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	some client in pool.app_clients
	client.client_type == "server"
	client.client_secret == ""
	result := {
		"check_id": "cognito_app_client_secret",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Cognito server-side app client '%s' has no client secret configured",
			[client.client_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_15",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_deletion_protection — User pool deletion protection enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.deletion_protection != "ACTIVE"
	result := {
		"check_id": "cognito_deletion_protection",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Cognito user pool '%s' deletion protection is not ACTIVE",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_16",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_ses_sender — SES sender ID configured (not default Cognito email)
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.email_configuration.email_sending_account == "COGNITO_DEFAULT"
	result := {
		"check_id": "cognito_ses_sender",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Cognito user pool '%s' uses default Cognito email (low deliverability)",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"remediation_id": "REM_cognito_17",
	}
}

# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
error contains result if {
	not input.cognito
	result := {
		"check_id": "cognito_error",
		"status": "error",
		"severity": "critical",
		"reason": "Cognito data missing from input — collector may have failed",
		"resource": "",
		"domain": "identity",
		"service": "cognito",
	}
}
