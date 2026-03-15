package aws.identity.cognito

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Rule cognito_01 — MFA required for user pool
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.mfa_configuration != "ON"
	pool.mfa_configuration != "OPTIONAL"
	result := {
		"check_id": "cognito_01",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Cognito user pool '%s' has MFA disabled",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"compliance": {
			"nist_800_53": ["IA-2(1)"],
			"pci_dss": ["8.4.2"],
			"hipaa": ["164.312(d)"],
		},
		"remediation_id": "REM_cognito_01",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_02 — Password policy: minimum length >= 8
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.policies.password_policy.minimum_length < 8
	result := {
		"check_id": "cognito_02",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Cognito user pool '%s' password minimum length %d < 8",
			[pool.user_pool_id, pool.policies.password_policy.minimum_length],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"compliance": {
			"nist_800_53": ["IA-5(1)"],
			"pci_dss": ["8.3.6"],
		},
		"remediation_id": "REM_cognito_02",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_03 — Password policy: requires uppercase letters
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.policies.password_policy.require_uppercase == false
	result := {
		"check_id": "cognito_03",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Cognito user pool '%s' does not require uppercase characters",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"compliance": {
			"nist_800_53": ["IA-5(1)"],
		},
		"remediation_id": "REM_cognito_02",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_04 — Password policy: requires lowercase letters
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.policies.password_policy.require_lowercase == false
	result := {
		"check_id": "cognito_04",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Cognito user pool '%s' does not require lowercase characters",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"compliance": {
			"nist_800_53": ["IA-5(1)"],
		},
		"remediation_id": "REM_cognito_02",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_05 — Password policy: requires numbers
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.policies.password_policy.require_numbers == false
	result := {
		"check_id": "cognito_05",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Cognito user pool '%s' does not require numbers in password",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"compliance": {
			"nist_800_53": ["IA-5(1)"],
		},
		"remediation_id": "REM_cognito_02",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_06 — Password policy: requires symbols
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.policies.password_policy.require_symbols == false
	result := {
		"check_id": "cognito_06",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Cognito user pool '%s' does not require symbols in password",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"compliance": {
			"nist_800_53": ["IA-5(1)"],
		},
		"remediation_id": "REM_cognito_02",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_07 — Advanced security mode must be ENFORCED
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.user_pool_add_ons.advanced_security_mode != "ENFORCED"
	result := {
		"check_id": "cognito_07",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Cognito user pool '%s' advanced security mode is not ENFORCED",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"compliance": {
			"nist_800_53": ["SI-3"],
			"pci_dss": ["6.3.3"],
		},
		"remediation_id": "REM_cognito_07",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_08 — Temporary password validity <= 7 days
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.policies.password_policy.temporary_password_validity_days > 7
	result := {
		"check_id": "cognito_08",
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
		"compliance": {
			"nist_800_53": ["IA-5"],
			"pci_dss": ["8.3.9"],
		},
		"remediation_id": "REM_cognito_02",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_09 — Email or phone verification required
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.auto_verified_attributes == []
	result := {
		"check_id": "cognito_09",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Cognito user pool '%s' has no auto-verified attributes (email/phone)",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"compliance": {
			"nist_800_53": ["IA-5"],
			"hipaa": ["164.312(d)"],
		},
		"remediation_id": "REM_cognito_09",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_10 — Device tracking enabled (USER_OPT_IN or ALWAYS)
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.device_configuration.challenge_required_on_new_device == false
	result := {
		"check_id": "cognito_10",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Cognito user pool '%s' does not challenge on new device",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"compliance": {
			"nist_800_53": ["IA-3"],
			"pci_dss": ["8.4.3"],
		},
		"remediation_id": "REM_cognito_10",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_11 — Access token validity <= 1 hour (3600 seconds)
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	some client in pool.app_clients
	client.access_token_validity > 60
	result := {
		"check_id": "cognito_11",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Cognito app client '%s' access token validity %d min exceeds 60 min",
			[client.client_id, client.access_token_validity],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"compliance": {
			"nist_800_53": ["AC-12"],
			"pci_dss": ["8.2.8"],
		},
		"remediation_id": "REM_cognito_11",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_12 — Refresh token validity <= 30 days
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	some client in pool.app_clients
	client.refresh_token_validity > 30
	result := {
		"check_id": "cognito_12",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Cognito app client '%s' refresh token validity %d days exceeds 30",
			[client.client_id, client.refresh_token_validity],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"compliance": {
			"nist_800_53": ["AC-12"],
		},
		"remediation_id": "REM_cognito_11",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_13 — No unauthenticated identities in identity pool
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.identity_pools
	pool.allow_unauthenticated_identities == true
	result := {
		"check_id": "cognito_13",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Cognito identity pool '%s' allows unauthenticated access",
			[pool.identity_pool_id],
		),
		"resource": pool.identity_pool_id,
		"domain": "identity",
		"service": "cognito",
		"compliance": {
			"nist_800_53": ["AC-3"],
			"pci_dss": ["7.2.1"],
			"cis_aws": ["2.1.5"],
		},
		"remediation_id": "REM_cognito_13",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_14 — App client does not use ALLOW_USER_PASSWORD_AUTH
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	some client in pool.app_clients
	"ALLOW_USER_PASSWORD_AUTH" in client.explicit_auth_flows
	result := {
		"check_id": "cognito_14",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Cognito app client '%s' allows plain USER_PASSWORD_AUTH — use SRP",
			[client.client_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"compliance": {
			"nist_800_53": ["IA-2"],
			"pci_dss": ["8.4.2"],
		},
		"remediation_id": "REM_cognito_14",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_15 — App client secret must be set for server-side clients
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	some client in pool.app_clients
	client.client_type == "server"
	client.client_secret == ""
	result := {
		"check_id": "cognito_15",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Cognito server-side app client '%s' has no client secret configured",
			[client.client_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"compliance": {
			"nist_800_53": ["IA-5"],
			"pci_dss": ["8.3.1"],
		},
		"remediation_id": "REM_cognito_15",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_16 — User pool deletion protection enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.deletion_protection != "ACTIVE"
	result := {
		"check_id": "cognito_16",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Cognito user pool '%s' deletion protection is not ACTIVE",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"compliance": {
			"nist_800_53": ["CP-9"],
		},
		"remediation_id": "REM_cognito_16",
	}
}

# ---------------------------------------------------------------------------
# Rule cognito_17 — SES sender ID configured (not default Cognito email)
# ---------------------------------------------------------------------------
violations contains result if {
	some pool in input.cognito.user_pools
	pool.email_configuration.email_sending_account == "COGNITO_DEFAULT"
	result := {
		"check_id": "cognito_17",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Cognito user pool '%s' uses default Cognito email (low deliverability)",
			[pool.user_pool_id],
		),
		"resource": pool.arn,
		"domain": "identity",
		"service": "cognito",
		"compliance": {
			"nist_800_53": ["IA-5"],
		},
		"remediation_id": "REM_cognito_17",
	}
}

# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
error contains result if {
	not input.cognito
	result := {
		"check_id": "cognito_00",
		"status": "error",
		"severity": "critical",
		"reason": "Cognito data missing from input — collector may have failed",
		"resource": "",
		"domain": "identity",
		"service": "cognito",
	}
}
