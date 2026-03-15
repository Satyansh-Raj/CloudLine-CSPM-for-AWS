package aws.identity.iam

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Rule iam_01 — Root account MFA enabled
# ---------------------------------------------------------------------------
violations contains result if {
	input.iam.account_summary.mfa_enabled == false
	result := {
		"check_id": "iam_01",
		"status": "alarm",
		"severity": "critical",
		"reason": "Root account does not have MFA enabled",
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":root"]),
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.5"],
			"nist_800_53": ["IA-2(1)"],
			"pci_dss": ["8.3.1"],
		},
		"remediation_id": "REM_01",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_02 — Password policy: minimum length >= 14
# ---------------------------------------------------------------------------
violations contains result if {
	policy := input.iam.password_policy
	policy.minimum_password_length < 14
	result := {
		"check_id": "iam_02",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Password policy minimum length is %d (required: 14)",
			[policy.minimum_password_length],
		),
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":password-policy"]),
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.9"],
			"nist_800_53": ["IA-5(1)"],
			"pci_dss": ["8.3.6"],
		},
		"remediation_id": "REM_02",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_03 — Password policy: requires uppercase letters
# ---------------------------------------------------------------------------
violations contains result if {
	input.iam.password_policy.require_uppercase_characters == false
	result := {
		"check_id": "iam_03",
		"status": "alarm",
		"severity": "medium",
		"reason": "Password policy does not require uppercase characters",
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":password-policy"]),
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.9"],
			"nist_800_53": ["IA-5(1)"],
		},
		"remediation_id": "REM_02",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_04 — Password policy: requires lowercase letters
# ---------------------------------------------------------------------------
violations contains result if {
	input.iam.password_policy.require_lowercase_characters == false
	result := {
		"check_id": "iam_04",
		"status": "alarm",
		"severity": "medium",
		"reason": "Password policy does not require lowercase characters",
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":password-policy"]),
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.9"],
			"nist_800_53": ["IA-5(1)"],
		},
		"remediation_id": "REM_02",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_05 — Password policy: requires numbers
# ---------------------------------------------------------------------------
violations contains result if {
	input.iam.password_policy.require_numbers == false
	result := {
		"check_id": "iam_05",
		"status": "alarm",
		"severity": "medium",
		"reason": "Password policy does not require numbers",
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":password-policy"]),
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.9"],
			"nist_800_53": ["IA-5(1)"],
		},
		"remediation_id": "REM_02",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_06 — Password policy: requires symbols
# ---------------------------------------------------------------------------
violations contains result if {
	input.iam.password_policy.require_symbols == false
	result := {
		"check_id": "iam_06",
		"status": "alarm",
		"severity": "medium",
		"reason": "Password policy does not require symbols",
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":password-policy"]),
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.9"],
			"nist_800_53": ["IA-5(1)"],
		},
		"remediation_id": "REM_02",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_07 — Password policy: prevents reuse (>= 24 passwords)
# ---------------------------------------------------------------------------
violations contains result if {
	policy := input.iam.password_policy
	policy.password_reuse_prevention < 24
	result := {
		"check_id": "iam_07",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Password reuse prevention is %d (required: 24)",
			[policy.password_reuse_prevention],
		),
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":password-policy"]),
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.9"],
			"nist_800_53": ["IA-5(1)"],
			"pci_dss": ["8.3.7"],
		},
		"remediation_id": "REM_02",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_08 — Password policy: max age <= 90 days
# ---------------------------------------------------------------------------
violations contains result if {
	policy := input.iam.password_policy
	policy.max_password_age > 90
	result := {
		"check_id": "iam_08",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Password max age is %d days (required: <= 90)",
			[policy.max_password_age],
		),
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":password-policy"]),
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.9"],
			"nist_800_53": ["IA-5(1)"],
			"pci_dss": ["8.3.9"],
		},
		"remediation_id": "REM_02",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_09 — All IAM users must have MFA enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some user in input.iam.users
	user.mfa_enabled == false
	user.password_enabled == true
	result := {
		"check_id": "iam_09",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf("IAM user '%s' has console access but no MFA", [user.username]),
		"resource": user.arn,
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.10"],
			"nist_800_53": ["IA-2(1)"],
			"pci_dss": ["8.4.2"],
		},
		"remediation_id": "REM_03",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_10 — No active root access keys
# ---------------------------------------------------------------------------
violations contains result if {
	summary := input.iam.account_summary
	summary.account_access_keys_present > 0
	result := {
		"check_id": "iam_10",
		"status": "alarm",
		"severity": "critical",
		"reason": "Root account has active access keys — must be deleted immediately",
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":root"]),
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.4"],
			"nist_800_53": ["AC-6"],
			"pci_dss": ["7.2.1"],
		},
		"remediation_id": "REM_01",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_11 — No inline policies attached directly to users
# ---------------------------------------------------------------------------
violations contains result if {
	some user in input.iam.users
	count(user.inline_policies) > 0
	result := {
		"check_id": "iam_11",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"IAM user '%s' has inline policies — use managed policies instead",
			[user.username],
		),
		"resource": user.arn,
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.16"],
			"nist_800_53": ["AC-6"],
		},
		"remediation_id": "REM_02",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_12 — No IAM user directly attached AdministratorAccess
# ---------------------------------------------------------------------------
violations contains result if {
	some user in input.iam.users
	some policy in user.attached_policies
	policy.policy_name == "AdministratorAccess"
	result := {
		"check_id": "iam_12",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"IAM user '%s' has AdministratorAccess — use roles with limited scope",
			[user.username],
		),
		"resource": user.arn,
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.16"],
			"nist_800_53": ["AC-6(5)"],
			"pci_dss": ["7.2.1"],
		},
		"remediation_id": "REM_02",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_13 — Access keys must be rotated within 90 days
# ---------------------------------------------------------------------------
violations contains result if {
	some user in input.iam.users
	some key in user.access_keys
	key.status == "Active"
	key.age_days > 90
	result := {
		"check_id": "iam_13",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Access key '%s' for user '%s' is %d days old (limit: 90)",
			[key.access_key_id, user.username, key.age_days],
		),
		"resource": user.arn,
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.14"],
			"nist_800_53": ["IA-5(1)"],
			"pci_dss": ["8.3.9"],
		},
		"remediation_id": "REM_03",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_14 — Users inactive > 90 days must have credentials disabled
# ---------------------------------------------------------------------------
violations contains result if {
	some user in input.iam.users
	user.days_since_last_use > 90
	user.password_enabled == true
	result := {
		"check_id": "iam_14",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"IAM user '%s' has been inactive for %d days",
			[user.username, user.days_since_last_use],
		),
		"resource": user.arn,
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.12"],
			"nist_800_53": ["AC-2(3)"],
			"pci_dss": ["8.2.6"],
		},
		"remediation_id": "REM_03",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_15 — IAM Access Analyzer must be enabled in all regions
# ---------------------------------------------------------------------------
violations contains result if {
	input.iam.access_analyzer.enabled == false
	result := {
		"check_id": "iam_15",
		"status": "alarm",
		"severity": "medium",
		"reason": "IAM Access Analyzer is not enabled — external access will go undetected",
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":access-analyzer"]),
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.21"],
			"nist_800_53": ["CA-7"],
		},
		"remediation_id": "REM_19",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_16 — No IAM managed policy allows action "*" on resource "*"
# ---------------------------------------------------------------------------
violations contains result if {
	some policy in input.iam.customer_managed_policies
	some statement in policy.document.Statement
	statement.Effect == "Allow"
	statement.Action == "*"
	statement.Resource == "*"
	result := {
		"check_id": "iam_16",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"IAM policy '%s' allows Action:* on Resource:* — violates least privilege",
			[policy.policy_name],
		),
		"resource": policy.arn,
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.16"],
			"nist_800_53": ["AC-6"],
			"pci_dss": ["7.2.1"],
		},
		"remediation_id": "REM_02",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_17 — Unused access keys (active but never used in 90 days) disabled
# ---------------------------------------------------------------------------
violations contains result if {
	some user in input.iam.users
	some key in user.access_keys
	key.status == "Active"
	key.last_used_days > 90
	result := {
		"check_id": "iam_17",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Access key '%s' for user '%s' unused for %d days",
			[key.access_key_id, user.username, key.last_used_days],
		),
		"resource": user.arn,
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.13"],
			"nist_800_53": ["AC-2(3)"],
			"pci_dss": ["8.2.6"],
		},
		"remediation_id": "REM_03",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_18 — IAM role trust policies must not allow all principals (*)
# ---------------------------------------------------------------------------
violations contains result if {
	some role in input.iam.roles
	some statement in role.trust_policy.Statement
	statement.Effect == "Allow"
	statement.Principal == "*"
	result := {
		"check_id": "iam_18",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"IAM role '%s' trust policy allows all principals (*)",
			[role.role_name],
		),
		"resource": role.arn,
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.16"],
			"nist_800_53": ["AC-6"],
		},
		"remediation_id": "REM_02",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_19 — No IAM user should have both console and programmatic access
# ---------------------------------------------------------------------------
violations contains result if {
	some user in input.iam.users
	user.password_enabled == true
	some key in user.access_keys
	key.status == "Active"
	result := {
		"check_id": "iam_19",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"IAM user '%s' has both console password and active access keys",
			[user.username],
		),
		"resource": user.arn,
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.15"],
			"nist_800_53": ["AC-2"],
		},
		"remediation_id": "REM_03",
	}
}

# ---------------------------------------------------------------------------
# Rule iam_20 — Support role for incident response must exist
# ---------------------------------------------------------------------------
violations contains result if {
	roles := [r | some r in input.iam.roles; contains(lower(r.role_name), "support")]
	count(roles) == 0
	result := {
		"check_id": "iam_20",
		"status": "alarm",
		"severity": "low",
		"reason": "No IAM role with 'support' in name found — incident response may be impaired",
		"resource": concat("", ["arn:aws:iam::", input.account_id, ":role/"]),
		"domain": "identity",
		"service": "iam",
		"compliance": {
			"cis_aws": ["1.20"],
			"nist_800_53": ["IR-2"],
		},
		"remediation_id": "REM_02",
	}
}

# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
error contains result if {
	not input.iam
	result := {
		"check_id": "iam_00",
		"status": "error",
		"severity": "critical",
		"reason": "IAM data missing from input — collector may have failed",
		"resource": "",
		"domain": "identity",
		"service": "iam",
	}
}
