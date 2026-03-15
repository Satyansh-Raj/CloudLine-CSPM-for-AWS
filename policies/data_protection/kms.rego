package aws.data_protection.kms

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Rule kms_01 — Customer-managed key rotation must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	key.key_state == "Enabled"
	key.key_rotation_enabled == false
	result := {
		"check_id": "kms_01",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"KMS CMK '%s' (%s) does not have automatic key rotation enabled",
			[key.key_id, key.description],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"compliance": {
			"cis_aws": ["3.7"],
			"nist_800_53": ["IA-5(1)"],
			"pci_dss": ["3.7.4"],
		},
		"remediation_id": "REM_kms_01",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_02 — Key policy must not allow Principal: * without conditions
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	some stmt in key.policy.Statement
	stmt.Effect == "Allow"
	stmt.Principal == "*"
	not stmt.Condition
	result := {
		"check_id": "kms_02",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"KMS key '%s' policy allows all principals (*) without conditions",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"compliance": {
			"nist_800_53": ["AC-3"],
			"pci_dss": ["3.7.2"],
		},
		"remediation_id": "REM_kms_02",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_03 — Key must not be pending deletion without approval tag
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_state == "PendingDeletion"
	not key.tags.deletion_approved
	result := {
		"check_id": "kms_03",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"KMS key '%s' is pending deletion but lacks deletion_approved tag",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"compliance": {
			"nist_800_53": ["CP-9"],
			"pci_dss": ["3.7.1"],
		},
		"remediation_id": "REM_kms_03",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_04 — Key policy must separate administrators from users
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	admin_principals := {p |
		some stmt in key.policy.Statement
		stmt.Sid == "KeyAdministration"
		some p in stmt.Principal.AWS
	}
	user_principals := {p |
		some stmt in key.policy.Statement
		stmt.Sid == "KeyUsage"
		some p in stmt.Principal.AWS
	}
	count(admin_principals & user_principals) > 0
	result := {
		"check_id": "kms_04",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"KMS key '%s' has overlapping admin and user principals (no separation of duties)",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"compliance": {
			"nist_800_53": ["AC-5"],
			"pci_dss": ["7.2.4"],
		},
		"remediation_id": "REM_kms_04",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_05 — Key must have a non-empty description
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	key.description == ""
	result := {
		"check_id": "kms_05",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"KMS key '%s' has no description — purpose is undocumented",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"compliance": {
			"nist_800_53": ["CM-8"],
		},
		"remediation_id": "REM_kms_05",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_06 — Multi-region keys must only be used where required
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	key.multi_region == true
	not key.tags.multi_region_justified
	result := {
		"check_id": "kms_06",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"KMS key '%s' is multi-region without a multi_region_justified tag",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"compliance": {
			"nist_800_53": ["CM-6"],
		},
		"remediation_id": "REM_kms_06",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_07 — Key policy must not grant cross-account access to unknown accounts
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	some stmt in key.policy.Statement
	stmt.Effect == "Allow"
	some principal in stmt.Principal.AWS
	not startswith(principal, concat("", ["arn:aws:iam::", input.account_id]))
	not stmt.Condition["aws:PrincipalOrgID"]
	not key.tags.cross_account_approved
	result := {
		"check_id": "kms_07",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"KMS key '%s' grants cross-account access without org condition",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"compliance": {
			"nist_800_53": ["AC-3"],
		},
		"remediation_id": "REM_kms_07",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_08 — Keys must have owner and purpose tags
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	not key.tags.owner
	result := {
		"check_id": "kms_08",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"KMS key '%s' is missing an owner tag",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"compliance": {
			"nist_800_53": ["CM-8"],
		},
		"remediation_id": "REM_kms_08",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_09 — Disabled keys older than 90 days should be scheduled for deletion
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	key.key_state == "Disabled"
	key.days_since_disabled > 90
	not key.tags.deletion_reviewed
	result := {
		"check_id": "kms_09",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"KMS key '%s' has been disabled for %d days — review for deletion",
			[key.key_id, key.days_since_disabled],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"compliance": {
			"nist_800_53": ["CM-8"],
		},
		"remediation_id": "REM_kms_09",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_10 — Key policy must not use root account wildcard for all actions
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	some stmt in key.policy.Statement
	stmt.Effect == "Allow"
	stmt.Action == "kms:*"
	stmt.Principal.AWS == concat("", ["arn:aws:iam::", input.account_id, ":root"])
	not stmt.Condition
	result := {
		"check_id": "kms_10",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"KMS key '%s' grants kms:* to root without conditions — over-privileged",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"compliance": {
			"nist_800_53": ["AC-6"],
			"pci_dss": ["3.7.2"],
		},
		"remediation_id": "REM_kms_10",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_11 — Key aliases must not use the aws/ prefix (reserved for AWS)
# ---------------------------------------------------------------------------
violations contains result if {
	some alias in input.kms.aliases
	alias.target_key_id
	startswith(alias.alias_name, "alias/aws/")
	alias.key_manager == "CUSTOMER"
	result := {
		"check_id": "kms_11",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"KMS alias '%s' uses reserved aws/ prefix for a customer-managed key",
			[alias.alias_name],
		),
		"resource": alias.alias_arn,
		"domain": "data_protection",
		"service": "kms",
		"compliance": {
			"nist_800_53": ["CM-6"],
		},
		"remediation_id": "REM_kms_11",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_12 — Symmetric keys used for S3 must have rotation enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	key.key_spec == "SYMMETRIC_DEFAULT"
	key.tags.used_for == "s3"
	key.key_rotation_enabled == false
	result := {
		"check_id": "kms_12",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"KMS symmetric key '%s' used for S3 does not have rotation enabled",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"compliance": {
			"cis_aws": ["3.7"],
			"nist_800_53": ["IA-5(1)"],
		},
		"remediation_id": "REM_kms_01",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_13 — CloudWatch alarm must exist for key deletion/disablement
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	key.key_state == "Enabled"
	not key.deletion_alarm_configured
	result := {
		"check_id": "kms_13",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"KMS key '%s' has no CloudWatch alarm configured for deletion events",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"compliance": {
			"cis_aws": ["3.7"],
			"nist_800_53": ["AU-6"],
		},
		"remediation_id": "REM_kms_13",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_14 — Key material origin must not be EXTERNAL without approval
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.origin == "EXTERNAL"
	not key.tags.external_key_approved
	result := {
		"check_id": "kms_14",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"KMS key '%s' uses EXTERNAL key material without approval tag",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"compliance": {
			"nist_800_53": ["SC-12"],
			"pci_dss": ["3.7.3"],
		},
		"remediation_id": "REM_kms_14",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_15 — Key grants must not grant kms:Decrypt to unapproved services
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	some grant in key.grants
	"kms:Decrypt" in grant.operations
	not grant.retiring_principal
	result := {
		"check_id": "kms_15",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"KMS key '%s' has a grant for kms:Decrypt without a retiring principal",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"compliance": {
			"nist_800_53": ["AC-3"],
		},
		"remediation_id": "REM_kms_15",
	}
}

# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
error contains result if {
	not input.kms
	result := {
		"check_id": "kms_00",
		"status": "error",
		"severity": "critical",
		"reason": "KMS data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
		"service": "kms",
	}
}
