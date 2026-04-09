package aws.data_protection.kms

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Rule kms_key_rotation — Customer-managed key rotation must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	key.key_state == "Enabled"
	key.key_rotation_enabled == false
	result := {
		"check_id": "kms_key_rotation",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"KMS CMK '%s' (%s) does not have automatic key rotation enabled",
			[key.key_id, key.description],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"remediation_id": "REM_kms_01",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_no_public_principal — Key policy must not allow Principal: * without conditions
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	some stmt in key.policy.Statement
	stmt.Effect == "Allow"
	stmt.Principal == "*"
	not stmt.Condition
	result := {
		"check_id": "kms_no_public_principal",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"KMS key '%s' policy allows all principals (*) without conditions",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"remediation_id": "REM_kms_02",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_pending_deletion_approval — Key must not be pending deletion without approval tag
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_state == "PendingDeletion"
	not key.tags.deletion_approved
	result := {
		"check_id": "kms_pending_deletion_approval",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"KMS key '%s' is pending deletion but lacks deletion_approved tag",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"remediation_id": "REM_kms_03",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_separate_admin_users — Key policy must separate administrators from users
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
		"check_id": "kms_separate_admin_users",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"KMS key '%s' has overlapping admin and user principals (no separation of duties)",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"remediation_id": "REM_kms_04",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_key_description — Key must have a non-empty description
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	key.description == ""
	result := {
		"check_id": "kms_key_description",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"KMS key '%s' has no description — purpose is undocumented",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"remediation_id": "REM_kms_05",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_multi_region_required — Multi-region keys must only be used where required
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	key.multi_region == true
	not key.tags.multi_region_justified
	result := {
		"check_id": "kms_multi_region_required",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"KMS key '%s' is multi-region without a multi_region_justified tag",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"remediation_id": "REM_kms_06",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_no_unknown_cross_account — Key policy must not grant cross-account access to unknown accounts
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
		"check_id": "kms_no_unknown_cross_account",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"KMS key '%s' grants cross-account access without org condition",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"remediation_id": "REM_kms_07",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_owner_purpose_tags — Keys must have owner and purpose tags
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	not key.key_state in {"PendingDeletion", "PendingReplicaDeletion"}
	not key.tags.owner
	result := {
		"check_id": "kms_owner_purpose_tags",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"KMS key '%s' is missing an owner tag",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"remediation_id": "REM_kms_08",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_disabled_keys_cleanup — Disabled keys older than 90 days should be scheduled for deletion
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	key.key_state == "Disabled"
	key.days_since_disabled > 90
	not key.tags.deletion_reviewed
	result := {
		"check_id": "kms_disabled_keys_cleanup",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"KMS key '%s' has been disabled for %d days — review for deletion",
			[key.key_id, key.days_since_disabled],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"remediation_id": "REM_kms_09",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_no_root_wildcard — Key policy must not use root account wildcard for all actions
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
		"check_id": "kms_no_root_wildcard",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"KMS key '%s' grants kms:* to root without MFA condition — keep root access but add aws:MultiFactorAuthPresent to enforce MFA for all root key administration",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"remediation_id": "REM_kms_10",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_no_aws_alias_prefix — Key aliases must not use the aws/ prefix (reserved for AWS)
# ---------------------------------------------------------------------------
violations contains result if {
	some alias in input.kms.aliases
	alias.target_key_id
	startswith(alias.alias_name, "alias/aws/")
	alias.key_manager == "CUSTOMER"
	result := {
		"check_id": "kms_no_aws_alias_prefix",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"KMS alias '%s' uses reserved aws/ prefix for a customer-managed key",
			[alias.alias_name],
		),
		"resource": alias.alias_arn,
		"domain": "data_protection",
		"service": "kms",
		"remediation_id": "REM_kms_11",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_s3_rotation — Symmetric keys used for S3 must have rotation enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	key.key_spec == "SYMMETRIC_DEFAULT"
	key.tags.used_for == "s3"
	key.key_rotation_enabled == false
	result := {
		"check_id": "kms_s3_rotation",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"KMS symmetric key '%s' used for S3 does not have rotation enabled",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"remediation_id": "REM_kms_01",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_deletion_alarm — CloudWatch alarm must exist for key deletion/disablement
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	key.key_state == "Enabled"
	not key.deletion_alarm_configured
	result := {
		"check_id": "kms_deletion_alarm",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"KMS key '%s' has no CloudWatch alarm configured for deletion events",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"remediation_id": "REM_kms_13",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_external_material_approval — Key material origin must not be EXTERNAL without approval
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.origin == "EXTERNAL"
	not key.tags.external_key_approved
	result := {
		"check_id": "kms_external_material_approval",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"KMS key '%s' uses EXTERNAL key material without approval tag",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"remediation_id": "REM_kms_14",
	}
}

# ---------------------------------------------------------------------------
# Rule kms_decrypt_grant_approved — Key grants must not grant kms:Decrypt to unapproved services
# ---------------------------------------------------------------------------
violations contains result if {
	some key in input.kms.keys
	key.key_manager == "CUSTOMER"
	some grant in key.grants
	"kms:Decrypt" in grant.operations
	not grant.retiring_principal
	result := {
		"check_id": "kms_decrypt_grant_approved",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"KMS key '%s' has a grant for kms:Decrypt without a retiring principal",
			[key.key_id],
		),
		"resource": key.arn,
		"domain": "data_protection",
		"service": "kms",
		"remediation_id": "REM_kms_15",
	}
}

# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
error contains result if {
	not input.kms
	result := {
		"check_id": "kms_error",
		"status": "error",
		"severity": "critical",
		"reason": "KMS data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
		"service": "kms",
	}
}
