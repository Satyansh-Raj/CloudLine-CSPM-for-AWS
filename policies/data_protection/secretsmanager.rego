package aws.data_protection.secretsmanager

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Rule secretsmanager_01 — Automatic rotation must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some secret in input.secrets_manager.secrets
	secret.rotation_enabled == false
	result := {
		"check_id": "secretsmanager_01",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Secrets Manager secret '%s' does not have automatic rotation enabled",
			[secret.name],
		),
		"resource": secret.arn,
		"domain": "data_protection",
		"service": "secretsmanager",
		"compliance": {
			"cis_aws": ["2.1.4"],
			"nist_800_53": ["IA-5(1)"],
			"pci_dss": ["8.3.9"],
		},
		"remediation_id": "REM_secretsmanager_01",
	}
}

# ---------------------------------------------------------------------------
# Rule secretsmanager_02 — Rotation interval must be <= 90 days
# ---------------------------------------------------------------------------
violations contains result if {
	some secret in input.secrets_manager.secrets
	secret.rotation_enabled == true
	secret.rotation_rules.automatically_after_days > 90
	result := {
		"check_id": "secretsmanager_02",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Secret '%s' rotation interval is %d days (max: 90)",
			[secret.name, secret.rotation_rules.automatically_after_days],
		),
		"resource": secret.arn,
		"domain": "data_protection",
		"service": "secretsmanager",
		"compliance": {
			"nist_800_53": ["IA-5(1)"],
			"pci_dss": ["8.3.9"],
		},
		"remediation_id": "REM_secretsmanager_02",
	}
}

# ---------------------------------------------------------------------------
# Rule secretsmanager_03 — Secret must not allow public access via resource policy
# ---------------------------------------------------------------------------
violations contains result if {
	some secret in input.secrets_manager.secrets
	some stmt in secret.resource_policy.Statement
	stmt.Effect == "Allow"
	stmt.Principal == "*"
	not stmt.Condition
	result := {
		"check_id": "secretsmanager_03",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Secrets Manager secret '%s' resource policy allows public access",
			[secret.name],
		),
		"resource": secret.arn,
		"domain": "data_protection",
		"service": "secretsmanager",
		"compliance": {
			"nist_800_53": ["AC-3"],
			"pci_dss": ["3.3.1"],
		},
		"remediation_id": "REM_secretsmanager_03",
	}
}

# ---------------------------------------------------------------------------
# Rule secretsmanager_04 — Secret must be encrypted with customer-managed KMS key
# ---------------------------------------------------------------------------
violations contains result if {
	some secret in input.secrets_manager.secrets
	secret.tags.data_classification == "sensitive"
	endswith(secret.kms_key_id, "aws/secretsmanager")
	result := {
		"check_id": "secretsmanager_04",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Sensitive secret '%s' uses AWS-managed key instead of CMK",
			[secret.name],
		),
		"resource": secret.arn,
		"domain": "data_protection",
		"service": "secretsmanager",
		"compliance": {
			"nist_800_53": ["SC-28(1)"],
			"hipaa": ["164.312(a)(2)(iv)"],
		},
		"remediation_id": "REM_secretsmanager_04",
	}
}

# ---------------------------------------------------------------------------
# Rule secretsmanager_05 — Secret must not be unused for > 90 days
# ---------------------------------------------------------------------------
violations contains result if {
	some secret in input.secrets_manager.secrets
	secret.days_since_last_accessed > 90
	result := {
		"check_id": "secretsmanager_05",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Secret '%s' has not been accessed in %d days — may be stale",
			[secret.name, secret.days_since_last_accessed],
		),
		"resource": secret.arn,
		"domain": "data_protection",
		"service": "secretsmanager",
		"compliance": {
			"nist_800_53": ["AC-2(3)"],
		},
		"remediation_id": "REM_secretsmanager_05",
	}
}

# ---------------------------------------------------------------------------
# Rule secretsmanager_06 — Secret must not have cross-account access without
#                          org ID condition
# ---------------------------------------------------------------------------
violations contains result if {
	some secret in input.secrets_manager.secrets
	some stmt in secret.resource_policy.Statement
	stmt.Effect == "Allow"
	stmt.Principal.AWS
	not startswith(stmt.Principal.AWS, concat("", ["arn:aws:iam::", input.account_id]))
	not stmt.Condition["aws:PrincipalOrgID"]
	result := {
		"check_id": "secretsmanager_06",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Secret '%s' allows cross-account access without org ID condition",
			[secret.name],
		),
		"resource": secret.arn,
		"domain": "data_protection",
		"service": "secretsmanager",
		"compliance": {
			"nist_800_53": ["AC-3"],
		},
		"remediation_id": "REM_secretsmanager_06",
	}
}

# ---------------------------------------------------------------------------
# Rule secretsmanager_07 — Secret must not be scheduled for deletion without approval
# ---------------------------------------------------------------------------
violations contains result if {
	some secret in input.secrets_manager.secrets
	secret.deleted_date != null
	not secret.tags.deletion_approved
	result := {
		"check_id": "secretsmanager_07",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Secret '%s' is scheduled for deletion without deletion_approved tag",
			[secret.name],
		),
		"resource": secret.arn,
		"domain": "data_protection",
		"service": "secretsmanager",
		"compliance": {
			"nist_800_53": ["CP-9"],
		},
		"remediation_id": "REM_secretsmanager_07",
	}
}

# ---------------------------------------------------------------------------
# Rule secretsmanager_08 — Secret must have owner and purpose tags
# ---------------------------------------------------------------------------
violations contains result if {
	some secret in input.secrets_manager.secrets
	not secret.tags.owner
	result := {
		"check_id": "secretsmanager_08",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Secret '%s' is missing an owner tag",
			[secret.name],
		),
		"resource": secret.arn,
		"domain": "data_protection",
		"service": "secretsmanager",
		"compliance": {
			"nist_800_53": ["CM-8"],
		},
		"remediation_id": "REM_secretsmanager_08",
	}
}

# ---------------------------------------------------------------------------
# Rule secretsmanager_09 — Secret name must not reveal its purpose or type
# ---------------------------------------------------------------------------
sensitive_name_patterns := {
	"password", "passwd", "apikey", "api_key",
	"private_key", "privatekey", "db_pass",
}

violations contains result if {
	some secret in input.secrets_manager.secrets
	lower_name := lower(secret.name)
	some pattern in sensitive_name_patterns
	contains(lower_name, pattern)
	result := {
		"check_id": "secretsmanager_09",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Secret name '%s' reveals sensitive information in its name",
			[secret.name],
		),
		"resource": secret.arn,
		"domain": "data_protection",
		"service": "secretsmanager",
		"compliance": {
			"nist_800_53": ["IA-5"],
		},
		"remediation_id": "REM_secretsmanager_09",
	}
}

# ---------------------------------------------------------------------------
# Rule secretsmanager_10 — Rotation function must be validated (not orphaned)
# ---------------------------------------------------------------------------
violations contains result if {
	some secret in input.secrets_manager.secrets
	secret.rotation_enabled == true
	secret.rotation_lambda_arn
	secret.rotation_function_exists == false
	result := {
		"check_id": "secretsmanager_10",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Secret '%s' rotation Lambda '%s' does not exist or is unreachable",
			[secret.name, secret.rotation_lambda_arn],
		),
		"resource": secret.arn,
		"domain": "data_protection",
		"service": "secretsmanager",
		"compliance": {
			"nist_800_53": ["IA-5(1)"],
		},
		"remediation_id": "REM_secretsmanager_10",
	}
}

# ---------------------------------------------------------------------------
# Rule secretsmanager_11 — Secret description must not be empty
# ---------------------------------------------------------------------------
violations contains result if {
	some secret in input.secrets_manager.secrets
	secret.description == ""
	result := {
		"check_id": "secretsmanager_11",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Secret '%s' has no description — purpose is undocumented",
			[secret.name],
		),
		"resource": secret.arn,
		"domain": "data_protection",
		"service": "secretsmanager",
		"compliance": {
			"nist_800_53": ["CM-8"],
		},
		"remediation_id": "REM_secretsmanager_11",
	}
}

# ---------------------------------------------------------------------------
# Rule secretsmanager_12 — Multi-region replication for critical secrets
# ---------------------------------------------------------------------------
violations contains result if {
	some secret in input.secrets_manager.secrets
	secret.tags.data_criticality == "high"
	count(secret.replication_status) == 0
	result := {
		"check_id": "secretsmanager_12",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"High-criticality secret '%s' has no multi-region replication configured",
			[secret.name],
		),
		"resource": secret.arn,
		"domain": "data_protection",
		"service": "secretsmanager",
		"compliance": {
			"nist_800_53": ["CP-9"],
		},
		"remediation_id": "REM_secretsmanager_12",
	}
}

# ---------------------------------------------------------------------------
# Rule secretsmanager_13 — Wildcard principal in secret policy must be blocked
# ---------------------------------------------------------------------------
violations contains result if {
	some secret in input.secrets_manager.secrets
	some stmt in secret.resource_policy.Statement
	stmt.Effect == "Allow"
	stmt.Principal == "*"
	result := {
		"check_id": "secretsmanager_13",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Secret '%s' policy has wildcard principal (allows any AWS principal)",
			[secret.name],
		),
		"resource": secret.arn,
		"domain": "data_protection",
		"service": "secretsmanager",
		"compliance": {
			"nist_800_53": ["AC-3"],
			"pci_dss": ["3.3.1"],
		},
		"remediation_id": "REM_secretsmanager_03",
	}
}

# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
error contains result if {
	not input.secrets_manager
	result := {
		"check_id": "secretsmanager_00",
		"status": "error",
		"severity": "critical",
		"reason": "Secrets Manager data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
		"service": "secretsmanager",
	}
}
