package aws.data_protection.s3

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Rule s3_block_public_acls — Block public access: BlockPublicAcls must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.public_access_block.block_public_acls == false
	result := {
		"check_id": "s3_block_public_acls",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"S3 bucket '%s' does not block public ACLs",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_01",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_ignore_public_acls — Block public access: IgnorePublicAcls must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.public_access_block.ignore_public_acls == false
	result := {
		"check_id": "s3_ignore_public_acls",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"S3 bucket '%s' does not ignore public ACLs",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_01",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_block_public_policy — Block public access: BlockPublicPolicy must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.public_access_block.block_public_policy == false
	result := {
		"check_id": "s3_block_public_policy",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"S3 bucket '%s' does not block public policies",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_01",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_restrict_public_buckets — Block public access: RestrictPublicBuckets must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.public_access_block.restrict_public_buckets == false
	result := {
		"check_id": "s3_restrict_public_buckets",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"S3 bucket '%s' does not restrict public buckets",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_01",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_encryption — Server-side encryption must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	not bucket.encryption.rules
	result := {
		"check_id": "s3_encryption",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"S3 bucket '%s' does not have server-side encryption enabled",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_05",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_versioning — Versioning must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.versioning.status != "Enabled"
	bucket.tags.data_classification == "sensitive"
	result := {
		"check_id": "s3_versioning",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Sensitive S3 bucket '%s' does not have versioning enabled",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_06",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_mfa_delete — MFA delete must be enabled on sensitive buckets
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.tags.data_classification == "sensitive"
	bucket.versioning.mfa_delete != "Enabled"
	result := {
		"check_id": "s3_mfa_delete",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Sensitive S3 bucket '%s' does not have MFA delete enabled",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_07",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_access_logging — Server access logging must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	not bucket.logging.target_bucket
	bucket.tags.environment == "production"
	result := {
		"check_id": "s3_access_logging",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Production S3 bucket '%s' does not have access logging enabled",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_08",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_deny_http — Bucket policy must deny HTTP (require SSL/TLS)
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	not bucket.policy_denies_http
	result := {
		"check_id": "s3_deny_http",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"S3 bucket '%s' policy does not deny unencrypted (HTTP) access",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_09",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_no_public_read_acl — No bucket ACL must grant public-read access
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	some grant in bucket.acl.grants
	grant.grantee.uri == "http://acs.amazonaws.com/groups/global/AllUsers"
	grant.permission == "READ"
	result := {
		"check_id": "s3_no_public_read_acl",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"S3 bucket '%s' ACL grants public READ access",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_01",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_no_public_write_acl — No bucket ACL must grant public-write access
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	some grant in bucket.acl.grants
	grant.grantee.uri == "http://acs.amazonaws.com/groups/global/AllUsers"
	grant.permission == "WRITE"
	result := {
		"check_id": "s3_no_public_write_acl",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"S3 bucket '%s' ACL grants public WRITE access",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_01",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_lifecycle_policy — Lifecycle policy must be configured
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.tags.environment == "production"
	not bucket.lifecycle_rules
	result := {
		"check_id": "s3_lifecycle_policy",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Production S3 bucket '%s' has no lifecycle policy configured",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_12",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_object_lock — Object Lock must be enabled for compliance buckets
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.tags.compliance_required == "true"
	bucket.object_lock.enabled != true
	result := {
		"check_id": "s3_object_lock",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Compliance-required S3 bucket '%s' does not have Object Lock enabled",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_13",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_cors_wildcard — CORS must not allow all origins (*)
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	some rule in bucket.cors_rules
	"*" in rule.allowed_origins
	result := {
		"check_id": "s3_cors_wildcard",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"S3 bucket '%s' CORS rule allows all origins (*)",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_14",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_kms_encryption — KMS encryption must be used for sensitive data buckets
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.tags.data_classification == "sensitive"
	some rule in bucket.encryption.rules
	rule.apply_server_side_encryption_by_default.sse_algorithm != "aws:kms"
	result := {
		"check_id": "s3_kms_encryption",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Sensitive S3 bucket '%s' uses AES-256 instead of KMS encryption",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_15",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_no_public_principal — Bucket policy must not allow Principal: * without conditions
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	some stmt in bucket.policy.Statement
	stmt.Effect == "Allow"
	stmt.Principal == "*"
	not stmt.Condition
	result := {
		"check_id": "s3_no_public_principal",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"S3 bucket '%s' policy allows public access (Principal: * with no Condition)",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_01",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_replication — Replication must be configured for critical data buckets
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.tags.data_criticality == "high"
	not bucket.replication_configuration.rules
	result := {
		"check_id": "s3_replication",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"High-criticality S3 bucket '%s' has no replication configured",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_17",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_event_notifications — Event notifications must be configured on security-critical buckets
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.tags.security_monitoring == "required"
	not bucket.notification_configuration
	result := {
		"check_id": "s3_event_notifications",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Security-monitored S3 bucket '%s' has no event notifications configured",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_18",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_cross_account_org_id — Cross-account access must include aws:PrincipalOrgID condition
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	some stmt in bucket.policy.Statement
	stmt.Effect == "Allow"
	stmt.Principal.AWS
	not startswith(stmt.Principal.AWS, concat("", ["arn:aws:iam::", input.account_id]))
	not stmt.Condition["aws:PrincipalOrgID"]
	result := {
		"check_id": "s3_cross_account_org_id",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"S3 bucket '%s' allows cross-account access without org ID condition",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_19",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_intelligent_tiering — Intelligent-Tiering must be enabled for large data buckets
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.size_gb > 100
	not bucket.intelligent_tiering_enabled
	result := {
		"check_id": "s3_intelligent_tiering",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"S3 bucket '%s' (%d GB) has no Intelligent-Tiering configured",
			[bucket.name, bucket.size_gb],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"remediation_id": "REM_s3_20",
	}
}

# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
error contains result if {
	not input.s3
	result := {
		"check_id": "s3_error",
		"status": "error",
		"severity": "critical",
		"reason": "S3 data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
		"service": "s3",
	}
}
