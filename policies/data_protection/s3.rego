package aws.data_protection.s3

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Rule s3_01 — Block public access: BlockPublicAcls must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.public_access_block.block_public_acls == false
	result := {
		"check_id": "s3_01",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"S3 bucket '%s' does not block public ACLs",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"cis_aws": ["2.1.5"],
			"nist_800_53": ["AC-3"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_s3_01",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_02 — Block public access: IgnorePublicAcls must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.public_access_block.ignore_public_acls == false
	result := {
		"check_id": "s3_02",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"S3 bucket '%s' does not ignore public ACLs",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"cis_aws": ["2.1.5"],
			"nist_800_53": ["AC-3"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_s3_01",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_03 — Block public access: BlockPublicPolicy must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.public_access_block.block_public_policy == false
	result := {
		"check_id": "s3_03",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"S3 bucket '%s' does not block public policies",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"cis_aws": ["2.1.5"],
			"nist_800_53": ["AC-3"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_s3_01",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_04 — Block public access: RestrictPublicBuckets must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.public_access_block.restrict_public_buckets == false
	result := {
		"check_id": "s3_04",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"S3 bucket '%s' does not restrict public buckets",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"cis_aws": ["2.1.5"],
			"nist_800_53": ["AC-3"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_s3_01",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_05 — Server-side encryption must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	not bucket.encryption.rules
	result := {
		"check_id": "s3_05",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"S3 bucket '%s' does not have server-side encryption enabled",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"cis_aws": ["2.1.1"],
			"nist_800_53": ["SC-28"],
			"pci_dss": ["3.5.1"],
			"hipaa": ["164.312(a)(2)(iv)"],
		},
		"remediation_id": "REM_s3_05",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_06 — Versioning must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.versioning.status != "Enabled"
	bucket.tags.data_classification == "sensitive"
	result := {
		"check_id": "s3_06",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Sensitive S3 bucket '%s' does not have versioning enabled",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"cis_aws": ["2.1.3"],
			"nist_800_53": ["CP-9"],
			"pci_dss": ["12.3.4"],
		},
		"remediation_id": "REM_s3_06",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_07 — MFA delete must be enabled on sensitive buckets
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.tags.data_classification == "sensitive"
	bucket.versioning.mfa_delete != "Enabled"
	result := {
		"check_id": "s3_07",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Sensitive S3 bucket '%s' does not have MFA delete enabled",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"cis_aws": ["2.1.3"],
			"nist_800_53": ["MP-6"],
		},
		"remediation_id": "REM_s3_07",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_08 — Server access logging must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	not bucket.logging.target_bucket
	bucket.tags.environment == "production"
	result := {
		"check_id": "s3_08",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Production S3 bucket '%s' does not have access logging enabled",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"cis_aws": ["3.6"],
			"nist_800_53": ["AU-12"],
			"pci_dss": ["10.2"],
		},
		"remediation_id": "REM_s3_08",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_09 — Bucket policy must deny HTTP (require SSL/TLS)
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	not bucket.policy_denies_http
	result := {
		"check_id": "s3_09",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"S3 bucket '%s' policy does not deny unencrypted (HTTP) access",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"cis_aws": ["2.1.2"],
			"nist_800_53": ["SC-8"],
			"pci_dss": ["4.2.1"],
		},
		"remediation_id": "REM_s3_09",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_10 — No bucket ACL must grant public-read access
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	some grant in bucket.acl.grants
	grant.grantee.uri == "http://acs.amazonaws.com/groups/global/AllUsers"
	grant.permission == "READ"
	result := {
		"check_id": "s3_10",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"S3 bucket '%s' ACL grants public READ access",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"cis_aws": ["2.1.5"],
			"nist_800_53": ["AC-3"],
			"pci_dss": ["3.3.1"],
		},
		"remediation_id": "REM_s3_01",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_11 — No bucket ACL must grant public-write access
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	some grant in bucket.acl.grants
	grant.grantee.uri == "http://acs.amazonaws.com/groups/global/AllUsers"
	grant.permission == "WRITE"
	result := {
		"check_id": "s3_11",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"S3 bucket '%s' ACL grants public WRITE access",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"cis_aws": ["2.1.5"],
			"nist_800_53": ["AC-3"],
			"pci_dss": ["3.3.1"],
		},
		"remediation_id": "REM_s3_01",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_12 — Lifecycle policy must be configured
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.tags.environment == "production"
	not bucket.lifecycle_rules
	result := {
		"check_id": "s3_12",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Production S3 bucket '%s' has no lifecycle policy configured",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"nist_800_53": ["SI-12"],
		},
		"remediation_id": "REM_s3_12",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_13 — Object Lock must be enabled for compliance buckets
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.tags.compliance_required == "true"
	bucket.object_lock.enabled != true
	result := {
		"check_id": "s3_13",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Compliance-required S3 bucket '%s' does not have Object Lock enabled",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"nist_800_53": ["AU-9"],
			"pci_dss": ["10.5"],
			"hipaa": ["164.312(c)(1)"],
		},
		"remediation_id": "REM_s3_13",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_14 — CORS must not allow all origins (*)
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	some rule in bucket.cors_rules
	"*" in rule.allowed_origins
	result := {
		"check_id": "s3_14",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"S3 bucket '%s' CORS rule allows all origins (*)",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"nist_800_53": ["SI-10"],
			"owasp": ["A05:2021"],
		},
		"remediation_id": "REM_s3_14",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_15 — KMS encryption must be used for sensitive data buckets
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.tags.data_classification == "sensitive"
	some rule in bucket.encryption.rules
	rule.apply_server_side_encryption_by_default.sse_algorithm != "aws:kms"
	result := {
		"check_id": "s3_15",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Sensitive S3 bucket '%s' uses AES-256 instead of KMS encryption",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"nist_800_53": ["SC-28(1)"],
			"pci_dss": ["3.5.1"],
			"hipaa": ["164.312(a)(2)(iv)"],
		},
		"remediation_id": "REM_s3_15",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_16 — Bucket policy must not allow Principal: * without conditions
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	some stmt in bucket.policy.Statement
	stmt.Effect == "Allow"
	stmt.Principal == "*"
	not stmt.Condition
	result := {
		"check_id": "s3_16",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"S3 bucket '%s' policy allows public access (Principal: * with no Condition)",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"cis_aws": ["2.1.5"],
			"nist_800_53": ["AC-3"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_s3_01",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_17 — Replication must be configured for critical data buckets
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.tags.data_criticality == "high"
	not bucket.replication_configuration.rules
	result := {
		"check_id": "s3_17",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"High-criticality S3 bucket '%s' has no replication configured",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"nist_800_53": ["CP-9"],
			"hipaa": ["164.308(a)(7)"],
		},
		"remediation_id": "REM_s3_17",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_18 — Event notifications must be configured on security-critical buckets
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.tags.security_monitoring == "required"
	not bucket.notification_configuration
	result := {
		"check_id": "s3_18",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Security-monitored S3 bucket '%s' has no event notifications configured",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"nist_800_53": ["AU-12"],
		},
		"remediation_id": "REM_s3_18",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_19 — Cross-account access must include aws:PrincipalOrgID condition
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	some stmt in bucket.policy.Statement
	stmt.Effect == "Allow"
	stmt.Principal.AWS
	not startswith(stmt.Principal.AWS, concat("", ["arn:aws:iam::", input.account_id]))
	not stmt.Condition["aws:PrincipalOrgID"]
	result := {
		"check_id": "s3_19",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"S3 bucket '%s' allows cross-account access without org ID condition",
			[bucket.name],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"nist_800_53": ["AC-3"],
			"pci_dss": ["7.2.1"],
		},
		"remediation_id": "REM_s3_19",
	}
}

# ---------------------------------------------------------------------------
# Rule s3_20 — Intelligent-Tiering must be enabled for large data buckets
# ---------------------------------------------------------------------------
violations contains result if {
	some bucket in input.s3.buckets
	bucket.size_gb > 100
	not bucket.intelligent_tiering_enabled
	result := {
		"check_id": "s3_20",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"S3 bucket '%s' (%d GB) has no Intelligent-Tiering configured",
			[bucket.name, bucket.size_gb],
		),
		"resource": concat("", ["arn:aws:s3:::", bucket.name]),
		"domain": "data_protection",
		"service": "s3",
		"compliance": {
			"nist_800_53": ["SI-12"],
		},
		"remediation_id": "REM_s3_20",
	}
}

# ---------------------------------------------------------------------------
# Error handler
# ---------------------------------------------------------------------------
error contains result if {
	not input.s3
	result := {
		"check_id": "s3_00",
		"status": "error",
		"severity": "critical",
		"reason": "S3 data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
		"service": "s3",
	}
}
