package aws.data_protection.storage

import future.keywords.if
import future.keywords.in

# =============================================================================
# STORAGE POLICY — covers EBS and EFS
# Rule naming: storage_01 … storage_20
# =============================================================================

# ---------------------------------------------------------------------------
# Rule storage_ebs_encryption — EBS: all volumes must be encrypted
# ---------------------------------------------------------------------------
violations contains result if {
	some vol in input.ebs.volumes
	vol.encrypted == false
	result := {
		"check_id": "storage_ebs_encryption",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf("EBS volume '%s' is not encrypted", [vol.volume_id]),
		"resource": concat("", ["arn:aws:ec2:", input.region, ":", input.account_id, ":volume/", vol.volume_id]),
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_01",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_ebs_default_encryption — EBS: default encryption must be enabled at account level
# ---------------------------------------------------------------------------
violations contains result if {
	input.ebs.default_encryption_enabled == false
	result := {
		"check_id": "storage_ebs_default_encryption",
		"status": "alarm",
		"severity": "high",
		"reason": "EBS default encryption is not enabled for this region/account",
		"resource": concat("", ["arn:aws:ec2:", input.region, ":", input.account_id, ":volume/*"]),
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_02",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_ebs_snapshot_private — EBS: snapshots must not be publicly shared
# ---------------------------------------------------------------------------
violations contains result if {
	some snap in input.ebs.snapshots
	some perm in snap.create_volume_permissions
	perm.group == "all"
	result := {
		"check_id": "storage_ebs_snapshot_private",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf("EBS snapshot '%s' is publicly accessible", [snap.snapshot_id]),
		"resource": concat("", ["arn:aws:ec2:", input.region, ":", input.account_id, ":snapshot/", snap.snapshot_id]),
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_03",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_ebs_snapshot_encrypted — EBS: snapshots must be encrypted
# ---------------------------------------------------------------------------
violations contains result if {
	some snap in input.ebs.snapshots
	snap.encrypted == false
	snap.owner_id == input.account_id
	result := {
		"check_id": "storage_ebs_snapshot_encrypted",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf("EBS snapshot '%s' is not encrypted", [snap.snapshot_id]),
		"resource": concat("", ["arn:aws:ec2:", input.region, ":", input.account_id, ":snapshot/", snap.snapshot_id]),
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_04",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_ebs_unattached_review — EBS: unattached volumes older than 30 days must be reviewed
# ---------------------------------------------------------------------------
violations contains result if {
	some vol in input.ebs.volumes
	vol.state == "available"
	vol.days_since_detached > 30
	result := {
		"check_id": "storage_ebs_unattached_review",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"EBS volume '%s' has been unattached for %d days",
			[vol.volume_id, vol.days_since_detached],
		),
		"resource": concat("", ["arn:aws:ec2:", input.region, ":", input.account_id, ":volume/", vol.volume_id]),
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_05",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_ebs_snapshot_approved_accts — EBS: snapshots must only be shared with approved accounts
# ---------------------------------------------------------------------------
violations contains result if {
	some snap in input.ebs.snapshots
	snap.owner_id == input.account_id
	some perm in snap.create_volume_permissions
	perm.user_id
	not perm.user_id in input.ebs.approved_sharing_accounts
	result := {
		"check_id": "storage_ebs_snapshot_approved_accts",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"EBS snapshot '%s' is shared with unapproved account '%s'",
			[snap.snapshot_id, perm.user_id],
		),
		"resource": concat("", ["arn:aws:ec2:", input.region, ":", input.account_id, ":snapshot/", snap.snapshot_id]),
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_06",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_ebs_snapshot_lifecycle — EBS: snapshot lifecycle manager must be configured
# ---------------------------------------------------------------------------
violations contains result if {
	input.ebs.lifecycle_policies_count == 0
	result := {
		"check_id": "storage_ebs_snapshot_lifecycle",
		"status": "alarm",
		"severity": "medium",
		"reason": "No EBS snapshot lifecycle policies configured — snapshots may accumulate",
		"resource": concat("", ["arn:aws:ec2:", input.region, ":", input.account_id, ":snapshot/*"]),
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_07",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_ebs_no_magnetic — EBS: production volumes must not use deprecated magnetic type
# ---------------------------------------------------------------------------
violations contains result if {
	some vol in input.ebs.volumes
	vol.tags.environment == "production"
	vol.volume_type == "standard"
	result := {
		"check_id": "storage_ebs_no_magnetic",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Production EBS volume '%s' uses deprecated magnetic (standard) type",
			[vol.volume_id],
		),
		"resource": concat("", ["arn:aws:ec2:", input.region, ":", input.account_id, ":volume/", vol.volume_id]),
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_08",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_ebs_kms_encryption — EBS: sensitive volumes must use customer-managed KMS key
# ---------------------------------------------------------------------------
violations contains result if {
	some vol in input.ebs.volumes
	vol.encrypted == true
	vol.tags.data_classification == "sensitive"
	endswith(vol.kms_key_id, "aws/ebs")
	result := {
		"check_id": "storage_ebs_kms_encryption",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Sensitive EBS volume '%s' uses AWS-managed key instead of CMK",
			[vol.volume_id],
		),
		"resource": concat("", ["arn:aws:ec2:", input.region, ":", input.account_id, ":volume/", vol.volume_id]),
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_09",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_efs_encryption_rest — EFS: file system must have encryption at rest enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some fs in input.efs.file_systems
	fs.encrypted == false
	result := {
		"check_id": "storage_efs_encryption_rest",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf("EFS file system '%s' is not encrypted at rest", [fs.file_system_id]),
		"resource": fs.file_system_arn,
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_10",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_efs_encryption_transit — EFS: encryption in transit must be enforced via TLS mount
# ---------------------------------------------------------------------------
violations contains result if {
	some fs in input.efs.file_systems
	fs.transit_encryption_enabled == false
	result := {
		"check_id": "storage_efs_encryption_transit",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"EFS file system '%s' does not enforce encryption in transit",
			[fs.file_system_id],
		),
		"resource": fs.file_system_arn,
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_11",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_efs_backup — EFS: backup must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some fs in input.efs.file_systems
	fs.backup_policy.status != "ENABLED"
	result := {
		"check_id": "storage_efs_backup",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"EFS file system '%s' does not have AWS Backup enabled",
			[fs.file_system_id],
		),
		"resource": fs.file_system_arn,
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_12",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_efs_no_public_policy — EFS: must not be publicly accessible via resource policy
# ---------------------------------------------------------------------------
violations contains result if {
	some fs in input.efs.file_systems
	some stmt in fs.resource_policy.Statement
	stmt.Effect == "Allow"
	stmt.Principal == "*"
	not stmt.Condition
	result := {
		"check_id": "storage_efs_no_public_policy",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"EFS file system '%s' resource policy allows public access",
			[fs.file_system_id],
		),
		"resource": fs.file_system_arn,
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_13",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_efs_access_point_enforcement — EFS: access points must enforce root directory and user identity
# ---------------------------------------------------------------------------
violations contains result if {
	some ap in input.efs.access_points
	not ap.posix_user.uid
	result := {
		"check_id": "storage_efs_access_point_enforcement",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"EFS access point '%s' does not enforce a POSIX user identity",
			[ap.access_point_id],
		),
		"resource": ap.access_point_arn,
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_14",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_efs_kms_encryption — EFS: must use customer-managed KMS key for sensitive data
# ---------------------------------------------------------------------------
violations contains result if {
	some fs in input.efs.file_systems
	fs.encrypted == true
	fs.tags.data_classification == "sensitive"
	endswith(fs.kms_key_id, "aws/elasticfilesystem")
	result := {
		"check_id": "storage_efs_kms_encryption",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Sensitive EFS file system '%s' uses AWS-managed key instead of CMK",
			[fs.file_system_id],
		),
		"resource": fs.file_system_arn,
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_15",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_efs_private_subnets — EFS: mount targets must be in private subnets only
# ---------------------------------------------------------------------------
violations contains result if {
	some mt in input.efs.mount_targets
	mt.subnet_map_public_ip == true
	result := {
		"check_id": "storage_efs_private_subnets",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"EFS mount target '%s' is in a public subnet",
			[mt.mount_target_id],
		),
		"resource": mt.mount_target_id,
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_16",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_efs_lifecycle — EFS: lifecycle management must be configured
# ---------------------------------------------------------------------------
violations contains result if {
	some fs in input.efs.file_systems
	not fs.lifecycle_policies
	result := {
		"check_id": "storage_efs_lifecycle",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"EFS file system '%s' has no lifecycle management policy configured",
			[fs.file_system_id],
		),
		"resource": fs.file_system_arn,
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_17",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_efs_tags — EFS: file system must have owner and data classification tags
# ---------------------------------------------------------------------------
violations contains result if {
	some fs in input.efs.file_systems
	not fs.tags.owner
	result := {
		"check_id": "storage_efs_tags",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"EFS file system '%s' is missing an owner tag",
			[fs.file_system_id],
		),
		"resource": fs.file_system_arn,
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_18",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_efs_replication — EFS: replication must be configured for critical file systems
# ---------------------------------------------------------------------------
violations contains result if {
	some fs in input.efs.file_systems
	fs.tags.data_criticality == "high"
	count(fs.replication_configuration.destinations) == 0
	result := {
		"check_id": "storage_efs_replication",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"High-criticality EFS file system '%s' has no replication configured",
			[fs.file_system_id],
		),
		"resource": fs.file_system_arn,
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_19",
	}
}

# ---------------------------------------------------------------------------
# Rule storage_efs_throughput_mode — EFS: throughput mode must be set appropriately for production
# ---------------------------------------------------------------------------
violations contains result if {
	some fs in input.efs.file_systems
	fs.tags.environment == "production"
	fs.throughput_mode == "bursting"
	fs.size_in_bytes.value_in_ia > 1073741824
	result := {
		"check_id": "storage_efs_throughput_mode",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"Production EFS file system '%s' uses bursting mode with large data (>1GB infrequent)",
			[fs.file_system_id],
		),
		"resource": fs.file_system_arn,
		"domain": "data_protection",
		"service": "storage",
		"remediation_id": "REM_storage_20",
	}
}

# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
error contains result if {
	not input.ebs
	result := {
		"check_id": "storage_ebs_error",
		"status": "error",
		"severity": "critical",
		"reason": "EBS data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
		"service": "storage",
	}
}

error contains result if {
	not input.efs
	result := {
		"check_id": "storage_efs_error",
		"status": "error",
		"severity": "critical",
		"reason": "EFS data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
		"service": "storage",
	}
}
