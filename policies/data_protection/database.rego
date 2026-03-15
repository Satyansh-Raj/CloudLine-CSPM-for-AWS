package aws.data_protection.database

import future.keywords.if
import future.keywords.in

# =============================================================================
# DATABASE POLICY — covers RDS, DynamoDB, and Aurora
# Rule naming: db_01 … db_20
# =============================================================================

# Default database ports that must be changed
default_db_ports := {3306, 5432, 1433, 1521, 5439}

# ---------------------------------------------------------------------------
# Rule db_01 — RDS/Aurora instances must not be publicly accessible
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	db.publicly_accessible == true
	result := {
		"check_id": "db_01",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf("RDS instance '%s' is publicly accessible", [db.db_instance_identifier]),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"cis_aws": ["2.3.2"],
			"nist_800_53": ["AC-3"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_db_01",
	}
}

# ---------------------------------------------------------------------------
# Rule db_02 — RDS/Aurora storage must be encrypted
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	db.storage_encrypted == false
	result := {
		"check_id": "db_02",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf("RDS instance '%s' storage is not encrypted", [db.db_instance_identifier]),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"cis_aws": ["2.3.1"],
			"nist_800_53": ["SC-28"],
			"pci_dss": ["3.5.1"],
			"hipaa": ["164.312(a)(2)(iv)"],
		},
		"remediation_id": "REM_db_02",
	}
}

# ---------------------------------------------------------------------------
# Rule db_03 — RDS backup retention must be >= 7 days
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	db.backup_retention_period < 7
	result := {
		"check_id": "db_03",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"RDS instance '%s' backup retention %d days < 7",
			[db.db_instance_identifier, db.backup_retention_period],
		),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"cis_aws": ["2.3.4"],
			"nist_800_53": ["CP-9"],
			"pci_dss": ["12.3.4"],
		},
		"remediation_id": "REM_db_03",
	}
}

# ---------------------------------------------------------------------------
# Rule db_04 — RDS/Aurora must use Multi-AZ in production
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	db.tags.environment == "production"
	db.multi_az == false
	result := {
		"check_id": "db_04",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Production RDS instance '%s' is not in Multi-AZ deployment",
			[db.db_instance_identifier],
		),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"nist_800_53": ["CP-7"],
		},
		"remediation_id": "REM_db_04",
	}
}

# ---------------------------------------------------------------------------
# Rule db_05 — RDS/Aurora deletion protection must be enabled in production
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	db.tags.environment == "production"
	db.deletion_protection == false
	result := {
		"check_id": "db_05",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Production RDS instance '%s' has deletion protection disabled",
			[db.db_instance_identifier],
		),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"nist_800_53": ["CP-9"],
		},
		"remediation_id": "REM_db_05",
	}
}

# ---------------------------------------------------------------------------
# Rule db_06 — RDS/Aurora IAM database authentication must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	db.iam_database_authentication_enabled == false
	result := {
		"check_id": "db_06",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"RDS instance '%s' does not have IAM database authentication enabled",
			[db.db_instance_identifier],
		),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"cis_aws": ["2.3.5"],
			"nist_800_53": ["IA-2"],
		},
		"remediation_id": "REM_db_06",
	}
}

# ---------------------------------------------------------------------------
# Rule db_07 — RDS/Aurora snapshots must not be publicly accessible
# ---------------------------------------------------------------------------
violations contains result if {
	some snap in input.rds.db_snapshots
	snap.attributes.restore == ["all"]
	result := {
		"check_id": "db_07",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf("RDS snapshot '%s' is publicly accessible", [snap.db_snapshot_identifier]),
		"resource": snap.db_snapshot_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"cis_aws": ["2.3.3"],
			"nist_800_53": ["AC-3"],
			"pci_dss": ["3.3.1"],
		},
		"remediation_id": "REM_db_07",
	}
}

# ---------------------------------------------------------------------------
# Rule db_08 — RDS/Aurora CloudWatch log exports must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	count(db.enabled_cloudwatch_logs_exports) == 0
	result := {
		"check_id": "db_08",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"RDS instance '%s' has no CloudWatch log exports configured",
			[db.db_instance_identifier],
		),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"nist_800_53": ["AU-9"],
			"pci_dss": ["10.5"],
		},
		"remediation_id": "REM_db_08",
	}
}

# ---------------------------------------------------------------------------
# Rule db_09 — RDS auto minor version upgrade must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	db.auto_minor_version_upgrade == false
	result := {
		"check_id": "db_09",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"RDS instance '%s' auto minor version upgrade is disabled",
			[db.db_instance_identifier],
		),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"nist_800_53": ["SI-2"],
			"pci_dss": ["6.3.3"],
		},
		"remediation_id": "REM_db_09",
	}
}

# ---------------------------------------------------------------------------
# Rule db_10 — RDS must not use default database port
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	db.db_instance_port in default_db_ports
	result := {
		"check_id": "db_10",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"RDS instance '%s' uses default port %d",
			[db.db_instance_identifier, db.db_instance_port],
		),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"nist_800_53": ["CM-6"],
		},
		"remediation_id": "REM_db_10",
	}
}

# ---------------------------------------------------------------------------
# Rule db_11 — DynamoDB encryption at rest must use KMS
# ---------------------------------------------------------------------------
violations contains result if {
	some table in input.dynamodb.tables
	table.sse_description.status != "ENABLED"
	result := {
		"check_id": "db_11",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"DynamoDB table '%s' does not have KMS encryption enabled",
			[table.table_name],
		),
		"resource": table.table_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"cis_aws": ["2.5.1"],
			"nist_800_53": ["SC-28"],
			"pci_dss": ["3.5.1"],
			"hipaa": ["164.312(a)(2)(iv)"],
		},
		"remediation_id": "REM_db_11",
	}
}

# ---------------------------------------------------------------------------
# Rule db_12 — DynamoDB Point-in-Time Recovery (PITR) must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some table in input.dynamodb.tables
	table.continuous_backups.point_in_time_recovery_description.point_in_time_recovery_status != "ENABLED"
	result := {
		"check_id": "db_12",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"DynamoDB table '%s' does not have PITR enabled",
			[table.table_name],
		),
		"resource": table.table_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"cis_aws": ["2.5.2"],
			"nist_800_53": ["CP-9"],
			"pci_dss": ["12.3.4"],
		},
		"remediation_id": "REM_db_12",
	}
}

# ---------------------------------------------------------------------------
# Rule db_13 — DynamoDB deletion protection must be enabled for production
# ---------------------------------------------------------------------------
violations contains result if {
	some table in input.dynamodb.tables
	table.tags.environment == "production"
	table.deletion_protection_enabled == false
	result := {
		"check_id": "db_13",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Production DynamoDB table '%s' has deletion protection disabled",
			[table.table_name],
		),
		"resource": table.table_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"nist_800_53": ["CP-9"],
		},
		"remediation_id": "REM_db_13",
	}
}

# ---------------------------------------------------------------------------
# Rule db_14 — DynamoDB resource policy must not allow public access
# ---------------------------------------------------------------------------
violations contains result if {
	some table in input.dynamodb.tables
	some stmt in table.resource_policy.Statement
	stmt.Effect == "Allow"
	stmt.Principal == "*"
	not stmt.Condition
	result := {
		"check_id": "db_14",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"DynamoDB table '%s' resource policy allows public access",
			[table.table_name],
		),
		"resource": table.table_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"nist_800_53": ["AC-3"],
			"pci_dss": ["7.2.1"],
		},
		"remediation_id": "REM_db_14",
	}
}

# ---------------------------------------------------------------------------
# Rule db_15 — DynamoDB auto-scaling must be configured for production tables
# ---------------------------------------------------------------------------
violations contains result if {
	some table in input.dynamodb.tables
	table.tags.environment == "production"
	table.billing_mode == "PROVISIONED"
	table.auto_scaling_enabled == false
	result := {
		"check_id": "db_15",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Production DynamoDB table '%s' uses PROVISIONED mode without auto-scaling",
			[table.table_name],
		),
		"resource": table.table_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"nist_800_53": ["SC-5"],
		},
		"remediation_id": "REM_db_15",
	}
}

# ---------------------------------------------------------------------------
# Rule db_16 — Aurora clusters must not be publicly accessible
# ---------------------------------------------------------------------------
violations contains result if {
	some cluster in input.rds.db_clusters
	cluster.publicly_accessible == true
	result := {
		"check_id": "db_16",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Aurora cluster '%s' is publicly accessible",
			[cluster.db_cluster_identifier],
		),
		"resource": cluster.db_cluster_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"cis_aws": ["2.3.2"],
			"nist_800_53": ["AC-3"],
			"pci_dss": ["1.3.1"],
		},
		"remediation_id": "REM_db_01",
	}
}

# ---------------------------------------------------------------------------
# Rule db_17 — Aurora storage must be encrypted
# ---------------------------------------------------------------------------
violations contains result if {
	some cluster in input.rds.db_clusters
	cluster.storage_encrypted == false
	result := {
		"check_id": "db_17",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Aurora cluster '%s' storage is not encrypted",
			[cluster.db_cluster_identifier],
		),
		"resource": cluster.db_cluster_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"nist_800_53": ["SC-28"],
			"pci_dss": ["3.5.1"],
			"hipaa": ["164.312(a)(2)(iv)"],
		},
		"remediation_id": "REM_db_02",
	}
}

# ---------------------------------------------------------------------------
# Rule db_18 — Aurora deletion protection must be enabled in production
# ---------------------------------------------------------------------------
violations contains result if {
	some cluster in input.rds.db_clusters
	cluster.tags.environment == "production"
	cluster.deletion_protection == false
	result := {
		"check_id": "db_18",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Production Aurora cluster '%s' has deletion protection disabled",
			[cluster.db_cluster_identifier],
		),
		"resource": cluster.db_cluster_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"nist_800_53": ["CP-9"],
		},
		"remediation_id": "REM_db_05",
	}
}

# ---------------------------------------------------------------------------
# Rule db_19 — Aurora Backtrack must be enabled for critical clusters
# ---------------------------------------------------------------------------
violations contains result if {
	some cluster in input.rds.db_clusters
	cluster.tags.data_criticality == "high"
	cluster.backtrack_window == 0
	contains(cluster.engine, "aurora-mysql")
	result := {
		"check_id": "db_19",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Critical Aurora MySQL cluster '%s' does not have Backtrack enabled",
			[cluster.db_cluster_identifier],
		),
		"resource": cluster.db_cluster_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"nist_800_53": ["CP-9"],
		},
		"remediation_id": "REM_db_19",
	}
}

# ---------------------------------------------------------------------------
# Rule db_20 — Aurora IAM authentication must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some cluster in input.rds.db_clusters
	cluster.iam_database_authentication_enabled == false
	result := {
		"check_id": "db_20",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Aurora cluster '%s' does not have IAM database authentication enabled",
			[cluster.db_cluster_identifier],
		),
		"resource": cluster.db_cluster_arn,
		"domain": "data_protection",
		"service": "database",
		"compliance": {
			"cis_aws": ["2.3.5"],
			"nist_800_53": ["IA-2"],
		},
		"remediation_id": "REM_db_06",
	}
}

# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
error contains result if {
	not input.rds
	result := {
		"check_id": "db_00_rds",
		"status": "error",
		"severity": "critical",
		"reason": "RDS/Aurora data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
		"service": "database",
	}
}

error contains result if {
	not input.dynamodb
	result := {
		"check_id": "db_00_dynamodb",
		"status": "error",
		"severity": "critical",
		"reason": "DynamoDB data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
		"service": "database",
	}
}
