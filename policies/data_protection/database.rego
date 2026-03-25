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
# Rule db_rds_no_public_access — RDS/Aurora instances must not be publicly accessible
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	db.publicly_accessible == true
	result := {
		"check_id": "db_rds_no_public_access",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf("RDS instance '%s' is publicly accessible", [db.db_instance_identifier]),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_01",
	}
}

# ---------------------------------------------------------------------------
# Rule db_rds_encryption — RDS/Aurora storage must be encrypted
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	db.storage_encrypted == false
	result := {
		"check_id": "db_rds_encryption",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf("RDS instance '%s' storage is not encrypted", [db.db_instance_identifier]),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_02",
	}
}

# ---------------------------------------------------------------------------
# Rule db_rds_backup_retention — RDS backup retention must be >= 7 days
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	db.backup_retention_period < 7
	result := {
		"check_id": "db_rds_backup_retention",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"RDS instance '%s' backup retention %d days < 7",
			[db.db_instance_identifier, db.backup_retention_period],
		),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_03",
	}
}

# ---------------------------------------------------------------------------
# Rule db_rds_multi_az — RDS/Aurora must use Multi-AZ in production
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	db.tags.environment == "production"
	db.multi_az == false
	result := {
		"check_id": "db_rds_multi_az",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Production RDS instance '%s' is not in Multi-AZ deployment",
			[db.db_instance_identifier],
		),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_04",
	}
}

# ---------------------------------------------------------------------------
# Rule db_rds_deletion_protection — RDS/Aurora deletion protection must be enabled in production
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	db.tags.environment == "production"
	db.deletion_protection == false
	result := {
		"check_id": "db_rds_deletion_protection",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Production RDS instance '%s' has deletion protection disabled",
			[db.db_instance_identifier],
		),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_05",
	}
}

# ---------------------------------------------------------------------------
# Rule db_rds_iam_auth — RDS/Aurora IAM database authentication must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	db.iam_database_authentication_enabled == false
	result := {
		"check_id": "db_rds_iam_auth",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"RDS instance '%s' does not have IAM database authentication enabled",
			[db.db_instance_identifier],
		),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_06",
	}
}

# ---------------------------------------------------------------------------
# Rule db_rds_snapshot_private — RDS/Aurora snapshots must not be publicly accessible
# ---------------------------------------------------------------------------
violations contains result if {
	some snap in input.rds.db_snapshots
	snap.attributes.restore == ["all"]
	result := {
		"check_id": "db_rds_snapshot_private",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf("RDS snapshot '%s' is publicly accessible", [snap.db_snapshot_identifier]),
		"resource": snap.db_snapshot_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_07",
	}
}

# ---------------------------------------------------------------------------
# Rule db_rds_log_exports — RDS/Aurora CloudWatch log exports must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	count(db.enabled_cloudwatch_logs_exports) == 0
	result := {
		"check_id": "db_rds_log_exports",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"RDS instance '%s' has no CloudWatch log exports configured",
			[db.db_instance_identifier],
		),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_08",
	}
}

# ---------------------------------------------------------------------------
# Rule db_rds_auto_minor_upgrade — RDS auto minor version upgrade must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	db.auto_minor_version_upgrade == false
	result := {
		"check_id": "db_rds_auto_minor_upgrade",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"RDS instance '%s' auto minor version upgrade is disabled",
			[db.db_instance_identifier],
		),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_09",
	}
}

# ---------------------------------------------------------------------------
# Rule db_rds_no_default_port — RDS must not use default database port
# ---------------------------------------------------------------------------
violations contains result if {
	some db in input.rds.db_instances
	db.db_instance_port in default_db_ports
	result := {
		"check_id": "db_rds_no_default_port",
		"status": "alarm",
		"severity": "low",
		"reason": sprintf(
			"RDS instance '%s' uses default port %d",
			[db.db_instance_identifier, db.db_instance_port],
		),
		"resource": db.db_instance_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_10",
	}
}

# ---------------------------------------------------------------------------
# Rule db_dynamodb_kms_encryption — DynamoDB encryption at rest must use KMS
# ---------------------------------------------------------------------------
violations contains result if {
	some table in input.dynamodb.tables
	table.sse_description.status != "ENABLED"
	result := {
		"check_id": "db_dynamodb_kms_encryption",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"DynamoDB table '%s' does not have KMS encryption enabled",
			[table.table_name],
		),
		"resource": table.table_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_11",
	}
}

# ---------------------------------------------------------------------------
# Rule db_dynamodb_pitr — DynamoDB Point-in-Time Recovery (PITR) must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some table in input.dynamodb.tables
	table.continuous_backups.point_in_time_recovery_description.point_in_time_recovery_status != "ENABLED"
	result := {
		"check_id": "db_dynamodb_pitr",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"DynamoDB table '%s' does not have PITR enabled",
			[table.table_name],
		),
		"resource": table.table_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_12",
	}
}

# ---------------------------------------------------------------------------
# Rule db_dynamodb_deletion_protection — DynamoDB deletion protection must be enabled for production
# ---------------------------------------------------------------------------
violations contains result if {
	some table in input.dynamodb.tables
	table.tags.environment == "production"
	table.deletion_protection_enabled == false
	result := {
		"check_id": "db_dynamodb_deletion_protection",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Production DynamoDB table '%s' has deletion protection disabled",
			[table.table_name],
		),
		"resource": table.table_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_13",
	}
}

# ---------------------------------------------------------------------------
# Rule db_dynamodb_no_public_policy — DynamoDB resource policy must not allow public access
# ---------------------------------------------------------------------------
violations contains result if {
	some table in input.dynamodb.tables
	some stmt in table.resource_policy.Statement
	stmt.Effect == "Allow"
	stmt.Principal == "*"
	not stmt.Condition
	result := {
		"check_id": "db_dynamodb_no_public_policy",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"DynamoDB table '%s' resource policy allows public access",
			[table.table_name],
		),
		"resource": table.table_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_14",
	}
}

# ---------------------------------------------------------------------------
# Rule db_dynamodb_auto_scaling — DynamoDB auto-scaling must be configured for production tables
# ---------------------------------------------------------------------------
violations contains result if {
	some table in input.dynamodb.tables
	table.tags.environment == "production"
	table.billing_mode == "PROVISIONED"
	table.auto_scaling_enabled == false
	result := {
		"check_id": "db_dynamodb_auto_scaling",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Production DynamoDB table '%s' uses PROVISIONED mode without auto-scaling",
			[table.table_name],
		),
		"resource": table.table_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_15",
	}
}

# ---------------------------------------------------------------------------
# Rule db_aurora_no_public_access — Aurora clusters must not be publicly accessible
# ---------------------------------------------------------------------------
violations contains result if {
	some cluster in input.rds.db_clusters
	cluster.publicly_accessible == true
	result := {
		"check_id": "db_aurora_no_public_access",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Aurora cluster '%s' is publicly accessible",
			[cluster.db_cluster_identifier],
		),
		"resource": cluster.db_cluster_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_01",
	}
}

# ---------------------------------------------------------------------------
# Rule db_aurora_encryption — Aurora storage must be encrypted
# ---------------------------------------------------------------------------
violations contains result if {
	some cluster in input.rds.db_clusters
	cluster.storage_encrypted == false
	result := {
		"check_id": "db_aurora_encryption",
		"status": "alarm",
		"severity": "critical",
		"reason": sprintf(
			"Aurora cluster '%s' storage is not encrypted",
			[cluster.db_cluster_identifier],
		),
		"resource": cluster.db_cluster_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_02",
	}
}

# ---------------------------------------------------------------------------
# Rule db_aurora_deletion_protection — Aurora deletion protection must be enabled in production
# ---------------------------------------------------------------------------
violations contains result if {
	some cluster in input.rds.db_clusters
	cluster.tags.environment == "production"
	cluster.deletion_protection == false
	result := {
		"check_id": "db_aurora_deletion_protection",
		"status": "alarm",
		"severity": "high",
		"reason": sprintf(
			"Production Aurora cluster '%s' has deletion protection disabled",
			[cluster.db_cluster_identifier],
		),
		"resource": cluster.db_cluster_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_05",
	}
}

# ---------------------------------------------------------------------------
# Rule db_aurora_backtrack — Aurora Backtrack must be enabled for critical clusters
# ---------------------------------------------------------------------------
violations contains result if {
	some cluster in input.rds.db_clusters
	cluster.tags.data_criticality == "high"
	cluster.backtrack_window == 0
	contains(cluster.engine, "aurora-mysql")
	result := {
		"check_id": "db_aurora_backtrack",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Critical Aurora MySQL cluster '%s' does not have Backtrack enabled",
			[cluster.db_cluster_identifier],
		),
		"resource": cluster.db_cluster_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_19",
	}
}

# ---------------------------------------------------------------------------
# Rule db_aurora_iam_auth — Aurora IAM authentication must be enabled
# ---------------------------------------------------------------------------
violations contains result if {
	some cluster in input.rds.db_clusters
	cluster.iam_database_authentication_enabled == false
	result := {
		"check_id": "db_aurora_iam_auth",
		"status": "alarm",
		"severity": "medium",
		"reason": sprintf(
			"Aurora cluster '%s' does not have IAM database authentication enabled",
			[cluster.db_cluster_identifier],
		),
		"resource": cluster.db_cluster_arn,
		"domain": "data_protection",
		"service": "database",
		"remediation_id": "REM_db_06",
	}
}

# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
error contains result if {
	not input.rds
	result := {
		"check_id": "db_rds_error",
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
		"check_id": "db_dynamodb_error",
		"status": "error",
		"severity": "critical",
		"reason": "DynamoDB data missing from input — collector may have failed",
		"resource": "",
		"domain": "data_protection",
		"service": "database",
	}
}
