# modules/dynamodb/outputs.tf

output "state_table_name" {
  description = "Name of the violation-state DynamoDB table"
  value       = aws_dynamodb_table.violation_state.name
}

output "state_table_arn" {
  description = "ARN of the violation-state DynamoDB table"
  value       = aws_dynamodb_table.violation_state.arn
}

output "state_table_stream_arn" {
  description = "DynamoDB Stream ARN for the violation-state table"
  value       = aws_dynamodb_table.violation_state.stream_arn
}

output "trends_table_name" {
  description = "Name of the compliance-trends DynamoDB table"
  value       = aws_dynamodb_table.compliance_trends.name
}

output "correlation_table_name" {
  description = "Name of the event-correlation DynamoDB table"
  value       = aws_dynamodb_table.event_correlation.name
}

output "audit_table_name" {
  description = "Name of the remediation-audit DynamoDB table"
  value       = aws_dynamodb_table.remediation_audit.name
}

output "config_table_name" {
  description = "Name of the auto-remediation-config DynamoDB table"
  value       = aws_dynamodb_table.auto_remediation_config.name
}
