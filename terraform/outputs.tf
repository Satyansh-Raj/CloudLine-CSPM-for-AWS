# terraform/outputs.tf
# Key outputs for the CloudLine root module.

output "lambda_function_arn" {
  description = "ARN of the CloudLine event-handler Lambda function"
  value       = module.lambda.function_arn
}

output "lambda_function_name" {
  description = "Name of the CloudLine event-handler Lambda function"
  value       = module.lambda.function_name
}

output "dynamodb_state_table" {
  description = "Name of the primary violation-state DynamoDB table"
  value       = module.dynamodb.state_table_name
}

output "sns_topic_arn" {
  description = "ARN of the CloudLine alerts SNS topic"
  value       = module.sns.topic_arn
}

output "cloudtrail_trail_arn" {
  description = "ARN of the CloudLine CloudTrail trail"
  value       = module.cloudtrail.trail_arn
}

output "eventbridge_rule_count" {
  description = "Number of EventBridge rules created (one per AWS service)"
  value       = length(module.eventbridge.rule_arns)
}
