# modules/iam/variables.tf

variable "environment" {
  description = "Deployment environment (e.g. production, staging)"
  type        = string
  default     = "production"
}

variable "prefix" {
  description = "Resource name prefix"
  type        = string
  default     = "cloudline"
}

variable "dynamodb_state_table_arn" {
  description = "ARN of the violation-state DynamoDB table"
  type        = string
}

variable "sns_topic_arn" {
  description = "ARN of the CloudLine alerts SNS topic"
  type        = string
}

variable "lambda_function_name" {
  description = "Name of the Lambda function (used for scoping policies)"
  type        = string
  default     = "cloudline-event-handler"
}
