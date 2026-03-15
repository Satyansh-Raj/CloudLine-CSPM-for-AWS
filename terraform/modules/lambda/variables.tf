# modules/lambda/variables.tf

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

variable "lambda_role_arn" {
  description = "ARN of the IAM role for the Lambda function"
  type        = string
}

variable "aws_account_id" {
  description = "AWS account ID passed to the Lambda as an environment variable"
  type        = string
}

variable "aws_region" {
  description = "AWS region where the Lambda is deployed"
  type        = string
  default     = "us-east-1"
}

variable "dynamodb_state_table" {
  description = "Name of the DynamoDB violation-state table"
  type        = string
  default     = "cloudline-violation-state"
}

variable "sns_topic_arn" {
  description = "ARN of the CloudLine alerts SNS topic"
  type        = string
}

variable "deployment_zip_path" {
  description = "Local path to the Lambda deployment zip (built by package_lambda.sh)"
  type        = string
  default     = "../deployment.zip"
}
