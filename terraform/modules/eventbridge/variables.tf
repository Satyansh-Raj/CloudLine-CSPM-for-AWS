# modules/eventbridge/variables.tf

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

variable "lambda_function_arn" {
  description = "ARN of the CloudLine Lambda function to invoke"
  type        = string
}

variable "lambda_function_name" {
  description = "Name of the CloudLine Lambda function"
  type        = string
}
