# modules/dynamodb/variables.tf

variable "environment" {
  description = "Deployment environment (e.g. production, staging)"
  type        = string
  default     = "production"
}

variable "prefix" {
  description = "Resource name prefix applied to all DynamoDB tables"
  type        = string
  default     = "cloudline"
}
