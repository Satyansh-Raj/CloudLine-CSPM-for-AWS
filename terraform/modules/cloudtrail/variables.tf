# modules/cloudtrail/variables.tf

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
