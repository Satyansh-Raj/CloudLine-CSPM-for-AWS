# modules/sns/variables.tf

variable "environment" {
  description = "Deployment environment (e.g. production, staging)"
  type        = string
  default     = "production"
}

variable "alert_emails" {
  description = "List of email addresses to subscribe to alert notifications. Leave empty to skip."
  type        = list(string)
  default     = []
}

variable "alert_phone" {
  description = "Phone number in E.164 format for SMS alerts (e.g. +919876543210). Leave empty to skip."
  type        = string
  default     = ""
}

variable "prefix" {
  description = "Resource name prefix"
  type        = string
  default     = "cloudline"
}
