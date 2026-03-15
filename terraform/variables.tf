# terraform/variables.tf

variable "aws_account_id" {
  description = "Your 12-digit AWS account ID."
  type        = string
}

variable "aws_region" {
  description = "AWS region to deploy CloudLine into."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment label used in resource names (e.g. production, dev)."
  type        = string
  default     = "production"
}

variable "prefix" {
  description = "Short prefix for all resource names. Change if deploying multiple instances."
  type        = string
  default     = "cloudline"
}

variable "alert_emails" {
  description = "List of email addresses for security alert notifications. Leave empty to skip."
  type        = list(string)
  default     = []
}

variable "alert_phone" {
  description = "Phone number in E.164 format for SMS alerts (e.g. +919876543210). Leave empty to skip."
  type        = string
  default     = ""
}
