# modules/sns/outputs.tf

output "topic_arn" {
  description = "ARN of the CloudLine alerts SNS topic"
  value       = aws_sns_topic.cloudline_alerts.arn
}

output "topic_name" {
  description = "Name of the CloudLine alerts SNS topic"
  value       = aws_sns_topic.cloudline_alerts.name
}
