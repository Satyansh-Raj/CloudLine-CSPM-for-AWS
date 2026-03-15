# modules/cloudtrail/outputs.tf

output "trail_arn" {
  description = "ARN of the CloudLine CloudTrail trail"
  value       = aws_cloudtrail.cloudline.arn
}

output "trail_name" {
  description = "Name of the CloudLine CloudTrail trail"
  value       = aws_cloudtrail.cloudline.name
}

output "log_group_arn" {
  description = "ARN of the CloudWatch Log Group for CloudTrail"
  value       = aws_cloudwatch_log_group.cloudtrail.arn
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket storing CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.id
}
