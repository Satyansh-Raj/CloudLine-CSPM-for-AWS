# modules/iam/outputs.tf

output "lambda_role_arn" {
  description = "ARN of the CloudLine Lambda execution role"
  value       = aws_iam_role.cloudline_lambda.arn
}

output "lambda_role_name" {
  description = "Name of the CloudLine Lambda execution role"
  value       = aws_iam_role.cloudline_lambda.name
}

output "scanner_user_name" {
  description = "Name of the CloudLine scanner IAM user"
  value       = aws_iam_user.cloudline_scanner.name
}

output "scanner_user_arn" {
  description = "ARN of the CloudLine scanner IAM user"
  value       = aws_iam_user.cloudline_scanner.arn
}
