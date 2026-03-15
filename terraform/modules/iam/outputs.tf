# modules/iam/outputs.tf

output "lambda_role_arn" {
  description = "ARN of the CloudLine Lambda execution role"
  value       = aws_iam_role.cloudline_lambda.arn
}

output "lambda_role_name" {
  description = "Name of the CloudLine Lambda execution role"
  value       = aws_iam_role.cloudline_lambda.name
}
