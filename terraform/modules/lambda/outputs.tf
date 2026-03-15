# modules/lambda/outputs.tf

output "function_arn" {
  description = "ARN of the CloudLine event-handler Lambda function"
  value       = aws_lambda_function.cloudline_event_handler.arn
}

output "function_name" {
  description = "Name of the CloudLine event-handler Lambda function"
  value       = aws_lambda_function.cloudline_event_handler.function_name
}

output "invoke_arn" {
  description = "Invoke ARN of the Lambda function (used by API Gateway)"
  value       = aws_lambda_function.cloudline_event_handler.invoke_arn
}
