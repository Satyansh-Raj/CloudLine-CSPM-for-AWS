# modules/lambda/main.tf
# CloudLine Lambda function — event handler for real-time detection.

resource "aws_lambda_function" "cloudline_event_handler" {
  filename      = var.deployment_zip_path
  function_name = "${var.prefix}-event-handler"
  role          = var.lambda_role_arn
  handler       = "handler.lambda_handler"
  runtime       = "python3.11"

  timeout     = 120
  memory_size = 512

  # Recompute source_code_hash when the zip changes
  source_code_hash = filebase64sha256(var.deployment_zip_path)

  environment {
    variables = {
      AWS_ACCOUNT_ID        = var.aws_account_id
      DYNAMODB_STATE_TABLE  = var.dynamodb_state_table
      SNS_TOPIC_ARN         = var.sns_topic_arn
      OPA_BINARY_PATH       = "/var/task/bin/opa"
      OPA_POLICY_DIR        = "/var/task/policies"
      OPA_MODE              = "cli"
    }
  }

  tags = {
    Project     = "CloudLine"
    Environment = var.environment
  }
}

# CloudWatch Log Group — pre-create so retention is enforced from day one
resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${aws_lambda_function.cloudline_event_handler.function_name}"
  retention_in_days = 14

  tags = {
    Project     = "CloudLine"
    Environment = var.environment
  }
}
