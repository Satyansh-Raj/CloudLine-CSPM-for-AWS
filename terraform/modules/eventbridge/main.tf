# modules/eventbridge/main.tf
# EventBridge rules that trigger the CloudLine Lambda on CloudTrail events.

# ---------------------------------------------------------------------------
# Rule 1: S3 events
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "s3" {
  name        = "${var.prefix}-s3-events"
  description = "Trigger CloudLine on S3 configuration changes"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateBucket",
        "PutBucketPublicAccessBlock",
        "PutBucketPolicy",
        "PutBucketEncryption",
        "DeleteBucketEncryption",
        "DeleteBucket",
        "DeleteBucketPolicy",
        "DeletePublicAccessBlock",
      ]
    }
  })

  tags = {
    Project     = "CloudLine"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_event_target" "s3" {
  rule = aws_cloudwatch_event_rule.s3.name
  arn  = var.lambda_function_arn
}

resource "aws_lambda_permission" "s3" {
  statement_id  = "AllowEventBridgeInvoke-s3-events"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3.arn
}

# ---------------------------------------------------------------------------
# Rule 2: EC2 events
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "ec2" {
  name        = "${var.prefix}-ec2-events"
  description = "Trigger CloudLine on EC2 configuration changes"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress",
        "CreateSecurityGroup",
        "DeleteSecurityGroup",
        "RunInstances",
        "ModifyInstanceMetadataOptions",
        "TerminateInstances",
        "ModifyInstanceAttribute",
        "CreateVolume",
        "DeleteVolume",
        "CreateFlowLogs",
        "DeleteFlowLogs",
      ]
    }
  })

  tags = {
    Project     = "CloudLine"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_event_target" "ec2" {
  rule = aws_cloudwatch_event_rule.ec2.name
  arn  = var.lambda_function_arn
}

resource "aws_lambda_permission" "ec2" {
  statement_id  = "AllowEventBridgeInvoke-ec2-events"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ec2.arn
}

# ---------------------------------------------------------------------------
# Rule 3: IAM events
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "iam" {
  name        = "${var.prefix}-iam-events"
  description = "Trigger CloudLine on IAM configuration changes"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateUser",
        "CreateAccessKey",
        "DeleteAccessKey",
        "DeleteUser",
        "AttachRolePolicy",
        "UpdateAccountPasswordPolicy",
        "DetachRolePolicy",
        "DeleteRolePolicy",
      ]
    }
  })

  tags = {
    Project     = "CloudLine"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_event_target" "iam" {
  rule = aws_cloudwatch_event_rule.iam.name
  arn  = var.lambda_function_arn
}

resource "aws_lambda_permission" "iam" {
  statement_id  = "AllowEventBridgeInvoke-iam-events"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam.arn
}

# ---------------------------------------------------------------------------
# Rule 4: CloudTrail events
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "cloudtrail" {
  name        = "${var.prefix}-cloudtrail-events"
  description = "Trigger CloudLine on CloudTrail configuration changes"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "StartLogging",
        "CreateTrail",
        "StopLogging",
        "DeleteTrail",
      ]
    }
  })

  tags = {
    Project     = "CloudLine"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_event_target" "cloudtrail" {
  rule = aws_cloudwatch_event_rule.cloudtrail.name
  arn  = var.lambda_function_arn
}

resource "aws_lambda_permission" "cloudtrail" {
  statement_id  = "AllowEventBridgeInvoke-cloudtrail-events"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloudtrail.arn
}

# ---------------------------------------------------------------------------
# Rule 5: RDS events
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "rds" {
  name        = "${var.prefix}-rds-events"
  description = "Trigger CloudLine on RDS configuration changes"

  event_pattern = jsonencode({
    source      = ["aws.rds"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateDBInstance",
        "ModifyDBInstance",
        "DeleteDBInstance",
      ]
    }
  })

  tags = {
    Project     = "CloudLine"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_event_target" "rds" {
  rule = aws_cloudwatch_event_rule.rds.name
  arn  = var.lambda_function_arn
}

resource "aws_lambda_permission" "rds" {
  statement_id  = "AllowEventBridgeInvoke-rds-events"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.rds.arn
}

# ---------------------------------------------------------------------------
# Rule 6: Lambda function events
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "lambda_svc" {
  name        = "${var.prefix}-lambda-events"
  description = "Trigger CloudLine on Lambda configuration changes"

  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateFunction20150331",
        "DeleteFunction20150331",
        "UpdateFunctionConfiguration20150331v2",
      ]
    }
  })

  tags = {
    Project     = "CloudLine"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_event_target" "lambda_svc" {
  rule = aws_cloudwatch_event_rule.lambda_svc.name
  arn  = var.lambda_function_arn
}

resource "aws_lambda_permission" "lambda_svc" {
  statement_id  = "AllowEventBridgeInvoke-lambda-events"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.lambda_svc.arn
}

# ---------------------------------------------------------------------------
# Rule 7: GuardDuty events
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "${var.prefix}-guardduty-events"
  description = "Trigger CloudLine on GuardDuty configuration changes"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateDetector",
        "DeleteDetector",
      ]
    }
  })

  tags = {
    Project     = "CloudLine"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_event_target" "guardduty" {
  rule = aws_cloudwatch_event_rule.guardduty.name
  arn  = var.lambda_function_arn
}

resource "aws_lambda_permission" "guardduty" {
  statement_id  = "AllowEventBridgeInvoke-guardduty-events"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty.arn
}
