# modules/sns/main.tf
# SNS topic for CloudLine security alerts.

data "aws_caller_identity" "current" {}

resource "aws_sns_topic" "cloudline_alerts" {
  name = "${var.prefix}-alerts"

  tags = {
    Project     = "CloudLine"
    Environment = var.environment
  }
}

# Email subscriptions — one per address in alert_emails
resource "aws_sns_topic_subscription" "email" {
  count = length(var.alert_emails)

  topic_arn = aws_sns_topic.cloudline_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_emails[count.index]
}

# Optional SMS subscription — only created when alert_phone is set
resource "aws_sns_topic_subscription" "sms" {
  count = var.alert_phone != "" ? 1 : 0

  topic_arn = aws_sns_topic.cloudline_alerts.arn
  protocol  = "sms"
  endpoint  = var.alert_phone
}

# Resource policy — allow CloudWatch Alarms to publish to the topic
resource "aws_sns_topic_policy" "cloudline_alerts" {
  arn = aws_sns_topic.cloudline_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudWatchPublish"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.cloudline_alerts.arn
      },
      {
        Sid    = "AllowTopicOwner"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = [
          "SNS:GetTopicAttributes",
          "SNS:SetTopicAttributes",
          "SNS:AddPermission",
          "SNS:RemovePermission",
          "SNS:DeleteTopic",
          "SNS:Subscribe",
          "SNS:ListSubscriptionsByTopic",
          "SNS:Publish",
        ]
        Resource = aws_sns_topic.cloudline_alerts.arn
        Condition = {
          StringEquals = {
            "AWS:SourceOwner" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}
