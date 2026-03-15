# modules/eventbridge/outputs.tf

output "rule_arns" {
  description = "Map of EventBridge rule name to ARN"
  value = {
    s3         = aws_cloudwatch_event_rule.s3.arn
    ec2        = aws_cloudwatch_event_rule.ec2.arn
    iam        = aws_cloudwatch_event_rule.iam.arn
    cloudtrail = aws_cloudwatch_event_rule.cloudtrail.arn
    rds        = aws_cloudwatch_event_rule.rds.arn
    lambda_svc = aws_cloudwatch_event_rule.lambda_svc.arn
    guardduty  = aws_cloudwatch_event_rule.guardduty.arn
  }
}
