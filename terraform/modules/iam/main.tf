# modules/iam/main.tf
# IAM role and policies for the CloudLine Lambda function.

# ---------------------------------------------------------------------------
# Trust policy — allow Lambda service to assume this role
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    sid     = "AllowLambdaAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudline_lambda" {
  name               = "${var.prefix}-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = {
    Project     = "CloudLine"
    Environment = var.environment
  }
}

# ---------------------------------------------------------------------------
# Policy 1: Basic Lambda execution (CloudWatch Logs)
# ---------------------------------------------------------------------------
resource "aws_iam_role_policy" "lambda_logs" {
  name = "${var.prefix}-lambda-logs"
  role = aws_iam_role.cloudline_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "*"
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Policy 2: DynamoDB access — violation-state table + all indexes
# ---------------------------------------------------------------------------
resource "aws_iam_role_policy" "lambda_dynamodb" {
  name = "${var.prefix}-lambda-dynamodb"
  role = aws_iam_role.cloudline_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBStateTable"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan",
        ]
        Resource = [
          var.dynamodb_state_table_arn,
          "${var.dynamodb_state_table_arn}/index/*",
        ]
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Policy 3: SNS Publish — alert topic
# ---------------------------------------------------------------------------
resource "aws_iam_role_policy" "lambda_sns" {
  name = "${var.prefix}-lambda-sns"
  role = aws_iam_role.cloudline_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = var.sns_topic_arn
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Policy 4: AWS read permissions for CloudLine collectors
# ---------------------------------------------------------------------------
resource "aws_iam_role_policy" "lambda_aws_read" {
  name = "${var.prefix}-lambda-aws-read"
  role = aws_iam_role.cloudline_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # EC2
      {
        Sid    = "EC2Read"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVolumes",
          "ec2:DescribeVpcs",
          "ec2:DescribeFlowLogs",
          "ec2:DescribeSubnets",
        ]
        Resource = "*"
      },
      # S3
      {
        Sid    = "S3Read"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:ListBuckets",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketPolicy",
          "s3:GetBucketEncryption",
          "s3:GetBucketVersioning",
          "s3:GetBucketLogging",
          "s3:GetBucketAcl",
          "s3:GetBucketTagging",
        ]
        Resource = "*"
      },
      # IAM
      {
        Sid    = "IAMRead"
        Effect = "Allow"
        Action = [
          "iam:GetAccountPasswordPolicy",
          "iam:ListUsers",
          "iam:ListMFADevices",
          "iam:GetLoginProfile",
          "iam:ListAccessKeys",
          "iam:GetAccessKeyLastUsed",
          "iam:ListAttachedRolePolicies",
          "iam:GetRolePolicy",
          "iam:ListRoles",
        ]
        Resource = "*"
      },
      # RDS
      {
        Sid    = "RDSRead"
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
        ]
        Resource = "*"
      },
      # Lambda
      {
        Sid    = "LambdaRead"
        Effect = "Allow"
        Action = [
          "lambda:ListFunctions",
          "lambda:GetFunctionConfiguration",
          "lambda:GetPolicy",
          "lambda:ListTags",
        ]
        Resource = "*"
      },
      # GuardDuty
      {
        Sid    = "GuardDutyRead"
        Effect = "Allow"
        Action = [
          "guardduty:ListDetectors",
          "guardduty:GetDetector",
        ]
        Resource = "*"
      },
      # CloudTrail
      {
        Sid    = "CloudTrailRead"
        Effect = "Allow"
        Action = [
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
        ]
        Resource = "*"
      },
      # KMS
      {
        Sid    = "KMSRead"
        Effect = "Allow"
        Action = [
          "kms:ListKeys",
          "kms:DescribeKey",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
        ]
        Resource = "*"
      }
    ]
  })
}
