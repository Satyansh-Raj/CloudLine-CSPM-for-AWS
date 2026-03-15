# terraform/main.tf
# CloudLine — deploys the full real-time detection pipeline.
#
# Resources created:
#   - CloudTrail trail (multi-region, with S3 + CloudWatch Logs)
#   - 7 EventBridge rules (one per AWS service)
#   - Lambda function (cloudline-event-handler)
#   - 5 DynamoDB tables
#   - SNS alert topic
#   - IAM role with least-privilege permissions
#
# Usage:
#   cp terraform.tfvars.example terraform.tfvars
#   # set aws_account_id in terraform.tfvars
#   terraform init && terraform apply

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

module "dynamodb" {
  source      = "./modules/dynamodb"
  environment = var.environment
  prefix      = var.prefix
}

module "sns" {
  source      = "./modules/sns"
  environment = var.environment
  prefix      = var.prefix
  alert_emails = var.alert_emails
  alert_phone = var.alert_phone
}

module "iam" {
  source                   = "./modules/iam"
  environment              = var.environment
  prefix                   = var.prefix
  dynamodb_state_table_arn = module.dynamodb.state_table_arn
  sns_topic_arn            = module.sns.topic_arn
}

module "cloudtrail" {
  source      = "./modules/cloudtrail"
  environment = var.environment
  prefix      = var.prefix
}

module "lambda" {
  source               = "./modules/lambda"
  environment          = var.environment
  prefix               = var.prefix
  lambda_role_arn      = module.iam.lambda_role_arn
  aws_account_id       = var.aws_account_id
  aws_region           = var.aws_region
  dynamodb_state_table = module.dynamodb.state_table_name
  sns_topic_arn        = module.sns.topic_arn
}

module "eventbridge" {
  source               = "./modules/eventbridge"
  environment          = var.environment
  prefix               = var.prefix
  lambda_function_arn  = module.lambda.function_arn
  lambda_function_name = module.lambda.function_name
}
