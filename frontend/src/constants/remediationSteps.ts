/**
 * Remediation steps for each check ID, pre-filled with
 * the actual resource data extracted from the violation ARN.
 *
 * Assumes AWS CLI is installed and configured with
 * administrator-level credentials on the operator's machine.
 */

export interface RemediationMethod {
  console: string[];
  cli: string;
  terraform: string;
}

// ─── ARN parser ───────────────────────────────────────────────

interface ParsedArn {
  raw: string;
  service: string;
  region: string; // empty string when not in ARN (S3, IAM)
  accountId: string; // empty string when not in ARN
  resourceType: string;
  resourceId: string;
}

function parseArn(resource: string): ParsedArn {
  const fallback: ParsedArn = {
    raw: resource,
    service: "",
    region: "",
    accountId: "",
    resourceType: "",
    resourceId: resource || "<RESOURCE_ID>",
  };

  if (!resource.startsWith("arn:")) {
    return { ...fallback, resourceId: resource || "<RESOURCE_ID>" };
  }

  const parts = resource.split(":");
  if (parts.length < 6) return fallback;

  const service = parts[2] ?? "";
  const region = parts[3] ?? "";
  const accountId = parts[4] ?? "";
  const resourcePart = parts.slice(5).join(":");

  let resourceType = "";
  let resourceId = resourcePart;

  const noSplit = [
    "root",
    "no-trails",
    "no-recorder",
    "no-detector",
    "no-plans",
    "access-analyzer",
    "password-policy",
  ];

  if (resourcePart.includes("/")) {
    const idx = resourcePart.indexOf("/");
    resourceType = resourcePart.slice(0, idx);
    resourceId = resourcePart.slice(idx + 1);
  } else if (resourcePart.includes(":") && !noSplit.includes(resourcePart)) {
    const idx = resourcePart.indexOf(":");
    resourceType = resourcePart.slice(0, idx);
    resourceId = resourcePart.slice(idx + 1);
  }

  // Secrets Manager ARNs append a random 6-char suffix
  // (e.g. "MySecret-yEqB2B") that is NOT part of the
  // secret name. Strip it so --secret-id works correctly.
  if (service === "secretsmanager" && resourceType === "secret") {
    resourceId = resourceId.replace(/-[A-Za-z0-9]{6}$/, "");
  }

  return {
    raw: resource,
    service,
    region,
    accountId,
    resourceType,
    resourceId,
  };
}

// ─── Shell variable helpers ───────────────────────────────────
// Produce clean bash variable assignments.
// If the value came from the ARN it is embedded as a literal.
// If absent, it is derived from the configured AWS CLI profile.

function reg(r: string): string {
  return r ? `REGION="${r}"` : `REGION=$(aws configure get region)`;
}

function acct(a: string): string {
  return a
    ? `ACCOUNT_ID="${a}"`
    : `ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)`;
}

// ─── Factory type ─────────────────────────────────────────────

type RemediationFactory = (p: ParsedArn) => RemediationMethod;

// ─── Per-check factories ──────────────────────────────────────

const FACTORIES: Record<string, RemediationFactory> = {
  // iam_root_mfa — Root account MFA
  iam_root_mfa: ({ accountId }) => ({
    console: [
      "Sign in to the AWS Management Console as the root user.",
      "Click the account name (top-right) → Security credentials.",
      "Scroll to Multi-factor authentication (MFA) → Assign MFA device.",
      "Choose Authenticator app → Continue.",
      "Scan the QR code with your authenticator app.",
      "Enter two consecutive MFA codes → Add MFA.",
    ],
    cli: `\
# Root account MFA cannot be set via CLI — use the Console steps above.
# Verify current MFA status:
${acct(accountId)}

aws iam get-account-summary \\
  --query 'SummaryMap.AccountMFAEnabled'
# Returns 1 when enabled, 0 when disabled`,
    terraform: `\
# Root MFA must be enabled via Console.
# Enforce it organisation-wide with an SCP:
${acct(accountId)}

resource "aws_organizations_policy" "require_mfa" {
  name = "RequireMFA"
  type = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = "*"
      Resource = "*"
      Condition = {
        BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" }
      }
    }]
  })
}

resource "aws_organizations_policy_attachment" "require_mfa" {
  policy_id = aws_organizations_policy.require_mfa.id
  target_id = "${accountId || "$ACCOUNT_ID"}"
}`,
  }),

  // iam_pwd_min_length — Weak IAM password policy
  iam_pwd_min_length: ({ accountId }) => ({
    console: [
      "Open the IAM console → Account settings.",
      "Click Change password policy.",
      "Set minimum length = 14, require uppercase, lowercase, numbers, symbols.",
      "Enable password reuse prevention (last 24).",
      "Enable password expiration (90 days).",
      "Click Save changes.",
    ],
    cli: `\
${acct(accountId)}

aws iam update-account-password-policy \\
  --minimum-password-length 14 \\
  --require-uppercase-characters \\
  --require-lowercase-characters \\
  --require-numbers \\
  --require-symbols \\
  --allow-users-to-change-password \\
  --max-password-age 90 \\
  --password-reuse-prevention 24 \\
  --no-hard-expiry

aws iam get-account-password-policy`,
    terraform: `\
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}`,
  }),

  // iam_user_mfa — IAM user MFA not enabled
  iam_user_mfa: ({ resourceId, accountId }) => ({
    console: [
      `Open IAM console → Users → select "${resourceId}".`,
      "Click Security credentials tab.",
      "Under Multi-factor authentication → Assign MFA device.",
      "Select Authenticator app → Continue.",
      "Scan the QR code and enter two consecutive OTP codes.",
      "Click Add MFA.",
    ],
    cli: `\
USERNAME="${resourceId}"
${acct(accountId)}

# Step 1 — create a virtual MFA device
aws iam create-virtual-mfa-device \\
  --virtual-mfa-device-name "${resourceId}-mfa" \\
  --outfile /tmp/${resourceId}-qrcode.png \\
  --bootstrap-method QRCodePNG

# Step 2 — open the QR code and scan it with your authenticator app
open /tmp/${resourceId}-qrcode.png

# Step 3 — activate (enter two consecutive OTP codes from the app)
aws iam enable-mfa-device \\
  --user-name "$USERNAME" \\
  --serial-number "arn:aws:iam::$ACCOUNT_ID:mfa/${resourceId}-mfa" \\
  --authentication-code1 <CODE1> \\
  --authentication-code2 <CODE2>

# Verify
aws iam list-mfa-devices --user-name "$USERNAME"`,
    terraform: `\
# User: ${resourceId}
resource "aws_iam_virtual_mfa_device" "user_mfa" {
  virtual_mfa_device_name = "${resourceId}-mfa"
  tags = { User = "${resourceId}" }
}
# Activation requires live OTP codes — complete via CLI after plan/apply.`,
  }),

  // s3_block_public_acls — S3 public access not blocked
  s3_block_public_acls: ({ resourceId }) => ({
    console: [
      `Open S3 console → select bucket "${resourceId}".`,
      "Permissions tab → Block public access (bucket settings) → Edit.",
      "Enable all four block options.",
      "Save changes → confirm.",
    ],
    cli: `\
BUCKET="${resourceId}"

aws s3api put-public-access-block \\
  --bucket "$BUCKET" \\
  --public-access-block-configuration \\
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Verify
aws s3api get-public-access-block --bucket "$BUCKET"`,
    terraform: `\
resource "aws_s3_bucket_public_access_block" "fix" {
  bucket                  = "${resourceId}"
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}`,
  }),

  // cloudtrail_enabled — CloudTrail logging disabled
  cloudtrail_enabled: ({ region, accountId, resourceId }) => {
    const trailName =
      resourceId === "no-trails" ? "cloudline-trail" : resourceId;
    return {
      console: [
        "Open CloudTrail console → Trails → Create trail.",
        "Name the trail, enable 'Apply to all regions'.",
        "Set or create an S3 bucket for log storage.",
        "Enable log file validation.",
        "Click Create trail.",
      ],
      cli: `\
${reg(region)}
${acct(accountId)}
TRAIL_NAME="${trailName}"
BUCKET="cloudtrail-logs-$ACCOUNT_ID"

# Create log bucket
aws s3api create-bucket \\
  --bucket "$BUCKET" \\
  --region "$REGION" \\
  --create-bucket-configuration LocationConstraint="$REGION"

aws s3api put-public-access-block \\
  --bucket "$BUCKET" \\
  --public-access-block-configuration \\
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Create and start trail
aws cloudtrail create-trail \\
  --name "$TRAIL_NAME" \\
  --s3-bucket-name "$BUCKET" \\
  --is-multi-region-trail \\
  --enable-log-file-validation

aws cloudtrail start-logging --name "$TRAIL_NAME"

# Verify
aws cloudtrail get-trail-status --name "$TRAIL_NAME" \\
  --query '{IsLogging:IsLoggingEnabled}'`,
      terraform: `\
variable "region" { default = "${region || "us-east-1"}" }

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "cloudtrail" {
  bucket = "cloudtrail-logs-\${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_cloudtrail" "main" {
  name                          = "${trailName}"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}`,
    };
  },

  // cloudtrail_multi_region — No multi-region CloudTrail trail
  cloudtrail_multi_region: ({ region, accountId }) => ({
    console: [
      "Open CloudTrail console → Trails.",
      "Edit existing trail or create new one.",
      "Enable 'Apply trail to all regions'.",
      "Save.",
    ],
    cli: `\
${reg(region)}
${acct(accountId)}

# Update existing trail to multi-region
# aws cloudtrail update-trail \\
#   --name <TRAIL_NAME> \\
#   --is-multi-region-trail \\
#   --region "$REGION"

# Or create a new multi-region trail
aws cloudtrail create-trail \\
  --name cloudline-multi-region \\
  --s3-bucket-name "cloudtrail-logs-$ACCOUNT_ID" \\
  --is-multi-region-trail \\
  --enable-log-file-validation

aws cloudtrail start-logging --name cloudline-multi-region`,
    terraform: `\
resource "aws_cloudtrail" "fix" {
  name                  = "multi-region-trail"
  s3_bucket_name        = var.log_bucket
  is_multi_region_trail = true
}`,
  }),

  // cloudtrail_log_validation — CloudTrail log file validation disabled
  cloudtrail_log_validation: ({ resourceId, region }) => ({
    console: [
      `Open CloudTrail console → Trails → select "${resourceId}".`,
      "General details → Edit.",
      "Enable 'Log file validation'.",
      "Save.",
    ],
    cli: `\
TRAIL="${resourceId}"
${reg(region)}

aws cloudtrail update-trail \\
  --name "$TRAIL" \\
  --enable-log-file-validation \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudtrail" "fix" {
  name                       = "${resourceId}"
  enable_log_file_validation = true
}`,
  }),

  // cloudtrail_s3_private — CloudTrail S3 log bucket publicly accessible
  cloudtrail_s3_private: ({ resourceId }) => ({
    console: [
      `Open S3 console → select CloudTrail log bucket "${resourceId}".`,
      "Permissions → Block public access → Edit.",
      "Enable all four block options.",
      "Save changes.",
    ],
    cli: `\
BUCKET="${resourceId}"

aws s3api put-public-access-block \\
  --bucket "$BUCKET" \\
  --public-access-block-configuration \\
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`,
    terraform: `\
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = "${resourceId}"
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}`,
  }),

  // cloudtrail_cloudwatch_logs — CloudTrail not integrated with CloudWatch Logs
  cloudtrail_cloudwatch_logs: ({ resourceId, region, accountId }) => ({
    console: [
      `Open CloudTrail console → Trails → select "${resourceId}".`,
      "CloudWatch Logs → Edit.",
      "Select or create a log group and IAM role.",
      "Save.",
    ],
    cli: `\
TRAIL="${resourceId}"
${reg(region)}
${acct(accountId)}

# Create log group
aws logs create-log-group \\
  --log-group-name "/aws/cloudtrail/$TRAIL" \\
  --region "$REGION"

# Create IAM role for CloudTrail → CloudWatch
# Then update trail:
# aws cloudtrail update-trail \\
#   --name "$TRAIL" \\
#   --cloud-watch-logs-log-group-arn "<LOG_GROUP_ARN>" \\
#   --cloud-watch-logs-role-arn "<ROLE_ARN>" \\
#   --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${resourceId}"
  retention_in_days = 365
}

resource "aws_cloudtrail" "fix" {
  name                  = "${resourceId}"
  cloud_watch_logs_group_arn = "\${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cw.arn
}`,
  }),

  // cloudtrail_kms_encryption — CloudTrail logs not encrypted with KMS
  cloudtrail_kms_encryption: ({ resourceId, region }) => ({
    console: [
      `Open CloudTrail console → Trails → select "${resourceId}".`,
      "General details → Edit.",
      "Enable SSE-KMS encryption → select or create a KMS key.",
      "Save.",
    ],
    cli: `\
TRAIL="${resourceId}"
${reg(region)}

# Create KMS key for CloudTrail
KEY_ID=$(aws kms create-key \\
  --description "CloudTrail encryption" \\
  --region "$REGION" \\
  --query 'KeyMetadata.KeyId' --output text)

aws cloudtrail update-trail \\
  --name "$TRAIL" \\
  --kms-key-id "$KEY_ID" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_kms_key" "cloudtrail" {
  description         = "CloudTrail log encryption"
  enable_key_rotation = true
}

resource "aws_cloudtrail" "fix" {
  name       = "${resourceId}"
  kms_key_id = aws_kms_key.cloudtrail.arn
}`,
  }),

  // cloudtrail_sns_notification — CloudTrail has no SNS notification
  cloudtrail_sns_notification: ({ resourceId, region }) => ({
    console: [
      `Open CloudTrail console → Trails → select "${resourceId}".`,
      "General details → Edit.",
      "SNS notification → select or create an SNS topic.",
      "Save.",
    ],
    cli: `\
TRAIL="${resourceId}"
${reg(region)}

TOPIC_ARN=$(aws sns create-topic \\
  --name "cloudtrail-notifications" \\
  --region "$REGION" \\
  --query TopicArn --output text)

aws cloudtrail update-trail \\
  --name "$TRAIL" \\
  --sns-topic-name "$TOPIC_ARN" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_sns_topic" "cloudtrail" {
  name = "cloudtrail-notifications"
}

resource "aws_cloudtrail" "fix" {
  name          = "${resourceId}"
  sns_topic_name = aws_sns_topic.cloudtrail.arn
}`,
  }),

  // cloudtrail_mgmt_events — CloudTrail not logging management events
  cloudtrail_mgmt_events: ({ resourceId, region }) => ({
    console: [
      `Open CloudTrail console → Trails → select "${resourceId}".`,
      "Event selectors → Edit.",
      "Enable management events (Read + Write).",
      "Save.",
    ],
    cli: `\
TRAIL="${resourceId}"
${reg(region)}

aws cloudtrail put-event-selectors \\
  --trail-name "$TRAIL" \\
  --event-selectors '[{
    "ReadWriteType":"All",
    "IncludeManagementEvents":true
  }]' \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudtrail" "fix" {
  name = "${resourceId}"
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}`,
  }),

  // cloudtrail_read_write_events — CloudTrail logging write events only
  cloudtrail_read_write_events: ({ resourceId, region }) => ({
    console: [
      `Open CloudTrail console → Trails → select "${resourceId}".`,
      "Event selectors → Edit.",
      "Change Read/Write type from 'Write-only' to 'All'.",
      "Save.",
    ],
    cli: `\
TRAIL="${resourceId}"
${reg(region)}

aws cloudtrail put-event-selectors \\
  --trail-name "$TRAIL" \\
  --event-selectors '[{
    "ReadWriteType":"All",
    "IncludeManagementEvents":true
  }]' \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudtrail" "fix" {
  name = "${resourceId}"
  event_selector {
    read_write_type = "All"
  }
}`,
  }),

  // cloudtrail_s3_data_events — CloudTrail not logging S3 data events
  cloudtrail_s3_data_events: ({ resourceId, region }) => ({
    console: [
      `Open CloudTrail console → Trails → select "${resourceId}".`,
      "Event selectors → Edit.",
      "Data events → Add data event → S3.",
      "Log all S3 buckets or specific ones.",
      "Save.",
    ],
    cli: `\
TRAIL="${resourceId}"
${reg(region)}

aws cloudtrail put-event-selectors \\
  --trail-name "$TRAIL" \\
  --event-selectors '[{
    "ReadWriteType":"All",
    "IncludeManagementEvents":true,
    "DataResources":[{
      "Type":"AWS::S3::Object",
      "Values":["arn:aws:s3"]
    }]
  }]' \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudtrail" "fix" {
  name = "${resourceId}"
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3"]
    }
  }
}`,
  }),

  // cloudtrail_lambda_data_events — CloudTrail not logging Lambda data events
  cloudtrail_lambda_data_events: ({ resourceId, region }) => ({
    console: [
      `Open CloudTrail console → Trails → select "${resourceId}".`,
      "Event selectors → Edit.",
      "Data events → Add → Lambda.",
      "Log all Lambda functions.",
      "Save.",
    ],
    cli: `\
TRAIL="${resourceId}"
${reg(region)}

aws cloudtrail put-event-selectors \\
  --trail-name "$TRAIL" \\
  --event-selectors '[{
    "ReadWriteType":"All",
    "IncludeManagementEvents":true,
    "DataResources":[{
      "Type":"AWS::Lambda::Function",
      "Values":["arn:aws:lambda"]
    }]
  }]' \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudtrail" "fix" {
  name = "${resourceId}"
  event_selector {
    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:aws:lambda"]
    }
  }
}`,
  }),

  // cloudtrail_insights — CloudTrail Insights not enabled
  cloudtrail_insights: ({ resourceId, region }) => ({
    console: [
      `Open CloudTrail console → Trails → select "${resourceId}".`,
      "Insights → Edit.",
      "Enable Insights events (API call rate, API error rate).",
      "Save.",
    ],
    cli: `\
TRAIL="${resourceId}"
${reg(region)}

aws cloudtrail put-insight-selectors \\
  --trail-name "$TRAIL" \\
  --insight-selectors '[
    {"InsightType":"ApiCallRateInsight"},
    {"InsightType":"ApiErrorRateInsight"}
  ]' \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudtrail" "fix" {
  name = "${resourceId}"
  insight_selector {
    insight_type = "ApiCallRateInsight"
  }
  insight_selector {
    insight_type = "ApiErrorRateInsight"
  }
}`,
  }),

  // cloudtrail_global_events — Multi-region trail excludes global service events
  cloudtrail_global_events: ({ resourceId, region }) => ({
    console: [
      `Open CloudTrail console → Trails → select "${resourceId}".`,
      "General details → Edit.",
      "Enable 'Include global service events'.",
      "Save.",
    ],
    cli: `\
TRAIL="${resourceId}"
${reg(region)}

aws cloudtrail update-trail \\
  --name "$TRAIL" \\
  --include-global-service-events \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudtrail" "fix" {
  name                          = "${resourceId}"
  include_global_service_events = true
}`,
  }),

  // cloudtrail_retention_365 — CloudTrail log retention < 365 days
  cloudtrail_retention_365: ({ resourceId, region }) => ({
    console: [
      "Open CloudWatch console → Log groups.",
      `Select the CloudTrail log group for "${resourceId}".`,
      "Actions → Edit retention → set to 365 days or more.",
    ],
    cli: `\
TRAIL="${resourceId}"
${reg(region)}

# Set CloudWatch log group retention
aws logs put-retention-policy \\
  --log-group-name "/aws/cloudtrail/$TRAIL" \\
  --retention-in-days 365 \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${resourceId}"
  retention_in_days = 365
}`,
  }),

  // cloudtrail_s3_mfa_delete — CloudTrail S3 bucket MFA delete disabled
  cloudtrail_s3_mfa_delete: ({ resourceId }) => ({
    console: [
      `CloudTrail S3 bucket "${resourceId}" does not have MFA Delete.`,
      "MFA Delete must be enabled by the root account via CLI.",
    ],
    cli: `\
BUCKET="${resourceId}"

# Must be run as ROOT account with MFA
aws s3api put-bucket-versioning \\
  --bucket "$BUCKET" \\
  --versioning-configuration Status=Enabled,MFADelete=Enabled \\
  --mfa "<MFA_SERIAL> <MFA_CODE>"`,
    terraform: `\
# MFA Delete requires root credentials — enable via CLI.
resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = "${resourceId}"
  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Enabled"
  }
}`,
  }),

  // vpc_flow_logs — VPC flow logs disabled
  vpc_flow_logs: ({ resourceId }) => ({
    console: [
      `Open VPC console → Your VPCs → select "${resourceId}".`,
      "Actions → Create flow log.",
      "Filter: All, Destination: CloudWatch Logs.",
      "Select or create an IAM role for delivery.",
      "Click Create flow log.",
    ],
    cli: `\
VPC_ID="${resourceId}"
${acct("")}
${reg("")}
LOG_GROUP="/aws/vpc/flowlogs/$VPC_ID"

# Create CloudWatch Logs group
aws logs create-log-group \\
  --log-group-name "$LOG_GROUP" \\
  --region "$REGION"

# Create IAM role for VPC Flow Logs
aws iam create-role \\
  --role-name vpc-flow-log-role \\
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Principal":{"Service":"vpc-flow-logs.amazonaws.com"},
      "Action":"sts:AssumeRole"
    }]
  }'

aws iam put-role-policy \\
  --role-name vpc-flow-log-role \\
  --policy-name AllowCloudWatchLogs \\
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Action":["logs:CreateLogStream","logs:PutLogEvents","logs:DescribeLogGroups"],
      "Resource":"*"
    }]
  }'

# Enable flow logs on VPC
aws ec2 create-flow-logs \\
  --resource-type VPC \\
  --resource-ids "$VPC_ID" \\
  --traffic-type ALL \\
  --log-destination-type cloud-watch-logs \\
  --log-group-name "$LOG_GROUP" \\
  --deliver-logs-permission-arn \\
    "arn:aws:iam::$ACCOUNT_ID:role/vpc-flow-log-role"

# Verify
aws ec2 describe-flow-logs \\
  --filter Name=resource-id,Values="$VPC_ID" \\
  --query 'FlowLogs[].{Status:FlowLogStatus,LogGroup:LogGroupName}'`,
    terraform: `\
resource "aws_cloudwatch_log_group" "flow_log" {
  name              = "/aws/vpc/flowlogs/${resourceId}"
  retention_in_days = 90
}

resource "aws_iam_role" "flow_log" {
  name = "vpc-flow-log-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_log" {
  role = aws_iam_role.flow_log.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream","logs:PutLogEvents","logs:DescribeLogGroups"]
      Resource = "*"
    }]
  })
}

resource "aws_flow_log" "fix" {
  vpc_id          = "${resourceId}"
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn
}`,
  }),

  // ec2_no_open_ssh — Open SSH / RDP in Security Group
  ec2_no_open_ssh: ({ resourceId }) => ({
    console: [
      `Open EC2 console → Security Groups → select "${resourceId}".`,
      "Inbound rules → Edit inbound rules.",
      "Remove rules with Source 0.0.0.0/0 or ::/0 on port 22 (SSH) or 3389 (RDP).",
      "Add new rules with Source set to your corporate IP range (e.g. 203.0.113.0/24).",
      "Save rules.",
    ],
    cli: `\
SG_ID="${resourceId}"
TRUSTED_CIDR="<YOUR_IP>/32"   # replace with your IP or corporate CIDR

# Remove open SSH access (IPv4 and IPv6)
aws ec2 revoke-security-group-ingress \\
  --group-id "$SG_ID" \\
  --protocol tcp --port 22 --cidr 0.0.0.0/0

aws ec2 revoke-security-group-ingress \\
  --group-id "$SG_ID" \\
  --ip-permissions '[{"IpProtocol":"tcp","FromPort":22,"ToPort":22,"Ipv6Ranges":[{"CidrIpv6":"::/0"}]}]'

# Remove open RDP access
aws ec2 revoke-security-group-ingress \\
  --group-id "$SG_ID" \\
  --protocol tcp --port 3389 --cidr 0.0.0.0/0

# Re-add SSH restricted to trusted CIDR only
aws ec2 authorize-security-group-ingress \\
  --group-id "$SG_ID" \\
  --protocol tcp --port 22 \\
  --cidr "$TRUSTED_CIDR"

# Verify
aws ec2 describe-security-groups \\
  --group-ids "$SG_ID" \\
  --query 'SecurityGroups[0].IpPermissions'`,
    terraform: `\
# Security Group: ${resourceId}
# Import first: terraform import aws_security_group.fix ${resourceId}

resource "aws_security_group" "fix" {
  # existing SG — import before applying

  ingress {
    description = "SSH from trusted CIDR only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["<YOUR_IP>/32"]  # replace with your CIDR
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`,
  }),

  // ec2_imdsv2 — EC2 IMDSv2 not enforced
  ec2_imdsv2: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Instances → select "${resourceId}".`,
      "Actions → Instance settings → Modify instance metadata options.",
      "HTTP tokens → Required.",
      "HTTP PUT response hop limit → 1.",
      "Save.",
    ],
    cli: `\
INSTANCE_ID="${resourceId}"
${reg(region)}

aws ec2 modify-instance-metadata-options \\
  --instance-id "$INSTANCE_ID" \\
  --http-tokens required \\
  --http-endpoint enabled \\
  --http-put-response-hop-limit 1 \\
  --region "$REGION"

# Verify
aws ec2 describe-instances \\
  --instance-ids "$INSTANCE_ID" \\
  --region "$REGION" \\
  --query 'Reservations[0].Instances[0].MetadataOptions'`,
    terraform: `\
# Instance: ${resourceId}
# Import: terraform import aws_instance.fix ${resourceId}

resource "aws_instance" "fix" {
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}`,
  }),

  // ec2_no_public_ip — Production EC2 has public IP
  ec2_no_public_ip: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Instances → select "${resourceId}".`,
      "This instance has a public IP. To remove it:",
      "Allocate an Elastic IP if needed for NAT/load balancer.",
      "Move instance to a private subnet behind an ALB or NAT Gateway.",
      "Ensure the subnet has map_public_ip_on_launch = false.",
    ],
    cli: `\
INSTANCE_ID="${resourceId}"
${reg(region)}

# Disassociate public IP (if using Elastic IP)
ASSOC_ID=$(aws ec2 describe-addresses \\
  --filters Name=instance-id,Values="$INSTANCE_ID" \\
  --region "$REGION" \\
  --query 'Addresses[0].AssociationId' --output text)

if [ "$ASSOC_ID" != "None" ]; then
  aws ec2 disassociate-address \\
    --association-id "$ASSOC_ID" --region "$REGION"
fi

# For auto-assigned public IPs, move to a private subnet:
# 1. Stop instance
# 2. Change subnet to one with MapPublicIpOnLaunch=false
# 3. Start instance

# Verify
aws ec2 describe-instances \\
  --instance-ids "$INSTANCE_ID" \\
  --region "$REGION" \\
  --query 'Reservations[0].Instances[0].PublicIpAddress'`,
    terraform: `\
# Instance: ${resourceId}
resource "aws_instance" "fix" {
  associate_public_ip_address = false
  subnet_id                   = var.private_subnet_id
}

# Ensure the subnet does not auto-assign public IPs:
resource "aws_subnet" "private" {
  map_public_ip_on_launch = false
}`,
  }),

  // ec2_no_default_vpc — EC2 running in default VPC
  ec2_no_default_vpc: ({ resourceId, region }) => ({
    console: [
      `Instance "${resourceId}" is in the default VPC.`,
      "Create a custom VPC with proper network segmentation.",
      "Launch a replacement instance in the custom VPC.",
      "Migrate data/config from the old instance.",
      "Terminate the old instance in the default VPC.",
    ],
    cli: `\
INSTANCE_ID="${resourceId}"
${reg(region)}

# Identify current VPC
aws ec2 describe-instances \\
  --instance-ids "$INSTANCE_ID" \\
  --region "$REGION" \\
  --query 'Reservations[0].Instances[0].{VpcId:VpcId,SubnetId:SubnetId}'

# Create AMI from existing instance
AMI_ID=$(aws ec2 create-image \\
  --instance-id "$INSTANCE_ID" \\
  --name "migration-${resourceId}" \\
  --no-reboot \\
  --region "$REGION" \\
  --query ImageId --output text)

echo "AMI: $AMI_ID — launch in custom VPC subnet"`,
    terraform: `\
# Migrate instance ${resourceId} from default VPC:

resource "aws_vpc" "custom" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "custom-vpc" }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.custom.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false
}

resource "aws_instance" "migrated" {
  ami       = var.ami_id
  subnet_id = aws_subnet.private.id
}`,
  }),

  // ec2_detailed_monitoring — EC2 detailed monitoring disabled
  ec2_detailed_monitoring: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Instances → select "${resourceId}".`,
      "Actions → Monitor and troubleshoot → Manage detailed monitoring.",
      "Check 'Enable' → Confirm.",
    ],
    cli: `\
INSTANCE_ID="${resourceId}"
${reg(region)}

aws ec2 monitor-instances \\
  --instance-ids "$INSTANCE_ID" \\
  --region "$REGION"

# Verify
aws ec2 describe-instances \\
  --instance-ids "$INSTANCE_ID" \\
  --region "$REGION" \\
  --query 'Reservations[0].Instances[0].Monitoring.State'`,
    terraform: `\
# Instance: ${resourceId}
resource "aws_instance" "fix" {
  monitoring = true
}`,
  }),

  // ec2_no_open_rdp — Security group allows RDP from 0.0.0.0/0
  ec2_no_open_rdp: ({ resourceId }) => ({
    console: [
      `Open EC2 console → Security Groups → select "${resourceId}".`,
      "Inbound rules → Edit inbound rules.",
      "Remove rules allowing port 3389 from 0.0.0.0/0 or ::/0.",
      "Add RDP rule restricted to your corporate IP range.",
      "Save rules.",
    ],
    cli: `\
SG_ID="${resourceId}"
TRUSTED_CIDR="<YOUR_IP>/32"

# Remove open RDP (IPv4)
aws ec2 revoke-security-group-ingress \\
  --group-id "$SG_ID" \\
  --protocol tcp --port 3389 --cidr 0.0.0.0/0

# Remove open RDP (IPv6)
aws ec2 revoke-security-group-ingress \\
  --group-id "$SG_ID" \\
  --ip-permissions '[{"IpProtocol":"tcp","FromPort":3389,"ToPort":3389,"Ipv6Ranges":[{"CidrIpv6":"::/0"}]}]'

# Re-add restricted RDP
aws ec2 authorize-security-group-ingress \\
  --group-id "$SG_ID" \\
  --protocol tcp --port 3389 \\
  --cidr "$TRUSTED_CIDR"

# Verify
aws ec2 describe-security-groups \\
  --group-ids "$SG_ID" \\
  --query 'SecurityGroups[0].IpPermissions'`,
    terraform: `\
resource "aws_security_group_rule" "rdp" {
  type              = "ingress"
  security_group_id = "${resourceId}"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  cidr_blocks       = ["<YOUR_IP>/32"]
  description       = "RDP from trusted CIDR only"
}`,
  }),

  // ec2_no_all_inbound — Security group allows all inbound traffic
  ec2_no_all_inbound: ({ resourceId }) => ({
    console: [
      `Open EC2 console → Security Groups → select "${resourceId}".`,
      "Inbound rules → Edit inbound rules.",
      "Remove the rule allowing all traffic from 0.0.0.0/0.",
      "Add specific rules for only required ports and sources.",
      "Save rules.",
    ],
    cli: `\
SG_ID="${resourceId}"

# Remove all-traffic inbound rule
aws ec2 revoke-security-group-ingress \\
  --group-id "$SG_ID" \\
  --protocol -1 --cidr 0.0.0.0/0

aws ec2 revoke-security-group-ingress \\
  --group-id "$SG_ID" \\
  --ip-permissions '[{"IpProtocol":"-1","Ipv6Ranges":[{"CidrIpv6":"::/0"}]}]'

# Add only required rules (example: HTTPS from internal)
aws ec2 authorize-security-group-ingress \\
  --group-id "$SG_ID" \\
  --protocol tcp --port 443 \\
  --cidr 10.0.0.0/8

# Verify
aws ec2 describe-security-groups \\
  --group-ids "$SG_ID" \\
  --query 'SecurityGroups[0].IpPermissions'`,
    terraform: `\
resource "aws_security_group" "fix" {
  # Remove any ingress block with protocol="-1" cidr=0.0.0.0/0
  # Replace with specific rules:

  ingress {
    description = "HTTPS from internal"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}`,
  }),

  // ec2_root_ebs_encrypted — EC2 root EBS volume not encrypted
  ec2_root_ebs_encrypted: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Instances → select "${resourceId}".`,
      "Storage tab → note the root volume ID.",
      "Stop the instance → create snapshot of root volume.",
      "Copy snapshot with encryption → create volume from encrypted snapshot.",
      "Detach old root volume → attach encrypted volume as /dev/xvda.",
      "Start the instance.",
    ],
    cli: `\
INSTANCE_ID="${resourceId}"
${reg(region)}

# Get root volume
ROOT_VOL=$(aws ec2 describe-instances \\
  --instance-ids "$INSTANCE_ID" \\
  --region "$REGION" \\
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[?DeviceName==\`/dev/xvda\`].Ebs.VolumeId' \\
  --output text)

# Stop instance
aws ec2 stop-instances --instance-ids "$INSTANCE_ID" --region "$REGION"
aws ec2 wait instance-stopped --instance-ids "$INSTANCE_ID" --region "$REGION"

# Snapshot → encrypt → new volume
SNAP=$(aws ec2 create-snapshot --volume-id "$ROOT_VOL" --region "$REGION" --query SnapshotId --output text)
aws ec2 wait snapshot-completed --snapshot-ids "$SNAP" --region "$REGION"

ENC_SNAP=$(aws ec2 copy-snapshot --source-region "$REGION" --source-snapshot-id "$SNAP" --encrypted --region "$REGION" --query SnapshotId --output text)
aws ec2 wait snapshot-completed --snapshot-ids "$ENC_SNAP" --region "$REGION"

AZ=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" --query 'Reservations[0].Instances[0].Placement.AvailabilityZone' --output text)
NEW_VOL=$(aws ec2 create-volume --snapshot-id "$ENC_SNAP" --encrypted --availability-zone "$AZ" --region "$REGION" --query VolumeId --output text)

# Swap volumes
aws ec2 detach-volume --volume-id "$ROOT_VOL" --region "$REGION"
aws ec2 wait volume-available --volume-ids "$ROOT_VOL" --region "$REGION"
aws ec2 attach-volume --volume-id "$NEW_VOL" --instance-id "$INSTANCE_ID" --device /dev/xvda --region "$REGION"
aws ec2 start-instances --instance-ids "$INSTANCE_ID" --region "$REGION"`,
    terraform: `\
# Enable default EBS encryption to prevent future issues:
resource "aws_ebs_encryption_by_default" "fix" {
  enabled = true
}

# For existing instances, re-create with encrypted root:
resource "aws_instance" "fix" {
  root_block_device {
    encrypted = true
  }
}`,
  }),

  // ec2_no_admin_role — EC2 instance has admin IAM role
  ec2_no_admin_role: ({ resourceId, region, accountId }) => ({
    console: [
      "NOTE: The goal is not to remove admin capability — it is to stop granting permanent AdministratorAccess directly to an instance role.",
      "Path A (regular EC2): IAM → Roles → find the instance role → detach AdministratorAccess → create a customer-managed policy listing only the specific services this instance calls → attach it.",
      "Path B (management/bastion host): Follow the same assumable role pattern as iam_no_admin_access — create a CloudLineAdminRole with AdministratorAccess and a trust policy for this instance's role → the instance assumes it only when needed via sts:AssumeRole.",
      `EC2 console → Instances → select "${resourceId}" → Actions → Security → Modify IAM role → switch to the scoped role.`,
    ],
    cli: `\
INSTANCE_ID="${resourceId}"
ACCOUNT_ID="${accountId}"
${reg(region)}

# Check what the current role is
CURRENT_ROLE=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --region "$REGION" --query 'Reservations[0].Instances[0].IamInstanceProfile.Arn' --output text)
echo "Current instance profile: $CURRENT_ROLE"
ROLE_NAME=$(echo "$CURRENT_ROLE" | awk -F/ '{print $NF}')

# List what this role currently does (what services it calls)
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue="$ROLE_NAME" --region "$REGION" --query 'Events[].EventName' --output text | tr '\\t' '\\n' | sort -u

# Path A: Create a scoped role with only required actions (replace example actions)
cat > /tmp/ec2-scoped-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "arn:aws:s3:::your-bucket/*" },
    { "Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:PutLogEvents"], "Resource": "*" }
  ]
}
EOF

aws iam create-role --role-name "$ROLE_NAME-scoped" --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam put-role-policy --role-name "$ROLE_NAME-scoped" --policy-name "scoped-access" --policy-document file:///tmp/ec2-scoped-policy.json
aws iam create-instance-profile --instance-profile-name "$ROLE_NAME-scoped"
aws iam add-role-to-instance-profile --instance-profile-name "$ROLE_NAME-scoped" --role-name "$ROLE_NAME-scoped"

# Replace the instance profile
ASSOC_ID=$(aws ec2 describe-iam-instance-profile-associations --filters Name=instance-id,Values="$INSTANCE_ID" --query 'IamInstanceProfileAssociations[0].AssociationId' --output text)
aws ec2 replace-iam-instance-profile-association --association-id "$ASSOC_ID" --iam-instance-profile Name="$ROLE_NAME-scoped"
echo "Role replaced. Verify with:"
aws ec2 describe-iam-instance-profile-associations --filters Name=instance-id,Values="$INSTANCE_ID" --query 'IamInstanceProfileAssociations[0].IamInstanceProfile.Arn'`,
    terraform: `\
resource "aws_iam_role" "scoped" {
  name = "ec2-least-privilege"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "scoped" {
  role = aws_iam_role.scoped.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["<specific-resources>"]
    }]
  })
}

resource "aws_iam_instance_profile" "scoped" {
  role = aws_iam_role.scoped.name
}`,
  }),

  // ec2_snapshot_private — EBS snapshot publicly accessible
  ec2_snapshot_private: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Snapshots → select "${resourceId}".`,
      "Actions → Modify permissions.",
      "Change from Public to Private.",
      "Save.",
    ],
    cli: `\
SNAP_ID="${resourceId}"
${reg(region)}

aws ec2 modify-snapshot-attribute \\
  --snapshot-id "$SNAP_ID" \\
  --attribute createVolumePermission \\
  --operation-type remove \\
  --group-names all \\
  --region "$REGION"

# Verify
aws ec2 describe-snapshot-attribute \\
  --snapshot-id "$SNAP_ID" \\
  --attribute createVolumePermission \\
  --region "$REGION"`,
    terraform: `\
# Block public snapshot sharing at account level:
resource "aws_ebs_snapshot_block_public_access" "fix" {
  state = "block-all-sharing"
}`,
  }),

  // ec2_termination_protection — Production EC2 termination protection off
  ec2_termination_protection: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Instances → select "${resourceId}".`,
      "Actions → Instance settings → Change termination protection.",
      "Enable → Save.",
    ],
    cli: `\
INSTANCE_ID="${resourceId}"
${reg(region)}

aws ec2 modify-instance-attribute \\
  --instance-id "$INSTANCE_ID" \\
  --disable-api-termination \\
  --region "$REGION"

# Verify
aws ec2 describe-instance-attribute \\
  --instance-id "$INSTANCE_ID" \\
  --attribute disableApiTermination \\
  --region "$REGION"`,
    terraform: `\
resource "aws_instance" "fix" {
  disable_api_termination = true
}`,
  }),

  // ec2_stopped_cleanup — EC2 instance stopped > 90 days
  ec2_stopped_cleanup: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Instances → select "${resourceId}".`,
      "Instance has been stopped for > 90 days.",
      "If no longer needed: Actions → Instance state → Terminate.",
      "If needed later: create an AMI first, then terminate.",
    ],
    cli: `\
INSTANCE_ID="${resourceId}"
${reg(region)}

# Confirm stopped state and duration
aws ec2 describe-instances \\
  --instance-ids "$INSTANCE_ID" \\
  --region "$REGION" \\
  --query 'Reservations[0].Instances[0].{State:State.Name,StoppedAt:StateTransitionReason}'

# Create AMI backup before terminating
aws ec2 create-image \\
  --instance-id "$INSTANCE_ID" \\
  --name "backup-${resourceId}" \\
  --no-reboot \\
  --region "$REGION"

# Terminate after backup
# aws ec2 terminate-instances \\
#   --instance-ids "$INSTANCE_ID" --region "$REGION"`,
    terraform: `\
# Instance ${resourceId} has been stopped > 90 days.
# Remove the resource from Terraform config and run apply
# to terminate it. Create an AMI first if needed:

resource "aws_ami_from_instance" "backup" {
  name               = "backup-${resourceId}"
  source_instance_id = "${resourceId}"
}`,
  }),

  // ec2_no_ipv6_all_ports — Security group allows all IPv6 inbound
  ec2_no_ipv6_all_ports: ({ resourceId }) => ({
    console: [
      `Open EC2 console → Security Groups → select "${resourceId}".`,
      "Inbound rules → Edit inbound rules.",
      "Remove rules allowing all traffic from ::/0.",
      "Add specific IPv6 rules for required ports only.",
      "Save rules.",
    ],
    cli: `\
SG_ID="${resourceId}"

# Remove all-traffic IPv6 inbound
aws ec2 revoke-security-group-ingress \\
  --group-id "$SG_ID" \\
  --ip-permissions '[{"IpProtocol":"-1","Ipv6Ranges":[{"CidrIpv6":"::/0"}]}]'

# Verify
aws ec2 describe-security-groups \\
  --group-ids "$SG_ID" \\
  --query 'SecurityGroups[0].IpPermissions'`,
    terraform: `\
# Security Group: ${resourceId}
# Remove any ingress rule with ipv6_cidr_blocks = ["::/0"]
# and protocol = "-1". Replace with specific rules.

resource "aws_security_group_rule" "https_ipv6" {
  type              = "ingress"
  security_group_id = "${resourceId}"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  ipv6_cidr_blocks  = ["<YOUR_IPV6_CIDR>"]
}`,
  }),

  // ec2_instance_profile — EC2 instance has no IAM instance profile
  ec2_instance_profile: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Instances → select "${resourceId}".`,
      "Actions → Security → Modify IAM role.",
      "Select an appropriate IAM role → Update.",
    ],
    cli: `\
INSTANCE_ID="${resourceId}"
${reg(region)}

# Create a minimal instance profile if needed:
# aws iam create-role --role-name ec2-base-role \\
#   --assume-role-policy-document '{
#     "Version":"2012-10-17",
#     "Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]
#   }'
# aws iam attach-role-policy --role-name ec2-base-role \\
#   --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
# aws iam create-instance-profile --instance-profile-name ec2-base
# aws iam add-role-to-instance-profile \\
#   --instance-profile-name ec2-base --role-name ec2-base-role

aws ec2 associate-iam-instance-profile \\
  --instance-id "$INSTANCE_ID" \\
  --iam-instance-profile Name=ec2-base \\
  --region "$REGION"

# Verify
aws ec2 describe-instances \\
  --instance-ids "$INSTANCE_ID" \\
  --region "$REGION" \\
  --query 'Reservations[0].Instances[0].IamInstanceProfile'`,
    terraform: `\
resource "aws_iam_role" "ec2_base" {
  name = "ec2-base-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.ec2_base.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_base" {
  role = aws_iam_role.ec2_base.name
}

resource "aws_instance" "fix" {
  iam_instance_profile = aws_iam_instance_profile.ec2_base.name
}`,
  }),

  // ec2_no_open_443_internal — Internal SG allows HTTPS from public
  ec2_no_open_443_internal: ({ resourceId }) => ({
    console: [
      `Open EC2 console → Security Groups → select "${resourceId}".`,
      "This SG is tagged 'internal' but allows HTTPS from 0.0.0.0/0.",
      "Inbound rules → Edit → restrict port 443 source to internal CIDRs.",
      "Save rules.",
    ],
    cli: `\
SG_ID="${resourceId}"

# Remove public HTTPS
aws ec2 revoke-security-group-ingress \\
  --group-id "$SG_ID" \\
  --protocol tcp --port 443 --cidr 0.0.0.0/0

# Add internal-only HTTPS
aws ec2 authorize-security-group-ingress \\
  --group-id "$SG_ID" \\
  --protocol tcp --port 443 \\
  --cidr 10.0.0.0/8

# Verify
aws ec2 describe-security-groups \\
  --group-ids "$SG_ID" \\
  --query 'SecurityGroups[0].IpPermissions'`,
    terraform: `\
resource "aws_security_group_rule" "internal_https" {
  type              = "ingress"
  security_group_id = "${resourceId}"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
  description       = "HTTPS from internal only"
}`,
  }),

  // ec2_no_unrestricted_outbound — Production SG allows all outbound
  ec2_no_unrestricted_outbound: ({ resourceId }) => ({
    console: [
      `Open EC2 console → Security Groups → select "${resourceId}".`,
      "Outbound rules → Edit outbound rules.",
      "Remove the 'All traffic to 0.0.0.0/0' rule.",
      "Add specific outbound rules (HTTPS, DNS, etc.).",
      "Save rules.",
    ],
    cli: `\
SG_ID="${resourceId}"

# Remove unrestricted outbound
aws ec2 revoke-security-group-egress \\
  --group-id "$SG_ID" \\
  --protocol -1 --cidr 0.0.0.0/0

# Add specific outbound rules
aws ec2 authorize-security-group-egress \\
  --group-id "$SG_ID" \\
  --protocol tcp --port 443 --cidr 0.0.0.0/0

aws ec2 authorize-security-group-egress \\
  --group-id "$SG_ID" \\
  --protocol udp --port 53 --cidr 0.0.0.0/0

aws ec2 authorize-security-group-egress \\
  --group-id "$SG_ID" \\
  --protocol tcp --port 53 --cidr 0.0.0.0/0

# Verify
aws ec2 describe-security-groups \\
  --group-ids "$SG_ID" \\
  --query 'SecurityGroups[0].IpPermissionsEgress'`,
    terraform: `\
resource "aws_security_group" "fix" {
  egress {
    description = "HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "DNS outbound"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`,
  }),

  // ec2_no_key_pairs_prod — Production EC2 uses key pair instead of SSM
  ec2_no_key_pairs_prod: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Instances → select "${resourceId}".`,
      "Install SSM Agent on the instance (pre-installed on Amazon Linux 2+).",
      "Attach IAM role with AmazonSSMManagedInstanceCore policy.",
      "Use Session Manager instead of SSH for access.",
      "Remove SSH key pair and close port 22 in security group.",
    ],
    cli: `\
INSTANCE_ID="${resourceId}"
${reg(region)}

# Attach SSM policy to the instance role
ROLE=$(aws ec2 describe-instances \\
  --instance-ids "$INSTANCE_ID" \\
  --region "$REGION" \\
  --query 'Reservations[0].Instances[0].IamInstanceProfile.Arn' \\
  --output text)

echo "Ensure role has AmazonSSMManagedInstanceCore attached"

# Start a Session Manager session (replaces SSH)
# aws ssm start-session \\
#   --target "$INSTANCE_ID" --region "$REGION"

# After SSM is working, close port 22 in security group
# aws ec2 revoke-security-group-ingress \\
#   --group-id <SG_ID> --protocol tcp --port 22 --cidr 0.0.0.0/0`,
    terraform: `\
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = var.instance_role_name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Launch without key pair:
resource "aws_instance" "fix" {
  key_name = null  # no SSH key
  # Use SSM Session Manager for access
}`,
  }),

  // ec2_no_deprecated_types — EC2 using deprecated instance type
  ec2_no_deprecated_types: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Instances → select "${resourceId}".`,
      "Actions → Instance settings → Change instance type.",
      "Select a current-generation type (e.g. t3.micro).",
      "Stop the instance first if required → Apply.",
    ],
    cli: `\
INSTANCE_ID="${resourceId}"
${reg(region)}

# Check current type
aws ec2 describe-instances \\
  --instance-ids "$INSTANCE_ID" \\
  --region "$REGION" \\
  --query 'Reservations[0].Instances[0].InstanceType'

# Stop → change type → start
aws ec2 stop-instances \\
  --instance-ids "$INSTANCE_ID" --region "$REGION"
aws ec2 wait instance-stopped \\
  --instance-ids "$INSTANCE_ID" --region "$REGION"

aws ec2 modify-instance-attribute \\
  --instance-id "$INSTANCE_ID" \\
  --instance-type '{"Value":"t3.micro"}' \\
  --region "$REGION"

aws ec2 start-instances \\
  --instance-ids "$INSTANCE_ID" --region "$REGION"`,
    terraform: `\
resource "aws_instance" "fix" {
  instance_type = "t3.micro"  # replace deprecated type
}`,
  }),

  // ec2_no_unused_eips — Unused Elastic IP not released
  ec2_no_unused_eips: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Elastic IPs → select "${resourceId}".`,
      "If not in use: Actions → Release Elastic IP address.",
      "Confirm release.",
    ],
    cli: `\
EIP_ALLOC="${resourceId}"
${reg(region)}

# Check if associated
aws ec2 describe-addresses \\
  --allocation-ids "$EIP_ALLOC" \\
  --region "$REGION" \\
  --query 'Addresses[0].{IP:PublicIp,InstanceId:InstanceId,AssociationId:AssociationId}'

# Release if unused
aws ec2 release-address \\
  --allocation-id "$EIP_ALLOC" \\
  --region "$REGION"`,
    terraform: `\
# Remove the unused aws_eip resource from config:
# resource "aws_eip" "unused" { ... }
# Run terraform apply to release it.`,
  }),

  // ec2_ami_private — Account-owned AMI publicly shared
  ec2_ami_private: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → AMIs → select "${resourceId}".`,
      "Actions → Edit AMI permissions.",
      "Change from Public to Private.",
      "Save.",
    ],
    cli: `\
AMI_ID="${resourceId}"
${reg(region)}

# Make AMI private
aws ec2 modify-image-attribute \\
  --image-id "$AMI_ID" \\
  --launch-permission '{"Remove":[{"Group":"all"}]}' \\
  --region "$REGION"

# Block public sharing at account level
aws ec2 enable-image-block-public-access \\
  --image-block-public-access-state block-new-sharing \\
  --region "$REGION"

# Verify
aws ec2 describe-image-attribute \\
  --image-id "$AMI_ID" \\
  --attribute launchPermission \\
  --region "$REGION"`,
    terraform: `\
# AMI: ${resourceId}
# Ensure the AMI is not publicly shared:

resource "aws_ami_launch_permission" "fix" {
  image_id = "${resourceId}"
  # Only share with specific accounts:
  account_id = "<TRUSTED_ACCOUNT_ID>"
}

# Block public AMI sharing at account level:
resource "aws_ec2_image_block_public_access" "fix" {
  state = "block-new-sharing"
}`,
  }),

  // db_rds_no_public_access — Insecure RDS configuration
  db_rds_no_public_access: ({ resourceId, region }) => ({
    console: [
      `Open RDS console → Databases → select "${resourceId}".`,
      "Modify → Connectivity: Public accessibility = No.",
      "Storage: enable encryption (requires snapshot restore if unencrypted).",
      "Enable Multi-AZ and deletion protection.",
      "Apply immediately.",
    ],
    cli: `\
DB_ID="${resourceId}"
${reg(region)}

# Disable public accessibility
aws rds modify-db-instance \\
  --db-instance-identifier "$DB_ID" \\
  --no-publicly-accessible \\
  --region "$REGION" \\
  --apply-immediately

# Enable Multi-AZ
aws rds modify-db-instance \\
  --db-instance-identifier "$DB_ID" \\
  --multi-az \\
  --region "$REGION" \\
  --apply-immediately

# Enable deletion protection
aws rds modify-db-instance \\
  --db-instance-identifier "$DB_ID" \\
  --deletion-protection \\
  --region "$REGION" \\
  --apply-immediately

# Verify
aws rds describe-db-instances \\
  --db-instance-identifier "$DB_ID" \\
  --region "$REGION" \\
  --query 'DBInstances[0].{Public:PubliclyAccessible,MultiAZ:MultiAZ,Encrypted:StorageEncrypted,Protected:DeletionProtection}'`,
    terraform: `\
# DB: ${resourceId}
# Import: terraform import aws_db_instance.fix ${resourceId}

resource "aws_db_instance" "fix" {
  identifier          = "${resourceId}"
  publicly_accessible = false
  multi_az            = true
  storage_encrypted   = true
  deletion_protection = true
  backup_retention_period = 7
  skip_final_snapshot     = false
}`,
  }),

  // db_rds_encryption — RDS storage not encrypted
  db_rds_encryption: ({ resourceId, region }) => ({
    console: [
      `Open RDS console → Databases → select "${resourceId}".`,
      "Encryption can only be enabled at creation or via snapshot restore.",
      "Take a snapshot → copy with encryption → restore to new instance.",
      "Update application connection string to the new endpoint.",
    ],
    cli: `\
DB_ID="${resourceId}"
${reg(region)}

# Create snapshot
aws rds create-db-snapshot \\
  --db-instance-identifier "$DB_ID" \\
  --db-snapshot-identifier "${resourceId}-pre-encrypt" \\
  --region "$REGION"
aws rds wait db-snapshot-available \\
  --db-snapshot-identifier "${resourceId}-pre-encrypt" --region "$REGION"

# Copy snapshot with encryption
aws rds copy-db-snapshot \\
  --source-db-snapshot-identifier "${resourceId}-pre-encrypt" \\
  --target-db-snapshot-identifier "${resourceId}-encrypted" \\
  --kms-key-id alias/aws/rds \\
  --region "$REGION"

# Restore from encrypted snapshot
# aws rds restore-db-instance-from-db-snapshot \\
#   --db-instance-identifier "${resourceId}-encrypted" \\
#   --db-snapshot-identifier "${resourceId}-encrypted" \\
#   --region "$REGION"`,
    terraform: `\
resource "aws_db_instance" "fix" {
  identifier        = "${resourceId}"
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}

resource "aws_kms_key" "rds" {
  description         = "RDS encryption"
  enable_key_rotation = true
}`,
  }),

  // db_rds_backup_retention — RDS backup retention < 7 days
  db_rds_backup_retention: ({ resourceId, region }) => ({
    console: [
      `Open RDS console → Databases → select "${resourceId}".`,
      "Modify → Backup retention period → set to 7 or more days.",
      "Apply immediately.",
    ],
    cli: `\
DB_ID="${resourceId}"
${reg(region)}

aws rds modify-db-instance \\
  --db-instance-identifier "$DB_ID" \\
  --backup-retention-period 7 \\
  --region "$REGION" \\
  --apply-immediately`,
    terraform: `\
resource "aws_db_instance" "fix" {
  identifier              = "${resourceId}"
  backup_retention_period = 7
}`,
  }),

  // db_rds_multi_az — Production RDS not Multi-AZ
  db_rds_multi_az: ({ resourceId, region }) => ({
    console: [
      `Open RDS console → Databases → select "${resourceId}".`,
      "Modify → enable Multi-AZ deployment.",
      "Apply immediately (brief failover expected).",
    ],
    cli: `\
DB_ID="${resourceId}"
${reg(region)}

aws rds modify-db-instance \\
  --db-instance-identifier "$DB_ID" \\
  --multi-az \\
  --region "$REGION" \\
  --apply-immediately`,
    terraform: `\
resource "aws_db_instance" "fix" {
  identifier = "${resourceId}"
  multi_az   = true
}`,
  }),

  // db_rds_deletion_protection — Production RDS deletion protection off
  db_rds_deletion_protection: ({ resourceId, region }) => ({
    console: [
      `Open RDS console → Databases → select "${resourceId}".`,
      "Modify → enable Deletion protection.",
      "Apply immediately.",
    ],
    cli: `\
DB_ID="${resourceId}"
${reg(region)}

aws rds modify-db-instance \\
  --db-instance-identifier "$DB_ID" \\
  --deletion-protection \\
  --region "$REGION" \\
  --apply-immediately`,
    terraform: `\
resource "aws_db_instance" "fix" {
  identifier          = "${resourceId}"
  deletion_protection = true
}`,
  }),

  // db_rds_iam_auth — RDS IAM database authentication not enabled
  db_rds_iam_auth: ({ resourceId, region }) => ({
    console: [
      `Open RDS console → Databases → select "${resourceId}".`,
      "Modify → enable IAM database authentication.",
      "Apply immediately.",
    ],
    cli: `\
DB_ID="${resourceId}"
${reg(region)}

aws rds modify-db-instance \\
  --db-instance-identifier "$DB_ID" \\
  --enable-iam-database-authentication \\
  --region "$REGION" \\
  --apply-immediately`,
    terraform: `\
resource "aws_db_instance" "fix" {
  identifier                          = "${resourceId}"
  iam_database_authentication_enabled = true
}`,
  }),

  // db_rds_snapshot_private — RDS snapshot publicly accessible
  db_rds_snapshot_private: ({ resourceId, region }) => ({
    console: [
      `Open RDS console → Snapshots → select "${resourceId}".`,
      "Actions → Share snapshot.",
      "Change from Public to Private.",
      "Save.",
    ],
    cli: `\
SNAP_ID="${resourceId}"
${reg(region)}

aws rds modify-db-snapshot-attribute \\
  --db-snapshot-identifier "$SNAP_ID" \\
  --attribute-name restore \\
  --values-to-remove all \\
  --region "$REGION"

# Verify
aws rds describe-db-snapshot-attributes \\
  --db-snapshot-identifier "$SNAP_ID" \\
  --region "$REGION"`,
    terraform: `\
# Ensure no public sharing on snapshots.
# Remove any aws_db_snapshot sharing resources
# that reference "all".`,
  }),

  // db_rds_log_exports — RDS CloudWatch log exports not enabled
  db_rds_log_exports: ({ resourceId, region }) => ({
    console: [
      `Open RDS console → Databases → select "${resourceId}".`,
      "Modify → Log exports → enable all relevant log types.",
      "Apply immediately.",
    ],
    cli: `\
DB_ID="${resourceId}"
${reg(region)}

# For MySQL/MariaDB:
aws rds modify-db-instance \\
  --db-instance-identifier "$DB_ID" \\
  --cloudwatch-logs-export-configuration \\
    '{"EnableLogTypes":["audit","error","general","slowquery"]}' \\
  --region "$REGION" \\
  --apply-immediately

# For PostgreSQL use: ["postgresql","upgrade"]`,
    terraform: `\
resource "aws_db_instance" "fix" {
  identifier                    = "${resourceId}"
  enabled_cloudwatch_logs_exports = [
    "audit", "error", "general", "slowquery",
  ]
}`,
  }),

  // db_rds_auto_minor_upgrade — RDS auto minor version upgrade disabled
  db_rds_auto_minor_upgrade: ({ resourceId, region }) => ({
    console: [
      `Open RDS console → Databases → select "${resourceId}".`,
      "Modify → enable Auto minor version upgrade.",
      "Apply immediately.",
    ],
    cli: `\
DB_ID="${resourceId}"
${reg(region)}

aws rds modify-db-instance \\
  --db-instance-identifier "$DB_ID" \\
  --auto-minor-version-upgrade \\
  --region "$REGION" \\
  --apply-immediately`,
    terraform: `\
resource "aws_db_instance" "fix" {
  identifier                = "${resourceId}"
  auto_minor_version_upgrade = true
}`,
  }),

  // db_rds_no_default_port — RDS using default database port
  db_rds_no_default_port: ({ resourceId, region }) => ({
    console: [
      `RDS instance "${resourceId}" uses a default port (3306/5432/etc).`,
      "Changing ports requires creating a new instance or restoring from snapshot.",
      "Update security groups and application connection strings.",
    ],
    cli: `\
DB_ID="${resourceId}"
${reg(region)}

# Check current port
aws rds describe-db-instances \\
  --db-instance-identifier "$DB_ID" \\
  --region "$REGION" \\
  --query 'DBInstances[0].Endpoint.Port'

# Change port (causes brief outage)
aws rds modify-db-instance \\
  --db-instance-identifier "$DB_ID" \\
  --db-port-number 5433 \\
  --region "$REGION" \\
  --apply-immediately`,
    terraform: `\
resource "aws_db_instance" "fix" {
  identifier = "${resourceId}"
  port       = 5433  # non-default port
}`,
  }),

  // db_dynamodb_kms_encryption — DynamoDB encryption not using KMS
  db_dynamodb_kms_encryption: ({ resourceId, region }) => ({
    console: [
      `Open DynamoDB console → Tables → select "${resourceId}".`,
      "Additional settings → Encryption → Manage encryption.",
      "Change to Customer managed KMS key.",
      "Select or create a key → Save.",
    ],
    cli: `\
TABLE="${resourceId}"
${reg(region)}

aws dynamodb update-table \\
  --table-name "$TABLE" \\
  --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=<KMS_KEY_ARN> \\
  --region "$REGION"`,
    terraform: `\
resource "aws_dynamodb_table" "fix" {
  name = "${resourceId}"
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.dynamo.arn
  }
}

resource "aws_kms_key" "dynamo" {
  description         = "DynamoDB encryption"
  enable_key_rotation = true
}`,
  }),

  // db_dynamodb_pitr — DynamoDB PITR not enabled
  db_dynamodb_pitr: ({ resourceId, region }) => ({
    console: [
      `Open DynamoDB console → Tables → select "${resourceId}".`,
      "Backups tab → Point-in-time recovery → Edit.",
      "Enable → Save.",
    ],
    cli: `\
TABLE="${resourceId}"
${reg(region)}

aws dynamodb update-continuous-backups \\
  --table-name "$TABLE" \\
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true \\
  --region "$REGION"`,
    terraform: `\
resource "aws_dynamodb_table" "fix" {
  name = "${resourceId}"
  point_in_time_recovery { enabled = true }
}`,
  }),

  // db_dynamodb_deletion_protection — Production DynamoDB deletion protection off
  db_dynamodb_deletion_protection: ({ resourceId, region }) => ({
    console: [
      `Open DynamoDB console → Tables → select "${resourceId}".`,
      "Additional settings → enable Deletion protection.",
      "Save.",
    ],
    cli: `\
TABLE="${resourceId}"
${reg(region)}

aws dynamodb update-table \\
  --table-name "$TABLE" \\
  --deletion-protection-enabled \\
  --region "$REGION"`,
    terraform: `\
resource "aws_dynamodb_table" "fix" {
  name                = "${resourceId}"
  deletion_protection_enabled = true
}`,
  }),

  // db_dynamodb_no_public_policy — DynamoDB resource policy allows public access
  db_dynamodb_no_public_policy: ({ resourceId, region }) => ({
    console: [
      `Open DynamoDB console → Tables → select "${resourceId}".`,
      "Access control → Resource policy → Edit.",
      "Remove statements with Principal: '*' and no conditions.",
      "Save.",
    ],
    cli: `\
TABLE="${resourceId}"
${reg(region)}

# View current policy
aws dynamodb get-resource-policy \\
  --resource-arn "arn:aws:dynamodb:$REGION:$(aws sts get-caller-identity --query Account --output text):table/$TABLE"

# Delete the public policy
aws dynamodb delete-resource-policy \\
  --resource-arn "arn:aws:dynamodb:$REGION:$(aws sts get-caller-identity --query Account --output text):table/$TABLE"`,
    terraform: `\
resource "aws_dynamodb_resource_policy" "fix" {
  resource_arn = aws_dynamodb_table.main.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.allowed_role_arn }
      Action    = ["dynamodb:GetItem", "dynamodb:Query"]
      Resource  = "*"
    }]
  })
}`,
  }),

  // db_dynamodb_auto_scaling — Production DynamoDB auto-scaling not configured
  db_dynamodb_auto_scaling: ({ resourceId, region }) => ({
    console: [
      `Open DynamoDB console → Tables → select "${resourceId}".`,
      "Additional settings → Read/write capacity.",
      "Change to On-demand or configure Auto Scaling.",
    ],
    cli: `\
TABLE="${resourceId}"
${reg(region)}

# Switch to on-demand (simplest)
aws dynamodb update-table \\
  --table-name "$TABLE" \\
  --billing-mode PAY_PER_REQUEST \\
  --region "$REGION"`,
    terraform: `\
resource "aws_dynamodb_table" "fix" {
  name         = "${resourceId}"
  billing_mode = "PAY_PER_REQUEST"
}`,
  }),

  // db_aurora_no_public_access — Aurora cluster publicly accessible
  db_aurora_no_public_access: ({ resourceId, region }) => ({
    console: [
      `Open RDS console → Databases → select Aurora cluster "${resourceId}".`,
      "Select each instance → Modify.",
      "Set Public accessibility = No.",
      "Apply immediately.",
    ],
    cli: `\
CLUSTER="${resourceId}"
${reg(region)}

# Get cluster instances
INSTANCES=$(aws rds describe-db-clusters \\
  --db-cluster-identifier "$CLUSTER" \\
  --region "$REGION" \\
  --query 'DBClusters[0].DBClusterMembers[].DBInstanceIdentifier' --output text)

for INST in $INSTANCES; do
  aws rds modify-db-instance \\
    --db-instance-identifier "$INST" \\
    --no-publicly-accessible \\
    --region "$REGION" \\
    --apply-immediately
done`,
    terraform: `\
resource "aws_rds_cluster_instance" "fix" {
  cluster_identifier  = "${resourceId}"
  publicly_accessible = false
}`,
  }),

  // db_aurora_encryption — Aurora storage not encrypted
  db_aurora_encryption: ({ resourceId, region }) => ({
    console: [
      "Aurora encryption is set at cluster creation.",
      `Take a snapshot of cluster "${resourceId}".`,
      "Copy snapshot with encryption → restore to new cluster.",
      "Update application endpoint.",
    ],
    cli: `\
CLUSTER="${resourceId}"
${reg(region)}

# Snapshot → encrypted copy → restore
aws rds create-db-cluster-snapshot \\
  --db-cluster-identifier "$CLUSTER" \\
  --db-cluster-snapshot-identifier "${resourceId}-pre-encrypt" \\
  --region "$REGION"

# Copy with encryption
# aws rds copy-db-cluster-snapshot \\
#   --source-db-cluster-snapshot-identifier "${resourceId}-pre-encrypt" \\
#   --target-db-cluster-snapshot-identifier "${resourceId}-encrypted" \\
#   --kms-key-id <KMS_KEY_ARN> \\
#   --region "$REGION"

# Restore
# aws rds restore-db-cluster-from-snapshot \\
#   --db-cluster-identifier "${resourceId}-encrypted" \\
#   --snapshot-identifier "${resourceId}-encrypted" \\
#   --region "$REGION"`,
    terraform: `\
resource "aws_rds_cluster" "fix" {
  cluster_identifier  = "${resourceId}"
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.aurora.arn
}`,
  }),

  // db_aurora_deletion_protection — Production Aurora deletion protection off
  db_aurora_deletion_protection: ({ resourceId, region }) => ({
    console: [
      `Open RDS console → Databases → select "${resourceId}".`,
      "Modify → enable Deletion protection.",
      "Apply immediately.",
    ],
    cli: `\
CLUSTER="${resourceId}"
${reg(region)}

aws rds modify-db-cluster \\
  --db-cluster-identifier "$CLUSTER" \\
  --deletion-protection \\
  --region "$REGION" \\
  --apply-immediately`,
    terraform: `\
resource "aws_rds_cluster" "fix" {
  cluster_identifier  = "${resourceId}"
  deletion_protection = true
}`,
  }),

  // db_aurora_backtrack — Aurora backtrack not enabled for critical clusters
  db_aurora_backtrack: ({ resourceId, region }) => ({
    console: [
      "Backtrack can only be enabled at cluster creation (MySQL-compatible only).",
      `Create a new Aurora cluster with backtrack enabled to replace "${resourceId}".`,
      "Restore data from snapshot.",
    ],
    cli: `\
CLUSTER="${resourceId}"
${reg(region)}

# Backtrack must be set at creation. Create new cluster:
# aws rds create-db-cluster \\
#   --db-cluster-identifier "${resourceId}-bt" \\
#   --engine aurora-mysql \\
#   --backtrack-window 72 \\
#   --region "$REGION"

echo "Backtrack requires cluster recreation for MySQL-compatible Aurora"`,
    terraform: `\
resource "aws_rds_cluster" "fix" {
  cluster_identifier = "${resourceId}"
  engine             = "aurora-mysql"
  backtrack_window   = 72  # hours
}`,
  }),

  // db_aurora_iam_auth — Aurora IAM authentication not enabled
  db_aurora_iam_auth: ({ resourceId, region }) => ({
    console: [
      `Open RDS console → Databases → select "${resourceId}".`,
      "Modify → enable IAM database authentication.",
      "Apply immediately.",
    ],
    cli: `\
CLUSTER="${resourceId}"
${reg(region)}

aws rds modify-db-cluster \\
  --db-cluster-identifier "$CLUSTER" \\
  --enable-iam-database-authentication \\
  --region "$REGION" \\
  --apply-immediately`,
    terraform: `\
resource "aws_rds_cluster" "fix" {
  cluster_identifier                  = "${resourceId}"
  iam_database_authentication_enabled = true
}`,
  }),

  // iam_inactive_user — Unused IAM credentials active
  iam_inactive_user: ({ resourceId }) => ({
    console: [
      `Open IAM console → Users → select "${resourceId}".`,
      "Security credentials tab → Access keys.",
      "For keys unused > 90 days: click Deactivate, then Delete.",
    ],
    cli: `\
USERNAME="${resourceId}"

# List all access keys with last-used dates
aws iam list-access-keys --user-name "$USERNAME"

# Check last-used date for a specific key (replace KEY_ID)
# aws iam get-access-key-last-used --access-key-id <KEY_ID>

# Deactivate the key (replace KEY_ID)
# aws iam update-access-key \\
#   --user-name "$USERNAME" \\
#   --access-key-id <KEY_ID> \\
#   --status Inactive

# Delete after confirming it is safe (replace KEY_ID)
# aws iam delete-access-key \\
#   --user-name "$USERNAME" \\
#   --access-key-id <KEY_ID>

# Full credential report (shows last-used across all users)
aws iam generate-credential-report
aws iam get-credential-report \\
  --query Content --output text | base64 -d | grep "^$USERNAME,"`,
    terraform: `\
# Deactivate an existing key via Terraform
resource "aws_iam_access_key" "fix" {
  user   = "${resourceId}"
  status = "Inactive"
}

# Best practice: replace long-lived keys with IAM roles
resource "aws_iam_role" "app_role" {
  name = "${resourceId}-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}`,
  }),

  // s3_encryption — Encryption in transit disabled (S3)
  s3_encryption: ({ resourceId }) => ({
    console: [
      `Open S3 console → bucket "${resourceId}" → Permissions.`,
      "Bucket policy → Edit.",
      "Add a Deny statement where aws:SecureTransport is false.",
      "Save changes.",
    ],
    cli: `\
BUCKET="${resourceId}"

aws s3api put-bucket-policy \\
  --bucket "$BUCKET" \\
  --policy '{
    "Version":"2012-10-17",
    "Statement":[{
      "Sid":"DenyNonHTTPS",
      "Effect":"Deny",
      "Principal":"*",
      "Action":"s3:*",
      "Resource":[
        "arn:aws:s3:::${resourceId}",
        "arn:aws:s3:::${resourceId}/*"
      ],
      "Condition":{"Bool":{"aws:SecureTransport":"false"}}
    }]
  }'

# Verify
aws s3api get-bucket-policy --bucket "$BUCKET"`,
    terraform: `\
resource "aws_s3_bucket_policy" "https_only" {
  bucket = "${resourceId}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyNonHTTPS"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [
        "arn:aws:s3:::${resourceId}",
        "arn:aws:s3:::${resourceId}/*",
      ]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}`,
  }),

  // s3_ignore_public_acls — S3 IgnorePublicAcls not enabled
  s3_ignore_public_acls: ({ resourceId }) => ({
    console: [
      `Open S3 console → select bucket "${resourceId}".`,
      "Permissions tab → Block public access → Edit.",
      "Enable 'Ignore public ACLs'.",
      "Save changes → confirm.",
    ],
    cli: `\
BUCKET="${resourceId}"

aws s3api put-public-access-block \\
  --bucket "$BUCKET" \\
  --public-access-block-configuration \\
    IgnorePublicAcls=true

# Verify
aws s3api get-public-access-block --bucket "$BUCKET"`,
    terraform: `\
resource "aws_s3_bucket_public_access_block" "fix" {
  bucket             = "${resourceId}"
  ignore_public_acls = true
}`,
  }),

  // s3_block_public_policy — S3 BlockPublicPolicy not enabled
  s3_block_public_policy: ({ resourceId }) => ({
    console: [
      `Open S3 console → select bucket "${resourceId}".`,
      "Permissions tab → Block public access → Edit.",
      "Enable 'Block public bucket policies'.",
      "Save changes → confirm.",
    ],
    cli: `\
BUCKET="${resourceId}"

aws s3api put-public-access-block \\
  --bucket "$BUCKET" \\
  --public-access-block-configuration \\
    BlockPublicPolicy=true

# Verify
aws s3api get-public-access-block --bucket "$BUCKET"`,
    terraform: `\
resource "aws_s3_bucket_public_access_block" "fix" {
  bucket              = "${resourceId}"
  block_public_policy = true
}`,
  }),

  // s3_restrict_public_buckets — S3 RestrictPublicBuckets not enabled
  s3_restrict_public_buckets: ({ resourceId }) => ({
    console: [
      `Open S3 console → select bucket "${resourceId}".`,
      "Permissions tab → Block public access → Edit.",
      "Enable 'Restrict access to public buckets'.",
      "Save changes → confirm.",
    ],
    cli: `\
BUCKET="${resourceId}"

aws s3api put-public-access-block \\
  --bucket "$BUCKET" \\
  --public-access-block-configuration \\
    RestrictPublicBuckets=true

# Verify
aws s3api get-public-access-block --bucket "$BUCKET"`,
    terraform: `\
resource "aws_s3_bucket_public_access_block" "fix" {
  bucket                  = "${resourceId}"
  restrict_public_buckets = true
}`,
  }),

  // s3_versioning — Sensitive S3 bucket versioning disabled
  s3_versioning: ({ resourceId }) => ({
    console: [
      `Open S3 console → select bucket "${resourceId}".`,
      "Properties tab → Bucket Versioning → Edit.",
      "Select Enable → Save changes.",
    ],
    cli: `\
BUCKET="${resourceId}"

aws s3api put-bucket-versioning \\
  --bucket "$BUCKET" \\
  --versioning-configuration Status=Enabled

# Verify
aws s3api get-bucket-versioning --bucket "$BUCKET"`,
    terraform: `\
resource "aws_s3_bucket_versioning" "fix" {
  bucket = "${resourceId}"
  versioning_configuration {
    status = "Enabled"
  }
}`,
  }),

  // s3_mfa_delete — Sensitive S3 bucket MFA delete disabled
  s3_mfa_delete: ({ resourceId }) => ({
    console: [
      `Open S3 console → select bucket "${resourceId}".`,
      "MFA Delete can only be enabled via CLI by the root account.",
      "Ensure versioning is enabled first.",
    ],
    cli: `\
BUCKET="${resourceId}"

# MFA Delete must be enabled by the ROOT account
# Replace <MFA_SERIAL> and <MFA_CODE> with root MFA device
aws s3api put-bucket-versioning \\
  --bucket "$BUCKET" \\
  --versioning-configuration Status=Enabled,MFADelete=Enabled \\
  --mfa "<MFA_SERIAL> <MFA_CODE>"

# Verify
aws s3api get-bucket-versioning --bucket "$BUCKET"`,
    terraform: `\
# MFA Delete cannot be enabled via Terraform — it requires
# root account credentials with MFA. Enable via CLI, then
# import the state:

resource "aws_s3_bucket_versioning" "fix" {
  bucket = "${resourceId}"
  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Enabled"
  }
}`,
  }),

  // s3_access_logging — Production S3 bucket access logging disabled
  s3_access_logging: ({ resourceId }) => ({
    console: [
      `Open S3 console → select bucket "${resourceId}".`,
      "Properties tab → Server access logging → Edit.",
      "Enable logging → select a target bucket and prefix.",
      "Save changes.",
    ],
    cli: `\
BUCKET="${resourceId}"
LOG_BUCKET="${resourceId}-access-logs"

# Create log bucket if it doesn't exist
aws s3api create-bucket \\
  --bucket "$LOG_BUCKET" \\
  --region "$(aws configure get region)" \\
  --create-bucket-configuration \\
    LocationConstraint="$(aws configure get region)"

# Enable logging
aws s3api put-bucket-logging \\
  --bucket "$BUCKET" \\
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "'"$LOG_BUCKET"'",
      "TargetPrefix": "s3-access-logs/"
    }
  }'

# Verify
aws s3api get-bucket-logging --bucket "$BUCKET"`,
    terraform: `\
resource "aws_s3_bucket" "access_logs" {
  bucket = "${resourceId}-access-logs"
}

resource "aws_s3_bucket_logging" "fix" {
  bucket        = "${resourceId}"
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3-access-logs/"
}`,
  }),

  // s3_deny_http — S3 bucket policy allows unencrypted HTTP
  s3_deny_http: ({ resourceId }) => ({
    console: [
      `Open S3 console → bucket "${resourceId}" → Permissions.`,
      "Bucket policy → Edit.",
      "Add a Deny statement where aws:SecureTransport is false.",
      "Save changes.",
    ],
    cli: `\
BUCKET="${resourceId}"

aws s3api put-bucket-policy \\
  --bucket "$BUCKET" \\
  --policy '{
    "Version":"2012-10-17",
    "Statement":[{
      "Sid":"DenyHTTP",
      "Effect":"Deny",
      "Principal":"*",
      "Action":"s3:*",
      "Resource":[
        "arn:aws:s3:::'"$BUCKET"'",
        "arn:aws:s3:::'"$BUCKET"'/*"
      ],
      "Condition":{"Bool":{"aws:SecureTransport":"false"}}
    }]
  }'

# Verify
aws s3api get-bucket-policy --bucket "$BUCKET"`,
    terraform: `\
resource "aws_s3_bucket_policy" "https_only" {
  bucket = "${resourceId}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyHTTP"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [
        "arn:aws:s3:::${resourceId}",
        "arn:aws:s3:::${resourceId}/*",
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}`,
  }),

  // s3_no_public_read_acl — S3 ACL grants public read access
  s3_no_public_read_acl: ({ resourceId }) => ({
    console: [
      `Open S3 console → select bucket "${resourceId}".`,
      "Permissions tab → Access control list (ACL) → Edit.",
      "Remove 'Everyone (public access)' READ permission.",
      "Save changes.",
      "Enable Block Public Access to prevent future ACL changes.",
    ],
    cli: `\
BUCKET="${resourceId}"

# Remove public ACL grants by setting private ACL
aws s3api put-bucket-acl \\
  --bucket "$BUCKET" \\
  --acl private

# Block future public ACL grants
aws s3api put-public-access-block \\
  --bucket "$BUCKET" \\
  --public-access-block-configuration \\
    BlockPublicAcls=true,IgnorePublicAcls=true

# Verify
aws s3api get-bucket-acl --bucket "$BUCKET"`,
    terraform: `\
resource "aws_s3_bucket_acl" "fix" {
  bucket = "${resourceId}"
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "fix" {
  bucket              = "${resourceId}"
  block_public_acls   = true
  ignore_public_acls  = true
}`,
  }),

  // s3_no_public_write_acl — S3 ACL grants public write access
  s3_no_public_write_acl: ({ resourceId }) => ({
    console: [
      `Open S3 console → select bucket "${resourceId}".`,
      "Permissions tab → Access control list (ACL) → Edit.",
      "Remove 'Everyone (public access)' WRITE permission.",
      "Save changes.",
      "Enable Block Public Access to prevent future ACL changes.",
    ],
    cli: `\
BUCKET="${resourceId}"

# Remove public ACL grants
aws s3api put-bucket-acl \\
  --bucket "$BUCKET" \\
  --acl private

# Block future public ACL grants
aws s3api put-public-access-block \\
  --bucket "$BUCKET" \\
  --public-access-block-configuration \\
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Verify
aws s3api get-bucket-acl --bucket "$BUCKET"`,
    terraform: `\
resource "aws_s3_bucket_acl" "fix" {
  bucket = "${resourceId}"
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "fix" {
  bucket                  = "${resourceId}"
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}`,
  }),

  // s3_lifecycle_policy — Production S3 bucket has no lifecycle policy
  s3_lifecycle_policy: ({ resourceId }) => ({
    console: [
      `Open S3 console → select bucket "${resourceId}".`,
      "Management tab → Create lifecycle rule.",
      "Name the rule, apply to all objects.",
      "Transition to Standard-IA after 30 days, Glacier after 90.",
      "Expire noncurrent versions after 365 days.",
      "Create rule.",
    ],
    cli: `\
BUCKET="${resourceId}"

aws s3api put-bucket-lifecycle-configuration \\
  --bucket "$BUCKET" \\
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "lifecycle-policy",
      "Status": "Enabled",
      "Filter": {},
      "Transitions": [
        {"Days": 30, "StorageClass": "STANDARD_IA"},
        {"Days": 90, "StorageClass": "GLACIER"}
      ],
      "NoncurrentVersionExpiration": {
        "NoncurrentDays": 365
      }
    }]
  }'

# Verify
aws s3api get-bucket-lifecycle-configuration \\
  --bucket "$BUCKET"`,
    terraform: `\
resource "aws_s3_bucket_lifecycle_configuration" "fix" {
  bucket = "${resourceId}"

  rule {
    id     = "lifecycle-policy"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}`,
  }),

  // s3_object_lock — Compliance S3 bucket Object Lock disabled
  s3_object_lock: ({ resourceId }) => ({
    console: [
      "Object Lock must be enabled at bucket creation time.",
      "Create a new bucket with Object Lock enabled.",
      `Copy objects from "${resourceId}" to the new bucket.`,
      "Set a default retention policy (Governance or Compliance mode).",
      "Update references to point to the new bucket.",
    ],
    cli: `\
BUCKET="${resourceId}"
NEW_BUCKET="${resourceId}-locked"
REGION=$(aws configure get region)

# Object Lock can only be enabled at creation — create a new bucket
aws s3api create-bucket \\
  --bucket "$NEW_BUCKET" \\
  --region "$REGION" \\
  --create-bucket-configuration LocationConstraint="$REGION" \\
  --object-lock-enabled-for-bucket

# Set default retention (Compliance mode, 365 days)
aws s3api put-object-lock-configuration \\
  --bucket "$NEW_BUCKET" \\
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 365
      }
    }
  }'

# Copy objects from old bucket
aws s3 sync "s3://$BUCKET" "s3://$NEW_BUCKET"

# Verify
aws s3api get-object-lock-configuration \\
  --bucket "$NEW_BUCKET"`,
    terraform: `\
# Object Lock must be enabled at bucket creation.
# Create a new bucket with lock enabled:

resource "aws_s3_bucket" "locked" {
  bucket              = "${resourceId}-locked"
  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "fix" {
  bucket = aws_s3_bucket.locked.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }
}`,
  }),

  // s3_cors_wildcard — S3 CORS configuration allows all origins
  s3_cors_wildcard: ({ resourceId }) => ({
    console: [
      `If bucket "${resourceId}" serves public content (static website, public assets): wildcard CORS is correct. Ensure bucket policy allows only s3:GetObject (read-only public) and enable S3 access logging to monitor usage.`,
      "If this is NOT a public content bucket: S3 console → bucket → Permissions → CORS → Edit → replace '*' in AllowedOrigins with your specific domains (e.g., https://app.example.com).",
    ],
    cli: `\
BUCKET="${resourceId}"

# Check if this is a public static site or a private bucket
aws s3api get-bucket-website --bucket "$BUCKET" 2>/dev/null && echo "Static website hosting is ON" || echo "Not a static website bucket"
aws s3api get-bucket-policy --bucket "$BUCKET" --query 'Policy' --output text 2>/dev/null | python3 -m json.tool | grep -A3 "Principal"

# If NOT a public bucket: restrict CORS to known origins
aws s3api put-bucket-cors --bucket "$BUCKET" --cors-configuration '{
  "CORSRules": [{
    "AllowedOrigins": ["https://your-domain.com"],
    "AllowedMethods": ["GET", "HEAD"],
    "AllowedHeaders": ["Authorization"],
    "MaxAgeSeconds": 3600
  }]
}'

# If IS a public bucket: leave CORS, enable access logging instead
LOGS_BUCKET="$BUCKET-logs"
aws s3api put-bucket-logging --bucket "$BUCKET" --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"'"$LOGS_BUCKET"'","TargetPrefix":"access/"}}'

# Verify
aws s3api get-bucket-cors --bucket "$BUCKET"`,
    terraform: `\
resource "aws_s3_bucket_cors_configuration" "fix" {
  bucket = "${resourceId}"

  cors_rule {
    allowed_origins = ["https://your-domain.com"]
    allowed_methods = ["GET", "HEAD"]
    allowed_headers = ["*"]
    max_age_seconds = 3600
  }
}`,
  }),

  // s3_kms_encryption — Sensitive S3 bucket not using KMS encryption
  s3_kms_encryption: ({ resourceId }) => ({
    console: [
      `Open S3 console → select bucket "${resourceId}".`,
      "Properties tab → Default encryption → Edit.",
      "Change encryption type to AWS-KMS.",
      "Select a customer managed KMS key (or create one).",
      "Enable Bucket Key to reduce KMS costs.",
      "Save changes.",
    ],
    cli: `\
BUCKET="${resourceId}"

# Create a customer-managed KMS key (or use an existing one)
KEY_ID=$(aws kms create-key \\
  --description "S3 encryption key for $BUCKET" \\
  --query 'KeyMetadata.KeyId' --output text)

aws kms create-alias \\
  --alias-name "alias/s3-$BUCKET" \\
  --target-key-id "$KEY_ID"

# Set bucket encryption to use KMS
aws s3api put-bucket-encryption \\
  --bucket "$BUCKET" \\
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "'"$KEY_ID"'"
      },
      "BucketKeyEnabled": true
    }]
  }'

# Verify
aws s3api get-bucket-encryption --bucket "$BUCKET"`,
    terraform: `\
resource "aws_kms_key" "s3" {
  description         = "S3 encryption for ${resourceId}"
  enable_key_rotation = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "fix" {
  bucket = "${resourceId}"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}`,
  }),

  // s3_no_public_principal — S3 policy allows Principal:* without conditions
  s3_no_public_principal: ({ resourceId }) => ({
    console: [
      `Open S3 console → bucket "${resourceId}" → Permissions.`,
      "Bucket policy → Edit.",
      "Find statements with Principal: '*' and no Condition.",
      "Add conditions (e.g. aws:PrincipalOrgID, VPC endpoint).",
      "Or replace '*' with specific account/role ARNs.",
      "Save changes.",
    ],
    cli: `\
BUCKET="${resourceId}"

# Review current policy
aws s3api get-bucket-policy --bucket "$BUCKET" \\
  --query Policy --output text | python3 -m json.tool

# Replace with a scoped policy (example):
aws s3api put-bucket-policy \\
  --bucket "$BUCKET" \\
  --policy '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Principal":"*",
      "Action":"s3:GetObject",
      "Resource":"arn:aws:s3:::'"$BUCKET"'/*",
      "Condition":{
        "StringEquals":{
          "aws:PrincipalOrgID":"<YOUR_ORG_ID>"
        }
      }
    }]
  }'

# Verify
aws s3api get-bucket-policy --bucket "$BUCKET"`,
    terraform: `\
resource "aws_s3_bucket_policy" "fix" {
  bucket = "${resourceId}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::${resourceId}/*"
      Condition = {
        StringEquals = {
          "aws:PrincipalOrgID" = var.org_id
        }
      }
    }]
  })
}`,
  }),

  // s3_replication — High-criticality S3 bucket has no replication
  s3_replication: ({ resourceId, region }) => ({
    console: [
      `Open S3 console → select bucket "${resourceId}".`,
      "Management tab → Replication rules → Create rule.",
      "Select destination bucket (different region).",
      "Choose or create an IAM role for replication.",
      "Enable versioning on both source and destination.",
      "Save.",
    ],
    cli: `\
BUCKET="${resourceId}"
${reg(region)}
DEST_REGION="us-west-2"  # change to your DR region
DEST_BUCKET="${resourceId}-replica"

# Enable versioning on source (required for replication)
aws s3api put-bucket-versioning \\
  --bucket "$BUCKET" \\
  --versioning-configuration Status=Enabled

# Create destination bucket with versioning
aws s3api create-bucket \\
  --bucket "$DEST_BUCKET" \\
  --region "$DEST_REGION" \\
  --create-bucket-configuration LocationConstraint="$DEST_REGION"

aws s3api put-bucket-versioning \\
  --bucket "$DEST_BUCKET" \\
  --versioning-configuration Status=Enabled

# Configure replication (requires IAM role — see Terraform)
echo "Create an IAM role for S3 replication, then run:"
echo "aws s3api put-bucket-replication --bucket $BUCKET --replication-configuration file://replication.json"`,
    terraform: `\
resource "aws_s3_bucket" "replica" {
  bucket   = "${resourceId}-replica"
  provider = aws.dr_region
}

resource "aws_s3_bucket_versioning" "source" {
  bucket = "${resourceId}"
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_versioning" "replica" {
  bucket   = aws_s3_bucket.replica.id
  provider = aws.dr_region
  versioning_configuration { status = "Enabled" }
}

resource "aws_iam_role" "replication" {
  name = "s3-replication-${resourceId}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_s3_bucket_replication_configuration" "fix" {
  bucket = "${resourceId}"
  role   = aws_iam_role.replication.arn

  rule {
    id     = "replicate-all"
    status = "Enabled"
    destination {
      bucket        = aws_s3_bucket.replica.arn
      storage_class = "STANDARD"
    }
  }
}`,
  }),

  // s3_event_notifications — Security-monitored S3 bucket no event notifications
  s3_event_notifications: ({ resourceId, region }) => ({
    console: [
      `Open S3 console → select bucket "${resourceId}".`,
      "Properties tab → Event notifications → Create event notification.",
      "Name the event, select event types (e.g. s3:ObjectCreated:*).",
      "Choose destination (SNS topic, SQS queue, or Lambda).",
      "Save changes.",
    ],
    cli: `\
BUCKET="${resourceId}"
${reg(region)}

# Create an SNS topic for S3 events
TOPIC_ARN=$(aws sns create-topic \\
  --name "s3-events-${resourceId}" \\
  --region "$REGION" \\
  --query TopicArn --output text)

# Configure event notifications
aws s3api put-bucket-notification-configuration \\
  --bucket "$BUCKET" \\
  --notification-configuration '{
    "TopicConfigurations": [{
      "TopicArn": "'"$TOPIC_ARN"'",
      "Events": [
        "s3:ObjectCreated:*",
        "s3:ObjectRemoved:*"
      ]
    }]
  }'

# Verify
aws s3api get-bucket-notification-configuration \\
  --bucket "$BUCKET"`,
    terraform: `\
resource "aws_sns_topic" "s3_events" {
  name = "s3-events-${resourceId}"
}

resource "aws_s3_bucket_notification" "fix" {
  bucket = "${resourceId}"

  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events    = [
      "s3:ObjectCreated:*",
      "s3:ObjectRemoved:*",
    ]
  }
}`,
  }),

  // s3_cross_account_org_id — S3 cross-account access missing org ID condition
  s3_cross_account_org_id: ({ resourceId }) => ({
    console: [
      `Open S3 console → bucket "${resourceId}" → Permissions.`,
      "Bucket policy → Edit.",
      "Find cross-account Allow statements.",
      "Add Condition: aws:PrincipalOrgID equals your org ID.",
      "Save changes.",
    ],
    cli: `\
BUCKET="${resourceId}"

# Get current policy
aws s3api get-bucket-policy --bucket "$BUCKET" \\
  --query Policy --output text | python3 -m json.tool

# Update policy to include org ID condition:
# Add to each cross-account statement:
#   "Condition": {
#     "StringEquals": {
#       "aws:PrincipalOrgID": "<YOUR_ORG_ID>"
#     }
#   }

# Get your org ID:
aws organizations describe-organization \\
  --query 'Organization.Id' --output text`,
    terraform: `\
data "aws_organizations_organization" "current" {}

resource "aws_s3_bucket_policy" "fix" {
  bucket = "${resourceId}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject"]
      Resource  = "arn:aws:s3:::${resourceId}/*"
      Condition = {
        StringEquals = {
          "aws:PrincipalOrgID" = data.aws_organizations_organization.current.id
        }
      }
    }]
  })
}`,
  }),

  // s3_intelligent_tiering — Large S3 bucket no Intelligent-Tiering
  s3_intelligent_tiering: ({ resourceId }) => ({
    console: [
      `Open S3 console → select bucket "${resourceId}".`,
      "Management tab → Create lifecycle rule.",
      "Name the rule, apply to all objects.",
      "Under Lifecycle rule actions → Transition to Intelligent-Tiering.",
      "Set transition after 0 days.",
      "Create rule.",
    ],
    cli: `\
BUCKET="${resourceId}"

aws s3api put-bucket-lifecycle-configuration \\
  --bucket "$BUCKET" \\
  --lifecycle-configuration '{
    "Rules": [{
      "ID": "intelligent-tiering",
      "Status": "Enabled",
      "Filter": {},
      "Transitions": [{
        "Days": 0,
        "StorageClass": "INTELLIGENT_TIERING"
      }]
    }]
  }'

# Optionally configure archive tiers
aws s3control put-bucket-lifecycle-configuration \\
  --bucket "$BUCKET" 2>/dev/null || true

# Verify
aws s3api get-bucket-lifecycle-configuration \\
  --bucket "$BUCKET"`,
    terraform: `\
resource "aws_s3_bucket_lifecycle_configuration" "fix" {
  bucket = "${resourceId}"

  rule {
    id     = "intelligent-tiering"
    status = "Enabled"

    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }
  }
}

resource "aws_s3_bucket_intelligent_tiering_configuration" "fix" {
  bucket = "${resourceId}"
  name   = "full-bucket"

  tiering {
    access_tier = "ARCHIVE_ACCESS"
    days        = 90
  }
  tiering {
    access_tier = "DEEP_ARCHIVE_ACCESS"
    days        = 180
  }
}`,
  }),

  // config_recorder_enabled — AWS Config not recording
  config_recorder_enabled: ({ accountId, region }) => ({
    console: [
      "Open AWS Config console → Get started.",
      "Select 'Record all resources supported in this region'.",
      "Choose or create an S3 bucket for delivery.",
      "Save.",
    ],
    cli: `\
${reg(region)}
${acct(accountId)}
BUCKET="aws-config-$ACCOUNT_ID-$REGION"

# Create S3 bucket for Config delivery
aws s3api create-bucket \\
  --bucket "$BUCKET" \\
  --region "$REGION" \\
  --create-bucket-configuration LocationConstraint="$REGION"

# Create IAM role for AWS Config
aws iam create-role \\
  --role-name aws-config-role \\
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Allow","Principal":{"Service":"config.amazonaws.com"},"Action":"sts:AssumeRole"}]
  }'

aws iam attach-role-policy \\
  --role-name aws-config-role \\
  --policy-arn arn:aws:iam::aws:policy/service-role/AWS_ConfigRole

# Start the recorder
aws configservice put-configuration-recorder \\
  --configuration-recorder \\
    "name=default,roleARN=arn:aws:iam::$ACCOUNT_ID:role/aws-config-role" \\
  --recording-group allSupported=true,includeGlobalResourceTypes=true

aws configservice put-delivery-channel \\
  --delivery-channel \\
    "name=default,s3BucketName=$BUCKET,configSnapshotDeliveryProperties={deliveryFrequency=Six_Hours}"

aws configservice start-configuration-recorder \\
  --configuration-recorder-name default

# Verify
aws configservice describe-configuration-recorder-status`,
    terraform: `\
data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "config" {
  bucket = "aws-config-\${data.aws_caller_identity.current.account_id}"
}

resource "aws_config_configuration_recorder" "main" {
  name     = "default"
  role_arn = aws_iam_role.config.arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "default"
  s3_bucket_name = aws_s3_bucket.config.bucket
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}`,
  }),

  // config_recorder_active — AWS Config recorder not active
  config_recorder_active: ({ region }) => ({
    console: [
      "Open AWS Config console → Settings.",
      "Start the configuration recorder.",
    ],
    cli: `\
${reg(region)}

aws configservice start-configuration-recorder \\
  --configuration-recorder-name default \\
  --region "$REGION"

# Verify
aws configservice describe-configuration-recorder-status \\
  --region "$REGION"`,
    terraform: `\
resource "aws_config_configuration_recorder_status" "fix" {
  name       = "default"
  is_enabled = true
}`,
  }),

  // config_delivery_channel — AWS Config delivery channel not configured
  config_delivery_channel: ({ region, accountId }) => ({
    console: [
      "Open AWS Config console → Settings.",
      "Set up a delivery channel with an S3 bucket.",
      "Save.",
    ],
    cli: `\
${reg(region)}
${acct(accountId)}

aws configservice put-delivery-channel \\
  --delivery-channel '{
    "name":"default",
    "s3BucketName":"aws-config-'"$ACCOUNT_ID"'-'"$REGION"'",
    "configSnapshotDeliveryProperties":{"deliveryFrequency":"Six_Hours"}
  }' \\
  --region "$REGION"`,
    terraform: `\
resource "aws_config_delivery_channel" "fix" {
  name           = "default"
  s3_bucket_name = var.config_bucket
  snapshot_delivery_properties {
    delivery_frequency = "Six_Hours"
  }
}`,
  }),

  // config_s3_private — Config S3 delivery bucket publicly accessible
  config_s3_private: ({ resourceId }) => ({
    console: [
      `Open S3 console → select Config bucket "${resourceId}".`,
      "Permissions → Block public access → Edit.",
      "Enable all four block options.",
      "Save.",
    ],
    cli: `\
BUCKET="${resourceId}"

aws s3api put-public-access-block \\
  --bucket "$BUCKET" \\
  --public-access-block-configuration \\
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`,
    terraform: `\
resource "aws_s3_bucket_public_access_block" "config" {
  bucket                  = "${resourceId}"
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}`,
  }),

  // config_rules_deployed — No AWS Config rules deployed
  config_rules_deployed: ({ region }) => ({
    console: [
      "Open AWS Config console → Rules → Add rule.",
      "Select AWS managed rules (e.g. s3-bucket-public-read-prohibited).",
      "Configure and save.",
    ],
    cli: `\
${reg(region)}

# Add essential Config rules
for RULE in s3-bucket-public-read-prohibited encrypted-volumes iam-root-access-key-check; do
  aws configservice put-config-rule \\
    --config-rule '{
      "ConfigRuleName":"'"$RULE"'",
      "Source":{"Owner":"AWS","SourceIdentifier":"'"$(echo $RULE | tr '-' '_' | tr '[:lower:]' '[:upper:]')"'"}
    }' \\
    --region "$REGION"
done`,
    terraform: `\
resource "aws_config_config_rule" "s3_public" {
  name = "s3-bucket-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
}

resource "aws_config_config_rule" "encrypted_volumes" {
  name = "encrypted-volumes"
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
}`,
  }),

  // config_sns_notification — Config no SNS compliance notification
  config_sns_notification: ({ region }) => ({
    console: [
      "Open AWS Config console → Settings.",
      "SNS topic → select or create a topic for compliance notifications.",
      "Save.",
    ],
    cli: `\
${reg(region)}

TOPIC_ARN=$(aws sns create-topic \\
  --name "config-compliance-alerts" \\
  --region "$REGION" \\
  --query TopicArn --output text)

aws configservice put-delivery-channel \\
  --delivery-channel '{
    "name":"default",
    "snsTopicARN":"'"$TOPIC_ARN"'"
  }' \\
  --region "$REGION"`,
    terraform: `\
resource "aws_sns_topic" "config" {
  name = "config-compliance-alerts"
}

resource "aws_config_delivery_channel" "fix" {
  sns_topic_arn = aws_sns_topic.config.arn
}`,
  }),

  // config_global_iam_resources — Config recorder excludes global IAM resources
  config_global_iam_resources: ({ region }) => ({
    console: [
      "Open AWS Config console → Settings → Edit.",
      "Check 'Include global resources (e.g., IAM)'.",
      "Save.",
    ],
    cli: `\
${reg(region)}

ROLE_ARN=$(aws configservice describe-configuration-recorders \\
  --region "$REGION" \\
  --query 'ConfigurationRecorders[0].roleARN' --output text)

aws configservice put-configuration-recorder \\
  --configuration-recorder \\
    "name=default,roleARN=$ROLE_ARN" \\
  --recording-group \\
    allSupported=true,includeGlobalResourceTypes=true \\
  --region "$REGION"`,
    terraform: `\
resource "aws_config_configuration_recorder" "fix" {
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}`,
  }),

  // config_multi_account_aggregator — Config multi-account aggregator not configured
  config_multi_account_aggregator: ({ region, accountId }) => ({
    console: [
      "Open AWS Config console → Aggregators → Create aggregator.",
      "Select 'Add individual account IDs' or 'Add my organization'.",
      "Select regions → Create.",
    ],
    cli: `\
${reg(region)}
${acct(accountId)}

aws configservice put-configuration-aggregator \\
  --configuration-aggregator-name "org-aggregator" \\
  --organization-aggregation-source \\
    RoleArn="arn:aws:iam::$ACCOUNT_ID:role/aws-config-aggregator",AllAwsRegions=true \\
  --region "$REGION"`,
    terraform: `\
resource "aws_config_configuration_aggregator" "fix" {
  name = "org-aggregator"
  organization_aggregation_source {
    all_regions = true
    role_arn    = var.aggregator_role_arn
  }
}`,
  }),

  // config_conformance_packs — No Config conformance packs deployed
  config_conformance_packs: ({ region }) => ({
    console: [
      "Open AWS Config console → Conformance packs → Deploy.",
      "Select a sample template (e.g. AWS Control Tower Detective Guardrails).",
      "Deploy.",
    ],
    cli: `\
${reg(region)}

aws configservice put-conformance-pack \\
  --conformance-pack-name "security-best-practices" \\
  --template-s3-uri "s3://config-conformance-pack-templates/security-best-practices.yaml" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_config_conformance_pack" "fix" {
  name          = "security-best-practices"
  template_body = file("conformance-pack.yaml")
}`,
  }),

  // config_remediation_actions — Non-compliant Config rules have no remediation
  config_remediation_actions: ({ resourceId, region }) => ({
    console: [
      `Open AWS Config console → Rules → select "${resourceId}".`,
      "Actions → Manage remediation.",
      "Select remediation action (SSM Automation document).",
      "Configure parameters → Save.",
    ],
    cli: `\
RULE="${resourceId}"
${reg(region)}

aws configservice put-remediation-configurations \\
  --remediation-configurations '[{
    "ConfigRuleName":"'"$RULE"'",
    "TargetType":"SSM_DOCUMENT",
    "TargetId":"<SSM_DOCUMENT_NAME>",
    "Automatic":false
  }]' \\
  --region "$REGION"`,
    terraform: `\
resource "aws_config_remediation_configuration" "fix" {
  config_rule_name = "${resourceId}"
  target_type      = "SSM_DOCUMENT"
  target_id        = var.ssm_document_name
  automatic        = false
}`,
  }),

  // config_daily_snapshots — Config snapshot delivery not set to daily
  config_daily_snapshots: ({ region }) => ({
    console: [
      "Open AWS Config console → Settings → Edit.",
      "Snapshot delivery frequency → TwentyFour_Hours.",
      "Save.",
    ],
    cli: `\
${reg(region)}

aws configservice put-delivery-channel \\
  --delivery-channel '{
    "name":"default",
    "configSnapshotDeliveryProperties":{"deliveryFrequency":"TwentyFour_Hours"}
  }' \\
  --region "$REGION"`,
    terraform: `\
resource "aws_config_delivery_channel" "fix" {
  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }
}`,
  }),

  // config_no_error_rules — AWS Config rules in ERROR state
  config_no_error_rules: ({ resourceId, region }) => ({
    console: [
      `Open AWS Config console → Rules → select "${resourceId}".`,
      "Check the error message in rule status.",
      "Fix the underlying issue (IAM permissions, missing resource, etc.).",
      "Re-evaluate the rule.",
    ],
    cli: `\
RULE="${resourceId}"
${reg(region)}

# Check rule status and error
aws configservice describe-config-rules \\
  --config-rule-names "$RULE" \\
  --region "$REGION"

# Re-evaluate after fixing
aws configservice start-config-rules-evaluation \\
  --config-rule-names "$RULE" \\
  --region "$REGION"`,
    terraform: `\
# Fix the underlying issue (IAM role, resource reference),
# then run terraform apply to re-deploy the rule.`,
  }),

  // awssec_guardduty_enabled — GuardDuty not enabled
  awssec_guardduty_enabled: ({ region, accountId }) => ({
    console: [
      "Open GuardDuty console → Get Started → Enable GuardDuty.",
      "Settings → Findings export → configure S3 export.",
      "For multi-account: Settings → Accounts → add members.",
    ],
    cli: `\
${reg(region)}
${acct(accountId)}

DETECTOR_ID=$(aws guardduty create-detector \\
  --enable \\
  --finding-publishing-frequency FIFTEEN_MINUTES \\
  --region "$REGION" \\
  --query DetectorId --output text)

echo "Detector ID: $DETECTOR_ID"

# Enable S3 and Kubernetes protection
aws guardduty update-detector \\
  --detector-id "$DETECTOR_ID" \\
  --region "$REGION" \\
  --data-sources S3Logs={Enable=true},Kubernetes={AuditLogs={Enable=true}}

# Verify
aws guardduty get-detector \\
  --detector-id "$DETECTOR_ID" \\
  --region "$REGION" \\
  --query '{Status:Status,Frequency:FindingPublishingFrequency}'`,
    terraform: `\
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs      { enable = true }
    kubernetes   { audit_logs { enable = true } }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes { enable = true }
      }
    }
  }
}`,
  }),

  // awssec_guardduty_detector — No GuardDuty detector found
  awssec_guardduty_detector: ({ region }) => ({
    console: ["Open GuardDuty console → Get Started → Enable GuardDuty."],
    cli: `\
${reg(region)}

aws guardduty create-detector \\
  --enable \\
  --finding-publishing-frequency FIFTEEN_MINUTES \\
  --region "$REGION"`,
    terraform: `\
resource "aws_guardduty_detector" "fix" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}`,
  }),

  // awssec_guardduty_s3_protection — GuardDuty S3 protection disabled
  awssec_guardduty_s3_protection: ({ resourceId, region }) => ({
    console: [`Open GuardDuty console → Settings → S3 Protection → Enable.`],
    cli: `\
DETECTOR_ID="${resourceId}"
${reg(region)}

aws guardduty update-detector \\
  --detector-id "$DETECTOR_ID" \\
  --data-sources S3Logs={Enable=true} \\
  --region "$REGION"`,
    terraform: `\
resource "aws_guardduty_detector" "fix" {
  datasources {
    s3_logs { enable = true }
  }
}`,
  }),

  // awssec_guardduty_malware_ec2 — GuardDuty malware protection disabled
  awssec_guardduty_malware_ec2: ({ resourceId, region }) => ({
    console: [
      "Open GuardDuty console → Settings → Malware Protection → Enable.",
    ],
    cli: `\
DETECTOR_ID="${resourceId}"
${reg(region)}

aws guardduty update-detector \\
  --detector-id "$DETECTOR_ID" \\
  --data-sources '{
    "MalwareProtection":{
      "ScanEc2InstanceWithFindings":{
        "EbsVolumes":{"Enable":true}
      }
    }
  }' \\
  --region "$REGION"`,
    terraform: `\
resource "aws_guardduty_detector" "fix" {
  datasources {
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes { enable = true }
      }
    }
  }
}`,
  }),

  // awssec_guardduty_no_suppress_crit — GuardDuty filter suppresses HIGH/CRITICAL findings
  awssec_guardduty_no_suppress_crit: ({ resourceId, region }) => ({
    console: [
      `Open GuardDuty console → Filters → select "${resourceId}".`,
      "Review suppression filter criteria.",
      "Remove or modify filters that suppress HIGH/CRITICAL findings.",
    ],
    cli: `\
DETECTOR_ID=$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text)
FILTER_NAME="${resourceId}"
${reg(region)}

# Delete the suppressive filter
aws guardduty delete-filter \\
  --detector-id "$DETECTOR_ID" \\
  --filter-name "$FILTER_NAME" \\
  --region "$REGION"`,
    terraform: `\
# Remove the aws_guardduty_filter resource that
# suppresses HIGH/CRITICAL severity findings.`,
  }),

  // awssec_guardduty_publish_frequency — GuardDuty finding frequency set to 24 hours
  awssec_guardduty_publish_frequency: ({ resourceId, region }) => ({
    console: [
      "Open GuardDuty console → Settings.",
      "Finding publishing frequency → FIFTEEN_MINUTES.",
      "Save.",
    ],
    cli: `\
DETECTOR_ID="${resourceId}"
${reg(region)}

aws guardduty update-detector \\
  --detector-id "$DETECTOR_ID" \\
  --finding-publishing-frequency FIFTEEN_MINUTES \\
  --region "$REGION"`,
    terraform: `\
resource "aws_guardduty_detector" "fix" {
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}`,
  }),

  // awssec_guardduty_sns_high — GuardDuty no SNS notification for HIGH findings
  awssec_guardduty_sns_high: ({ region }) => ({
    console: [
      "Open EventBridge console → Rules → Create rule.",
      "Event pattern: GuardDuty Finding with severity >= 7.",
      "Target: SNS topic for security alerts.",
      "Create.",
    ],
    cli: `\
${reg(region)}

TOPIC_ARN=$(aws sns create-topic \\
  --name "guardduty-high-findings" \\
  --region "$REGION" \\
  --query TopicArn --output text)

aws events put-rule \\
  --name "guardduty-high-severity" \\
  --event-pattern '{
    "source":["aws.guardduty"],
    "detail-type":["GuardDuty Finding"],
    "detail":{"severity":[{"numeric":[">=",7]}]}
  }' \\
  --region "$REGION"

aws events put-targets \\
  --rule "guardduty-high-severity" \\
  --targets "Id=sns,Arn=$TOPIC_ARN" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_sns_topic" "guardduty" {
  name = "guardduty-high-findings"
}

resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name = "guardduty-high-severity"
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail      = { severity = [{ numeric = [">=", 7] }] }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.guardduty_high.name
  arn  = aws_sns_topic.guardduty.arn
}`,
  }),

  // awssec_securityhub_enabled — AWS Security Hub not enabled
  awssec_securityhub_enabled: ({ region }) => ({
    console: [
      "Open Security Hub console → Go to Security Hub → Enable.",
      "Enable default security standards.",
    ],
    cli: `\
${reg(region)}

aws securityhub enable-security-hub \\
  --enable-default-standards \\
  --region "$REGION"`,
    terraform: `\
resource "aws_securityhub_account" "fix" {}`,
  }),

  // awssec_securityhub_cis_standard — Security Hub CIS AWS Foundations not enabled
  awssec_securityhub_cis_standard: ({ region }) => ({
    console: [
      "Open Security Hub console → Security standards.",
      "Enable 'CIS AWS Foundations Benchmark'.",
    ],
    cli: `\
${reg(region)}

aws securityhub batch-enable-standards \\
  --standards-subscription-requests \\
    '[{"StandardsArn":"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"}]' \\
  --region "$REGION"`,
    terraform: `\
resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
}`,
  }),

  // awssec_securityhub_fsbp_standard — Security Hub FSBP standard not enabled
  awssec_securityhub_fsbp_standard: ({ region }) => ({
    console: [
      "Open Security Hub console → Security standards.",
      "Enable 'AWS Foundational Security Best Practices'.",
    ],
    cli: `\
${reg(region)}

aws securityhub batch-enable-standards \\
  --standards-subscription-requests \\
    '[{"StandardsArn":"arn:aws:securityhub:'"$REGION"'::standards/aws-foundational-security-best-practices/v/1.0.0"}]' \\
  --region "$REGION"`,
    terraform: `\
resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:\${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
}`,
  }),

  // awssec_securityhub_no_suppress_crit — Security Hub CRITICAL finding suppressed without note
  awssec_securityhub_no_suppress_crit: ({ resourceId, region }) => ({
    console: [
      "Open Security Hub console → Findings.",
      `Find suppressed CRITICAL finding "${resourceId}".`,
      "Update workflow status to NOTIFIED or RESOLVED.",
      "Add a note explaining the justification.",
    ],
    cli: `\
${reg(region)}

# Update finding workflow status
aws securityhub batch-update-findings \\
  --finding-identifiers '[{"Id":"${resourceId}","ProductArn":"<PRODUCT_ARN>"}]' \\
  --workflow Status=NOTIFIED \\
  --note '{"Text":"Reviewed and actioned","UpdatedBy":"security-team"}' \\
  --region "$REGION"`,
    terraform: `\
# Remove or update the suppression automation rule
# that hides CRITICAL findings without notes.`,
  }),

  // awssec_securityhub_delegated_admin — Security Hub no delegated admin configured
  awssec_securityhub_delegated_admin: ({ region, accountId }) => ({
    console: [
      "Open Security Hub console → Settings → General.",
      "Designate a delegated administrator account.",
    ],
    cli: `\
${reg(region)}
${acct(accountId)}

aws securityhub enable-organization-admin-account \\
  --admin-account-id "$ACCOUNT_ID" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_securityhub_organization_admin_account" "fix" {
  admin_account_id = var.security_account_id
}`,
  }),

  // awssec_securityhub_sns_critical — Security Hub no SNS for CRITICAL findings
  awssec_securityhub_sns_critical: ({ region }) => ({
    console: [
      "Open EventBridge console → Rules → Create rule.",
      "Event pattern: Security Hub Finding with CRITICAL severity.",
      "Target: SNS topic.",
      "Create.",
    ],
    cli: `\
${reg(region)}

TOPIC_ARN=$(aws sns create-topic \\
  --name "securityhub-critical" \\
  --region "$REGION" \\
  --query TopicArn --output text)

aws events put-rule \\
  --name "securityhub-critical-findings" \\
  --event-pattern '{
    "source":["aws.securityhub"],
    "detail-type":["Security Hub Findings - Imported"],
    "detail":{"findings":{"Severity":{"Label":["CRITICAL"]}}}
  }' \\
  --region "$REGION"

aws events put-targets \\
  --rule "securityhub-critical-findings" \\
  --targets "Id=sns,Arn=$TOPIC_ARN" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_event_rule" "sechub_critical" {
  name = "securityhub-critical-findings"
  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail      = { findings = { Severity = { Label = ["CRITICAL"] } } }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.sechub_critical.name
  arn  = aws_sns_topic.security_alerts.arn
}`,
  }),

  // awssec_inspector_ec2_scanning — AWS Inspector EC2 scanning disabled
  awssec_inspector_ec2_scanning: ({ region }) => ({
    console: [
      "Open Inspector console → Settings → Account management.",
      "Enable EC2 scanning.",
    ],
    cli: `\
${reg(region)}

aws inspector2 enable \\
  --resource-types EC2 \\
  --region "$REGION"`,
    terraform: `\
resource "aws_inspector2_enabler" "ec2" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2"]
}`,
  }),

  // awssec_inspector_ecr_scanning — AWS Inspector ECR container scanning disabled
  awssec_inspector_ecr_scanning: ({ region }) => ({
    console: [
      "Open Inspector console → Settings → Account management.",
      "Enable ECR scanning.",
    ],
    cli: `\
${reg(region)}

aws inspector2 enable \\
  --resource-types ECR \\
  --region "$REGION"`,
    terraform: `\
resource "aws_inspector2_enabler" "ecr" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["ECR"]
}`,
  }),

  // awssec_inspector_lambda_scanning — AWS Inspector Lambda scanning disabled
  awssec_inspector_lambda_scanning: ({ region }) => ({
    console: [
      "Open Inspector console → Settings → Account management.",
      "Enable Lambda scanning.",
    ],
    cli: `\
${reg(region)}

aws inspector2 enable \\
  --resource-types LAMBDA \\
  --region "$REGION"`,
    terraform: `\
resource "aws_inspector2_enabler" "lambda" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["LAMBDA"]
}`,
  }),

  // awssec_inspector_critical_cve_30d — Inspector CRITICAL CVE open > 30 days
  awssec_inspector_critical_cve_30d: ({ resourceId, region }) => ({
    console: [
      `Open Inspector console → Findings → filter CRITICAL severity.`,
      `Find "${resourceId}" and apply the recommended patch.`,
      "Reboot if required → re-scan to verify.",
    ],
    cli: `\
${reg(region)}

# List critical findings
aws inspector2 list-findings \\
  --filter-criteria '{
    "severity":[{"comparison":"EQUALS","value":"CRITICAL"}]
  }' \\
  --region "$REGION"

# Apply patches via SSM
# aws ssm send-command \\
#   --instance-ids <INSTANCE_ID> \\
#   --document-name "AWS-RunPatchBaseline" \\
#   --parameters Operation=Install`,
    terraform: `\
# Patch the underlying resource. For EC2, use SSM Patch Manager:
resource "aws_ssm_patch_baseline" "fix" {
  name             = "security-patches"
  operating_system = "AMAZON_LINUX_2"
  approval_rule {
    approve_after_days = 0
    compliance_level   = "CRITICAL"
    patch_filter {
      key    = "SEVERITY"
      values = ["Critical"]
    }
  }
}`,
  }),

  // awssec_inspector_high_cve_90d — Inspector HIGH CVE open > 90 days
  awssec_inspector_high_cve_90d: ({ resourceId, region }) => ({
    console: [
      "Open Inspector console → Findings → filter HIGH severity.",
      `Find "${resourceId}" and apply the recommended patch.`,
      "Follow the same patching process as CRITICAL CVEs.",
    ],
    cli: `\
${reg(region)}

aws inspector2 list-findings \\
  --filter-criteria '{
    "severity":[{"comparison":"EQUALS","value":"HIGH"}]
  }' \\
  --region "$REGION"

# Apply patches via SSM Patch Manager`,
    terraform: `\
# Apply patches — same approach as awssec_17.
# Use SSM Patch Manager or update container images.`,
  }),

  // awssec_inspector_securityhub — Inspector not integrated with Security Hub
  awssec_inspector_securityhub: ({ region }) => ({
    console: [
      "Open Security Hub console → Integrations.",
      "Find Amazon Inspector → Accept findings.",
    ],
    cli: `\
${reg(region)}

aws securityhub enable-import-findings-for-product \\
  --product-arn "arn:aws:securityhub:$REGION::product/aws/inspector" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_securityhub_product_subscription" "inspector" {
  product_arn = "arn:aws:securityhub:\${var.region}::product/aws/inspector"
}`,
  }),

  // awssec_inspector_no_suppress_crit — Inspector suppression filter hides CRITICAL findings
  awssec_inspector_no_suppress_crit: ({ resourceId, region }) => ({
    console: [
      "Open Inspector console → Suppression rules.",
      `Select filter "${resourceId}" → review criteria.`,
      "Remove filters that suppress CRITICAL severity findings.",
    ],
    cli: `\
FILTER_ARN="${resourceId}"
${reg(region)}

aws inspector2 delete-filter \\
  --arn "$FILTER_ARN" \\
  --region "$REGION"`,
    terraform: `\
# Remove the aws_inspector2_filter resource that
# suppresses CRITICAL findings.`,
  }),

  // serverless_lambda_xray — Insecure Lambda configuration
  serverless_lambda_xray: ({ resourceId, region, accountId }) => ({
    console: [
      `Open Lambda console → function "${resourceId}".`,
      "Configuration → Permissions: verify execution role has least-privilege.",
      "Configuration → VPC: place the function in a private subnet.",
      "Configuration → Environment variables: move secrets to Secrets Manager.",
      "Save.",
    ],
    cli: `\
FUNCTION="${resourceId}"
${reg(region)}
${acct(accountId)}

# View current configuration
aws lambda get-function-configuration \\
  --function-name "$FUNCTION" \\
  --region "$REGION"

# Enable X-Ray active tracing
aws lambda update-function-configuration \\
  --function-name "$FUNCTION" \\
  --tracing-config Mode=Active \\
  --region "$REGION"

# Place in VPC (replace subnet/SG IDs with your values)
aws lambda update-function-configuration \\
  --function-name "$FUNCTION" \\
  --vpc-config SubnetIds=<SUBNET_ID>,SecurityGroupIds=<SG_ID> \\
  --region "$REGION"

# Attach least-privilege role (replace ROLE_ARN)
aws lambda update-function-configuration \\
  --function-name "$FUNCTION" \\
  --role arn:aws:iam::$ACCOUNT_ID:role/<LEAST_PRIVILEGE_ROLE> \\
  --region "$REGION"

# Verify
aws lambda get-function-configuration \\
  --function-name "$FUNCTION" \\
  --region "$REGION" \\
  --query '{VpcConfig:VpcConfig,TracingConfig:TracingConfig,Role:Role}'`,
    terraform: `\
# Function: ${resourceId}
# Import: terraform import aws_lambda_function.fix ${resourceId}

resource "aws_lambda_function" "fix" {
  function_name = "${resourceId}"
  role          = aws_iam_role.lambda_exec.arn

  vpc_config {
    subnet_ids         = [aws_subnet.private.id]
    security_group_ids = [aws_security_group.lambda.id]
  }

  tracing_config { mode = "Active" }

  environment {
    variables = {
      # No secrets in env vars — use Secrets Manager or SSM
      STAGE = "production"
    }
  }
}`,
  }),

  // serverless_lambda_kms_env — Lambda env vars not KMS encrypted
  serverless_lambda_kms_env: ({ resourceId, region }) => ({
    console: [
      `Open Lambda console → function "${resourceId}".`,
      "Configuration → Environment variables → Edit.",
      "Under Encryption configuration, enable helpers.",
      "Select a customer managed KMS key.",
      "Encrypt each environment variable value.",
      "Save.",
    ],
    cli: `\
FUNCTION="${resourceId}"
${reg(region)}

# Create or use existing KMS key
KEY_ARN="<YOUR_KMS_KEY_ARN>"

aws lambda update-function-configuration \\
  --function-name "$FUNCTION" \\
  --kms-key-arn "$KEY_ARN" \\
  --region "$REGION"

# Verify
aws lambda get-function-configuration \\
  --function-name "$FUNCTION" \\
  --region "$REGION" \\
  --query 'KMSKeyArn'`,
    terraform: `\
resource "aws_lambda_function" "fix" {
  function_name = "${resourceId}"
  kms_key_arn   = aws_kms_key.lambda.arn
}

resource "aws_kms_key" "lambda" {
  description         = "Lambda env var encryption"
  enable_key_rotation = true
}`,
  }),

  // serverless_lambda_runtime — Lambda using deprecated runtime
  serverless_lambda_runtime: ({ resourceId, region }) => ({
    console: [
      `Open Lambda console → function "${resourceId}".`,
      "Code tab → Runtime settings → Edit.",
      "Select a supported runtime version.",
      "Save and test the function.",
    ],
    cli: `\
FUNCTION="${resourceId}"
${reg(region)}

# Check current runtime
aws lambda get-function-configuration \\
  --function-name "$FUNCTION" \\
  --region "$REGION" \\
  --query 'Runtime'

# Update to supported runtime
aws lambda update-function-configuration \\
  --function-name "$FUNCTION" \\
  --runtime python3.12 \\
  --region "$REGION"`,
    terraform: `\
resource "aws_lambda_function" "fix" {
  function_name = "${resourceId}"
  runtime       = "python3.12"  # update to supported version
}`,
  }),

  // serverless_lambda_no_public_invoke — Lambda resource policy allows public invocation
  serverless_lambda_no_public_invoke: ({ resourceId, region }) => ({
    console: [
      "If this Lambda is intentionally public (webhook, SaaS callback): keep the public permission but add a Lambda authorizer or API key, enable WAF on the API Gateway in front, and check that the function validates all inputs.",
      "If this Lambda is NOT intentionally public: Configuration → Permissions → Resource-based policy → remove statements where Principal is '*' → add specific principal ARNs (e.g., API Gateway ARN, specific AWS account).",
      `Lambda console → function "${resourceId}" → Configuration → Permissions → Resource-based policy statements.`,
    ],
    cli: `\
FUNCTION="${resourceId}"
${reg(region)}

# Step 1 — view current resource policy to understand what is public
aws lambda get-policy --function-name "$FUNCTION" --region "$REGION" --query 'Policy' --output text | python3 -m json.tool

# Step 2a — if NOT intentionally public: remove the public statement
# Find the statement ID from the policy above
PUBLIC_SID="<STATEMENT_ID_WITH_STAR_PRINCIPAL>"
aws lambda remove-permission --function-name "$FUNCTION" --statement-id "$PUBLIC_SID" --region "$REGION"

# Then add a scoped permission (e.g., allow only your API Gateway)
API_ARN="arn:aws:execute-api:$REGION:<ACCOUNT_ID>:<API_ID>/*"
aws lambda add-permission --function-name "$FUNCTION" --statement-id "AllowAPIGateway" --action "lambda:InvokeFunction" --principal apigateway.amazonaws.com --source-arn "$API_ARN" --region "$REGION"

# Step 2b — if intentionally public: keep the permission, add a URL auth type
aws lambda create-function-url-config --function-name "$FUNCTION" --auth-type AWS_IAM --region "$REGION"
echo "For truly public endpoints use API Gateway with WAF + throttling in front of Lambda instead of a raw public resource policy."`,
    terraform: `\
# For API Gateway-triggered Lambda (scoped, not public):
resource "aws_lambda_permission" "allow_apigw" {
  function_name = "${resourceId}"
  statement_id  = "AllowAPIGateway"
  action        = "lambda:InvokeFunction"
  principal     = "apigateway.amazonaws.com"
  source_arn    = "\${var.api_gateway_arn}/*"
}

# For a truly public function URL, use IAM auth or put API Gateway + WAF in front:
# resource "aws_lambda_function_url" "public" {
#   function_name      = "${resourceId}"
#   authorization_type = "NONE"  # only if WAF + rate limiting exists upstream
# }`,
  }),

  // serverless_lambda_no_admin_role — Lambda execution role has AdministratorAccess
  serverless_lambda_no_admin_role: ({ resourceId, region }) => ({
    console: [
      `Open Lambda console → function "${resourceId}" → Configuration → Permissions → Execution role → click role link.`,
      "In IAM, check recent CloudTrail events for this role to see which AWS services this function actually calls.",
      "Create a customer-managed policy with only those specific actions and resources.",
      "Attach the new scoped policy → detach AdministratorAccess.",
    ],
    cli: `\
FUNCTION="${resourceId}"
${reg(region)}

# Get the execution role name
ROLE_ARN=$(aws lambda get-function-configuration --function-name "$FUNCTION" --region "$REGION" --query 'Role' --output text)
ROLE_NAME=$(echo "$ROLE_ARN" | awk -F/ '{print $NF}')
echo "Execution role: $ROLE_NAME"

# Check CloudTrail to see what services this function actually uses
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue="$ROLE_NAME" --region "$REGION" --query 'Events[].EventName' --output text | tr '\\t' '\\n' | sort -u

# Create a scoped policy based on what you find above (replace the actions list)
cat > /tmp/lambda-scoped.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["s3:GetObject", "dynamodb:PutItem"], "Resource": "*" },
    { "Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "arn:aws:logs:*:*:*" }
  ]
}
EOF

POLICY_ARN=$(aws iam create-policy --policy-name "$ROLE_NAME-scoped" --policy-document file:///tmp/lambda-scoped.json --query 'Policy.Arn' --output text)
aws iam attach-role-policy --role-name "$ROLE_NAME" --policy-arn "$POLICY_ARN"

# Only after verifying the function works with the scoped policy:
aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
echo "Verify the Lambda still works, then confirm the fix is complete."`,
    terraform: `\
resource "aws_iam_role" "lambda_exec" {
  name = "${resourceId}-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Scoped policy — replace actions with what this function actually needs
resource "aws_iam_role_policy" "scoped" {
  role = aws_iam_role.lambda_exec.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject", "dynamodb:PutItem"], Resource = "*" },
      { Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], Resource = "arn:aws:logs:*:*:*" }
    ]
  })
}
# Remove the aws_iam_role_policy_attachment for AdministratorAccess.`,
  }),

  // serverless_ecs_no_privileged — ECS container running in privileged mode
  serverless_ecs_no_privileged: ({ resourceId, region }) => ({
    console: [
      "First confirm WHY privileged mode is set — check with the team that owns this task definition.",
      "If privileged is NOT actually required: ECS → Task Definitions → create new revision → edit container → uncheck Privileged → register → update service.",
      "If privileged IS required (Docker-in-Docker, raw socket access, kernel module): create a new revision that removes privileged=true and instead adds only the specific Linux capabilities needed via 'linuxParameters.capabilities.add' (e.g., NET_ADMIN, SYS_PTRACE).",
      "Update the service to use the new task definition revision.",
    ],
    cli: `\
TASK_DEF="${resourceId}"
${reg(region)}

# Check which containers use privileged mode and why
aws ecs describe-task-definition --task-definition "$TASK_DEF" --region "$REGION" --query 'taskDefinition.containerDefinitions[].{Name:name,Privileged:privileged,Capabilities:linuxParameters.capabilities}'

# Export task definition JSON for editing
aws ecs describe-task-definition --task-definition "$TASK_DEF" --region "$REGION" --query 'taskDefinition' > /tmp/taskdef.json

# Edit /tmp/taskdef.json:
# Option A (preferred): remove "privileged": true, add specific caps instead:
#   "linuxParameters": {
#     "capabilities": { "add": ["NET_ADMIN"], "drop": ["ALL"] }
#   }
# Option B: set "privileged": false if the container does not need elevated access at all

# Re-register with the fixed definition (strip read-only fields first)
python3 -c "
import json, sys
d = json.load(open('/tmp/taskdef.json'))
for f in ['taskDefinitionArn','revision','status','registeredAt','registeredBy','requiresAttributes','compatibilities']:
    d.pop(f, None)
json.dump(d, sys.stdout, indent=2)
" > /tmp/taskdef-fixed.json

aws ecs register-task-definition --cli-input-json file:///tmp/taskdef-fixed.json --region "$REGION"`,
    terraform: `\
resource "aws_ecs_task_definition" "fix" {
  family = "${resourceId}"

  container_definitions = jsonencode([{
    name  = "app"
    image = var.image

    # Remove privileged = true.
    # If specific capabilities are required, use linuxParameters:
    linuxParameters = {
      capabilities = {
        add  = ["NET_ADMIN"]  # add only what is specifically needed
        drop = ["ALL"]         # drop everything else
      }
    }
  }])
}`,
  }),

  // serverless_ecs_readonly_root — ECS container root FS not read-only
  serverless_ecs_readonly_root: ({ resourceId, region }) => ({
    console: [
      `Open ECS console → Task Definitions → select "${resourceId}".`,
      "Create new revision.",
      "Edit container → enable 'Read only root file system'.",
      "Add tmpfs or EFS mounts for writable paths.",
      "Register and update the service.",
    ],
    cli: `\
TASK_DEF="${resourceId}"
${reg(region)}

# Register new revision with readonlyRootFilesystem=true
# In container definition JSON, set:
# "readonlyRootFilesystem": true
# Add mount points for writable dirs (/tmp, /var/run)`,
    terraform: `\
resource "aws_ecs_task_definition" "fix" {
  family = "${resourceId}"
  container_definitions = jsonencode([{
    name                     = "app"
    image                    = var.image
    readonlyRootFilesystem   = true
    mountPoints = [{
      sourceVolume  = "tmp"
      containerPath = "/tmp"
    }]
  }])
  volume { name = "tmp" }
}`,
  }),

  // serverless_ecs_cloudwatch_logs — ECS container not using CloudWatch Logs
  serverless_ecs_cloudwatch_logs: ({ resourceId, region }) => ({
    console: [
      `Open ECS console → Task Definitions → select "${resourceId}".`,
      "Create new revision.",
      "Edit container → Log configuration → awslogs driver.",
      "Set log group, region, and stream prefix.",
      "Register and update the service.",
    ],
    cli: `\
TASK_DEF="${resourceId}"
${reg(region)}

# In container definition JSON, add:
# "logConfiguration": {
#   "logDriver": "awslogs",
#   "options": {
#     "awslogs-group": "/ecs/${resourceId}",
#     "awslogs-region": "$REGION",
#     "awslogs-stream-prefix": "ecs"
#   }
# }

# Create log group
aws logs create-log-group \\
  --log-group-name "/ecs/${resourceId}" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${resourceId}"
  retention_in_days = 30
}

# In container definition:
# log_configuration {
#   log_driver = "awslogs"
#   options = {
#     "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
#     "awslogs-region"        = var.region
#     "awslogs-stream-prefix" = "ecs"
#   }
# }`,
  }),

  // serverless_ecs_no_host_network — ECS task using host network mode
  serverless_ecs_no_host_network: ({ resourceId, region }) => ({
    console: [
      `Open ECS console → Task Definitions → select "${resourceId}".`,
      "Create new revision.",
      "Change Network Mode from 'host' to 'awsvpc'.",
      "Register and update the service.",
    ],
    cli: `\
TASK_DEF="${resourceId}"
${reg(region)}

# Register new revision with awsvpc network mode
# In task definition JSON: "networkMode": "awsvpc"`,
    terraform: `\
resource "aws_ecs_task_definition" "fix" {
  family       = "${resourceId}"
  network_mode = "awsvpc"
}`,
  }),

  // serverless_ecs_container_insights — ECS cluster Container Insights disabled
  serverless_ecs_container_insights: ({ resourceId, region }) => ({
    console: [
      `Open ECS console → Clusters → select "${resourceId}".`,
      "Update cluster → enable Container Insights.",
      "Update.",
    ],
    cli: `\
CLUSTER="${resourceId}"
${reg(region)}

aws ecs update-cluster-settings \\
  --cluster "$CLUSTER" \\
  --settings name=containerInsights,value=enabled \\
  --region "$REGION"

# Verify
aws ecs describe-clusters \\
  --clusters "$CLUSTER" \\
  --region "$REGION" \\
  --query 'clusters[0].settings'`,
    terraform: `\
resource "aws_ecs_cluster" "fix" {
  name = "${resourceId}"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}`,
  }),

  // serverless_eks_private_endpoint — EKS API endpoint publicly accessible
  serverless_eks_private_endpoint: ({ resourceId, region }) => ({
    console: [
      `Open EKS console → Clusters → select "${resourceId}".`,
      "Networking tab → Manage networking.",
      "Disable public access or restrict to specific CIDRs.",
      "Enable private access.",
      "Save changes.",
    ],
    cli: `\
CLUSTER="${resourceId}"
${reg(region)}

aws eks update-cluster-config \\
  --name "$CLUSTER" \\
  --region "$REGION" \\
  --resources-vpc-config \\
    endpointPublicAccess=false,endpointPrivateAccess=true

# Or restrict public access to specific CIDRs:
# aws eks update-cluster-config \\
#   --name "$CLUSTER" --region "$REGION" \\
#   --resources-vpc-config \\
#     endpointPublicAccess=true,publicAccessCidrs="<YOUR_CIDR>/32",endpointPrivateAccess=true`,
    terraform: `\
resource "aws_eks_cluster" "fix" {
  name = "${resourceId}"
  vpc_config {
    endpoint_public_access  = false
    endpoint_private_access = true
  }
}`,
  }),

  // serverless_eks_secrets_encryption — EKS secrets encryption not enabled
  serverless_eks_secrets_encryption: ({ resourceId, region }) => ({
    console: [
      `Open EKS console → Clusters → select "${resourceId}".`,
      "Configuration tab → Secrets encryption → Associate.",
      "Select a KMS key → Associate.",
    ],
    cli: `\
CLUSTER="${resourceId}"
${reg(region)}

aws eks associate-encryption-config \\
  --cluster-name "$CLUSTER" \\
  --encryption-config '[{
    "resources":["secrets"],
    "provider":{"keyArn":"<KMS_KEY_ARN>"}
  }]' \\
  --region "$REGION"`,
    terraform: `\
resource "aws_eks_cluster" "fix" {
  name = "${resourceId}"
  encryption_config {
    resources = ["secrets"]
    provider  { key_arn = aws_kms_key.eks.arn }
  }
}

resource "aws_kms_key" "eks" {
  description         = "EKS secrets encryption"
  enable_key_rotation = true
}`,
  }),

  // serverless_eks_audit_logs — EKS audit logs not enabled
  serverless_eks_audit_logs: ({ resourceId, region }) => ({
    console: [
      `Open EKS console → Clusters → select "${resourceId}".`,
      "Observability tab → Manage logging.",
      "Enable: API server, Audit, Authenticator, Controller manager, Scheduler.",
      "Save changes.",
    ],
    cli: `\
CLUSTER="${resourceId}"
${reg(region)}

aws eks update-cluster-config \\
  --name "$CLUSTER" \\
  --region "$REGION" \\
  --logging '{
    "clusterLogging":[{
      "types":["api","audit","authenticator","controllerManager","scheduler"],
      "enabled":true
    }]
  }'`,
    terraform: `\
resource "aws_eks_cluster" "fix" {
  name = "${resourceId}"
  enabled_cluster_log_types = [
    "api", "audit", "authenticator",
    "controllerManager", "scheduler",
  ]
}`,
  }),

  // serverless_eks_private_subnets — EKS node group not in private subnet
  serverless_eks_private_subnets: ({ resourceId, region }) => ({
    console: [
      `Open EKS console → Clusters → Node groups → "${resourceId}".`,
      "Node groups cannot be moved — delete and recreate.",
      "Create a new node group using private subnets.",
    ],
    cli: `\
NODE_GROUP="${resourceId}"
${reg(region)}

# Delete and recreate in private subnets
# aws eks delete-nodegroup \\
#   --cluster-name <CLUSTER> \\
#   --nodegroup-name "$NODE_GROUP" \\
#   --region "$REGION"

# aws eks create-nodegroup \\
#   --cluster-name <CLUSTER> \\
#   --nodegroup-name "$NODE_GROUP-private" \\
#   --subnets <PRIVATE_SUBNET_1> <PRIVATE_SUBNET_2> \\
#   --node-role <NODE_ROLE_ARN> \\
#   --region "$REGION"`,
    terraform: `\
resource "aws_eks_node_group" "fix" {
  cluster_name = var.cluster_name
  subnet_ids   = var.private_subnet_ids
  # Use private subnets only
}`,
  }),

  // serverless_eks_version_current — EKS using end-of-life Kubernetes version
  serverless_eks_version_current: ({ resourceId, region }) => ({
    console: [
      `Open EKS console → Clusters → select "${resourceId}".`,
      "Click Update cluster version.",
      "Select the latest supported version.",
      "Update → then update node groups.",
    ],
    cli: `\
CLUSTER="${resourceId}"
${reg(region)}

# Check current version
aws eks describe-cluster \\
  --name "$CLUSTER" \\
  --region "$REGION" \\
  --query 'cluster.version'

# Update to latest
aws eks update-cluster-version \\
  --name "$CLUSTER" \\
  --kubernetes-version "1.29" \\
  --region "$REGION"

# After cluster update, update node groups:
# aws eks update-nodegroup-version \\
#   --cluster-name "$CLUSTER" \\
#   --nodegroup-name <NODE_GROUP> \\
#   --region "$REGION"`,
    terraform: `\
resource "aws_eks_cluster" "fix" {
  name    = "${resourceId}"
  version = "1.29"  # update to supported version
}`,
  }),

  // serverless_ecr_image_scanning — ECR image scanning disabled
  serverless_ecr_image_scanning: ({ resourceId, region }) => ({
    console: [
      `Open ECR console → Repositories → select "${resourceId}".`,
      "Edit → enable 'Scan on push'.",
      "Save.",
    ],
    cli: `\
REPO="${resourceId}"
${reg(region)}

aws ecr put-image-scanning-configuration \\
  --repository-name "$REPO" \\
  --image-scanning-configuration scanOnPush=true \\
  --region "$REGION"

# Verify
aws ecr describe-repositories \\
  --repository-names "$REPO" \\
  --region "$REGION" \\
  --query 'repositories[0].imageScanningConfiguration'`,
    terraform: `\
resource "aws_ecr_repository" "fix" {
  name = "${resourceId}"
  image_scanning_configuration {
    scan_on_push = true
  }
}`,
  }),

  // serverless_ecr_private — ECR repository publicly accessible
  serverless_ecr_private: ({ resourceId, region }) => ({
    console: [
      `Open ECR console → Repositories → select "${resourceId}".`,
      "Permissions → Edit policy JSON.",
      "Remove statements allowing public access.",
      "Save.",
    ],
    cli: `\
REPO="${resourceId}"
${reg(region)}

# Delete public policy
aws ecr delete-repository-policy \\
  --repository-name "$REPO" \\
  --region "$REGION"

# Set private policy
aws ecr set-repository-policy \\
  --repository-name "$REPO" \\
  --region "$REGION" \\
  --policy-text '{
    "Version":"2012-10-17",
    "Statement":[{
      "Sid":"AllowPull",
      "Effect":"Allow",
      "Principal":{"AWS":"<TRUSTED_ACCOUNT_ARN>"},
      "Action":["ecr:GetDownloadUrlForLayer","ecr:BatchGetImage"]
    }]
  }'`,
    terraform: `\
resource "aws_ecr_repository_policy" "fix" {
  repository = "${resourceId}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowPull"
      Effect    = "Allow"
      Principal = { AWS = var.trusted_account_arn }
      Action    = [
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
      ]
    }]
  })
}`,
  }),

  // serverless_ecr_tag_immutability — ECR image tag immutability disabled
  serverless_ecr_tag_immutability: ({ resourceId, region }) => ({
    console: [
      `Open ECR console → Repositories → select "${resourceId}".`,
      "Edit → enable 'Tag immutability'.",
      "Save.",
    ],
    cli: `\
REPO="${resourceId}"
${reg(region)}

aws ecr put-image-tag-mutability \\
  --repository-name "$REPO" \\
  --image-tag-mutability IMMUTABLE \\
  --region "$REGION"

# Verify
aws ecr describe-repositories \\
  --repository-names "$REPO" \\
  --region "$REGION" \\
  --query 'repositories[0].imageTagMutability'`,
    terraform: `\
resource "aws_ecr_repository" "fix" {
  name                 = "${resourceId}"
  image_tag_mutability = "IMMUTABLE"
}`,
  }),

  // serverless_ecr_lifecycle_policy — ECR no lifecycle policy configured
  serverless_ecr_lifecycle_policy: ({ resourceId, region }) => ({
    console: [
      `Open ECR console → Repositories → select "${resourceId}".`,
      "Lifecycle Policy → Create rule.",
      "Expire untagged images older than 30 days.",
      "Keep only last 10 tagged images.",
      "Save.",
    ],
    cli: `\
REPO="${resourceId}"
${reg(region)}

aws ecr put-lifecycle-policy \\
  --repository-name "$REPO" \\
  --region "$REGION" \\
  --lifecycle-policy-text '{
    "rules": [
      {
        "rulePriority": 1,
        "description": "Expire untagged after 30 days",
        "selection": {
          "tagStatus": "untagged",
          "countType": "sinceImagePushed",
          "countUnit": "days",
          "countNumber": 30
        },
        "action": { "type": "expire" }
      },
      {
        "rulePriority": 2,
        "description": "Keep last 10 tagged images",
        "selection": {
          "tagStatus": "tagged",
          "tagPrefixList": ["v"],
          "countType": "imageCountMoreThan",
          "countNumber": 10
        },
        "action": { "type": "expire" }
      }
    ]
  }'`,
    terraform: `\
resource "aws_ecr_lifecycle_policy" "fix" {
  repository = "${resourceId}"
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged after 30 days"
        selection    = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 30
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep last 10 tagged"
        selection    = {
          tagStatus      = "tagged"
          tagPrefixList  = ["v"]
          countType      = "imageCountMoreThan"
          countNumber    = 10
        }
        action = { type = "expire" }
      },
    ]
  })
}`,
  }),

  // serverless_ecr_kms_encryption — ECR repository not encrypted with KMS
  serverless_ecr_kms_encryption: ({ resourceId, region }) => ({
    console: [
      "ECR encryption is set at repository creation and cannot be changed.",
      `Create a new repository to replace "${resourceId}" with KMS encryption.`,
      "Migrate images using docker pull/tag/push or ECR replication.",
    ],
    cli: `\
REPO="${resourceId}"
${reg(region)}

# Create replacement repo with KMS encryption
aws ecr create-repository \\
  --repository-name "${resourceId}-encrypted" \\
  --encryption-configuration encryptionType=KMS \\
  --region "$REGION"

# Migrate images
# docker pull <old-repo-uri>:tag
# docker tag <old-repo-uri>:tag <new-repo-uri>:tag
# docker push <new-repo-uri>:tag`,
    terraform: `\
resource "aws_ecr_repository" "fix" {
  name = "${resourceId}"
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }
}

resource "aws_kms_key" "ecr" {
  description         = "ECR repository encryption"
  enable_key_rotation = true
}`,
  }),

  // vpc_nacl_no_all_inbound — Overly permissive Network ACL
  vpc_nacl_no_all_inbound: ({ resourceId }) => ({
    console: [
      `Open VPC console → Network ACLs → select "${resourceId}".`,
      "Inbound rules → Edit: remove ALLOW rules for all ports from 0.0.0.0/0.",
      "Add specific ALLOW rules for required traffic only.",
      "Add DENY all at a high rule number (e.g. 32766).",
      "Repeat for Outbound rules.",
    ],
    cli: `\
NACL_ID="${resourceId}"

# View current rules
aws ec2 describe-network-acls \\
  --network-acl-ids "$NACL_ID" \\
  --query 'NetworkAcls[0].Entries'

# Remove overly permissive inbound rule (adjust rule number to match above)
aws ec2 delete-network-acl-entry \\
  --network-acl-id "$NACL_ID" \\
  --rule-number 100 \\
  --ingress

# Add HTTPS allow (internal traffic only)
aws ec2 create-network-acl-entry \\
  --network-acl-id "$NACL_ID" \\
  --rule-number 100 \\
  --protocol tcp --rule-action allow --ingress \\
  --cidr-block 10.0.0.0/8 \\
  --port-range From=443,To=443

# Add SSH allow (internal only)
aws ec2 create-network-acl-entry \\
  --network-acl-id "$NACL_ID" \\
  --rule-number 110 \\
  --protocol tcp --rule-action allow --ingress \\
  --cidr-block 10.0.0.0/8 \\
  --port-range From=22,To=22

# Deny all other inbound
aws ec2 create-network-acl-entry \\
  --network-acl-id "$NACL_ID" \\
  --rule-number 32766 \\
  --protocol -1 --rule-action deny --ingress \\
  --cidr-block 0.0.0.0/0`,
    terraform: `\
# Network ACL: ${resourceId}
# Import: terraform import aws_network_acl.fix ${resourceId}

resource "aws_network_acl" "fix" {
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "10.0.0.0/8"
    from_port  = 443
    to_port    = 443
  }
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "10.0.0.0/8"
    from_port  = 22
    to_port    = 22
  }
  ingress {
    rule_no    = 32766
    protocol   = "-1"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}`,
  }),

  // vpc_default_no_resources — Default VPC has resources attached
  vpc_default_no_resources: ({ resourceId, region }) => ({
    console: [
      `Default VPC "${resourceId}" has resources deployed.`,
      "Create a custom VPC with proper subnets and security.",
      "Migrate all resources from the default VPC.",
      "Consider deleting the default VPC after migration.",
    ],
    cli: `\
VPC_ID="${resourceId}"
${reg(region)}

# List resources in the default VPC
aws ec2 describe-instances \\
  --filters Name=vpc-id,Values="$VPC_ID" \\
  --region "$REGION" \\
  --query 'Reservations[].Instances[].{Id:InstanceId,Type:InstanceType,State:State.Name}'

aws ec2 describe-network-interfaces \\
  --filters Name=vpc-id,Values="$VPC_ID" \\
  --region "$REGION" \\
  --query 'NetworkInterfaces[].{Id:NetworkInterfaceId,Type:InterfaceType}'

# After migrating all resources, delete the default VPC:
# aws ec2 delete-vpc --vpc-id "$VPC_ID" --region "$REGION"`,
    terraform: `\
# Create a custom VPC to replace the default:
resource "aws_vpc" "custom" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "production-vpc" }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.custom.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false
}

# Migrate resources, then remove default VPC:
# resource "aws_default_vpc" "default" {
#   # terraform destroy to remove
# }`,
  }),

  // vpc_default_sg_no_inbound — Default security group allows inbound
  vpc_default_sg_no_inbound: ({ resourceId }) => ({
    console: [
      `Open VPC console → Security Groups → select default SG "${resourceId}".`,
      "Inbound rules → Edit → remove all inbound rules.",
      "Save rules.",
    ],
    cli: `\
SG_ID="${resourceId}"

# Remove all inbound rules from default SG
RULES=$(aws ec2 describe-security-groups \\
  --group-ids "$SG_ID" \\
  --query 'SecurityGroups[0].IpPermissions' \\
  --output json)

if [ "$RULES" != "[]" ]; then
  aws ec2 revoke-security-group-ingress \\
    --group-id "$SG_ID" \\
    --ip-permissions "$RULES"
fi

# Verify
aws ec2 describe-security-groups \\
  --group-ids "$SG_ID" \\
  --query 'SecurityGroups[0].IpPermissions'`,
    terraform: `\
# Lock down the default security group:
resource "aws_default_security_group" "fix" {
  vpc_id = var.vpc_id
  # No ingress or egress blocks = deny all
}`,
  }),

  // vpc_default_sg_no_outbound — Default security group allows outbound
  vpc_default_sg_no_outbound: ({ resourceId }) => ({
    console: [
      `Open VPC console → Security Groups → select default SG "${resourceId}".`,
      "Outbound rules → Edit → remove all outbound rules.",
      "Save rules.",
    ],
    cli: `\
SG_ID="${resourceId}"

# Remove all outbound rules from default SG
RULES=$(aws ec2 describe-security-groups \\
  --group-ids "$SG_ID" \\
  --query 'SecurityGroups[0].IpPermissionsEgress' \\
  --output json)

if [ "$RULES" != "[]" ]; then
  aws ec2 revoke-security-group-egress \\
    --group-id "$SG_ID" \\
    --ip-permissions "$RULES"
fi

# Verify
aws ec2 describe-security-groups \\
  --group-ids "$SG_ID" \\
  --query 'SecurityGroups[0].IpPermissionsEgress'`,
    terraform: `\
# Lock down the default security group:
resource "aws_default_security_group" "fix" {
  vpc_id = var.vpc_id
  # No ingress or egress blocks = deny all
}`,
  }),

  // vpc_dns_resolution — VPC DNS resolution disabled
  vpc_dns_resolution: ({ resourceId, region }) => ({
    console: [
      `Open VPC console → Your VPCs → select "${resourceId}".`,
      "Actions → Edit VPC settings.",
      "Enable 'DNS resolution' → Save.",
    ],
    cli: `\
VPC_ID="${resourceId}"
${reg(region)}

aws ec2 modify-vpc-attribute \\
  --vpc-id "$VPC_ID" \\
  --enable-dns-support '{"Value":true}' \\
  --region "$REGION"

# Verify
aws ec2 describe-vpc-attribute \\
  --vpc-id "$VPC_ID" \\
  --attribute enableDnsSupport \\
  --region "$REGION"`,
    terraform: `\
resource "aws_vpc" "fix" {
  enable_dns_support = true
}`,
  }),

  // vpc_dns_hostnames — VPC DNS hostnames disabled
  vpc_dns_hostnames: ({ resourceId, region }) => ({
    console: [
      `Open VPC console → Your VPCs → select "${resourceId}".`,
      "Actions → Edit VPC settings.",
      "Enable 'DNS hostnames' → Save.",
    ],
    cli: `\
VPC_ID="${resourceId}"
${reg(region)}

aws ec2 modify-vpc-attribute \\
  --vpc-id "$VPC_ID" \\
  --enable-dns-hostnames '{"Value":true}' \\
  --region "$REGION"

# Verify
aws ec2 describe-vpc-attribute \\
  --vpc-id "$VPC_ID" \\
  --attribute enableDnsHostnames \\
  --region "$REGION"`,
    terraform: `\
resource "aws_vpc" "fix" {
  enable_dns_hostnames = true
}`,
  }),

  // vpc_private_no_public_ip — Private subnet auto-assigns public IPs
  vpc_private_no_public_ip: ({ resourceId, region }) => ({
    console: [
      `Open VPC console → Subnets → select "${resourceId}".`,
      "Actions → Edit subnet settings.",
      "Uncheck 'Auto-assign public IPv4 address'.",
      "Save.",
    ],
    cli: `\
SUBNET_ID="${resourceId}"
${reg(region)}

aws ec2 modify-subnet-attribute \\
  --subnet-id "$SUBNET_ID" \\
  --no-map-public-ip-on-launch \\
  --region "$REGION"

# Verify
aws ec2 describe-subnets \\
  --subnet-ids "$SUBNET_ID" \\
  --region "$REGION" \\
  --query 'Subnets[0].MapPublicIpOnLaunch'`,
    terraform: `\
resource "aws_subnet" "fix" {
  map_public_ip_on_launch = false
}`,
  }),

  // vpc_private_no_igw_route — Private route table routes to internet gateway
  vpc_private_no_igw_route: ({ resourceId, region }) => ({
    console: [
      `Open VPC console → Route Tables → select "${resourceId}".`,
      "Routes tab → Edit routes.",
      "Remove the 0.0.0.0/0 route pointing to an Internet Gateway.",
      "If outbound internet is needed, route through a NAT Gateway.",
      "Save routes.",
    ],
    cli: `\
RT_ID="${resourceId}"
${reg(region)}

# Find the IGW route
aws ec2 describe-route-tables \\
  --route-table-ids "$RT_ID" \\
  --region "$REGION" \\
  --query 'RouteTables[0].Routes[?GatewayId!=\`local\`]'

# Remove IGW route (replace igw-xxx)
# aws ec2 delete-route \\
#   --route-table-id "$RT_ID" \\
#   --destination-cidr-block 0.0.0.0/0 \\
#   --region "$REGION"

# Add NAT Gateway route instead:
# aws ec2 create-route \\
#   --route-table-id "$RT_ID" \\
#   --destination-cidr-block 0.0.0.0/0 \\
#   --nat-gateway-id <NAT_GW_ID> \\
#   --region "$REGION"`,
    terraform: `\
# Remove IGW route from private route table:
resource "aws_route_table" "private" {
  vpc_id = var.vpc_id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  # Do NOT route to aws_internet_gateway
}`,
  }),

  // vpc_multi_az — Production VPC spans only 1 AZ
  vpc_multi_az: ({ resourceId, region }) => ({
    console: [
      `Open VPC console → Subnets → filter by VPC "${resourceId}".`,
      "Create subnets in at least 2 availability zones.",
      "Update Auto Scaling groups and load balancers to use multiple AZs.",
    ],
    cli: `\
VPC_ID="${resourceId}"
${reg(region)}

# List current subnets and AZs
aws ec2 describe-subnets \\
  --filters Name=vpc-id,Values="$VPC_ID" \\
  --region "$REGION" \\
  --query 'Subnets[].{Id:SubnetId,AZ:AvailabilityZone,CIDR:CidrBlock}'

# Create subnet in a second AZ
# aws ec2 create-subnet \\
#   --vpc-id "$VPC_ID" \\
#   --cidr-block "10.0.2.0/24" \\
#   --availability-zone "${region}b" \\
#   --region "$REGION"`,
    terraform: `\
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "az_a" {
  vpc_id            = "${resourceId}"
  cidr_block        = "10.0.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
}

resource "aws_subnet" "az_b" {
  vpc_id            = "${resourceId}"
  cidr_block        = "10.0.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]
}`,
  }),

  // vpc_sg_no_all_ports — Security group allows all ports from internet
  vpc_sg_no_all_ports: ({ resourceId }) => ({
    console: [
      `Open EC2 console → Security Groups → select "${resourceId}".`,
      "Inbound rules → Edit inbound rules.",
      "Remove rules allowing all ports (0-65535) from 0.0.0.0/0.",
      "Add specific port rules for required traffic.",
      "Save rules.",
    ],
    cli: `\
SG_ID="${resourceId}"

# Remove all-ports rule
aws ec2 revoke-security-group-ingress \\
  --group-id "$SG_ID" \\
  --protocol tcp --port 0-65535 --cidr 0.0.0.0/0

# Add only required ports
aws ec2 authorize-security-group-ingress \\
  --group-id "$SG_ID" \\
  --protocol tcp --port 443 --cidr 0.0.0.0/0

# Verify
aws ec2 describe-security-groups \\
  --group-ids "$SG_ID" \\
  --query 'SecurityGroups[0].IpPermissions'`,
    terraform: `\
resource "aws_security_group" "fix" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS only"
  }
}`,
  }),

  // vpc_peering_internal_cidr — VPC peering uses unrestricted CIDR
  vpc_peering_internal_cidr: ({ resourceId, region }) => ({
    console: [
      `Open VPC console → Peering Connections → select "${resourceId}".`,
      "Check route tables for 0.0.0.0/0 routes via this peering connection.",
      "Replace with the specific VPC CIDR of the peer.",
    ],
    cli: `\
PCX_ID="${resourceId}"
${reg(region)}

# Get peering details
aws ec2 describe-vpc-peering-connections \\
  --vpc-peering-connection-ids "$PCX_ID" \\
  --region "$REGION" \\
  --query 'VpcPeeringConnections[0].{Requester:RequesterVpcInfo.CidrBlock,Accepter:AccepterVpcInfo.CidrBlock}'

# Update route tables: replace 0.0.0.0/0 with peer CIDR
# aws ec2 replace-route \\
#   --route-table-id <RT_ID> \\
#   --destination-cidr-block <PEER_VPC_CIDR> \\
#   --vpc-peering-connection-id "$PCX_ID" \\
#   --region "$REGION"`,
    terraform: `\
# Route to peer VPC using specific CIDR, not 0.0.0.0/0:
resource "aws_route" "peering" {
  route_table_id            = var.route_table_id
  destination_cidr_block    = var.peer_vpc_cidr  # e.g. "10.1.0.0/16"
  vpc_peering_connection_id = "${resourceId}"
}`,
  }),

  // vpc_endpoints_s3_dynamodb — Production VPC has no S3 VPC endpoint
  vpc_endpoints_s3_dynamodb: ({ resourceId, region }) => ({
    console: [
      `Open VPC console → Endpoints → Create endpoint.`,
      "Service: com.amazonaws.<region>.s3 (Gateway type).",
      `Select VPC "${resourceId}" and route tables.`,
      "Create endpoint.",
    ],
    cli: `\
VPC_ID="${resourceId}"
${reg(region)}

# Get route table IDs for the VPC
RT_IDS=$(aws ec2 describe-route-tables \\
  --filters Name=vpc-id,Values="$VPC_ID" \\
  --region "$REGION" \\
  --query 'RouteTables[].RouteTableId' --output text)

aws ec2 create-vpc-endpoint \\
  --vpc-id "$VPC_ID" \\
  --service-name "com.amazonaws.$REGION.s3" \\
  --route-table-ids $RT_IDS \\
  --region "$REGION"

# Verify
aws ec2 describe-vpc-endpoints \\
  --filters Name=vpc-id,Values="$VPC_ID" \\
  --region "$REGION" \\
  --query 'VpcEndpoints[].{Id:VpcEndpointId,Service:ServiceName}'`,
    terraform: `\
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = "${resourceId}"
  service_name = "com.amazonaws.${region || "us-east-1"}.s3"

  route_table_ids = var.route_table_ids
  tags = { Name = "s3-gateway-endpoint" }
}`,
  }),

  // vpc_cidr_not_slash8 — VPC CIDR block too broad (/8)
  vpc_cidr_not_slash8: ({ resourceId, region }) => ({
    console: [
      `VPC "${resourceId}" uses an overly broad CIDR (e.g. /8).`,
      "Create a new VPC with a more specific CIDR (e.g. /16 or /20).",
      "Migrate resources to the new VPC.",
      "VPC CIDRs cannot be changed after creation.",
    ],
    cli: `\
VPC_ID="${resourceId}"
${reg(region)}

# Check current CIDR
aws ec2 describe-vpcs \\
  --vpc-ids "$VPC_ID" \\
  --region "$REGION" \\
  --query 'Vpcs[0].CidrBlock'

# Create a properly sized VPC
# aws ec2 create-vpc \\
#   --cidr-block "10.0.0.0/16" \\
#   --region "$REGION"

echo "VPC CIDR cannot be shrunk. Create a new VPC and migrate."`,
    terraform: `\
# Create a properly sized VPC:
resource "aws_vpc" "right_sized" {
  cidr_block           = "10.0.0.0/16"  # /16 instead of /8
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "right-sized-vpc" }
}`,
  }),

  // vpc_nacl_no_admin_ports — NACL allows admin ports from internet
  vpc_nacl_no_admin_ports: ({ resourceId }) => ({
    console: [
      `Open VPC console → Network ACLs → select "${resourceId}".`,
      "Inbound rules → Edit.",
      "Remove ALLOW rules for ports 22, 3389 from 0.0.0.0/0.",
      "Add ALLOW rules restricted to internal CIDRs.",
    ],
    cli: `\
NACL_ID="${resourceId}"

# View current rules
aws ec2 describe-network-acls \\
  --network-acl-ids "$NACL_ID" \\
  --query 'NetworkAcls[0].Entries[?Egress==\`false\`]'

# Delete rules allowing admin ports from 0.0.0.0/0
# (adjust rule numbers to match your NACL)
# aws ec2 delete-network-acl-entry \\
#   --network-acl-id "$NACL_ID" \\
#   --rule-number <RULE_NUM> --ingress

# Add restricted SSH from internal only
aws ec2 create-network-acl-entry \\
  --network-acl-id "$NACL_ID" \\
  --rule-number 100 \\
  --protocol tcp --rule-action allow --ingress \\
  --cidr-block 10.0.0.0/8 \\
  --port-range From=22,To=22`,
    terraform: `\
resource "aws_network_acl_rule" "ssh_internal" {
  network_acl_id = "${resourceId}"
  rule_number    = 100
  protocol       = "tcp"
  rule_action    = "allow"
  egress         = false
  cidr_block     = "10.0.0.0/8"
  from_port      = 22
  to_port        = 22
}`,
  }),

  // vpc_tgw_restrict_propagation — Transit GW default route propagation on
  vpc_tgw_restrict_propagation: ({ resourceId, region }) => ({
    console: [
      `Open VPC console → Transit Gateways → select "${resourceId}".`,
      "Transit gateway route tables → select default.",
      "Disable automatic route propagation.",
      "Manually add only required routes.",
    ],
    cli: `\
TGW_ID="${resourceId}"
${reg(region)}

# Get default route table
RT_ID=$(aws ec2 describe-transit-gateways \\
  --transit-gateway-ids "$TGW_ID" \\
  --region "$REGION" \\
  --query 'TransitGateways[0].Options.AssociationDefaultRouteTableId' --output text)

# Disable auto propagation on attachments
# aws ec2 disable-transit-gateway-route-table-propagation \\
#   --transit-gateway-route-table-id "$RT_ID" \\
#   --transit-gateway-attachment-id <ATTACHMENT_ID> \\
#   --region "$REGION"

echo "Disable default route propagation and add routes manually"`,
    terraform: `\
resource "aws_ec2_transit_gateway" "fix" {
  default_route_table_propagation = "disable"
  default_route_table_association = "disable"
  tags = { Name = "controlled-tgw" }
}`,
  }),

  // vpc_private_nat_gateway — Production VPC has no NAT Gateway
  vpc_private_nat_gateway: ({ resourceId, region }) => ({
    console: [
      `Open VPC console → NAT Gateways → Create NAT Gateway.`,
      `Select a public subnet in VPC "${resourceId}".`,
      "Allocate an Elastic IP → Create.",
      "Update private subnet route tables: 0.0.0.0/0 → NAT GW.",
    ],
    cli: `\
VPC_ID="${resourceId}"
${reg(region)}

# Get a public subnet
PUB_SUBNET=$(aws ec2 describe-subnets \\
  --filters Name=vpc-id,Values="$VPC_ID" \\
  --region "$REGION" \\
  --query 'Subnets[?MapPublicIpOnLaunch==\`true\`].SubnetId | [0]' --output text)

# Allocate EIP
EIP_ALLOC=$(aws ec2 allocate-address \\
  --domain vpc --region "$REGION" \\
  --query AllocationId --output text)

# Create NAT Gateway
NAT_ID=$(aws ec2 create-nat-gateway \\
  --subnet-id "$PUB_SUBNET" \\
  --allocation-id "$EIP_ALLOC" \\
  --region "$REGION" \\
  --query 'NatGateway.NatGatewayId' --output text)

echo "NAT Gateway: $NAT_ID"
echo "Update private route tables: 0.0.0.0/0 → $NAT_ID"`,
    terraform: `\
resource "aws_eip" "nat" {
  domain = "vpc"
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = var.public_subnet_id
  tags = { Name = "production-nat" }
}

resource "aws_route" "private_nat" {
  route_table_id         = var.private_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main.id
}`,
  }),

  // vpc_sg_no_db_ports_open — Security group allows database ports from internet
  vpc_sg_no_db_ports_open: ({ resourceId }) => ({
    console: [
      `Open EC2 console → Security Groups → select "${resourceId}".`,
      "Inbound rules → Edit.",
      "Remove rules allowing DB ports (3306, 5432, 1433, 27017, 6379, 9200) from 0.0.0.0/0.",
      "Add rules restricted to application security groups or internal CIDRs.",
      "Save rules.",
    ],
    cli: `\
SG_ID="${resourceId}"

# Remove public access on common DB ports
for PORT in 3306 5432 1433 27017 6379 9200; do
  aws ec2 revoke-security-group-ingress \\
    --group-id "$SG_ID" \\
    --protocol tcp --port "$PORT" --cidr 0.0.0.0/0 2>/dev/null
done

# Add access from app SG only (replace APP_SG_ID)
# aws ec2 authorize-security-group-ingress \\
#   --group-id "$SG_ID" \\
#   --protocol tcp --port 5432 \\
#   --source-group <APP_SG_ID>

# Verify
aws ec2 describe-security-groups \\
  --group-ids "$SG_ID" \\
  --query 'SecurityGroups[0].IpPermissions'`,
    terraform: `\
resource "aws_security_group_rule" "db_from_app" {
  type                     = "ingress"
  security_group_id        = "${resourceId}"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = var.app_sg_id
  description              = "PostgreSQL from app tier only"
}`,
  }),

  // vpc_no_igw_sensitive — Restricted VPC has internet gateway
  vpc_no_igw_sensitive: ({ resourceId, region }) => ({
    console: [
      `VPC "${resourceId}" is tagged data_classification=restricted but has an IGW.`,
      "Open VPC console → Internet Gateways.",
      "Select the IGW attached to this VPC → Actions → Detach.",
      "Then Actions → Delete.",
      "Use VPC endpoints for AWS service access instead.",
    ],
    cli: `\
VPC_ID="${resourceId}"
${reg(region)}

# Find attached IGW
IGW_ID=$(aws ec2 describe-internet-gateways \\
  --filters Name=attachment.vpc-id,Values="$VPC_ID" \\
  --region "$REGION" \\
  --query 'InternetGateways[0].InternetGatewayId' --output text)

# Detach and delete
aws ec2 detach-internet-gateway \\
  --internet-gateway-id "$IGW_ID" \\
  --vpc-id "$VPC_ID" \\
  --region "$REGION"

aws ec2 delete-internet-gateway \\
  --internet-gateway-id "$IGW_ID" \\
  --region "$REGION"

# Remove 0.0.0.0/0 routes from route tables
echo "Also remove any routes pointing to $IGW_ID"`,
    terraform: `\
# Remove the aws_internet_gateway resource for this VPC.
# Use VPC endpoints instead:

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = "${resourceId}"
  service_name = "com.amazonaws.${region || "us-east-1"}.s3"
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id       = "${resourceId}"
  service_name = "com.amazonaws.${region || "us-east-1"}.dynamodb"
}`,
  }),

  // vpc_flow_logs_reject — VPC flow logs capture ACCEPT traffic only
  vpc_flow_logs_reject: ({ resourceId, region }) => ({
    console: [
      `Open VPC console → Your VPCs → select "${resourceId}".`,
      "Flow logs tab → select the flow log capturing ACCEPT only.",
      "Delete it and create a new flow log with Filter: ALL.",
    ],
    cli: `\
VPC_ID="${resourceId}"
${reg(region)}

# Find existing flow log with ACCEPT filter
FL_ID=$(aws ec2 describe-flow-logs \\
  --filter Name=resource-id,Values="$VPC_ID" \\
  --region "$REGION" \\
  --query 'FlowLogs[?TrafficType==\`ACCEPT\`].FlowLogId' --output text)

# Delete ACCEPT-only flow log
aws ec2 delete-flow-logs \\
  --flow-log-ids "$FL_ID" \\
  --region "$REGION"

# Create flow log capturing ALL traffic
aws ec2 create-flow-logs \\
  --resource-type VPC \\
  --resource-ids "$VPC_ID" \\
  --traffic-type ALL \\
  --log-destination-type cloud-watch-logs \\
  --log-group-name "/aws/vpc/flowlogs/$VPC_ID" \\
  --deliver-logs-permission-arn \\
    "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/vpc-flow-log-role" \\
  --region "$REGION"

# Verify
aws ec2 describe-flow-logs \\
  --filter Name=resource-id,Values="$VPC_ID" \\
  --region "$REGION" \\
  --query 'FlowLogs[].{Id:FlowLogId,Filter:TrafficType}'`,
    terraform: `\
resource "aws_flow_log" "all_traffic" {
  vpc_id          = "${resourceId}"
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn
}`,
  }),

  // secretsmanager_auto_rotation — Secrets not in Secrets Manager
  secretsmanager_auto_rotation: ({ resourceId, region }) => ({
    console: [
      "Open Secrets Manager console → Store a new secret.",
      "Select 'Other type of secret' → enter key-value pairs.",
      `Name: ${resourceId || "myapp/secret"}.`,
      "Configure rotation (optional) → Store.",
      "Update your application to retrieve via SDK instead of env vars.",
    ],
    cli: `\
SECRET_NAME="${resourceId || "myapp/secret"}"
${reg(region)}

# Store the secret (replace <VALUE> with the actual secret value)
aws secretsmanager create-secret \\
  --name "$SECRET_NAME" \\
  --description "Migrated by CloudLine remediation" \\
  --secret-string '{"key":"<VALUE>"}' \\
  --region "$REGION"

# Get the secret ARN
aws secretsmanager describe-secret \\
  --secret-id "$SECRET_NAME" \\
  --region "$REGION" \\
  --query ARN --output text

# Enable 30-day automatic rotation (requires a rotation Lambda)
# aws secretsmanager rotate-secret \\
#   --secret-id "$SECRET_NAME" \\
#   --rotation-rules AutomaticallyAfterDays=30 \\
#   --region "$REGION"`,
    terraform: `\
resource "aws_secretsmanager_secret" "fix" {
  name                    = "${resourceId || "myapp/secret"}"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "fix" {
  secret_id     = aws_secretsmanager_secret.fix.id
  secret_string = jsonencode({ key = var.secret_value })
}

variable "secret_value" {
  description = "The secret value to store"
  sensitive   = true
}`,
  }),

  // secretsmanager_rotation_interval — Secret rotation interval exceeds 90 days
  secretsmanager_rotation_interval: ({ resourceId, region }) => ({
    console: [
      `Open Secrets Manager → select "${resourceId}".`,
      "Rotation configuration → Edit rotation.",
      "Set rotation interval to 90 days or less.",
      "Save.",
    ],
    cli: `\
SECRET="${resourceId}"
${reg(region)}

aws secretsmanager rotate-secret \\
  --secret-id "$SECRET" \\
  --rotation-rules AutomaticallyAfterDays=90 \\
  --region "$REGION"`,
    terraform: `\
resource "aws_secretsmanager_secret_rotation" "fix" {
  secret_id           = "${resourceId}"
  rotation_lambda_arn = var.rotation_lambda_arn
  rotation_rules { automatically_after_days = 90 }
}`,
  }),

  // secretsmanager_no_public_access — Secret resource policy allows public access
  secretsmanager_no_public_access: ({ resourceId, region }) => ({
    console: [
      `Open Secrets Manager → select "${resourceId}".`,
      "Resource permissions → Edit.",
      "Remove statements with Principal: '*' and no conditions.",
      "Save.",
    ],
    cli: `\
SECRET="${resourceId}"
${reg(region)}

aws secretsmanager delete-resource-policy \\
  --secret-id "$SECRET" \\
  --region "$REGION"

# Re-add scoped policy if needed
aws secretsmanager put-resource-policy \\
  --secret-id "$SECRET" \\
  --region "$REGION" \\
  --resource-policy '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Principal":{"AWS":"<ROLE_ARN>"},
      "Action":"secretsmanager:GetSecretValue",
      "Resource":"*"
    }]
  }'`,
    terraform: `\
resource "aws_secretsmanager_secret_policy" "fix" {
  secret_arn = "${resourceId}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.allowed_role_arn }
      Action    = "secretsmanager:GetSecretValue"
      Resource  = "*"
    }]
  })
}`,
  }),

  // secretsmanager_kms_encryption — Secret not encrypted with customer KMS key
  secretsmanager_kms_encryption: ({ resourceId, region }) => ({
    console: [
      `Open Secrets Manager → select "${resourceId}".`,
      "Actions → Edit encryption key.",
      "Select a customer managed KMS key.",
      "Save.",
    ],
    cli: `\
SECRET="${resourceId}"
${reg(region)}

aws secretsmanager update-secret \\
  --secret-id "$SECRET" \\
  --kms-key-id <KMS_KEY_ARN> \\
  --region "$REGION"`,
    terraform: `\
resource "aws_secretsmanager_secret" "fix" {
  name       = "${resourceId}"
  kms_key_id = aws_kms_key.secrets.arn
}`,
  }),

  // secretsmanager_unused_cleanup — Secret unused for more than 90 days
  secretsmanager_unused_cleanup: ({ resourceId, region }) => ({
    console: [
      `Open Secrets Manager → select "${resourceId}".`,
      "Check 'Last retrieved date'.",
      "If no longer needed: Actions → Delete secret.",
      "Set recovery window (7-30 days).",
    ],
    cli: `\
SECRET="${resourceId}"
${reg(region)}

# Check last accessed
aws secretsmanager describe-secret \\
  --secret-id "$SECRET" \\
  --region "$REGION" \\
  --query '{LastAccessed:LastAccessedDate,LastChanged:LastChangedDate}'

# Delete if unused (30-day recovery window)
# aws secretsmanager delete-secret \\
#   --secret-id "$SECRET" \\
#   --recovery-window-in-days 30 \\
#   --region "$REGION"`,
    terraform: `\
# Remove the unused secret resource from Terraform config.
# Terraform will schedule deletion with recovery window.`,
  }),

  // secretsmanager_cross_account_org — Secret has cross-account access without condition
  secretsmanager_cross_account_org: ({ resourceId, region }) => ({
    console: [
      `Open Secrets Manager → select "${resourceId}".`,
      "Resource permissions → Edit.",
      "Add aws:PrincipalOrgID condition to cross-account statements.",
      "Save.",
    ],
    cli: `\
SECRET="${resourceId}"
${reg(region)}

aws secretsmanager put-resource-policy \\
  --secret-id "$SECRET" \\
  --region "$REGION" \\
  --resource-policy '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Principal":"*",
      "Action":"secretsmanager:GetSecretValue",
      "Resource":"*",
      "Condition":{
        "StringEquals":{"aws:PrincipalOrgID":"<ORG_ID>"}
      }
    }]
  }'`,
    terraform: `\
resource "aws_secretsmanager_secret_policy" "fix" {
  secret_arn = "${resourceId}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "secretsmanager:GetSecretValue"
      Resource  = "*"
      Condition = {
        StringEquals = { "aws:PrincipalOrgID" = var.org_id }
      }
    }]
  })
}`,
  }),

  // secretsmanager_deletion_approval — Secret scheduled for deletion without approval
  secretsmanager_deletion_approval: ({ resourceId, region }) => ({
    console: [
      `Open Secrets Manager → select "${resourceId}".`,
      "If deletion was unintended: Actions → Cancel deletion.",
      "Add a tag 'deletion_approved=true' before scheduling.",
    ],
    cli: `\
SECRET="${resourceId}"
${reg(region)}

# Cancel accidental deletion
aws secretsmanager restore-secret \\
  --secret-id "$SECRET" \\
  --region "$REGION"

# Tag with approval before re-scheduling
aws secretsmanager tag-resource \\
  --secret-id "$SECRET" \\
  --tags Key=deletion_approved,Value=true \\
  --region "$REGION"`,
    terraform: `\
resource "aws_secretsmanager_secret" "fix" {
  name                    = "${resourceId}"
  recovery_window_in_days = 30
  tags = { deletion_approved = "true" }
}`,
  }),

  // secretsmanager_owner_purpose_tags — Secret missing owner/purpose tags
  secretsmanager_owner_purpose_tags: ({ resourceId, region }) => ({
    console: [
      `Open Secrets Manager → select "${resourceId}".`,
      "Tags → Edit.",
      "Add: owner=<team>, purpose=<description>.",
      "Save.",
    ],
    cli: `\
SECRET="${resourceId}"
${reg(region)}

aws secretsmanager tag-resource \\
  --secret-id "$SECRET" \\
  --tags Key=owner,Value="<team>" Key=purpose,Value="<description>" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_secretsmanager_secret" "fix" {
  name = "${resourceId}"
  tags = {
    owner   = "<team>"
    purpose = "<description>"
  }
}`,
  }),

  // secretsmanager_name_not_revealing — Secret name reveals its type
  secretsmanager_name_not_revealing: ({ resourceId, region }) => ({
    console: [
      "Secret names should not reveal their type (e.g. 'prod-db-password').",
      "Create a new secret with a generic name (e.g. 'prod/db/credentials').",
      `Migrate references from "${resourceId}" to the new name.`,
      "Delete the old secret.",
    ],
    cli: `\
SECRET="${resourceId}"
${reg(region)}

# Get current value
VALUE=$(aws secretsmanager get-secret-value \\
  --secret-id "$SECRET" \\
  --region "$REGION" \\
  --query SecretString --output text)

# Create with generic name
aws secretsmanager create-secret \\
  --name "prod/app/credentials" \\
  --secret-string "$VALUE" \\
  --region "$REGION"

# Update app references, then delete old secret`,
    terraform: `\
# Rename by creating new and removing old:
resource "aws_secretsmanager_secret" "renamed" {
  name = "prod/app/credentials"  # generic name
}`,
  }),

  // secretsmanager_rotation_validated — Secret rotation function is orphaned
  secretsmanager_rotation_validated: ({ resourceId, region }) => ({
    console: [
      `Open Secrets Manager → select "${resourceId}".`,
      "Rotation configuration → Edit.",
      "Verify the rotation Lambda function exists and is functional.",
      "Fix or reassign the rotation function.",
    ],
    cli: `\
SECRET="${resourceId}"
${reg(region)}

# Check rotation config
aws secretsmanager describe-secret \\
  --secret-id "$SECRET" \\
  --region "$REGION" \\
  --query '{RotationEnabled:RotationEnabled,RotationLambdaARN:RotationLambdaARN}'

# Verify the Lambda function exists
# aws lambda get-function --function-name <ROTATION_LAMBDA_ARN>

# If orphaned, disable rotation or assign a new function
# aws secretsmanager cancel-rotate-secret --secret-id "$SECRET"`,
    terraform: `\
resource "aws_secretsmanager_secret_rotation" "fix" {
  secret_id           = "${resourceId}"
  rotation_lambda_arn = aws_lambda_function.rotation.arn
  rotation_rules { automatically_after_days = 90 }
}`,
  }),

  // secretsmanager_description_required — Secret has no description
  secretsmanager_description_required: ({ resourceId, region }) => ({
    console: [
      `Open Secrets Manager → select "${resourceId}".`,
      "Actions → Edit description.",
      "Add a meaningful description.",
      "Save.",
    ],
    cli: `\
SECRET="${resourceId}"
${reg(region)}

aws secretsmanager update-secret \\
  --secret-id "$SECRET" \\
  --description "Describe the secret purpose and owner" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_secretsmanager_secret" "fix" {
  name        = "${resourceId}"
  description = "Describe the secret purpose and owner"
}`,
  }),

  // secretsmanager_multi_region — Critical secret has no multi-region replication
  secretsmanager_multi_region: ({ resourceId, region }) => ({
    console: [
      `Open Secrets Manager → select "${resourceId}".`,
      "Actions → Replicate secret to other regions.",
      "Select destination region → Replicate.",
    ],
    cli: `\
SECRET="${resourceId}"
${reg(region)}

aws secretsmanager replicate-secret-to-regions \\
  --secret-id "$SECRET" \\
  --add-replica-regions Region=us-west-2 \\
  --region "$REGION"`,
    terraform: `\
resource "aws_secretsmanager_secret" "fix" {
  name = "${resourceId}"
  replica { region = "us-west-2" }
}`,
  }),

  // secretsmanager_no_wildcard_principal — Secret policy has wildcard principal
  secretsmanager_no_wildcard_principal: ({ resourceId, region }) => ({
    console: [
      `Open Secrets Manager → select "${resourceId}".`,
      "Resource permissions → Edit.",
      "Replace Principal: '*' with specific IAM ARNs.",
      "Save.",
    ],
    cli: `\
SECRET="${resourceId}"
${reg(region)}

aws secretsmanager put-resource-policy \\
  --secret-id "$SECRET" \\
  --region "$REGION" \\
  --resource-policy '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Principal":{"AWS":"<SPECIFIC_ROLE_ARN>"},
      "Action":"secretsmanager:GetSecretValue",
      "Resource":"*"
    }]
  }'`,
    terraform: `\
resource "aws_secretsmanager_secret_policy" "fix" {
  secret_arn = "${resourceId}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.allowed_role_arn }
      Action    = "secretsmanager:GetSecretValue"
      Resource  = "*"
    }]
  })
}`,
  }),

  // storage_ebs_encryption — EBS encryption disabled
  storage_ebs_encryption: ({ resourceId, region }) => ({
    console: [
      "Enable EBS encryption by default: EC2 → Settings → EBS encryption → Enable.",
      `To encrypt existing volume "${resourceId}":`,
      "EC2 → Volumes → select volume → Actions → Create Snapshot.",
      "Snapshots → select snapshot → Actions → Copy → check Encrypt → Copy.",
      "Create a new volume from the encrypted snapshot.",
      "Stop instance, detach old volume, attach encrypted volume, start instance.",
    ],
    cli: `\
VOL_ID="${resourceId}"
${reg(region)}

# Enable EBS encryption by default (affects all future volumes)
aws ec2 enable-ebs-encryption-by-default --region "$REGION"

# Encrypt the existing volume
SNAP_ID=$(aws ec2 create-snapshot \\
  --volume-id "$VOL_ID" \\
  --description "Pre-encryption snapshot" \\
  --region "$REGION" \\
  --query SnapshotId --output text)

echo "Snapshot: $SNAP_ID — waiting for completion..."
aws ec2 wait snapshot-completed --snapshot-ids "$SNAP_ID" --region "$REGION"

ENC_SNAP_ID=$(aws ec2 copy-snapshot \\
  --source-region "$REGION" \\
  --source-snapshot-id "$SNAP_ID" \\
  --encrypted \\
  --region "$REGION" \\
  --query SnapshotId --output text)

echo "Encrypted snapshot: $ENC_SNAP_ID — waiting..."
aws ec2 wait snapshot-completed --snapshot-ids "$ENC_SNAP_ID" --region "$REGION"

NEW_VOL=$(aws ec2 create-volume \\
  --snapshot-id "$ENC_SNAP_ID" \\
  --encrypted \\
  --region "$REGION" \\
  --query VolumeId --output text)

echo "New encrypted volume: $NEW_VOL"
echo "Next: stop instance → detach $VOL_ID → attach $NEW_VOL → start"`,
    terraform: `\
resource "aws_ebs_encryption_by_default" "fix" {
  enabled = true
}

resource "aws_kms_key" "ebs" {
  description             = "EBS encryption key"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

# Replacement volume (get AZ from: aws ec2 describe-volumes --volume-ids ${resourceId})
resource "aws_ebs_volume" "encrypted" {
  availability_zone = "${region || "us-east-1"}a"  # set correct AZ
  size              = 20                            # match existing size
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs.arn
  tags = { Name = "encrypted-${resourceId}" }
}`,
  }),

  // storage_ebs_default_encryption — EBS default encryption not enabled
  storage_ebs_default_encryption: ({ region }) => ({
    console: [
      "Open EC2 console → EBS → Settings.",
      "Click 'Always encrypt new EBS volumes'.",
      "Select default KMS key or a customer managed key.",
      "Click Update.",
    ],
    cli: `\
${reg(region)}

aws ec2 enable-ebs-encryption-by-default \\
  --region "$REGION"

# Optionally set a custom default KMS key:
# aws ec2 modify-ebs-default-kms-key-id \\
#   --kms-key-id <KMS_KEY_ID> \\
#   --region "$REGION"

# Verify
aws ec2 get-ebs-encryption-by-default \\
  --region "$REGION"`,
    terraform: `\
resource "aws_ebs_encryption_by_default" "fix" {
  enabled = true
}

# Optionally set a custom default key:
# resource "aws_ebs_default_kms_key" "fix" {
#   key_arn = aws_kms_key.ebs.arn
# }`,
  }),

  // storage_ebs_snapshot_private — EBS snapshot publicly shared
  storage_ebs_snapshot_private: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Snapshots → select "${resourceId}".`,
      "Actions → Modify permissions.",
      "Change from Public to Private.",
      "Save.",
    ],
    cli: `\
SNAP_ID="${resourceId}"
${reg(region)}

# Remove public sharing
aws ec2 modify-snapshot-attribute \\
  --snapshot-id "$SNAP_ID" \\
  --attribute createVolumePermission \\
  --operation-type remove \\
  --group-names all \\
  --region "$REGION"

# Verify
aws ec2 describe-snapshot-attribute \\
  --snapshot-id "$SNAP_ID" \\
  --attribute createVolumePermission \\
  --region "$REGION"`,
    terraform: `\
# Snapshot: ${resourceId}
# Ensure no aws_snapshot_create_volume_permission
# resources grant public access.

# Block public sharing at account level:
resource "aws_ebs_snapshot_block_public_access" "fix" {
  state = "block-all-sharing"
}`,
  }),

  // storage_ebs_snapshot_encrypted — EBS snapshot not encrypted
  storage_ebs_snapshot_encrypted: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Snapshots → select "${resourceId}".`,
      "Actions → Copy snapshot.",
      "Check 'Encrypt this snapshot' → select KMS key.",
      "Copy → delete the original unencrypted snapshot.",
    ],
    cli: `\
SNAP_ID="${resourceId}"
${reg(region)}

# Copy snapshot with encryption
ENC_SNAP=$(aws ec2 copy-snapshot \\
  --source-region "$REGION" \\
  --source-snapshot-id "$SNAP_ID" \\
  --encrypted \\
  --region "$REGION" \\
  --query SnapshotId --output text)

echo "Encrypted snapshot: $ENC_SNAP"
aws ec2 wait snapshot-completed \\
  --snapshot-ids "$ENC_SNAP" --region "$REGION"

# After verifying, delete the unencrypted original:
# aws ec2 delete-snapshot \\
#   --snapshot-id "$SNAP_ID" --region "$REGION"`,
    terraform: `\
# Copy the snapshot with encryption enabled:
resource "aws_ebs_snapshot_copy" "encrypted" {
  source_snapshot_id = "${resourceId}"
  source_region      = "${region || "us-east-1"}"
  encrypted          = true

  tags = { Name = "encrypted-copy-${resourceId}" }
}

# Enable default encryption to prevent future issues:
resource "aws_ebs_encryption_by_default" "fix" {
  enabled = true
}`,
  }),

  // storage_ebs_unattached_review — Unattached EBS volume older than 30 days
  storage_ebs_unattached_review: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Volumes → select "${resourceId}".`,
      "Verify it is in 'available' state (unattached).",
      "If no longer needed: Actions → Delete volume.",
      "If needed later: Actions → Create snapshot first, then delete.",
    ],
    cli: `\
VOL_ID="${resourceId}"
${reg(region)}

# Confirm volume is unattached
aws ec2 describe-volumes \\
  --volume-ids "$VOL_ID" \\
  --region "$REGION" \\
  --query 'Volumes[0].{State:State,Created:CreateTime,Size:Size}'

# Create a snapshot backup before deleting
aws ec2 create-snapshot \\
  --volume-id "$VOL_ID" \\
  --description "Backup before cleanup" \\
  --region "$REGION"

# Delete the unattached volume
# aws ec2 delete-volume \\
#   --volume-id "$VOL_ID" --region "$REGION"`,
    terraform: `\
# Volume: ${resourceId}
# If no longer needed, simply remove the aws_ebs_volume
# resource from your Terraform config and run apply.
# Terraform will delete the unattached volume.

# If you want to keep a snapshot:
resource "aws_ebs_snapshot" "backup" {
  volume_id   = "${resourceId}"
  description = "Backup before cleanup"
}`,
  }),

  // storage_ebs_snapshot_approved_accts — EBS snapshot shared with unapproved account
  storage_ebs_snapshot_approved_accts: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Snapshots → select "${resourceId}".`,
      "Actions → Modify permissions.",
      "Remove unapproved account IDs.",
      "Add only approved account IDs.",
      "Save.",
    ],
    cli: `\
SNAP_ID="${resourceId}"
${reg(region)}

# List current sharing permissions
aws ec2 describe-snapshot-attribute \\
  --snapshot-id "$SNAP_ID" \\
  --attribute createVolumePermission \\
  --region "$REGION"

# Remove unapproved account (replace ACCOUNT_ID)
# aws ec2 modify-snapshot-attribute \\
#   --snapshot-id "$SNAP_ID" \\
#   --attribute createVolumePermission \\
#   --operation-type remove \\
#   --user-ids <UNAPPROVED_ACCOUNT_ID> \\
#   --region "$REGION"

# Verify
aws ec2 describe-snapshot-attribute \\
  --snapshot-id "$SNAP_ID" \\
  --attribute createVolumePermission \\
  --region "$REGION"`,
    terraform: `\
# Snapshot: ${resourceId}
# Remove any aws_snapshot_create_volume_permission
# resources that reference unapproved accounts.

# Only keep approved sharing:
resource "aws_snapshot_create_volume_permission" "approved" {
  snapshot_id = "${resourceId}"
  account_id  = "<APPROVED_ACCOUNT_ID>"
}`,
  }),

  // storage_ebs_snapshot_lifecycle — EBS snapshot lifecycle manager not configured
  storage_ebs_snapshot_lifecycle: ({ region }) => ({
    console: [
      "Open EC2 console → Lifecycle Manager → Create lifecycle policy.",
      "Policy type: EBS snapshot policy.",
      "Target: volumes with tag 'Backup=true'.",
      "Schedule: daily, retain 7 snapshots.",
      "Create policy.",
    ],
    cli: `\
${reg(region)}

aws dlm create-lifecycle-policy \\
  --description "Daily EBS snapshots" \\
  --state ENABLED \\
  --execution-role-arn "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/AWSDataLifecycleManagerDefaultRole" \\
  --policy-details '{
    "PolicyType": "EBS_SNAPSHOT_MANAGEMENT",
    "ResourceTypes": ["VOLUME"],
    "TargetTags": [{"Key": "Backup", "Value": "true"}],
    "Schedules": [{
      "Name": "DailySnapshot",
      "CreateRule": {"Interval": 24, "IntervalUnit": "HOURS", "Times": ["03:00"]},
      "RetainRule": {"Count": 7},
      "CopyTags": true
    }]
  }' \\
  --region "$REGION"

# Verify
aws dlm get-lifecycle-policies --region "$REGION"`,
    terraform: `\
resource "aws_dlm_lifecycle_policy" "snapshots" {
  description        = "Daily EBS snapshots"
  execution_role_arn = aws_iam_role.dlm.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["VOLUME"]
    target_tags    = { Backup = "true" }

    schedule {
      name = "DailySnapshot"
      create_rule { interval = 24 }
      retain_rule  { count = 7 }
      copy_tags    = true
    }
  }
}`,
  }),

  // storage_ebs_no_magnetic — Production EBS using deprecated magnetic type
  storage_ebs_no_magnetic: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Volumes → select "${resourceId}".`,
      "Actions → Modify volume.",
      "Change Volume type from 'standard' to 'gp3'.",
      "Apply changes.",
    ],
    cli: `\
VOL_ID="${resourceId}"
${reg(region)}

aws ec2 modify-volume \\
  --volume-id "$VOL_ID" \\
  --volume-type gp3 \\
  --region "$REGION"

# Wait for modification to complete
aws ec2 describe-volumes-modifications \\
  --volume-ids "$VOL_ID" \\
  --region "$REGION" \\
  --query 'VolumesModifications[0].ModificationState'`,
    terraform: `\
# Volume: ${resourceId}
# Import: terraform import aws_ebs_volume.fix ${resourceId}

resource "aws_ebs_volume" "fix" {
  type = "gp3"
  # Retain existing size, AZ, encryption settings
}`,
  }),

  // storage_ebs_kms_encryption — Sensitive EBS not using customer KMS key
  storage_ebs_kms_encryption: ({ resourceId, region }) => ({
    console: [
      `Volume "${resourceId}" uses AWS-managed key.`,
      "To switch to a customer KMS key, create a snapshot.",
      "Copy the snapshot selecting a customer managed KMS key.",
      "Create a new volume from the encrypted snapshot.",
      "Swap the volumes on the instance.",
    ],
    cli: `\
VOL_ID="${resourceId}"
${reg(region)}

# Create a customer KMS key
KEY_ID=$(aws kms create-key \\
  --description "EBS encryption key" \\
  --region "$REGION" \\
  --query 'KeyMetadata.KeyId' --output text)

# Snapshot → copy with CMK → new volume
SNAP=$(aws ec2 create-snapshot \\
  --volume-id "$VOL_ID" --region "$REGION" \\
  --query SnapshotId --output text)
aws ec2 wait snapshot-completed \\
  --snapshot-ids "$SNAP" --region "$REGION"

ENC_SNAP=$(aws ec2 copy-snapshot \\
  --source-region "$REGION" \\
  --source-snapshot-id "$SNAP" \\
  --encrypted --kms-key-id "$KEY_ID" \\
  --region "$REGION" \\
  --query SnapshotId --output text)
aws ec2 wait snapshot-completed \\
  --snapshot-ids "$ENC_SNAP" --region "$REGION"

echo "Create volume from $ENC_SNAP, then swap with $VOL_ID"`,
    terraform: `\
resource "aws_kms_key" "ebs_cmk" {
  description         = "Customer EBS encryption key"
  enable_key_rotation = true
}

resource "aws_ebs_volume" "fix" {
  encrypted  = true
  kms_key_id = aws_kms_key.ebs_cmk.arn
  # Set size, AZ, type to match original volume
}`,
  }),

  // storage_efs_encryption_rest — EFS encryption at rest not enabled
  storage_efs_encryption_rest: ({ resourceId, region }) => ({
    console: [
      "EFS encryption at rest can only be set at creation time.",
      "Create a new EFS file system with encryption enabled.",
      `Migrate data from "${resourceId}" using AWS DataSync.`,
      "Update mount targets and application references.",
    ],
    cli: `\
FS_ID="${resourceId}"
${reg(region)}

# Create a new encrypted EFS
NEW_FS=$(aws efs create-file-system \\
  --encrypted \\
  --performance-mode generalPurpose \\
  --throughput-mode bursting \\
  --region "$REGION" \\
  --query 'FileSystemId' --output text)

echo "New encrypted EFS: $NEW_FS"
echo "Use AWS DataSync to migrate data from $FS_ID to $NEW_FS"
echo "Then update mount targets and application config."`,
    terraform: `\
# Encryption at rest must be set at creation.
# Create a new encrypted file system:

resource "aws_efs_file_system" "encrypted" {
  encrypted = true

  tags = { Name = "encrypted-replacement" }
}

# Recreate mount targets for the new FS:
resource "aws_efs_mount_target" "fix" {
  file_system_id  = aws_efs_file_system.encrypted.id
  subnet_id       = var.subnet_id
  security_groups = [var.sg_id]
}`,
  }),

  // storage_efs_encryption_transit — EFS encryption in transit not enforced
  storage_efs_encryption_transit: ({ resourceId }) => ({
    console: [
      `Open EFS console → select "${resourceId}".`,
      "File system policy → Edit.",
      "Check 'Enforce in-transit encryption for all clients'.",
      "Save.",
    ],
    cli: `\
FS_ID="${resourceId}"

aws efs put-file-system-policy \\
  --file-system-id "$FS_ID" \\
  --policy '{
    "Version":"2012-10-17",
    "Statement":[{
      "Sid":"DenyNonTLS",
      "Effect":"Deny",
      "Principal":{"AWS":"*"},
      "Action":"*",
      "Resource":"*",
      "Condition":{
        "Bool":{"aws:SecureTransport":"false"}
      }
    }]
  }'

# Verify
aws efs describe-file-system-policy \\
  --file-system-id "$FS_ID"`,
    terraform: `\
resource "aws_efs_file_system_policy" "fix" {
  file_system_id = "${resourceId}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyNonTLS"
      Effect    = "Deny"
      Principal = { AWS = "*" }
      Action    = "*"
      Resource  = "*"
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}`,
  }),

  // storage_efs_backup — EFS backup not enabled
  storage_efs_backup: ({ resourceId, region }) => ({
    console: [
      `Open EFS console → select "${resourceId}".`,
      "General settings → Edit.",
      "Enable 'Automatic backups'.",
      "Save.",
    ],
    cli: `\
FS_ID="${resourceId}"
${reg(region)}

# Enable automatic backups
aws efs put-backup-policy \\
  --file-system-id "$FS_ID" \\
  --backup-policy Status=ENABLED \\
  --region "$REGION"

# Verify
aws efs describe-backup-policy \\
  --file-system-id "$FS_ID" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_efs_backup_policy" "fix" {
  file_system_id = "${resourceId}"

  backup_policy {
    status = "ENABLED"
  }
}`,
  }),

  // storage_efs_no_public_policy — EFS publicly accessible via resource policy
  storage_efs_no_public_policy: ({ resourceId }) => ({
    console: [
      `Open EFS console → select "${resourceId}".`,
      "File system policy → Edit.",
      "Remove or scope down statements with Principal: '*'.",
      "Add conditions or restrict to specific IAM roles.",
      "Save.",
    ],
    cli: `\
FS_ID="${resourceId}"

# View current policy
aws efs describe-file-system-policy \\
  --file-system-id "$FS_ID"

# Replace with scoped policy
aws efs put-file-system-policy \\
  --file-system-id "$FS_ID" \\
  --policy '{
    "Version":"2012-10-17",
    "Statement":[
      {
        "Sid":"DenyNonTLS",
        "Effect":"Deny",
        "Principal":{"AWS":"*"},
        "Action":"*",
        "Resource":"*",
        "Condition":{"Bool":{"aws:SecureTransport":"false"}}
      },
      {
        "Sid":"AllowSpecificRole",
        "Effect":"Allow",
        "Principal":{"AWS":"<ROLE_ARN>"},
        "Action":["elasticfilesystem:ClientMount","elasticfilesystem:ClientWrite"],
        "Resource":"*"
      }
    ]
  }'`,
    terraform: `\
resource "aws_efs_file_system_policy" "fix" {
  file_system_id = "${resourceId}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "*"
        Resource  = "*"
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid       = "AllowSpecificRole"
        Effect    = "Allow"
        Principal = { AWS = var.allowed_role_arn }
        Action    = [
          "elasticfilesystem:ClientMount",
          "elasticfilesystem:ClientWrite",
        ]
        Resource  = "*"
      },
    ]
  })
}`,
  }),

  // storage_efs_access_point_enforcement — EFS access points not enforcing user identity
  storage_efs_access_point_enforcement: ({ resourceId }) => ({
    console: [
      `Open EFS console → Access points → select "${resourceId}".`,
      "Access points cannot be modified — delete and recreate.",
      "Create new access point with POSIX user (uid, gid).",
      "Set root directory with creation info.",
    ],
    cli: `\
AP_ID="${resourceId}"

# Get current access point details
aws efs describe-access-points \\
  --access-point-id "$AP_ID"

# Delete and recreate with enforced POSIX identity
# FS_ID=$(aws efs describe-access-points \\
#   --access-point-id "$AP_ID" \\
#   --query 'AccessPoints[0].FileSystemId' --output text)

# aws efs delete-access-point --access-point-id "$AP_ID"

# aws efs create-access-point \\
#   --file-system-id "$FS_ID" \\
#   --posix-user "Uid=1000,Gid=1000" \\
#   --root-directory "Path=/app,CreationInfo={OwnerUid=1000,OwnerGid=1000,Permissions=755}"`,
    terraform: `\
resource "aws_efs_access_point" "fix" {
  file_system_id = var.efs_id

  posix_user {
    uid = 1000
    gid = 1000
  }

  root_directory {
    path = "/app"
    creation_info {
      owner_uid   = 1000
      owner_gid   = 1000
      permissions = "755"
    }
  }
}`,
  }),

  // storage_efs_kms_encryption — Sensitive EFS not using customer KMS key
  storage_efs_kms_encryption: ({ resourceId, region }) => ({
    console: [
      "EFS KMS key is set at creation and cannot be changed.",
      "Create a new EFS with a customer managed KMS key.",
      `Migrate data from "${resourceId}" using AWS DataSync.`,
      "Update mount targets and application references.",
    ],
    cli: `\
FS_ID="${resourceId}"
${reg(region)}

# Create a customer KMS key
KEY_ID=$(aws kms create-key \\
  --description "EFS encryption key" \\
  --region "$REGION" \\
  --query 'KeyMetadata.KeyId' --output text)

# Create new EFS with customer key
NEW_FS=$(aws efs create-file-system \\
  --encrypted --kms-key-id "$KEY_ID" \\
  --region "$REGION" \\
  --query 'FileSystemId' --output text)

echo "New EFS with CMK: $NEW_FS"
echo "Migrate data from $FS_ID using AWS DataSync"`,
    terraform: `\
resource "aws_kms_key" "efs" {
  description         = "EFS encryption key"
  enable_key_rotation = true
}

resource "aws_efs_file_system" "fix" {
  encrypted  = true
  kms_key_id = aws_kms_key.efs.arn

  tags = { Name = "encrypted-with-cmk" }
}`,
  }),

  // storage_efs_private_subnets — EFS mount targets not in private subnets
  storage_efs_private_subnets: ({ resourceId, region }) => ({
    console: [
      `Open EFS console → select the file system with mount target "${resourceId}".`,
      "Network tab → Manage.",
      "Remove mount targets in public subnets.",
      "Add mount targets in private subnets only.",
      "Save.",
    ],
    cli: `\
MT_ID="${resourceId}"
${reg(region)}

# Get file system ID from mount target
FS_ID=$(aws efs describe-mount-targets \\
  --mount-target-id "$MT_ID" \\
  --region "$REGION" \\
  --query 'MountTargets[0].FileSystemId' --output text)

# Delete mount target in public subnet
aws efs delete-mount-target \\
  --mount-target-id "$MT_ID" \\
  --region "$REGION"

# Create in a private subnet instead
# aws efs create-mount-target \\
#   --file-system-id "$FS_ID" \\
#   --subnet-id <PRIVATE_SUBNET_ID> \\
#   --security-groups <SG_ID> \\
#   --region "$REGION"`,
    terraform: `\
# Remove mount target from public subnet and add to private:

resource "aws_efs_mount_target" "private" {
  file_system_id  = var.efs_id
  subnet_id       = var.private_subnet_id
  security_groups = [var.efs_sg_id]
}`,
  }),

  // storage_efs_lifecycle — EFS lifecycle management not configured
  storage_efs_lifecycle: ({ resourceId }) => ({
    console: [
      `Open EFS console → select "${resourceId}".`,
      "General settings → Edit.",
      "Lifecycle management → Transition to IA after 30 days.",
      "Transition out of IA on first access.",
      "Save.",
    ],
    cli: `\
FS_ID="${resourceId}"

aws efs put-lifecycle-configuration \\
  --file-system-id "$FS_ID" \\
  --lifecycle-policies \\
    '[{"TransitionToIA":"AFTER_30_DAYS"},{"TransitionToPrimaryStorageClass":"AFTER_1_ACCESS"}]'

# Verify
aws efs describe-lifecycle-configuration \\
  --file-system-id "$FS_ID"`,
    terraform: `\
resource "aws_efs_file_system" "fix" {
  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }
  lifecycle_policy {
    transition_to_primary_storage_class = "AFTER_1_ACCESS"
  }
}`,
  }),

  // storage_efs_tags — EFS missing owner/classification tags
  storage_efs_tags: ({ resourceId, region }) => ({
    console: [
      `Open EFS console → select "${resourceId}".`,
      "Tags tab → Manage tags.",
      "Add tag: Key = 'owner', Value = '<team-or-email>'.",
      "Add tag: Key = 'data_classification', Value = 'internal'.",
      "Save.",
    ],
    cli: `\
FS_ID="${resourceId}"
${reg(region)}

aws efs tag-resource \\
  --resource-id "$FS_ID" \\
  --tags Key=owner,Value="<team-or-email>" \\
         Key=data_classification,Value=internal \\
  --region "$REGION"

# Verify
aws efs describe-file-systems \\
  --file-system-id "$FS_ID" \\
  --region "$REGION" \\
  --query 'FileSystems[0].Tags'`,
    terraform: `\
resource "aws_efs_file_system" "fix" {
  # existing config...

  tags = {
    owner               = "<team-or-email>"
    data_classification = "internal"
  }
}`,
  }),

  // storage_efs_replication — Critical EFS has no replication configured
  storage_efs_replication: ({ resourceId, region }) => ({
    console: [
      `Open EFS console → select "${resourceId}".`,
      "Replication tab → Create replication.",
      "Select destination region.",
      "Create replication.",
    ],
    cli: `\
FS_ID="${resourceId}"
${reg(region)}
DEST_REGION="us-west-2"  # change to your DR region

aws efs create-replication-configuration \\
  --source-file-system-id "$FS_ID" \\
  --destinations '[{"Region":"'"$DEST_REGION"'"}]' \\
  --region "$REGION"

# Verify
aws efs describe-replication-configurations \\
  --file-system-id "$FS_ID" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_efs_replication_configuration" "fix" {
  source_file_system_id = "${resourceId}"

  destination {
    region = "${region || "us-west-2"}"
  }
}`,
  }),

  // storage_efs_throughput_mode — EFS throughput mode not optimised for production
  storage_efs_throughput_mode: ({ resourceId, region }) => ({
    console: [
      `Open EFS console → select "${resourceId}".`,
      "General settings → Edit.",
      "Change Throughput mode to 'Elastic'.",
      "Save.",
    ],
    cli: `\
FS_ID="${resourceId}"
${reg(region)}

aws efs update-file-system \\
  --file-system-id "$FS_ID" \\
  --throughput-mode elastic \\
  --region "$REGION"

# Verify
aws efs describe-file-systems \\
  --file-system-id "$FS_ID" \\
  --region "$REGION" \\
  --query 'FileSystems[0].ThroughputMode'`,
    terraform: `\
resource "aws_efs_file_system" "fix" {
  throughput_mode = "elastic"
}`,
  }),

  // cloudwatch_root_usage_alarm — CloudWatch alarms not configured
  cloudwatch_root_usage_alarm: ({ region, accountId }) => ({
    console: [
      "Open CloudWatch console → Alarms → Create alarm.",
      "Select metric → CloudTrailMetrics namespace.",
      "Set threshold, period (300s), evaluation periods.",
      "Add SNS notification action → Create alarm.",
      "Repeat for: UnauthorizedAttemptCount, RootAccountUsage, IAMPolicyChanges.",
    ],
    cli: `\
${reg(region)}
${acct(accountId)}

# Create SNS topic for security alerts
TOPIC_ARN=$(aws sns create-topic \\
  --name security-alerts \\
  --region "$REGION" \\
  --query TopicArn --output text)

# Subscribe (replace with your email address)
aws sns subscribe \\
  --topic-arn "$TOPIC_ARN" \\
  --protocol email \\
  --notification-endpoint ops@example.com \\
  --region "$REGION"

# Alarm: unauthorized API calls
aws cloudwatch put-metric-alarm \\
  --alarm-name "UnauthorizedAPICalls" \\
  --namespace CloudTrailMetrics \\
  --metric-name UnauthorizedAttemptCount \\
  --statistic Sum --period 300 --threshold 1 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "$TOPIC_ARN" \\
  --treat-missing-data notBreaching \\
  --region "$REGION"

# Alarm: root account usage
aws cloudwatch put-metric-alarm \\
  --alarm-name "RootAccountUsage" \\
  --namespace CloudTrailMetrics \\
  --metric-name RootAccountUsage \\
  --statistic Sum --period 300 --threshold 1 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "$TOPIC_ARN" \\
  --treat-missing-data notBreaching \\
  --region "$REGION"`,
    terraform: `\
resource "aws_sns_topic" "security_alerts" {
  name = "security-alerts"
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api" {
  alarm_name          = "UnauthorizedAPICalls"
  namespace           = "CloudTrailMetrics"
  metric_name         = "UnauthorizedAttemptCount"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "RootAccountUsage"
  namespace           = "CloudTrailMetrics"
  metric_name         = "RootAccountUsage"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
}`,
  }),

  // cloudwatch_unauthorized_api_alarm — No alarm for unauthorized API calls
  cloudwatch_unauthorized_api_alarm: ({ region }) => ({
    console: [
      "Open CloudWatch console → Alarms → Create alarm.",
      "Select metric: CloudTrailMetrics → UnauthorizedAttemptCount.",
      "Set threshold >= 1, period 300s.",
      "Add SNS action → Create.",
    ],
    cli: `\
${reg(region)}

aws cloudwatch put-metric-alarm \\
  --alarm-name "UnauthorizedAPICalls" \\
  --namespace CloudTrailMetrics \\
  --metric-name UnauthorizedAttemptCount \\
  --statistic Sum --period 300 --threshold 1 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "<SNS_TOPIC_ARN>" \\
  --treat-missing-data notBreaching \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_metric_alarm" "unauthorized" {
  alarm_name          = "UnauthorizedAPICalls"
  namespace           = "CloudTrailMetrics"
  metric_name         = "UnauthorizedAttemptCount"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"
}`,
  }),

  // cloudwatch_no_mfa_login_alarm — No alarm for console login without MFA
  cloudwatch_no_mfa_login_alarm: ({ region }) => ({
    console: [
      "Open CloudWatch console → Alarms → Create alarm.",
      "Metric: CloudTrailMetrics → ConsoleSignInWithoutMFA.",
      "Threshold >= 1 → Add SNS action → Create.",
    ],
    cli: `\
${reg(region)}

aws cloudwatch put-metric-alarm \\
  --alarm-name "ConsoleLoginWithoutMFA" \\
  --namespace CloudTrailMetrics \\
  --metric-name ConsoleSignInWithoutMFA \\
  --statistic Sum --period 300 --threshold 1 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "<SNS_TOPIC_ARN>" \\
  --treat-missing-data notBreaching \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_metric_alarm" "no_mfa_login" {
  alarm_name          = "ConsoleLoginWithoutMFA"
  namespace           = "CloudTrailMetrics"
  metric_name         = "ConsoleSignInWithoutMFA"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn]
}`,
  }),

  // cloudwatch_iam_policy_alarm — No alarm for IAM policy changes
  cloudwatch_iam_policy_alarm: ({ region }) => ({
    console: [
      "Open CloudWatch console → Alarms → Create alarm.",
      "Metric: CloudTrailMetrics → IAMPolicyChanges.",
      "Threshold >= 1 → Add SNS action → Create.",
    ],
    cli: `\
${reg(region)}

aws cloudwatch put-metric-alarm \\
  --alarm-name "IAMPolicyChanges" \\
  --namespace CloudTrailMetrics \\
  --metric-name IAMPolicyChanges \\
  --statistic Sum --period 300 --threshold 1 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "<SNS_TOPIC_ARN>" \\
  --treat-missing-data notBreaching \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_metric_alarm" "iam_changes" {
  alarm_name  = "IAMPolicyChanges"
  namespace   = "CloudTrailMetrics"
  metric_name = "IAMPolicyChanges"
  statistic   = "Sum"
  period      = 300
  threshold   = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn]
}`,
  }),

  // cloudwatch_cloudtrail_alarm — No alarm for CloudTrail changes
  cloudwatch_cloudtrail_alarm: ({ region }) => ({
    console: [
      "Open CloudWatch console → Alarms → Create alarm.",
      "Metric: CloudTrailMetrics → CloudTrailConfigChanges.",
      "Threshold >= 1 → Add SNS action → Create.",
    ],
    cli: `\
${reg(region)}

aws cloudwatch put-metric-alarm \\
  --alarm-name "CloudTrailChanges" \\
  --namespace CloudTrailMetrics \\
  --metric-name CloudTrailConfigChanges \\
  --statistic Sum --period 300 --threshold 1 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "<SNS_TOPIC_ARN>" \\
  --treat-missing-data notBreaching \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_metric_alarm" "cloudtrail_changes" {
  alarm_name  = "CloudTrailChanges"
  namespace   = "CloudTrailMetrics"
  metric_name = "CloudTrailConfigChanges"
  statistic   = "Sum"
  period      = 300
  threshold   = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn]
}`,
  }),

  // cloudwatch_s3_policy_alarm — No alarm for S3 bucket policy changes
  cloudwatch_s3_policy_alarm: ({ region }) => ({
    console: [
      "Open CloudWatch console → Alarms → Create alarm.",
      "Metric: CloudTrailMetrics → S3BucketPolicyChanges.",
      "Threshold >= 1 → Add SNS action → Create.",
    ],
    cli: `\
${reg(region)}

aws cloudwatch put-metric-alarm \\
  --alarm-name "S3BucketPolicyChanges" \\
  --namespace CloudTrailMetrics \\
  --metric-name S3BucketPolicyChanges \\
  --statistic Sum --period 300 --threshold 1 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "<SNS_TOPIC_ARN>" \\
  --treat-missing-data notBreaching \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_metric_alarm" "s3_policy_changes" {
  alarm_name  = "S3BucketPolicyChanges"
  namespace   = "CloudTrailMetrics"
  metric_name = "S3BucketPolicyChanges"
  statistic   = "Sum"
  period      = 300
  threshold   = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn]
}`,
  }),

  // cloudwatch_vpc_changes_alarm — No alarm for VPC changes
  cloudwatch_vpc_changes_alarm: ({ region }) => ({
    console: ["Create CloudWatch alarm for VPC changes metric."],
    cli: `\
${reg(region)}

aws cloudwatch put-metric-alarm \\
  --alarm-name "VPCChanges" \\
  --namespace CloudTrailMetrics \\
  --metric-name VPCChanges \\
  --statistic Sum --period 300 --threshold 1 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "<SNS_TOPIC_ARN>" \\
  --treat-missing-data notBreaching \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_metric_alarm" "vpc_changes" {
  alarm_name  = "VPCChanges"
  namespace   = "CloudTrailMetrics"
  metric_name = "VPCChanges"
  statistic   = "Sum"
  period      = 300
  threshold   = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn]
}`,
  }),

  // cloudwatch_sg_changes_alarm — No alarm for security group changes
  cloudwatch_sg_changes_alarm: ({ region }) => ({
    console: ["Create CloudWatch alarm for SecurityGroupChanges metric."],
    cli: `\
${reg(region)}

aws cloudwatch put-metric-alarm \\
  --alarm-name "SecurityGroupChanges" \\
  --namespace CloudTrailMetrics \\
  --metric-name SecurityGroupChanges \\
  --statistic Sum --period 300 --threshold 1 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "<SNS_TOPIC_ARN>" \\
  --treat-missing-data notBreaching \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_metric_alarm" "sg_changes" {
  alarm_name  = "SecurityGroupChanges"
  namespace   = "CloudTrailMetrics"
  metric_name = "SecurityGroupChanges"
  statistic   = "Sum"
  period      = 300
  threshold   = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn]
}`,
  }),

  // cloudwatch_nacl_changes_alarm — No alarm for NACL changes
  cloudwatch_nacl_changes_alarm: ({ region }) => ({
    console: ["Create CloudWatch alarm for NACLChanges metric."],
    cli: `\
${reg(region)}

aws cloudwatch put-metric-alarm \\
  --alarm-name "NACLChanges" \\
  --namespace CloudTrailMetrics \\
  --metric-name NACLChanges \\
  --statistic Sum --period 300 --threshold 1 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "<SNS_TOPIC_ARN>" \\
  --treat-missing-data notBreaching \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_metric_alarm" "nacl_changes" {
  alarm_name  = "NACLChanges"
  namespace   = "CloudTrailMetrics"
  metric_name = "NACLChanges"
  statistic   = "Sum"
  period      = 300
  threshold   = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn]
}`,
  }),

  // cloudwatch_igw_changes_alarm — No alarm for internet gateway changes
  cloudwatch_igw_changes_alarm: ({ region }) => ({
    console: ["Create CloudWatch alarm for IGW changes metric."],
    cli: `\
${reg(region)}

aws cloudwatch put-metric-alarm \\
  --alarm-name "InternetGatewayChanges" \\
  --namespace CloudTrailMetrics \\
  --metric-name IGWChanges \\
  --statistic Sum --period 300 --threshold 1 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "<SNS_TOPIC_ARN>" \\
  --treat-missing-data notBreaching \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_metric_alarm" "igw_changes" {
  alarm_name  = "InternetGatewayChanges"
  namespace   = "CloudTrailMetrics"
  metric_name = "IGWChanges"
  statistic   = "Sum"
  period      = 300
  threshold   = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn]
}`,
  }),

  // cloudwatch_log_retention — CloudWatch log group has no retention policy
  cloudwatch_log_retention: ({ resourceId, region }) => ({
    console: [
      `Open CloudWatch console → Log groups → select "${resourceId}".`,
      "Actions → Edit retention → select retention period.",
    ],
    cli: `\
LOG_GROUP="${resourceId}"
${reg(region)}

aws logs put-retention-policy \\
  --log-group-name "$LOG_GROUP" \\
  --retention-in-days 90 \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_log_group" "fix" {
  name              = "${resourceId}"
  retention_in_days = 90
}`,
  }),

  // cloudwatch_log_kms_encryption — CloudWatch log group not encrypted with KMS
  cloudwatch_log_kms_encryption: ({ resourceId, region }) => ({
    console: [
      `Open CloudWatch console → Log groups → select "${resourceId}".`,
      "Actions → Edit → select KMS key.",
      "Save.",
    ],
    cli: `\
LOG_GROUP="${resourceId}"
${reg(region)}

aws logs associate-kms-key \\
  --log-group-name "$LOG_GROUP" \\
  --kms-key-id "<KMS_KEY_ARN>" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_log_group" "fix" {
  name       = "${resourceId}"
  kms_key_id = aws_kms_key.logs.arn
}`,
  }),

  // cloudwatch_alarm_sns_action — CloudWatch alarm has no SNS action
  cloudwatch_alarm_sns_action: ({ resourceId, region }) => ({
    console: [
      `Open CloudWatch console → Alarms → select "${resourceId}".`,
      "Edit → Notification → Add SNS topic action.",
      "Save.",
    ],
    cli: `\
ALARM="${resourceId}"
${reg(region)}

# Get current alarm config and update with SNS action
echo "Update alarm $ALARM to add --alarm-actions <SNS_TOPIC_ARN>"`,
    terraform: `\
resource "aws_cloudwatch_metric_alarm" "fix" {
  alarm_name    = "${resourceId}"
  alarm_actions = [var.sns_topic_arn]
}`,
  }),

  // cloudwatch_no_insufficient_data — CloudWatch alarm in INSUFFICIENT_DATA state
  cloudwatch_no_insufficient_data: ({ resourceId, region }) => ({
    console: [
      `Open CloudWatch console → Alarms → select "${resourceId}".`,
      "Check metric configuration — ensure the metric exists.",
      "Verify the namespace, metric name, and dimensions.",
    ],
    cli: `\
ALARM="${resourceId}"
${reg(region)}

# Check alarm config
aws cloudwatch describe-alarms \\
  --alarm-names "$ALARM" \\
  --region "$REGION"

# Verify the metric has data
# aws cloudwatch get-metric-statistics \\
#   --namespace <NS> --metric-name <METRIC> \\
#   --start-time <TIME> --end-time <TIME> \\
#   --period 300 --statistics Sum`,
    terraform: `\
# Verify the metric source is emitting data.
# Check namespace, metric_name, and dimensions match
# an active metric.`,
  }),

  // cloudwatch_failed_login_alarm — No alarm for failed console sign-in
  cloudwatch_failed_login_alarm: ({ region }) => ({
    console: ["Create CloudWatch alarm for FailedConsoleSignIn metric."],
    cli: `\
${reg(region)}

aws cloudwatch put-metric-alarm \\
  --alarm-name "FailedConsoleSignIn" \\
  --namespace CloudTrailMetrics \\
  --metric-name FailedConsoleSignIn \\
  --statistic Sum --period 300 --threshold 3 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "<SNS_TOPIC_ARN>" \\
  --treat-missing-data notBreaching \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_metric_alarm" "failed_login" {
  alarm_name  = "FailedConsoleSignIn"
  namespace   = "CloudTrailMetrics"
  metric_name = "FailedConsoleSignIn"
  statistic   = "Sum"
  period      = 300
  threshold   = 3
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn]
}`,
  }),

  // cloudwatch_cmk_deletion_alarm — No alarm for CMK deletion/disable
  cloudwatch_cmk_deletion_alarm: ({ region }) => ({
    console: ["Create CloudWatch alarm for KMS key deletion/disable events."],
    cli: `\
${reg(region)}

aws cloudwatch put-metric-alarm \\
  --alarm-name "CMKDeletionOrDisable" \\
  --namespace CloudTrailMetrics \\
  --metric-name CMKDeletion \\
  --statistic Sum --period 300 --threshold 1 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "<SNS_TOPIC_ARN>" \\
  --treat-missing-data notBreaching \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_metric_alarm" "cmk_deletion" {
  alarm_name  = "CMKDeletionOrDisable"
  namespace   = "CloudTrailMetrics"
  metric_name = "CMKDeletion"
  statistic   = "Sum"
  period      = 300
  threshold   = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn]
}`,
  }),

  // cloudwatch_config_changes_alarm — No alarm for AWS Config changes
  cloudwatch_config_changes_alarm: ({ region }) => ({
    console: ["Create CloudWatch alarm for Config configuration changes."],
    cli: `\
${reg(region)}

aws cloudwatch put-metric-alarm \\
  --alarm-name "AWSConfigChanges" \\
  --namespace CloudTrailMetrics \\
  --metric-name ConfigChanges \\
  --statistic Sum --period 300 --threshold 1 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "<SNS_TOPIC_ARN>" \\
  --treat-missing-data notBreaching \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_metric_alarm" "config_changes" {
  alarm_name  = "AWSConfigChanges"
  namespace   = "CloudTrailMetrics"
  metric_name = "ConfigChanges"
  statistic   = "Sum"
  period      = 300
  threshold   = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn]
}`,
  }),

  // cloudwatch_org_changes_alarm — No alarm for AWS Organizations changes
  cloudwatch_org_changes_alarm: ({ region }) => ({
    console: ["Create CloudWatch alarm for Organizations changes."],
    cli: `\
${reg(region)}

aws cloudwatch put-metric-alarm \\
  --alarm-name "OrganizationsChanges" \\
  --namespace CloudTrailMetrics \\
  --metric-name OrganizationsChanges \\
  --statistic Sum --period 300 --threshold 1 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "<SNS_TOPIC_ARN>" \\
  --treat-missing-data notBreaching \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_metric_alarm" "org_changes" {
  alarm_name  = "OrganizationsChanges"
  namespace   = "CloudTrailMetrics"
  metric_name = "OrganizationsChanges"
  statistic   = "Sum"
  period      = 300
  threshold   = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn]
}`,
  }),

  // cloudwatch_log_retention_90d — CloudWatch log group retention < 90 days
  cloudwatch_log_retention_90d: ({ resourceId, region }) => ({
    console: [
      `Open CloudWatch console → Log groups → select "${resourceId}".`,
      "Actions → Edit retention → set to at least 90 days.",
    ],
    cli: `\
LOG_GROUP="${resourceId}"
${reg(region)}

aws logs put-retention-policy \\
  --log-group-name "$LOG_GROUP" \\
  --retention-in-days 90 \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_log_group" "fix" {
  name              = "${resourceId}"
  retention_in_days = 90
}`,
  }),

  // cloudwatch_route_table_alarm — No alarm for route table changes
  cloudwatch_route_table_alarm: ({ region }) => ({
    console: ["Create CloudWatch alarm for route table changes metric."],
    cli: `\
${reg(region)}

aws cloudwatch put-metric-alarm \\
  --alarm-name "RouteTableChanges" \\
  --namespace CloudTrailMetrics \\
  --metric-name RouteTableChanges \\
  --statistic Sum --period 300 --threshold 1 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "<SNS_TOPIC_ARN>" \\
  --treat-missing-data notBreaching \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_metric_alarm" "route_table_changes" {
  alarm_name  = "RouteTableChanges"
  namespace   = "CloudTrailMetrics"
  metric_name = "RouteTableChanges"
  statistic   = "Sum"
  period      = 300
  threshold   = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn]
}`,
  }),

  // iam_access_analyzer — IAM Access Analyzer disabled
  iam_access_analyzer: ({ accountId }) => ({
    console: [
      "Open IAM console → Access analyzer.",
      "Click Create analyzer → scope: Account.",
      "Enter a name → Create.",
      "Review any findings surfaced immediately.",
    ],
    cli: `\
${acct(accountId)}

# Create analyzer only if one does not already exist
EXISTING=$(aws accessanalyzer list-analyzers --query 'analyzers[?name==\`cloudline-analyzer\`].arn' --output text)
if [ -z "$EXISTING" ]; then
  aws accessanalyzer create-analyzer --analyzer-name "cloudline-analyzer" --type ACCOUNT
  echo "Analyzer created."
else
  echo "Analyzer already exists: $EXISTING"
fi

# List active findings
ANALYZER_ARN=$(aws accessanalyzer list-analyzers --query 'analyzers[?name==\`cloudline-analyzer\`].arn' --output text)
aws accessanalyzer list-findings --analyzer-arn "$ANALYZER_ARN" --filter '{"status":{"eq":["ACTIVE"]}}'`,
    terraform: `\
resource "aws_accessanalyzer_analyzer" "fix" {
  analyzer_name = "cloudline-analyzer"
  type          = "ACCOUNT"
  tags = { ManagedBy = "terraform" }
}`,
  }),

  // iam_pwd_uppercase — Password policy: no uppercase required
  iam_pwd_uppercase: () => ({
    console: [
      "Open IAM console → Account settings.",
      "Click Change password policy.",
      "Ensure ALL settings are configured: uppercase, lowercase, numbers, symbols, min length 14, reuse prevention 24, max age 90.",
      "Click Save changes.",
    ],
    cli: `\
# IMPORTANT: This command replaces the ENTIRE password policy.
# All flags must be specified in a single call or unset
# flags revert to defaults.
aws iam update-account-password-policy \\
  --minimum-password-length 14 \\
  --require-uppercase-characters \\
  --require-lowercase-characters \\
  --require-numbers \\
  --require-symbols \\
  --allow-users-to-change-password \\
  --max-password-age 90 \\
  --password-reuse-prevention 24 \\
  --no-hard-expiry

# Verify
aws iam get-account-password-policy`,
    terraform: `\
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}`,
  }),

  // iam_pwd_lowercase — Password policy: no lowercase required
  iam_pwd_lowercase: () => ({
    console: [
      "Open IAM console → Account settings.",
      "Click Change password policy.",
      "Ensure ALL settings are configured: uppercase, lowercase, numbers, symbols, min length 14, reuse prevention 24, max age 90.",
      "Click Save changes.",
    ],
    cli: `\
# IMPORTANT: This command replaces the ENTIRE password policy.
# All flags must be specified in a single call or unset
# flags revert to defaults.
aws iam update-account-password-policy \\
  --minimum-password-length 14 \\
  --require-uppercase-characters \\
  --require-lowercase-characters \\
  --require-numbers \\
  --require-symbols \\
  --allow-users-to-change-password \\
  --max-password-age 90 \\
  --password-reuse-prevention 24 \\
  --no-hard-expiry

# Verify
aws iam get-account-password-policy`,
    terraform: `\
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}`,
  }),

  // iam_pwd_numbers — Password policy: no numbers required
  iam_pwd_numbers: () => ({
    console: [
      "Open IAM console → Account settings.",
      "Click Change password policy.",
      "Ensure ALL settings are configured: uppercase, lowercase, numbers, symbols, min length 14, reuse prevention 24, max age 90.",
      "Click Save changes.",
    ],
    cli: `\
# IMPORTANT: This command replaces the ENTIRE password policy.
# All flags must be specified in a single call or unset
# flags revert to defaults.
aws iam update-account-password-policy \\
  --minimum-password-length 14 \\
  --require-uppercase-characters \\
  --require-lowercase-characters \\
  --require-numbers \\
  --require-symbols \\
  --allow-users-to-change-password \\
  --max-password-age 90 \\
  --password-reuse-prevention 24 \\
  --no-hard-expiry

# Verify
aws iam get-account-password-policy`,
    terraform: `\
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}`,
  }),

  // iam_pwd_symbols — Password policy: no symbols required
  iam_pwd_symbols: () => ({
    console: [
      "Open IAM console → Account settings.",
      "Click Change password policy.",
      "Ensure ALL settings are configured: uppercase, lowercase, numbers, symbols, min length 14, reuse prevention 24, max age 90.",
      "Click Save changes.",
    ],
    cli: `\
# IMPORTANT: This command replaces the ENTIRE password policy.
# All flags must be specified in a single call or unset
# flags revert to defaults.
aws iam update-account-password-policy \\
  --minimum-password-length 14 \\
  --require-uppercase-characters \\
  --require-lowercase-characters \\
  --require-numbers \\
  --require-symbols \\
  --allow-users-to-change-password \\
  --max-password-age 90 \\
  --password-reuse-prevention 24 \\
  --no-hard-expiry

# Verify
aws iam get-account-password-policy`,
    terraform: `\
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}`,
  }),

  // iam_pwd_reuse — Password policy: insufficient reuse prevention
  iam_pwd_reuse: () => ({
    console: [
      "Open IAM console → Account settings.",
      "Click Change password policy.",
      "Ensure ALL settings are configured: uppercase, lowercase, numbers, symbols, min length 14, reuse prevention 24, max age 90.",
      "Click Save changes.",
    ],
    cli: `\
# IMPORTANT: This command replaces the ENTIRE password policy.
# All flags must be specified in a single call or unset
# flags revert to defaults.
aws iam update-account-password-policy \\
  --minimum-password-length 14 \\
  --require-uppercase-characters \\
  --require-lowercase-characters \\
  --require-numbers \\
  --require-symbols \\
  --allow-users-to-change-password \\
  --max-password-age 90 \\
  --password-reuse-prevention 24 \\
  --no-hard-expiry

# Verify
aws iam get-account-password-policy`,
    terraform: `\
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}`,
  }),

  // iam_pwd_max_age — Password policy: max age exceeds 90 days
  iam_pwd_max_age: () => ({
    console: [
      "Open IAM console → Account settings.",
      "Click Change password policy.",
      "Ensure ALL settings are configured: uppercase, lowercase, numbers, symbols, min length 14, reuse prevention 24, max age 90.",
      "Click Save changes.",
    ],
    cli: `\
# IMPORTANT: This command replaces the ENTIRE password policy.
# All flags must be specified in a single call or unset
# flags revert to defaults.
aws iam update-account-password-policy \\
  --minimum-password-length 14 \\
  --require-uppercase-characters \\
  --require-lowercase-characters \\
  --require-numbers \\
  --require-symbols \\
  --allow-users-to-change-password \\
  --max-password-age 90 \\
  --password-reuse-prevention 24 \\
  --no-hard-expiry

# Verify
aws iam get-account-password-policy`,
    terraform: `\
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}`,
  }),

  // iam_root_access_keys — Root account has active access keys
  iam_root_access_keys: ({ accountId }) => ({
    console: [
      "Sign in as the root user.",
      "Click account name (top-right) → Security credentials.",
      "Scroll to Access keys.",
      "Click Deactivate on each active key, then Delete.",
      "Create an IAM admin user with MFA instead.",
    ],
    cli: `\
${acct(accountId)}

# List root access keys (must be run as root)
aws iam list-access-keys

# Deactivate root key (replace KEY_ID)
# aws iam update-access-key \\
#   --access-key-id <KEY_ID> \\
#   --status Inactive

# Delete root key after confirming no breakage
# aws iam delete-access-key \\
#   --access-key-id <KEY_ID>

# Verify no active root keys remain
aws iam get-account-summary \\
  --query 'SummaryMap.AccountAccessKeysPresent'`,
    terraform: `\
# Root access keys cannot be managed via Terraform.
# Delete them manually via Console or CLI, then enforce
# with an SCP:
resource "aws_organizations_policy" "deny_root_keys" {
  name = "DenyRootAccessKeys"
  type = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Deny"
      Action    = "iam:CreateAccessKey"
      Resource  = "arn:aws:iam::*:root"
    }]
  })
}`,
  }),

  // iam_no_inline_policies — IAM user has inline policies
  iam_no_inline_policies: ({ resourceId, accountId }) => ({
    console: [
      `Open IAM console → Users → select "${resourceId}" → Permissions tab.`,
      "Expand each inline policy and copy its JSON document.",
      "Go to IAM → Policies → Create policy → paste the JSON (keep the same permissions — this is a customer-managed policy, not a broad AWS-managed one).",
      'Name it clearly (e.g. "${resourceId}-s3-read") → Create policy.',
      `Return to Users → "${resourceId}" → Add permissions → Attach policies → select the new policy.`,
      "Back on the Permissions tab, expand the original inline policy → click Remove → confirm.",
      "Repeat for each inline policy on this user.",
    ],
    cli: `\
USERNAME="${resourceId}"
ACCOUNT_ID="${accountId}"

# Step 1 — list inline policies on this user
INLINE_POLICIES=$(aws iam list-user-policies --user-name "$USERNAME" --query 'PolicyNames' --output text)
echo "Inline policies: $INLINE_POLICIES"

# Step 2 — for each inline policy: export it, create a customer-managed policy, attach it, then delete the inline
for POLICY_NAME in $INLINE_POLICIES; do
  echo "--- Processing: $POLICY_NAME"

  # Export the inline policy document
  aws iam get-user-policy --user-name "$USERNAME" --policy-name "$POLICY_NAME" --query 'PolicyDocument' --output json > /tmp/$POLICY_NAME.json

  # Create a customer-managed policy with identical permissions
  MANAGED_ARN=$(aws iam create-policy --policy-name "$USERNAME-$POLICY_NAME" --policy-document file:///tmp/$POLICY_NAME.json --query 'Policy.Arn' --output text)
  echo "Created managed policy: $MANAGED_ARN"

  # Attach the new managed policy to the user
  aws iam attach-user-policy --user-name "$USERNAME" --policy-arn "$MANAGED_ARN"
  echo "Attached $MANAGED_ARN to $USERNAME"

  # Remove the inline policy
  aws iam delete-user-policy --user-name "$USERNAME" --policy-name "$POLICY_NAME"
  echo "Deleted inline policy: $POLICY_NAME"
done

# Verify — should return empty list
echo "Remaining inline policies:"
aws iam list-user-policies --user-name "$USERNAME" --query 'PolicyNames' --output text`,
    terraform: `\
# Replace aws_iam_user_policy (inline) with aws_iam_policy + attachment.
# Keep the same Statement block — this is a customer-managed policy
# scoped to this user's exact needs, not a broad AWS-managed policy.

resource "aws_iam_policy" "fix" {
  name        = "${resourceId}-managed"
  description = "Customer-managed policy converted from inline for ${resourceId}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Paste the Statement array from the original inline policy here.
      # Keep the same Actions and Resources — only the storage location changes.
    ]
  })
}

resource "aws_iam_user_policy_attachment" "fix" {
  user       = "${resourceId}"
  policy_arn = aws_iam_policy.fix.arn
}

# Remove any aws_iam_user_policy blocks that were here before.`,
  }),

  // iam_no_admin_access — IAM user has AdministratorAccess permanently attached
  iam_no_admin_access: ({ resourceId, accountId }) => ({
    console: [
      "NOTE: The goal is NOT to remove admin capability — it is to make admin access time-limited and auditable via a role.",
      "IAM console → Roles → Create role → Trusted entity: AWS account → This account.",
      "Check 'Require MFA' under conditions → Next.",
      "Attach AdministratorAccess policy → Next → Name it 'CloudLineAdminRole' → Create role.",
      `IAM → Users → select "${resourceId}" → Permissions → Add permissions → Attach policies.`,
      "Create and attach a policy that allows only sts:AssumeRole on the new role ARN (see CLI tab for the policy JSON).",
      `Remove the direct AdministratorAccess attachment from "${resourceId}".`,
      `To use admin: "${resourceId}" runs 'aws sts assume-role ...' — CloudTrail logs every session.`,
    ],
    cli: `\
USERNAME="${resourceId}"
ACCOUNT_ID="${accountId}"
ROLE_NAME="CloudLineAdminRole"

# Step 1 — create an admin role with a trust policy that allows this user to assume it (MFA required)
cat > /tmp/trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::${accountId}:user/${resourceId}" },
    "Action": "sts:AssumeRole",
    "Condition": { "Bool": { "aws:MultiFactorAuthPresent": "true" } }
  }]
}
EOF

aws iam create-role --role-name "$ROLE_NAME" --assume-role-policy-document file:///tmp/trust-policy.json
aws iam attach-role-policy --role-name "$ROLE_NAME" --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
echo "Admin role created: arn:aws:iam::$ACCOUNT_ID:role/$ROLE_NAME"

# Step 2 — grant the user permission to assume the role (but nothing else)
cat > /tmp/assume-role-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": "arn:aws:iam::${accountId}:role/CloudLineAdminRole"
  }]
}
EOF

aws iam create-policy --policy-name "$USERNAME-can-assume-admin" --policy-document file:///tmp/assume-role-policy.json
POLICY_ARN=$(aws iam list-policies --query 'Policies[?PolicyName==\`'"$USERNAME-can-assume-admin"'\`].Arn' --output text)
aws iam attach-user-policy --user-name "$USERNAME" --policy-arn "$POLICY_ARN"

# Step 3 — remove the permanent AdministratorAccess from the user
aws iam detach-user-policy --user-name "$USERNAME" --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Verify
echo "User policies (should not include AdministratorAccess):"
aws iam list-attached-user-policies --user-name "$USERNAME" --query 'AttachedPolicies[].PolicyName' --output text

# Step 4 — how to use admin access going forward
echo "To assume admin role (requires MFA):"
echo "aws sts assume-role --role-arn arn:aws:iam::$ACCOUNT_ID:role/$ROLE_NAME --role-session-name admin-session --serial-number arn:aws:iam::$ACCOUNT_ID:mfa/$USERNAME --token-code <MFA_CODE>"`,
    terraform: `\
data "aws_caller_identity" "current" {}

# Admin role — AdministratorAccess attached to a role, not a user
resource "aws_iam_role" "admin" {
  name = "CloudLineAdminRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${accountId}:user/${resourceId}" }
      Action    = "sts:AssumeRole"
      Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Grant the user permission to assume the admin role only
resource "aws_iam_user_policy" "can_assume_admin" {
  name = "${resourceId}-assume-admin"
  user = "${resourceId}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = aws_iam_role.admin.arn
    }]
  })
}

# Remove the direct AdministratorAccess attachment:
# resource "aws_iam_user_policy_attachment" "admin" { ... }  ← DELETE THIS`,
  }),

  // iam_key_rotation — Access key not rotated within 90 days
  iam_key_rotation: ({ resourceId }) => ({
    console: [
      `Open IAM console → Users → select "${resourceId}".`,
      "Security credentials tab → Access keys.",
      "Click Create access key to generate a new key.",
      "Update all applications to use the new key.",
      "Deactivate the old key → test → Delete.",
    ],
    cli: `\
USERNAME="${resourceId}"

# List existing keys with age
aws iam list-access-keys --user-name "$USERNAME"

# Create a new key
aws iam create-access-key --user-name "$USERNAME"
# Save the AccessKeyId and SecretAccessKey securely!

# After updating applications, deactivate the old key:
# aws iam update-access-key \\
#   --user-name "$USERNAME" \\
#   --access-key-id <OLD_KEY_ID> \\
#   --status Inactive

# Confirm applications still work, then delete:
# aws iam delete-access-key \\
#   --user-name "$USERNAME" \\
#   --access-key-id <OLD_KEY_ID>

# Verify
aws iam list-access-keys --user-name "$USERNAME"`,
    terraform: `\
# User: ${resourceId}
# Rotate by replacing the aws_iam_access_key resource:

resource "aws_iam_access_key" "rotated" {
  user = "${resourceId}"
  # Terraform will create a new key.
  # Store the secret in a secure output or Secrets Manager.
}

# Best practice: replace long-lived keys with IAM roles
# for EC2/Lambda workloads.`,
  }),

  // iam_no_wildcard_policy — IAM policy allows Action:* on Resource:*
  iam_no_wildcard_policy: ({ resourceId }) => ({
    console: [
      `Open IAM console → Policies → select "${resourceId}".`,
      "Click Edit policy → JSON tab.",
      "Replace Action: '*' and Resource: '*' with specific actions and resources.",
      "Review policy → Save changes.",
    ],
    cli: `\
POLICY_ARN="${resourceId}"

# Get the current policy document
VERSION=$(aws iam get-policy \\
  --policy-arn "$POLICY_ARN" \\
  --query 'Policy.DefaultVersionId' \\
  --output text)

aws iam get-policy-version \\
  --policy-arn "$POLICY_ARN" \\
  --version-id "$VERSION" \\
  --query 'PolicyVersion.Document'

# Create a scoped replacement version:
# aws iam create-policy-version \\
#   --policy-arn "$POLICY_ARN" \\
#   --policy-document file://scoped-policy.json \\
#   --set-as-default

# Use IAM Access Analyzer to generate a least-privilege policy:
# aws accessanalyzer generate-policy \\
#   --policy-generation-details principalArn="<ROLE_ARN>"`,
    terraform: `\
# Policy: ${resourceId}
# Replace wildcard policy with scoped permissions:

resource "aws_iam_policy" "fix" {
  name = "scoped-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = [
        "s3:GetObject",
        "s3:PutObject",
        # Add only required actions
      ]
      Resource = [
        "arn:aws:s3:::my-bucket/*",
        # Add only required resources
      ]
    }]
  })
}`,
  }),

  // iam_unused_keys — Unused access key active > 90 days
  iam_unused_keys: ({ resourceId }) => ({
    console: [
      `Open IAM console → Users → select "${resourceId}".`,
      "Security credentials tab → Access keys.",
      "Check 'Last used' column — identify keys unused > 90 days.",
      "Click Deactivate on unused keys, then Delete.",
    ],
    cli: `\
USERNAME="${resourceId}"

# List access keys
aws iam list-access-keys --user-name "$USERNAME"

# Check last-used date for each key
# aws iam get-access-key-last-used --access-key-id <KEY_ID>

# Deactivate unused key
# aws iam update-access-key \\
#   --user-name "$USERNAME" \\
#   --access-key-id <KEY_ID> \\
#   --status Inactive

# Delete after confirming no impact
# aws iam delete-access-key \\
#   --user-name "$USERNAME" \\
#   --access-key-id <KEY_ID>

# Verify
aws iam list-access-keys --user-name "$USERNAME"`,
    terraform: `\
# User: ${resourceId}
# Deactivate the unused key:
resource "aws_iam_access_key" "deactivate" {
  user   = "${resourceId}"
  status = "Inactive"
}

# Best practice: migrate to IAM roles for workloads
# and eliminate long-lived access keys entirely.`,
  }),

  // iam_role_trust_wildcard — IAM role trust policy allows all principals
  iam_role_trust_wildcard: ({ resourceId }) => ({
    console: [
      `Open IAM console → Roles → select "${resourceId}".`,
      "Trust relationships tab → Edit trust policy.",
      "Replace Principal: '*' with specific accounts, services, or users.",
      "Add conditions (e.g. aws:PrincipalOrgID) for cross-account access.",
      "Click Update policy.",
    ],
    cli: `\
ROLE_NAME="${resourceId}"

# View current trust policy
aws iam get-role \\
  --role-name "$ROLE_NAME" \\
  --query 'Role.AssumeRolePolicyDocument'

# Update with a scoped trust policy (save to file first):
# cat > trust-policy.json << 'POLICY'
# {
#   "Version": "2012-10-17",
#   "Statement": [{
#     "Effect": "Allow",
#     "Principal": {
#       "AWS": "arn:aws:iam::<TRUSTED_ACCOUNT>:root"
#     },
#     "Action": "sts:AssumeRole",
#     "Condition": {
#       "StringEquals": {
#         "aws:PrincipalOrgID": "<ORG_ID>"
#       }
#     }
#   }]
# }
# POLICY

# aws iam update-assume-role-policy \\
#   --role-name "$ROLE_NAME" \\
#   --policy-document file://trust-policy.json

# Verify
aws iam get-role \\
  --role-name "$ROLE_NAME" \\
  --query 'Role.AssumeRolePolicyDocument'`,
    terraform: `\
# Role: ${resourceId}
resource "aws_iam_role" "fix" {
  name = "${resourceId}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::<TRUSTED_ACCOUNT>:root"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:PrincipalOrgID" = "<ORG_ID>"
        }
      }
    }]
  })
}`,
  }),

  // iam_dual_access — IAM user has both console and API access
  iam_dual_access: ({ resourceId }) => ({
    console: [
      "If this user legitimately needs both (e.g., a developer who deploys manually AND automates): enforce MFA on console access and rotate access keys every 90 days. Consider replacing long-term keys with STS temporary credentials (e.g., aws-vault, IAM Identity Center).",
      "If only console access is needed: IAM → Users → Security credentials → Access keys → Deactivate then Delete.",
      "If only programmatic access is needed: IAM → Users → Security credentials → Console sign-in → Disable.",
      "Best practice for automation: use IAM roles with STS AssumeRole instead of long-term access keys entirely.",
    ],
    cli: `\
USERNAME="${resourceId}"

# Audit what this user does with each credential type
echo "=== Console last sign-in ==="
aws iam get-user --user-name "$USERNAME" --query 'User.PasswordLastUsed'

echo "=== Access key usage ==="
aws iam list-access-keys --user-name "$USERNAME" --query 'AccessKeyMetadata[].{KeyId:AccessKeyId,Status:Status,Created:CreateDate}'
aws iam get-access-key-last-used --access-key-id $(aws iam list-access-keys --user-name "$USERNAME" --query 'AccessKeyMetadata[0].AccessKeyId' --output text) --query 'AccessKeyLastUsed'

# If keeping both: enforce MFA for console (requires MFA-enforced policy)
cat > /tmp/require-mfa.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyWithoutMFA",
    "Effect": "Deny",
    "NotAction": ["iam:CreateVirtualMFADevice", "iam:EnableMFADevice", "sts:GetSessionToken"],
    "Resource": "*",
    "Condition": { "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" } }
  }]
}
EOF
aws iam put-user-policy --user-name "$USERNAME" --policy-name "RequireMFA" --policy-document file:///tmp/require-mfa.json
echo "MFA enforcement policy attached. User must set up MFA before using console."

# Rotate access key if older than 90 days
KEY_ID=$(aws iam list-access-keys --user-name "$USERNAME" --query 'AccessKeyMetadata[0].AccessKeyId' --output text)
aws iam create-access-key --user-name "$USERNAME"
echo "New key created. Update applications, then deactivate old key:"
echo "aws iam update-access-key --user-name $USERNAME --access-key-id $KEY_ID --status Inactive"`,
    terraform: `\
# User: ${resourceId}
# Decide which access type to keep, remove the other.

# Console-only user (no access keys):
resource "aws_iam_user_login_profile" "console" {
  user = "${resourceId}"
}
# Do NOT create aws_iam_access_key for this user.

# API-only user (no console):
# resource "aws_iam_access_key" "api" {
#   user = "${resourceId}"
# }
# Do NOT create aws_iam_user_login_profile.`,
  }),

  // iam_support_role — No IAM support role found
  iam_support_role: ({ accountId }) => ({
    console: [
      "Open IAM console → Roles → Create role.",
      "Trusted entity: AWS account (this account).",
      "Attach policy: AWSSupportAccess.",
      "Name the role 'aws-support-role' → Create.",
      "Assign this role to your operations/incident response team.",
    ],
    cli: `\
${acct(accountId)}

# Create a support role
aws iam create-role \\
  --role-name aws-support-role \\
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Principal":{
        "AWS":"arn:aws:iam::'"$ACCOUNT_ID"':root"
      },
      "Action":"sts:AssumeRole"
    }]
  }'

# Attach AWSSupportAccess managed policy
aws iam attach-role-policy \\
  --role-name aws-support-role \\
  --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess

# Verify
aws iam get-role --role-name aws-support-role
aws iam list-attached-role-policies \\
  --role-name aws-support-role`,
    terraform: `\
data "aws_caller_identity" "current" {}

resource "aws_iam_role" "support" {
  name = "aws-support-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::\${data.aws_caller_identity.current.account_id}:root"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "support" {
  role       = aws_iam_role.support.name
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}`,
  }),

  // waf_cloudfront_association — WAF not associated with CloudFront
  waf_cloudfront_association: ({ resourceId, region }) => ({
    console: [
      `Open CloudFront console → select distribution "${resourceId}".`,
      "General tab → Edit.",
      "AWS WAF web ACL → select an existing WebACL or create one.",
      "Save changes.",
    ],
    cli: `\
DIST_ID="${resourceId}"
${reg(region)}
WEBACL_ARN="<WAF_WEBACL_ARN>"

aws wafv2 associate-web-acl \\
  --web-acl-arn "$WEBACL_ARN" \\
  --resource-arn "arn:aws:cloudfront::$(aws sts get-caller-identity --query Account --output text):distribution/$DIST_ID"`,
    terraform: `\
resource "aws_wafv2_web_acl_association" "cloudfront" {
  resource_arn = aws_cloudfront_distribution.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}`,
  }),

  // waf_alb_association — WAF not associated with ALB
  waf_alb_association: ({ resourceId, region }) => ({
    console: [
      `Open WAF console → Web ACLs → select or create a WebACL.`,
      `Associated resources → Add → select ALB "${resourceId}".`,
    ],
    cli: `\
ALB_ARN="${resourceId}"
${reg(region)}
WEBACL_ARN="<WAF_WEBACL_ARN>"

aws wafv2 associate-web-acl \\
  --web-acl-arn "$WEBACL_ARN" \\
  --resource-arn "$ALB_ARN" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = "${resourceId}"
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}`,
  }),

  // waf_managed_rules — AWS managed WAF rules not enabled
  waf_managed_rules: ({ resourceId, region }) => ({
    console: [
      `Open WAF console → Web ACLs → select "${resourceId}".`,
      "Rules tab → Add rules → Add managed rule groups.",
      "Enable AWS-AWSManagedRulesCommonRuleSet.",
      "Save.",
    ],
    cli: `\
WEBACL_ID="${resourceId}"
${reg(region)}

# Update WebACL to add AWS Managed Rules
# Use get-web-acl to get current config, add managed rule group, then update
echo "Use WAF console or update-web-acl with AWSManagedRulesCommonRuleSet"`,
    terraform: `\
resource "aws_wafv2_web_acl" "fix" {
  name  = "${resourceId}"
  scope = "REGIONAL"
  default_action { allow {} }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSet"
    }
  }
  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "WebACL"
  }
}`,
  }),

  // waf_rate_based_rules — WAF rate-based rules not configured
  waf_rate_based_rules: ({ resourceId }) => ({
    console: [
      `Open WAF console → Web ACLs → select "${resourceId}".`,
      "Rules → Add rules → Add my own rules.",
      "Rule type: Rate-based rule.",
      "Set rate limit (e.g. 2000 requests per 5 minutes).",
      "Action: Block → Add rule.",
    ],
    cli: `\
echo "Add rate-based rule via WAF console or update-web-acl CLI"
echo "Set limit to 2000 requests per 5 minutes with BLOCK action"`,
    terraform: `\
resource "aws_wafv2_web_acl" "fix" {
  rule {
    name     = "RateLimit"
    priority = 2
    action   { block {} }
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimit"
    }
  }
}`,
  }),

  // waf_sqli_protection — WAF SQL injection protection disabled
  waf_sqli_protection: ({ resourceId }) => ({
    console: [
      `Open WAF console → Web ACLs → select "${resourceId}".`,
      "Rules → Add managed rule groups.",
      "Enable AWS-AWSManagedRulesSQLiRuleSet.",
      "Set to Block (not Count).",
      "Save.",
    ],
    cli: `\
echo "Add AWSManagedRulesSQLiRuleSet to WebACL ${resourceId}"
echo "Ensure override_action is none (not count)"`,
    terraform: `\
rule {
  name     = "SQLiProtection"
  priority = 3
  override_action { none {} }
  statement {
    managed_rule_group_statement {
      vendor_name = "AWS"
      name        = "AWSManagedRulesSQLiRuleSet"
    }
  }
  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "SQLiProtection"
  }
}`,
  }),

  // waf_xss_protection — WAF XSS protection disabled
  waf_xss_protection: ({ resourceId }) => ({
    console: [
      `Open WAF console → Web ACLs → select "${resourceId}".`,
      "Rules → Add managed rule groups.",
      "Enable AWS-AWSManagedRulesKnownBadInputsRuleSet (includes XSS).",
      "Save.",
    ],
    cli: `\
echo "Add XSS rules to WebACL ${resourceId}"`,
    terraform: `\
rule {
  name     = "XSSProtection"
  priority = 4
  override_action { none {} }
  statement {
    managed_rule_group_statement {
      vendor_name = "AWS"
      name        = "AWSManagedRulesKnownBadInputsRuleSet"
    }
  }
  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "XSSProtection"
  }
}`,
  }),

  // waf_logging — WAF logging not enabled
  waf_logging: ({ resourceId, region }) => ({
    console: [
      `Open WAF console → Web ACLs → select "${resourceId}".`,
      "Logging and metrics → Enable logging.",
      "Select a Kinesis Firehose or S3 destination.",
      "Save.",
    ],
    cli: `\
WEBACL_ARN="${resourceId}"
${reg(region)}

# Create a log group (must start with aws-waf-logs-)
aws logs create-log-group \\
  --log-group-name "aws-waf-logs-cloudline" \\
  --region "$REGION"

LOG_ARN=$(aws logs describe-log-groups \\
  --log-group-name-prefix "aws-waf-logs-cloudline" \\
  --region "$REGION" \\
  --query 'logGroups[0].arn' --output text)

aws wafv2 put-logging-configuration \\
  --logging-configuration \\
    ResourceArn="$WEBACL_ARN",LogDestinationConfigs="$LOG_ARN" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-cloudline"
  retention_in_days = 30
}

resource "aws_wafv2_web_acl_logging_configuration" "fix" {
  resource_arn            = aws_wafv2_web_acl.main.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
}`,
  }),

  // waf_ip_reputation — WAF IP reputation rules not enabled
  waf_ip_reputation: ({ resourceId }) => ({
    console: [
      `Open WAF console → Web ACLs → select "${resourceId}".`,
      "Rules → Add managed rule groups.",
      "Enable AWS-AWSManagedRulesAmazonIpReputationList.",
      "Save.",
    ],
    cli: `\
echo "Add AWSManagedRulesAmazonIpReputationList to ${resourceId}"`,
    terraform: `\
rule {
  name     = "IPReputation"
  priority = 5
  override_action { none {} }
  statement {
    managed_rule_group_statement {
      vendor_name = "AWS"
      name        = "AWSManagedRulesAmazonIpReputationList"
    }
  }
  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "IPReputation"
  }
}`,
  }),

  // waf_bot_control — WAF bot control not enabled
  waf_bot_control: ({ resourceId }) => ({
    console: [
      `Open WAF console → Web ACLs → select "${resourceId}".`,
      "Rules → Add managed rule groups.",
      "Enable AWS-AWSManagedRulesBotControlRuleSet.",
      "Save.",
    ],
    cli: `\
echo "Add AWSManagedRulesBotControlRuleSet to ${resourceId}"`,
    terraform: `\
rule {
  name     = "BotControl"
  priority = 6
  override_action { none {} }
  statement {
    managed_rule_group_statement {
      vendor_name = "AWS"
      name        = "AWSManagedRulesBotControlRuleSet"
    }
  }
  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "BotControl"
  }
}`,
  }),

  // waf_no_count_critical — WAF critical rules in COUNT-only mode
  waf_no_count_critical: ({ resourceId }) => ({
    console: [
      `Open WAF console → Web ACLs → select "${resourceId}".`,
      "Rules → find SQLi rule in COUNT mode.",
      "Edit → change override action from Count to None (Block).",
      "Save.",
    ],
    cli: `\
echo "Change SQLi rule override from count to none in ${resourceId}"
echo "Use update-web-acl to set override_action to none"`,
    terraform: `\
# Change override_action from count to none:
rule {
  override_action { none {} }  # not: count {}
}`,
  }),

  // waf_shield_advanced — AWS Shield Advanced not enabled
  waf_shield_advanced: ({ region }) => ({
    console: [
      "Open Shield console → Getting started.",
      "Subscribe to AWS Shield Advanced.",
      "Add resources to protect (CloudFront, ALB, EIP).",
    ],
    cli: `\
${reg(region)}

aws shield create-subscription --region us-east-1

# Add protections
# aws shield create-protection \\
#   --name "ALB-protection" \\
#   --resource-arn <ALB_ARN>`,
    terraform: `\
resource "aws_shield_subscription" "advanced" {}

resource "aws_shield_protection" "alb" {
  name         = "ALB-protection"
  resource_arn = var.alb_arn
}`,
  }),

  // waf_default_block_apis — WAF API default action not BLOCK
  waf_default_block_apis: ({ resourceId }) => ({
    console: [
      `Open WAF console → Web ACLs → select "${resourceId}".`,
      "Default web ACL action → Edit.",
      "Change from Allow to Block.",
      "Save.",
    ],
    cli: `\
echo "Update default action to Block for ${resourceId}"
echo "Use update-web-acl with --default-action Block={}"`,
    terraform: `\
resource "aws_wafv2_web_acl" "fix" {
  default_action { block {} }
}`,
  }),

  // waf_known_bad_inputs — WAF known bad inputs rules not enabled
  waf_known_bad_inputs: ({ resourceId }) => ({
    console: [
      `Open WAF console → Web ACLs → select "${resourceId}".`,
      "Rules → Add managed rule groups.",
      "Enable AWS-AWSManagedRulesKnownBadInputsRuleSet.",
      "Save.",
    ],
    cli: `\
echo "Add AWSManagedRulesKnownBadInputsRuleSet to ${resourceId}"`,
    terraform: `\
rule {
  name     = "KnownBadInputs"
  priority = 7
  override_action { none {} }
  statement {
    managed_rule_group_statement {
      vendor_name = "AWS"
      name        = "AWSManagedRulesKnownBadInputsRuleSet"
    }
  }
  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "KnownBadInputs"
  }
}`,
  }),

  // waf_log_redaction — WAF log redaction hiding critical fields
  waf_log_redaction: ({ resourceId }) => ({
    console: [
      `Open WAF console → Web ACLs → select "${resourceId}".`,
      "Logging → Edit.",
      "Review redacted fields — remove Authorization header from redaction.",
      "Save.",
    ],
    cli: `\
echo "Update logging config for ${resourceId}"
echo "Remove Authorization from redacted fields"`,
    terraform: `\
resource "aws_wafv2_web_acl_logging_configuration" "fix" {
  resource_arn            = aws_wafv2_web_acl.main.arn
  log_destination_configs = [var.log_destination]
  # Remove redacted_fields block for Authorization header
}`,
  }),

  // apigw_access_logging — API Gateway access logging not enabled
  apigw_access_logging: ({ resourceId, region }) => ({
    console: [
      `Open API Gateway console → select API → Stages → "${resourceId}".`,
      "Logs/Tracing tab → Edit.",
      "Enable Access Logging → set destination ARN.",
      "Save.",
    ],
    cli: `\
STAGE="${resourceId}"
${reg(region)}

# Create log group
aws logs create-log-group \\
  --log-group-name "/aws/apigateway/access-logs" \\
  --region "$REGION"

echo "Enable access logging via API Gateway console or update-stage"`,
    terraform: `\
resource "aws_api_gateway_stage" "fix" {
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw.arn
  }
}

resource "aws_cloudwatch_log_group" "apigw" {
  name              = "/aws/apigateway/access-logs"
  retention_in_days = 30
}`,
  }),

  // apigw_execution_logging — API Gateway execution logging not enabled
  apigw_execution_logging: ({ resourceId, region: _region }) => ({
    console: [
      `Open API Gateway console → select API → Stages → "${resourceId}".`,
      "Logs/Tracing tab → Edit.",
      "CloudWatch Logs → select INFO or ERROR level.",
      "Save.",
    ],
    cli: `\
echo "Enable execution logging for stage ${resourceId}"
echo "Set logging level to INFO via update-stage"`,
    terraform: `\
resource "aws_api_gateway_method_settings" "fix" {
  rest_api_id = var.api_id
  stage_name  = var.stage_name
  method_path = "*/*"
  settings {
    logging_level = "INFO"
  }
}`,
  }),

  // apigw_tls_12 — API Gateway TLS 1.2 not enforced
  apigw_tls_12: ({ resourceId }) => ({
    console: [
      `Open API Gateway console → Custom domain names → "${resourceId}".`,
      "Edit → Security policy → TLS 1.2.",
      "Save.",
    ],
    cli: `\
echo "Update security policy to TLS_1_2 for ${resourceId}"`,
    terraform: `\
resource "aws_api_gateway_domain_name" "fix" {
  security_policy = "TLS_1_2"
}`,
  }),

  // apigw_waf_webacl — API Gateway WAF WebACL not associated
  apigw_waf_webacl: ({ resourceId, region }) => ({
    console: [
      `Open WAF console → Web ACLs → select or create one.`,
      `Associated resources → Add → select API Gateway stage "${resourceId}".`,
    ],
    cli: `\
STAGE_ARN="${resourceId}"
${reg(region)}

aws wafv2 associate-web-acl \\
  --web-acl-arn "<WEBACL_ARN>" \\
  --resource-arn "$STAGE_ARN" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_wafv2_web_acl_association" "apigw" {
  resource_arn = aws_api_gateway_stage.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}`,
  }),

  // apigw_throttling — API Gateway throttling not configured
  apigw_throttling: ({ resourceId }) => ({
    console: [
      `Open API Gateway console → select API → Stages → "${resourceId}".`,
      "Stage Editor → Default Method Throttling.",
      "Set rate and burst limits.",
      "Save.",
    ],
    cli: `\
echo "Configure throttling for stage ${resourceId}"`,
    terraform: `\
resource "aws_api_gateway_method_settings" "fix" {
  rest_api_id = var.api_id
  stage_name  = var.stage_name
  method_path = "*/*"
  settings {
    throttling_rate_limit  = 1000
    throttling_burst_limit = 500
  }
}`,
  }),

  // apigw_vpc_endpoint — Private API not using VPC endpoint
  apigw_vpc_endpoint: ({ resourceId, region }) => ({
    console: [
      `Open API Gateway console → select API "${resourceId}".`,
      "Settings → Endpoint type should be PRIVATE.",
      "Add VPC endpoint IDs in the resource policy.",
    ],
    cli: `\
${reg(region)}

# Create VPC endpoint for API Gateway
# aws ec2 create-vpc-endpoint \\
#   --vpc-id <VPC_ID> \\
#   --service-name com.amazonaws.$REGION.execute-api \\
#   --vpc-endpoint-type Interface \\
#   --subnet-ids <SUBNET_IDS> \\
#   --security-group-ids <SG_ID>`,
    terraform: `\
resource "aws_vpc_endpoint" "apigw" {
  vpc_id             = var.vpc_id
  service_name       = "com.amazonaws.${region || "us-east-1"}.execute-api"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = var.private_subnet_ids
  security_group_ids = [var.sg_id]
}`,
  }),

  // apigw_cors_wildcard — API Gateway CORS allows all origins
  apigw_cors_wildcard: ({ resourceId }) => ({
    console: [
      `If API "${resourceId}" is intentionally public (consumed by browser clients from any origin): wildcard CORS is correct. Protect the API instead with authentication (Cognito/Lambda authorizer), API keys, WAF rate limiting, and request validation.`,
      "If this is a private API only consumed by known origins: API Gateway console → select API → CORS settings → edit AllowOrigins → replace '*' with specific domains → re-deploy.",
    ],
    cli: `\
API_ID="${resourceId}"

# Check the API's current auth and usage plan setup
aws apigateway get-rest-api --rest-api-id "$API_ID" --query '{Name:name,Endpoint:endpointConfiguration}'
aws apigateway get-stages --rest-api-id "$API_ID" --query 'item[].{Stage:stageName,WAF:webAclArn,Logging:methodSettings}'

# For a private API: update CORS to restrict origins (HTTP API v2)
aws apigatewayv2 update-api --api-id "$API_ID" --cors-configuration 'AllowOrigins=["https://your-domain.com"],AllowMethods=["GET","POST"],AllowHeaders=["Content-Type","Authorization"]'

# For a public API: add WAF to rate-limit
echo "Attach a WAF WebACL with rate-based rules to the API stage:"
echo "aws wafv2 associate-web-acl --web-acl-arn <WAF_ARN> --resource-arn arn:aws:apigateway:<region>::/restapis/$API_ID/stages/<STAGE>"`,
    terraform: `\
# For private API: restrict CORS origins
resource "aws_apigatewayv2_api" "fix" {
  name          = "${resourceId}"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["https://your-domain.com"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["Content-Type", "Authorization"]
    max_age       = 300
  }
}

# For public API: keep * CORS but attach WAF
resource "aws_wafv2_web_acl_association" "api" {
  resource_arn = "arn:aws:apigateway:\${var.region}::/restapis/${resourceId}/stages/\${var.stage}"
  web_acl_arn  = var.waf_acl_arn
}`,
  }),

  // apigw_api_keys_required — API Gateway keys not required for usage plans
  apigw_api_keys_required: ({ resourceId }) => ({
    console: [
      `Open API Gateway console → Usage Plans → "${resourceId}".`,
      "Configure throttling rate and burst limits.",
      "Associated API stages → ensure API keys are required.",
    ],
    cli: `\
echo "Configure rate limits for usage plan ${resourceId}"`,
    terraform: `\
resource "aws_api_gateway_usage_plan" "fix" {
  name = "${resourceId}"
  throttle_settings {
    rate_limit  = 1000
    burst_limit = 500
  }
}`,
  }),

  // apigw_request_validation — API Gateway request validation disabled
  apigw_request_validation: ({ resourceId }) => ({
    console: [
      `Open API Gateway console → select API "${resourceId}".`,
      "Resources → select method → Method Request.",
      "Request Validator → select 'Validate body, query string parameters, and headers'.",
      "Deploy API.",
    ],
    cli: `\
echo "Enable request validation for ${resourceId}"`,
    terraform: `\
resource "aws_api_gateway_request_validator" "fix" {
  rest_api_id                 = var.api_id
  name                        = "validate-all"
  validate_request_body       = true
  validate_request_parameters = true
}`,
  }),

  // apigw_client_certificate — API Gateway backend certificate missing
  apigw_client_certificate: ({ resourceId, region }) => ({
    console: [
      `Open API Gateway console → select API → Stages → "${resourceId}".`,
      "Stage Editor → Client Certificate → Generate.",
      "Configure backend to trust this certificate.",
    ],
    cli: `\
${reg(region)}

aws apigateway generate-client-certificate \\
  --description "Backend mTLS cert" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_api_gateway_client_certificate" "fix" {
  description = "Backend mTLS certificate"
}

resource "aws_api_gateway_stage" "fix" {
  client_certificate_id = aws_api_gateway_client_certificate.fix.id
}`,
  }),

  // apigw_lb_https_listener — Load balancer has no HTTPS listener
  apigw_lb_https_listener: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Load Balancers → select "${resourceId}".`,
      "Listeners tab → Add listener.",
      "Protocol: HTTPS, Port: 443.",
      "Select or import SSL certificate.",
      "Save.",
    ],
    cli: `\
ALB_ARN="${resourceId}"
${reg(region)}

aws elbv2 create-listener \\
  --load-balancer-arn "$ALB_ARN" \\
  --protocol HTTPS --port 443 \\
  --certificates CertificateArn=<ACM_CERT_ARN> \\
  --default-actions Type=forward,TargetGroupArn=<TARGET_GROUP_ARN> \\
  --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06 \\
  --region "$REGION"`,
    terraform: `\
resource "aws_lb_listener" "https" {
  load_balancer_arn = "${resourceId}"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_cert_arn
  default_action {
    type             = "forward"
    target_group_arn = var.target_group_arn
  }
}`,
  }),

  // apigw_lb_tls_12 — Load balancer TLS policy below TLS 1.2
  apigw_lb_tls_12: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Load Balancers → select LB → Listeners.`,
      `Select HTTPS listener "${resourceId}" → Edit.`,
      "Security policy → ELBSecurityPolicy-TLS13-1-2-2021-06.",
      "Save.",
    ],
    cli: `\
LISTENER_ARN="${resourceId}"
${reg(region)}

aws elbv2 modify-listener \\
  --listener-arn "$LISTENER_ARN" \\
  --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06 \\
  --region "$REGION"`,
    terraform: `\
resource "aws_lb_listener" "fix" {
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}`,
  }),

  // apigw_lb_access_logging — Load balancer access logging disabled
  apigw_lb_access_logging: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Load Balancers → select "${resourceId}".`,
      "Attributes → Edit.",
      "Enable access logs → select S3 bucket.",
      "Save.",
    ],
    cli: `\
ALB_ARN="${resourceId}"
${reg(region)}

aws elbv2 modify-load-balancer-attributes \\
  --load-balancer-arn "$ALB_ARN" \\
  --attributes \\
    Key=access_logs.s3.enabled,Value=true \\
    Key=access_logs.s3.bucket,Value=<LOG_BUCKET> \\
    Key=access_logs.s3.prefix,Value=alb-logs \\
  --region "$REGION"`,
    terraform: `\
resource "aws_lb" "fix" {
  access_logs {
    bucket  = var.log_bucket
    prefix  = "alb-logs"
    enabled = true
  }
}`,
  }),

  // apigw_lb_deletion_protection — Production LB deletion protection off
  apigw_lb_deletion_protection: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Load Balancers → select "${resourceId}".`,
      "Attributes → Edit → enable Deletion protection.",
      "Save.",
    ],
    cli: `\
ALB_ARN="${resourceId}"
${reg(region)}

aws elbv2 modify-load-balancer-attributes \\
  --load-balancer-arn "$ALB_ARN" \\
  --attributes Key=deletion_protection.enabled,Value=true \\
  --region "$REGION"`,
    terraform: `\
resource "aws_lb" "fix" {
  enable_deletion_protection = true
}`,
  }),

  // apigw_lb_http_redirect_https — LB HTTP not redirecting to HTTPS
  apigw_lb_http_redirect_https: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Load Balancers → Listeners.`,
      `Select HTTP listener "${resourceId}" → Edit.`,
      "Default action → Redirect to HTTPS 443.",
      "Save.",
    ],
    cli: `\
LISTENER_ARN="${resourceId}"
${reg(region)}

aws elbv2 modify-listener \\
  --listener-arn "$LISTENER_ARN" \\
  --default-actions '[{
    "Type":"redirect",
    "RedirectConfig":{
      "Protocol":"HTTPS",
      "Port":"443",
      "StatusCode":"HTTP_301"
    }
  }]' \\
  --region "$REGION"`,
    terraform: `\
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = var.alb_arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}`,
  }),

  // apigw_lb_internal_not_public — Internal LB is internet-facing
  apigw_lb_internal_not_public: ({ resourceId, region }) => ({
    console: [
      `Load balancer "${resourceId}" is tagged internal but is internet-facing.`,
      "Recreate as an internal load balancer.",
      "LBs cannot be changed from internet-facing to internal.",
    ],
    cli: `\
ALB_ARN="${resourceId}"
${reg(region)}

echo "Create a new internal LB to replace this internet-facing one"
# aws elbv2 create-load-balancer \\
#   --name <NAME>-internal \\
#   --scheme internal \\
#   --subnets <PRIVATE_SUBNET_IDS> \\
#   --security-groups <SG_ID> \\
#   --region "$REGION"`,
    terraform: `\
resource "aws_lb" "internal" {
  name     = "internal-lb"
  internal = true
  subnets  = var.private_subnet_ids
}`,
  }),

  // apigw_lb_waf_webacl — Production ALB not associated with WAF
  apigw_lb_waf_webacl: ({ resourceId, region }) => ({
    console: [
      `Open WAF console → Web ACLs → select or create one.`,
      `Associated resources → Add → select ALB "${resourceId}".`,
    ],
    cli: `\
ALB_ARN="${resourceId}"
${reg(region)}

aws wafv2 associate-web-acl \\
  --web-acl-arn "<WEBACL_ARN>" \\
  --resource-arn "$ALB_ARN" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = "${resourceId}"
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}`,
  }),

  // apigw_lb_cert_not_expired — Load balancer TLS certificate expired
  apigw_lb_cert_not_expired: ({ resourceId, region }) => ({
    console: [
      `Open ACM console → find the expired certificate for "${resourceId}".`,
      "Request or import a new certificate.",
      "Update the LB listener to use the new certificate.",
    ],
    cli: `\
LISTENER_ARN="${resourceId}"
${reg(region)}

# Request a new certificate
NEW_CERT=$(aws acm request-certificate \\
  --domain-name "<YOUR_DOMAIN>" \\
  --validation-method DNS \\
  --region "$REGION" \\
  --query CertificateArn --output text)

echo "Validate the new cert, then update listener:"
echo "aws elbv2 modify-listener --listener-arn $LISTENER_ARN --certificates CertificateArn=$NEW_CERT"`,
    terraform: `\
resource "aws_acm_certificate" "new" {
  domain_name       = var.domain_name
  validation_method = "DNS"
}

resource "aws_lb_listener" "fix" {
  certificate_arn = aws_acm_certificate.new.arn
}`,
  }),

  // apigw_lb_drop_invalid_headers — LB drop invalid headers disabled
  apigw_lb_drop_invalid_headers: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Load Balancers → select "${resourceId}".`,
      "Attributes → Edit → enable 'Drop invalid header fields'.",
      "Save.",
    ],
    cli: `\
ALB_ARN="${resourceId}"
${reg(region)}

aws elbv2 modify-load-balancer-attributes \\
  --load-balancer-arn "$ALB_ARN" \\
  --attributes Key=routing.http.drop_invalid_header_fields.enabled,Value=true \\
  --region "$REGION"`,
    terraform: `\
resource "aws_lb" "fix" {
  drop_invalid_header_fields = true
}`,
  }),

  // apigw_lb_multi_az — LB deployed across only 1 AZ
  apigw_lb_multi_az: ({ resourceId, region }) => ({
    console: [
      `Open EC2 console → Load Balancers → select "${resourceId}".`,
      "Availability Zones → Edit.",
      "Add subnets in at least 2 AZs.",
      "Save.",
    ],
    cli: `\
ALB_ARN="${resourceId}"
${reg(region)}

aws elbv2 set-subnets \\
  --load-balancer-arn "$ALB_ARN" \\
  --subnets <SUBNET_AZ1> <SUBNET_AZ2> \\
  --region "$REGION"`,
    terraform: `\
resource "aws_lb" "fix" {
  subnets = var.multi_az_subnet_ids  # at least 2 AZs
}`,
  }),

  // cognito_mfa_required — Cognito user pool MFA disabled
  cognito_mfa_required: ({ resourceId, region }) => ({
    console: [
      `Open Cognito console → User pools → select "${resourceId}".`,
      "Sign-in experience → Multi-factor authentication → Edit.",
      "Set MFA enforcement to Required.",
      "Enable TOTP and/or SMS.",
      "Save.",
    ],
    cli: `\
POOL_ID="${resourceId}"
${reg(region)}

aws cognito-idp set-user-pool-mfa-config \\
  --user-pool-id "$POOL_ID" \\
  --mfa-configuration ON \\
  --software-token-mfa-configuration Enabled=true \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cognito_user_pool" "fix" {
  mfa_configuration = "ON"
  software_token_mfa_configuration {
    enabled = true
  }
}`,
  }),

  // cognito_pwd_min_length — Cognito password too short
  cognito_pwd_min_length: ({ resourceId, region }) => ({
    console: [
      `Open Cognito console → User pools → select "${resourceId}".`,
      "Sign-in experience → Password policy → Edit.",
      "Set minimum length to at least 8 characters.",
      "Save.",
    ],
    cli: `\
POOL_ID="${resourceId}"
${reg(region)}

# Password policy is set at pool creation or via update
echo "Update user pool password policy to minimum length 8"`,
    terraform: `\
resource "aws_cognito_user_pool" "fix" {
  password_policy {
    minimum_length    = 8
    require_uppercase = true
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
  }
}`,
  }),

  // cognito_pwd_uppercase — Cognito: no uppercase required
  cognito_pwd_uppercase: ({ resourceId }) => ({
    console: [
      `Open Cognito console → User pools → select "${resourceId}".`,
      "Sign-in experience → Password policy → Edit.",
      "Enable 'Require uppercase letters'.",
      "Save.",
    ],
    cli: `\
echo "Update password policy for ${resourceId}: require uppercase"`,
    terraform: `\
resource "aws_cognito_user_pool" "fix" {
  password_policy { require_uppercase = true }
}`,
  }),

  // cognito_pwd_lowercase — Cognito: no lowercase required
  cognito_pwd_lowercase: ({ resourceId }) => ({
    console: [
      `Open Cognito console → User pools → select "${resourceId}".`,
      "Sign-in experience → Password policy → Edit.",
      "Enable 'Require lowercase letters'.",
      "Save.",
    ],
    cli: `\
echo "Update password policy for ${resourceId}: require lowercase"`,
    terraform: `\
resource "aws_cognito_user_pool" "fix" {
  password_policy { require_lowercase = true }
}`,
  }),

  // cognito_pwd_numbers — Cognito: no numbers required
  cognito_pwd_numbers: ({ resourceId }) => ({
    console: [
      `Open Cognito console → User pools → select "${resourceId}".`,
      "Sign-in experience → Password policy → Edit.",
      "Enable 'Require numbers'.",
      "Save.",
    ],
    cli: `\
echo "Update password policy for ${resourceId}: require numbers"`,
    terraform: `\
resource "aws_cognito_user_pool" "fix" {
  password_policy { require_numbers = true }
}`,
  }),

  // cognito_pwd_symbols — Cognito: no symbols required
  cognito_pwd_symbols: ({ resourceId }) => ({
    console: [
      `Open Cognito console → User pools → select "${resourceId}".`,
      "Sign-in experience → Password policy → Edit.",
      "Enable 'Require special characters'.",
      "Save.",
    ],
    cli: `\
echo "Update password policy for ${resourceId}: require symbols"`,
    terraform: `\
resource "aws_cognito_user_pool" "fix" {
  password_policy { require_symbols = true }
}`,
  }),

  // cognito_advanced_security — Cognito advanced security not enforced
  cognito_advanced_security: ({ resourceId, region }) => ({
    console: [
      `Open Cognito console → User pools → select "${resourceId}".`,
      "Sign-in experience → Advanced security → Edit.",
      "Set to 'Enforced' mode.",
      "Save.",
    ],
    cli: `\
POOL_ID="${resourceId}"
${reg(region)}

echo "Enable advanced security features in ENFORCED mode for $POOL_ID"`,
    terraform: `\
resource "aws_cognito_user_pool" "fix" {
  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }
}`,
  }),

  // cognito_temp_pwd_validity — Cognito temp password validity > 7 days
  cognito_temp_pwd_validity: ({ resourceId }) => ({
    console: [
      `Open Cognito console → User pools → select "${resourceId}".`,
      "Sign-in experience → Password policy → Edit.",
      "Set temporary password validity to 7 days or less.",
      "Save.",
    ],
    cli: `\
echo "Set temporary password validity to 7 days for ${resourceId}"`,
    terraform: `\
resource "aws_cognito_user_pool" "fix" {
  password_policy {
    temporary_password_validity_days = 7
  }
}`,
  }),

  // cognito_verification_required — Cognito no auto-verified attributes
  cognito_verification_required: ({ resourceId }) => ({
    console: [
      `Open Cognito console → User pools → select "${resourceId}".`,
      "Sign-up experience → Attribute verification → Edit.",
      "Enable auto-verification for email or phone.",
      "Save.",
    ],
    cli: `\
echo "Set auto_verified_attributes for ${resourceId}"`,
    terraform: `\
resource "aws_cognito_user_pool" "fix" {
  auto_verified_attributes = ["email"]
}`,
  }),

  // cognito_device_tracking — Cognito no new device challenge
  cognito_device_tracking: ({ resourceId }) => ({
    console: [
      `Open Cognito console → User pools → select "${resourceId}".`,
      "Sign-in experience → Device tracking → Edit.",
      "Enable device remembering → 'Always' or 'User opt-in'.",
      "Save.",
    ],
    cli: `\
echo "Enable device tracking for ${resourceId}"`,
    terraform: `\
resource "aws_cognito_user_pool" "fix" {
  device_configuration {
    challenge_required_on_new_device      = true
    device_only_remembered_on_user_prompt = true
  }
}`,
  }),

  // cognito_access_token_validity — Cognito access token valid > 60 min
  cognito_access_token_validity: ({ resourceId }) => ({
    console: [
      `Open Cognito console → User pools → select "${resourceId}".`,
      "App integration → App clients → Edit.",
      "Set access token expiration to 60 minutes or less.",
      "Save.",
    ],
    cli: `\
echo "Set access token validity to 60 minutes for ${resourceId}"`,
    terraform: `\
resource "aws_cognito_user_pool_client" "fix" {
  access_token_validity = 60  # minutes
  token_validity_units {
    access_token = "minutes"
  }
}`,
  }),

  // cognito_refresh_token_validity — Cognito refresh token valid > 30 days
  cognito_refresh_token_validity: ({ resourceId }) => ({
    console: [
      `Open Cognito console → User pools → select "${resourceId}".`,
      "App integration → App clients → Edit.",
      "Set refresh token expiration to 30 days or less.",
      "Save.",
    ],
    cli: `\
echo "Set refresh token validity to 30 days for ${resourceId}"`,
    terraform: `\
resource "aws_cognito_user_pool_client" "fix" {
  refresh_token_validity = 30  # days
  token_validity_units {
    refresh_token = "days"
  }
}`,
  }),

  // cognito_no_unauth_identities — Cognito identity pool allows unauthenticated
  cognito_no_unauth_identities: ({ resourceId, region }) => ({
    console: [
      `Open Cognito console → Identity pools → select "${resourceId}".`,
      "Edit identity pool.",
      "Uncheck 'Enable access to unauthenticated identities'.",
      "Save.",
    ],
    cli: `\
POOL_ID="${resourceId}"
${reg(region)}

aws cognito-identity update-identity-pool \\
  --identity-pool-id "$POOL_ID" \\
  --no-allow-unauthenticated-identities \\
  --identity-pool-name "$(aws cognito-identity describe-identity-pool --identity-pool-id $POOL_ID --region $REGION --query IdentityPoolName --output text)" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cognito_identity_pool" "fix" {
  identity_pool_name               = var.pool_name
  allow_unauthenticated_identities = false
}`,
  }),

  // cognito_no_user_pwd_auth — Cognito app client uses plain password auth
  cognito_no_user_pwd_auth: ({ resourceId, region: _region }) => ({
    console: [
      `Open Cognito console → User pools → App clients → "${resourceId}".`,
      "Edit → Authentication flows.",
      "Remove ALLOW_USER_PASSWORD_AUTH.",
      "Enable ALLOW_USER_SRP_AUTH instead.",
      "Save.",
    ],
    cli: `\
echo "Update auth flows for app client ${resourceId}"
echo "Remove ALLOW_USER_PASSWORD_AUTH, enable ALLOW_USER_SRP_AUTH"`,
    terraform: `\
resource "aws_cognito_user_pool_client" "fix" {
  explicit_auth_flows = [
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]
}`,
  }),

  // cognito_app_client_secret — Cognito server client missing secret
  cognito_app_client_secret: ({ resourceId }) => ({
    console: [
      `Open Cognito console → User pools → App clients → "${resourceId}".`,
      "This is a server-side client but has no client secret.",
      "Delete and recreate the client with 'Generate client secret' enabled.",
    ],
    cli: `\
echo "Recreate app client ${resourceId} with generate_secret=true"`,
    terraform: `\
resource "aws_cognito_user_pool_client" "fix" {
  generate_secret = true
}`,
  }),

  // cognito_deletion_protection — Cognito user pool deletion protection off
  cognito_deletion_protection: ({ resourceId, region }) => ({
    console: [
      `Open Cognito console → User pools → select "${resourceId}".`,
      "User pool settings → enable Deletion protection.",
      "Save.",
    ],
    cli: `\
POOL_ID="${resourceId}"
${reg(region)}

aws cognito-idp update-user-pool \\
  --user-pool-id "$POOL_ID" \\
  --deletion-protection ACTIVE \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cognito_user_pool" "fix" {
  deletion_protection = "ACTIVE"
}`,
  }),

  // cognito_ses_sender — Cognito using default email sender
  cognito_ses_sender: ({ resourceId }) => ({
    console: [
      `Open Cognito console → User pools → select "${resourceId}".`,
      "Messaging → Email → Edit.",
      "Change from Cognito default to Amazon SES.",
      "Configure a verified SES identity.",
      "Save.",
    ],
    cli: `\
echo "Configure SES email sender for ${resourceId}"`,
    terraform: `\
resource "aws_cognito_user_pool" "fix" {
  email_configuration {
    email_sending_account = "DEVELOPER"
    source_arn            = var.ses_identity_arn
    from_email_address    = "noreply@yourdomain.com"
  }
}`,
  }),

  // kms_key_rotation — KMS key rotation not enabled
  kms_key_rotation: ({ resourceId, region }) => ({
    console: [
      `Open KMS console → Customer managed keys → select "${resourceId}".`,
      "Key rotation tab → Edit.",
      "Enable automatic key rotation.",
      "Save.",
    ],
    cli: `\
KEY_ID="${resourceId}"
${reg(region)}

aws kms enable-key-rotation \\
  --key-id "$KEY_ID" \\
  --region "$REGION"

# Verify
aws kms get-key-rotation-status \\
  --key-id "$KEY_ID" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_kms_key" "fix" {
  enable_key_rotation = true
}`,
  }),

  // kms_no_public_principal — KMS key policy allows Principal:*
  kms_no_public_principal: ({ resourceId, region }) => ({
    console: [
      `Open KMS console → select key "${resourceId}".`,
      "Key policy → Edit.",
      "Replace Principal: '*' with specific IAM ARNs.",
      "Save.",
    ],
    cli: `\
KEY_ID="${resourceId}"
${reg(region)}

# View current policy
aws kms get-key-policy \\
  --key-id "$KEY_ID" \\
  --policy-name default \\
  --region "$REGION"

# Put scoped policy
# aws kms put-key-policy \\
#   --key-id "$KEY_ID" \\
#   --policy-name default \\
#   --policy file://scoped-policy.json`,
    terraform: `\
resource "aws_kms_key" "fix" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowAdmin"
      Effect    = "Allow"
      Principal = { AWS = var.admin_role_arn }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}`,
  }),

  // kms_pending_deletion_approval — KMS key pending deletion without approval tag
  kms_pending_deletion_approval: ({ resourceId, region }) => ({
    console: [
      `Open KMS console → select key "${resourceId}".`,
      "If deletion was unintended: Actions → Cancel key deletion.",
      "Add tag 'deletion_approved=true' before scheduling.",
    ],
    cli: `\
KEY_ID="${resourceId}"
${reg(region)}

# Cancel deletion
aws kms cancel-key-deletion \\
  --key-id "$KEY_ID" \\
  --region "$REGION"

# Re-enable the key
aws kms enable-key \\
  --key-id "$KEY_ID" \\
  --region "$REGION"

# Tag with approval
aws kms tag-resource \\
  --key-id "$KEY_ID" \\
  --tags TagKey=deletion_approved,TagValue=true \\
  --region "$REGION"`,
    terraform: `\
resource "aws_kms_key" "fix" {
  is_enabled              = true
  deletion_window_in_days = 30
  tags = { deletion_approved = "true" }
}`,
  }),

  // kms_separate_admin_users — KMS key policy mixes admin and user roles
  kms_separate_admin_users: ({ resourceId, region }) => ({
    console: [
      `Open KMS console → select key "${resourceId}".`,
      "Key policy → Edit.",
      "Separate admin actions (kms:Create*, kms:Delete*, kms:Put*) from usage actions (kms:Encrypt, kms:Decrypt).",
      "Save.",
    ],
    cli: `\
KEY_ID="${resourceId}"
${reg(region)}

echo "Separate admin and usage permissions in key policy for $KEY_ID"`,
    terraform: `\
resource "aws_kms_key" "fix" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AdminOnly"
        Effect    = "Allow"
        Principal = { AWS = var.admin_role_arn }
        Action    = ["kms:Create*", "kms:Delete*", "kms:Put*", "kms:Enable*", "kms:Disable*", "kms:Describe*"]
        Resource  = "*"
      },
      {
        Sid       = "UsageOnly"
        Effect    = "Allow"
        Principal = { AWS = var.app_role_arn }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
      },
    ]
  })
}`,
  }),

  // kms_key_description — KMS key has no description
  kms_key_description: ({ resourceId, region }) => ({
    console: [
      `Open KMS console → select key "${resourceId}".`,
      "General configuration → Edit description.",
      "Add a meaningful description.",
      "Save.",
    ],
    cli: `\
KEY_ID="${resourceId}"
${reg(region)}

aws kms update-key-description \\
  --key-id "$KEY_ID" \\
  --description "Describe key purpose and owning service" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_kms_key" "fix" {
  description = "Describe key purpose and owning service"
}`,
  }),

  // kms_multi_region_required — KMS multi-region key used without justification
  kms_multi_region_required: ({ resourceId }) => ({
    console: [
      `KMS key "${resourceId}" is multi-region without justification tag.`,
      "Add tag 'multi_region_justification' with reason.",
      "Or recreate as a single-region key if multi-region is not needed.",
    ],
    cli: `\
KEY_ID="${resourceId}"

aws kms tag-resource \\
  --key-id "$KEY_ID" \\
  --tags TagKey=multi_region_justification,TagValue="DR replication"`,
    terraform: `\
resource "aws_kms_key" "fix" {
  multi_region = true
  tags = { multi_region_justification = "DR replication" }
}`,
  }),

  // kms_no_unknown_cross_account — KMS key allows unknown cross-account access
  kms_no_unknown_cross_account: ({ resourceId, region }) => ({
    console: [
      `Open KMS console → select key "${resourceId}".`,
      "Key policy → Edit.",
      "Remove unknown account IDs from Principal.",
      "Add aws:PrincipalOrgID condition.",
      "Save.",
    ],
    cli: `\
KEY_ID="${resourceId}"
${reg(region)}

echo "Update key policy to restrict cross-account access"
echo "Add Condition: aws:PrincipalOrgID = <ORG_ID>"`,
    terraform: `\
resource "aws_kms_key" "fix" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = ["kms:Decrypt"]
      Resource  = "*"
      Condition = {
        StringEquals = { "aws:PrincipalOrgID" = var.org_id }
      }
    }]
  })
}`,
  }),

  // kms_owner_purpose_tags — KMS key missing owner/purpose tags
  kms_owner_purpose_tags: ({ resourceId, region }) => ({
    console: [
      `Open KMS console → select key "${resourceId}".`,
      "Tags → Edit.",
      "Add: owner=<team>, purpose=<description>.",
      "Save.",
    ],
    cli: `\
KEY_ID="${resourceId}"
${reg(region)}

aws kms tag-resource \\
  --key-id "$KEY_ID" \\
  --tags TagKey=owner,TagValue="<team>" TagKey=purpose,TagValue="<description>" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_kms_key" "fix" {
  tags = {
    owner   = "<team>"
    purpose = "<description>"
  }
}`,
  }),

  // kms_disabled_keys_cleanup — Disabled KMS key not scheduled for deletion
  kms_disabled_keys_cleanup: ({ resourceId, region }) => ({
    console: [
      `Open KMS console → select disabled key "${resourceId}".`,
      "If no longer needed: Actions → Schedule key deletion.",
      "Set waiting period (7-30 days).",
      "If still needed: Actions → Enable key.",
    ],
    cli: `\
KEY_ID="${resourceId}"
${reg(region)}

# Schedule deletion (30-day waiting period)
aws kms schedule-key-deletion \\
  --key-id "$KEY_ID" \\
  --pending-window-in-days 30 \\
  --region "$REGION"

# Or re-enable if still needed:
# aws kms enable-key --key-id "$KEY_ID" --region "$REGION"`,
    terraform: `\
# Remove the disabled key resource or schedule deletion:
resource "aws_kms_key" "fix" {
  is_enabled              = false
  deletion_window_in_days = 30
}`,
  }),

  // kms_no_root_wildcard — KMS key policy grants root wildcard without MFA condition
  kms_no_root_wildcard: ({ resourceId, region }) => ({
    console: [
      `NOTE: Do NOT remove root access from the KMS key — root retaining kms:* is AWS best practice as a safety net. The issue is there is no MFA condition on the root statement.`,
      `Open KMS console → select key "${resourceId}" → Key policy → Edit.`,
      "Find the root account statement (Principal: arn:aws:iam::<account>:root).",
      'Add a Condition block requiring MFA: { "Bool": { "aws:MultiFactorAuthPresent": "true" } }',
      "Save changes.",
    ],
    cli: `\
KEY_ID="${resourceId}"
${reg(region)}
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Get current key policy
aws kms get-key-policy --key-id "$KEY_ID" --policy-name default --region "$REGION" --query 'Policy' --output text | python3 -m json.tool > /tmp/key-policy.json
echo "Current policy saved to /tmp/key-policy.json"
cat /tmp/key-policy.json

# The root statement currently looks like:
# { "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::$ACCOUNT_ID:root"}, "Action": "kms:*", "Resource": "*" }
#
# Add MFA condition — edit /tmp/key-policy.json to add:
# "Condition": { "Bool": { "aws:MultiFactorAuthPresent": "true" } }
#
# Example using python3 to patch it:
python3 - << 'PYEOF'
import json
with open('/tmp/key-policy.json') as f:
    policy = json.load(f)
import os
account_id = os.popen("aws sts get-caller-identity --query Account --output text").read().strip()
root_arn = f"arn:aws:iam::{account_id}:root"
for stmt in policy.get('Statement', []):
    principal = stmt.get('Principal', {})
    if isinstance(principal, dict) and principal.get('AWS') == root_arn:
        if 'Condition' not in stmt:
            stmt['Condition'] = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
            print("Added MFA condition to root statement")
with open('/tmp/key-policy-fixed.json', 'w') as f:
    json.dump(policy, f, indent=2)
PYEOF

# Apply the fixed policy
aws kms put-key-policy --key-id "$KEY_ID" --policy-name default --policy file:///tmp/key-policy-fixed.json --region "$REGION"
echo "Policy updated. Root retains kms:* but now requires MFA."`,
    terraform: `\
data "aws_caller_identity" "current" {}

resource "aws_kms_key" "fix" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Root retains full access — required as AWS safety net.
        # MFA condition enforces that root must authenticate with MFA
        # before performing any key administration action.
        Sid       = "RootAdminWithMFA"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::\${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
        Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
      }
    ]
  })
}`,
  }),

  // kms_no_aws_alias_prefix — KMS key alias uses reserved aws/ prefix
  kms_no_aws_alias_prefix: ({ resourceId, region }) => ({
    console: [
      `KMS alias "${resourceId}" uses reserved aws/ prefix.`,
      "Create a new alias without the aws/ prefix.",
      "Update references to use the new alias.",
    ],
    cli: `\
ALIAS="${resourceId}"
${reg(region)}

echo "Cannot modify aws/ prefixed aliases."
echo "Create a new alias: aws kms create-alias --alias-name alias/custom-name --target-key-id <KEY_ID>"`,
    terraform: `\
resource "aws_kms_alias" "fix" {
  name          = "alias/custom-name"  # not aws/ prefix
  target_key_id = aws_kms_key.main.id
}`,
  }),

  // kms_s3_rotation — KMS key for S3 rotation not enabled
  kms_s3_rotation: ({ resourceId, region }) => ({
    console: [
      `Open KMS console → select S3 encryption key "${resourceId}".`,
      "Key rotation → Edit → Enable.",
      "Save.",
    ],
    cli: `\
KEY_ID="${resourceId}"
${reg(region)}

aws kms enable-key-rotation \\
  --key-id "$KEY_ID" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_kms_key" "s3" {
  description         = "S3 encryption key"
  enable_key_rotation = true
}`,
  }),

  // kms_deletion_alarm — No CloudWatch alarm for KMS key deletion
  kms_deletion_alarm: ({ resourceId: _resourceId, region }) => ({
    console: [
      "Open CloudWatch console → Alarms → Create alarm.",
      "Select CloudTrail metric for KMS key deletion events.",
      "Set threshold and notification.",
    ],
    cli: `\
${reg(region)}

# Create metric filter for KMS deletion events
aws logs put-metric-filter \\
  --log-group-name "CloudTrail/DefaultLogGroup" \\
  --filter-name "KMSKeyDeletion" \\
  --filter-pattern '{ ($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion) }' \\
  --metric-transformations \\
    metricName=KMSKeyDeletion,metricNamespace=CloudTrailMetrics,metricValue=1 \\
  --region "$REGION"

# Create alarm
aws cloudwatch put-metric-alarm \\
  --alarm-name "KMSKeyDeletion" \\
  --namespace CloudTrailMetrics \\
  --metric-name KMSKeyDeletion \\
  --statistic Sum --period 300 --threshold 1 \\
  --comparison-operator GreaterThanOrEqualToThreshold \\
  --evaluation-periods 1 \\
  --alarm-actions "<SNS_TOPIC_ARN>" \\
  --region "$REGION"`,
    terraform: `\
resource "aws_cloudwatch_metric_alarm" "kms_deletion" {
  alarm_name          = "KMSKeyDeletion"
  namespace           = "CloudTrailMetrics"
  metric_name         = "KMSKeyDeletion"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  alarm_actions       = [var.sns_topic_arn]
}`,
  }),

  // kms_external_material_approval — KMS key material origin is EXTERNAL
  kms_external_material_approval: ({ resourceId }) => ({
    console: [
      `KMS key "${resourceId}" uses externally imported key material.`,
      "Ensure key material is securely managed and rotated manually.",
      "Consider migrating to AWS-generated key material for automatic rotation.",
    ],
    cli: `\
KEY_ID="${resourceId}"

# Check key origin
aws kms describe-key \\
  --key-id "$KEY_ID" \\
  --query 'KeyMetadata.Origin'

# If migrating: create a new key with AWS_KMS origin,
# re-encrypt data, then disable the external key`,
    terraform: `\
# Create a replacement key with AWS-managed material:
resource "aws_kms_key" "aws_managed" {
  description         = "Replacement for external key"
  enable_key_rotation = true
  # origin defaults to AWS_KMS
}`,
  }),

  // kms_decrypt_grant_approved — KMS key grant allows decrypt to unapproved service
  kms_decrypt_grant_approved: ({ resourceId, region }) => ({
    console: [
      `Open KMS console → select key "${resourceId}".`,
      "Key grants → review active grants.",
      "Revoke grants to unapproved services.",
    ],
    cli: `\
KEY_ID="${resourceId}"
${reg(region)}

# List grants
aws kms list-grants \\
  --key-id "$KEY_ID" \\
  --region "$REGION"

# Revoke unapproved grant
# aws kms revoke-grant \\
#   --key-id "$KEY_ID" \\
#   --grant-id <GRANT_ID> \\
#   --region "$REGION"`,
    terraform: `\
# Review and remove unapproved aws_kms_grant resources.
# Only grant Decrypt to approved services:
resource "aws_kms_grant" "approved" {
  key_id            = "${resourceId}"
  grantee_principal = var.approved_service_arn
  operations        = ["Decrypt"]
}`,
  }),

  // backup_01 — AWS Backup not configured
  backup_01: ({ accountId, region }) => ({
    console: [
      "Open AWS Backup console → Backup plans → Create backup plan.",
      "Choose 'Start with a template' (Daily-35day-Retention).",
      "Name the plan → Create plan.",
      "Resource assignments → assign by tag: Backup=true.",
    ],
    cli: `\
${reg(region)}
${acct(accountId)}
VAULT="cloudline-vault"

# Create backup vault
aws backup create-backup-vault \\
  --backup-vault-name "$VAULT" \\
  --region "$REGION"

# Create backup plan
PLAN_ID=$(aws backup create-backup-plan \\
  --region "$REGION" \\
  --backup-plan '{
    "BackupPlanName":"cloudline-daily-backup",
    "Rules":[{
      "RuleName":"DailyBackup",
      "TargetBackupVaultName":"'"$VAULT"'",
      "ScheduleExpression":"cron(0 5 ? * * *)",
      "StartWindowMinutes":60,
      "CompletionWindowMinutes":120,
      "Lifecycle":{"DeleteAfterDays":35}
    }]
  }' \\
  --query BackupPlanId --output text)

echo "Backup plan: $PLAN_ID"

# Assign tag-based resources
aws backup create-backup-selection \\
  --backup-plan-id "$PLAN_ID" \\
  --region "$REGION" \\
  --backup-selection '{
    "SelectionName":"TaggedResources",
    "IamRoleArn":"arn:aws:iam::'"$ACCOUNT_ID"':role/AWSBackupDefaultServiceRole",
    "ListOfTags":[{"ConditionType":"STRINGEQUALS","ConditionKey":"Backup","ConditionValue":"true"}]
  }'`,
    terraform: `\
resource "aws_backup_vault" "main" {
  name = "cloudline-vault"
}

resource "aws_backup_plan" "daily" {
  name = "cloudline-daily-backup"

  rule {
    rule_name         = "DailyBackup"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 5 ? * * *)"
    lifecycle { delete_after = 35 }
  }
}

resource "aws_backup_selection" "tagged" {
  iam_role_arn = "arn:aws:iam::${accountId || "${data.aws_caller_identity.current.account_id}"}:role/AWSBackupDefaultServiceRole"
  name         = "TaggedResources"
  plan_id      = aws_backup_plan.daily.id

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "true"
  }
}`,
  }),

  // cross_capital_one_pattern — Capital One pattern (SSRF → IMDS → S3)
  cross_capital_one_pattern: ({ resourceId, region }) => ({
    console: [
      `Step 1 — IMDSv2: EC2 → Instances → "${resourceId}" → Actions → Modify metadata options → Require HTTP tokens.`,
      "Step 2 — S3: block public access on all buckets (S3 console → each bucket → Permissions).",
      "Step 3 — IAM: remove s3:* wildcard from the EC2 instance role; use resource-level permissions.",
      "Step 4 — GuardDuty: enable to detect SSRF-based credential exfiltration.",
      "Step 5 — WAF: add a rule on public ALBs blocking requests to 169.254.169.254.",
    ],
    cli: `\
INSTANCE_ID="${resourceId}"
${reg(region)}

# 1. Enforce IMDSv2 on the affected instance
aws ec2 modify-instance-metadata-options \\
  --instance-id "$INSTANCE_ID" \\
  --http-tokens required \\
  --http-endpoint enabled \\
  --http-put-response-hop-limit 1 \\
  --region "$REGION"

# 2. Block public access on all S3 buckets
for BUCKET in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  aws s3api put-public-access-block \\
    --bucket "$BUCKET" \\
    --public-access-block-configuration \\
      BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
done

# 3. Enable GuardDuty
aws guardduty create-detector \\
  --enable \\
  --finding-publishing-frequency FIFTEEN_MINUTES \\
  --region "$REGION"

# Verify IMDSv2
aws ec2 describe-instances \\
  --instance-ids "$INSTANCE_ID" \\
  --region "$REGION" \\
  --query 'Reservations[0].Instances[0].MetadataOptions'`,
    terraform: `\
# IMDSv2 on affected instance: ${resourceId}
resource "aws_instance" "fix_imds" {
  # Import: terraform import aws_instance.fix_imds ${resourceId}
  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }
}

# Block public access at account level
resource "aws_s3_account_public_access_block" "fix" {
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# GuardDuty
resource "aws_guardduty_detector" "fix" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}`,
  }),

  // macie_not_enabled — AWS Macie not enabled
  macie_not_enabled: ({ region }) => ({
    console: [
      "Open the Amazon Macie console.",
      "Select your region from the top-right region selector.",
      "Click 'Get started' (or 'Enable Macie' if shown).",
      "Review the pricing page, then click 'Enable Macie'.",
      "Once enabled, create a job: Jobs → Create job → select S3 buckets → configure schedule.",
    ],
    cli: `\
${reg(region)}

# Enable Macie in the region
aws macie2 enable-macie --region "$REGION"

# Verify Macie is ENABLED
aws macie2 get-macie-session --region "$REGION" \\
  --query 'status' --output text

# Create a one-time classification job for all buckets
aws macie2 create-classification-job \\
  --name "cloudline-initial-scan" \\
  --job-type ONE_TIME \\
  --s3-job-definition '{"bucketDefinitions":[{"accountId":"'"$(aws sts get-caller-identity --query Account --output text)"'","buckets":[]}]}' \\
  --region "$REGION"`,
    terraform: `\
resource "aws_macie2_account" "main" {
  status                       = "ENABLED"
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_macie2_classification_job" "initial_scan" {
  depends_on = [aws_macie2_account.main]
  name       = "cloudline-initial-scan"
  job_type   = "ONE_TIME"

  s3_job_definition {
    bucket_definitions {
      account_id = data.aws_caller_identity.current.account_id
      buckets    = []  # empty = all buckets in account
    }
  }
}`,
  }),

  // macie_sensitive_bucket_public_access
  // — S3 bucket with Macie findings has public access
  macie_sensitive_bucket_public_access: ({ resourceId }) => ({
    console: [
      `Open S3 console → select bucket "${resourceId}".`,
      "Permissions tab → Block public access (bucket settings) → Edit.",
      "Enable all four block options → Save changes → Confirm.",
      "Permissions tab → Bucket policy → review and remove any public Allow statements.",
      "Return to Macie console to verify the finding severity decreases after the next scan.",
    ],
    cli: `\
BUCKET="${resourceId}"

# Block all public access
aws s3api put-public-access-block \\
  --bucket "$BUCKET" \\
  --public-access-block-configuration \\
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Remove any public bucket ACL
aws s3api put-bucket-acl --bucket "$BUCKET" --acl private

# Verify
aws s3api get-public-access-block --bucket "$BUCKET"`,
    terraform: `\
resource "aws_s3_bucket_public_access_block" "fix" {
  bucket                  = "${resourceId}"
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_acl" "fix" {
  bucket = "${resourceId}"
  acl    = "private"
}`,
  }),

  // macie_sensitive_data_no_kms
  // — S3 bucket with Macie findings lacks KMS encryption
  macie_sensitive_data_no_kms: ({ resourceId }) => ({
    console: [
      `Open S3 console → select bucket "${resourceId}".`,
      "Properties tab → Default encryption → Edit.",
      "Select 'AWS Key Management Service key (SSE-KMS)'.",
      "Choose an existing CMK or click 'Create a KMS key'.",
      "Enable 'Bucket Key' to reduce KMS API costs.",
      "Save changes.",
    ],
    cli: `\
BUCKET="${resourceId}"
# Replace with your CMK ARN or use 'aws/s3' for the managed key
KMS_KEY_ID="arn:aws:kms:<region>:<account-id>:key/<key-id>"

aws s3api put-bucket-encryption \\
  --bucket "$BUCKET" \\
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "'"$KMS_KEY_ID"'"
      },
      "BucketKeyEnabled": true
    }]
  }'

# Verify
aws s3api get-bucket-encryption --bucket "$BUCKET"`,
    terraform: `\
resource "aws_kms_key" "s3_key" {
  description             = "KMS key for S3 bucket ${resourceId}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "fix" {
  bucket = "${resourceId}"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_key.arn
    }
    bucket_key_enabled = true
  }
}`,
  }),
};

// ─── Public API ───────────────────────────────────────────────

export function getRemediation(
  checkId: string,
  resource = "",
): RemediationMethod | null {
  const factory = FACTORIES[checkId];
  if (!factory) return null;
  return factory(parseArn(resource));
}

export default FACTORIES;
