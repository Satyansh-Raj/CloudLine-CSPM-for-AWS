# modules/dynamodb/main.tf
# DynamoDB tables for CloudLine real-time detection pipeline.

# ---------------------------------------------------------------------------
# 1. violation-state — primary state store
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "violation_state" {
  name         = "${var.prefix}-violation-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  attribute {
    name = "risk_score"
    type = "S"
  }

  attribute {
    name = "domain"
    type = "S"
  }

  attribute {
    name = "last_evaluated"
    type = "S"
  }

  attribute {
    name = "check_id"
    type = "S"
  }

  # GSI: query by status, sorted by risk_score
  global_secondary_index {
    name            = "status-index"
    hash_key        = "status"
    range_key       = "risk_score"
    projection_type = "ALL"
  }

  # GSI: query by domain, sorted by last_evaluated
  global_secondary_index {
    name            = "domain-index"
    hash_key        = "domain"
    range_key       = "last_evaluated"
    projection_type = "ALL"
  }

  # GSI: query by check_id, sorted by status
  global_secondary_index {
    name            = "check-index"
    hash_key        = "check_id"
    range_key       = "status"
    projection_type = "ALL"
  }

  # DynamoDB Streams for downstream consumers
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  # TTL — auto-expire resolved states
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Project     = "CloudLine"
    Environment = var.environment
  }
}

# ---------------------------------------------------------------------------
# 2. compliance-trends — historical trend data
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "compliance_trends" {
  name         = "${var.prefix}-compliance-trends"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  tags = {
    Project     = "CloudLine"
    Environment = var.environment
  }
}

# ---------------------------------------------------------------------------
# 3. event-correlation — dedup and correlation window
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "event_correlation" {
  name         = "${var.prefix}-event-correlation"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Project     = "CloudLine"
    Environment = var.environment
  }
}

# ---------------------------------------------------------------------------
# 4. remediation-audit — audit trail for all remediation actions
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "remediation_audit" {
  name         = "${var.prefix}-remediation-audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  tags = {
    Project     = "CloudLine"
    Environment = var.environment
  }
}

# ---------------------------------------------------------------------------
# 5. auto-remediation-config — per-check auto-remediation flags
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "auto_remediation_config" {
  name         = "${var.prefix}-auto-remediation-config"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  tags = {
    Project     = "CloudLine"
    Environment = var.environment
  }
}
