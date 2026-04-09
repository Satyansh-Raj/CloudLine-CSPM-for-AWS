#!/bin/sh
# Creates DynamoDB Local tables for CloudLine.
# Runs as a one-shot init container.
#
# Tables use composite keys (pk + sk) matching the
# Terraform modules and StateManager expectations.
# violation-state has 3 GSIs and DynamoDB Streams.

set -e

ENDPOINT="http://dynamodb-local:8000"

echo "Waiting for DynamoDB Local..."
sleep 2

table_exists() {
    aws dynamodb describe-table \
        --table-name "$1" \
        --endpoint-url "$ENDPOINT" \
        > /dev/null 2>&1
}

# ---- violation-state (3 GSIs, streams, TTL) ----
if table_exists "violation-state"; then
    echo "Table violation-state already exists, skipping."
else
    echo "Creating table: violation-state"
    aws dynamodb create-table \
        --table-name "violation-state" \
        --attribute-definitions \
            AttributeName=pk,AttributeType=S \
            AttributeName=sk,AttributeType=S \
            AttributeName=status,AttributeType=S \
            AttributeName=risk_score,AttributeType=N \
            AttributeName=domain,AttributeType=S \
            AttributeName=last_evaluated,AttributeType=S \
            AttributeName=check_id,AttributeType=S \
        --key-schema \
            AttributeName=pk,KeyType=HASH \
            AttributeName=sk,KeyType=RANGE \
        --global-secondary-indexes \
            'IndexName=status-index,KeySchema=[{AttributeName=status,KeyType=HASH},{AttributeName=risk_score,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
            'IndexName=domain-index,KeySchema=[{AttributeName=domain,KeyType=HASH},{AttributeName=last_evaluated,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
            'IndexName=check-index,KeySchema=[{AttributeName=check_id,KeyType=HASH},{AttributeName=status,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
        --billing-mode PAY_PER_REQUEST \
        --stream-specification StreamEnabled=true,StreamViewType=NEW_AND_OLD_IMAGES \
        --endpoint-url "$ENDPOINT"
    echo "Created: violation-state (3 GSIs, streams)"

    # Enable TTL
    aws dynamodb update-time-to-live \
        --table-name "violation-state" \
        --time-to-live-specification Enabled=true,AttributeName=ttl \
        --endpoint-url "$ENDPOINT" 2>/dev/null || true
fi

# ---- resource-inventory (5 GSIs) ----
if table_exists "resource-inventory"; then
    echo "Table resource-inventory already exists, skipping."
else
    echo "Creating table: resource-inventory"
    aws dynamodb create-table \
        --table-name "resource-inventory" \
        --attribute-definitions \
            AttributeName=pk,AttributeType=S \
            AttributeName=sk,AttributeType=S \
            AttributeName=technology_category,AttributeType=S \
            AttributeName=risk_score,AttributeType=N \
            AttributeName=exposure,AttributeType=S \
            AttributeName=violation_count,AttributeType=N \
            AttributeName=service,AttributeType=S \
            AttributeName=last_seen,AttributeType=S \
            AttributeName=region,AttributeType=S \
            AttributeName=account_id,AttributeType=S \
        --key-schema \
            AttributeName=pk,KeyType=HASH \
            AttributeName=sk,KeyType=RANGE \
        --global-secondary-indexes \
            'IndexName=category-index,KeySchema=[{AttributeName=technology_category,KeyType=HASH},{AttributeName=risk_score,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
            'IndexName=exposure-index,KeySchema=[{AttributeName=exposure,KeyType=HASH},{AttributeName=violation_count,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
            'IndexName=service-index,KeySchema=[{AttributeName=service,KeyType=HASH},{AttributeName=last_seen,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
            'IndexName=region-index,KeySchema=[{AttributeName=region,KeyType=HASH},{AttributeName=technology_category,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
            'IndexName=account-index,KeySchema=[{AttributeName=account_id,KeyType=HASH},{AttributeName=last_seen,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
        --billing-mode PAY_PER_REQUEST \
        --endpoint-url "$ENDPOINT"
    echo "Created: resource-inventory (5 GSIs)"
fi

# ---- Simple composite-key tables (pk + sk) ----
create_composite_table() {
    TABLE_NAME="$1"

    if table_exists "$TABLE_NAME"; then
        echo "Table $TABLE_NAME already exists, skipping."
        return
    fi

    echo "Creating table: $TABLE_NAME"
    aws dynamodb create-table \
        --table-name "$TABLE_NAME" \
        --attribute-definitions \
            AttributeName=pk,AttributeType=S \
            AttributeName=sk,AttributeType=S \
        --key-schema \
            AttributeName=pk,KeyType=HASH \
            AttributeName=sk,KeyType=RANGE \
        --billing-mode PAY_PER_REQUEST \
        --endpoint-url "$ENDPOINT"
    echo "Created: $TABLE_NAME"
}

create_composite_table "compliance-trends"
create_composite_table "event-correlation"
create_composite_table "target-accounts"

# ---- macie-findings (2 GSIs: bucket-index, severity-index) ----
if table_exists "macie-findings"; then
    echo "Table macie-findings already exists, skipping."
else
    echo "Creating table: macie-findings"
    aws dynamodb create-table \
        --table-name "macie-findings" \
        --attribute-definitions \
            AttributeName=pk,AttributeType=S \
            AttributeName=sk,AttributeType=S \
            AttributeName=bucket_name,AttributeType=S \
            AttributeName=severity,AttributeType=S \
            AttributeName=first_observed_at,AttributeType=S \
        --key-schema \
            AttributeName=pk,KeyType=HASH \
            AttributeName=sk,KeyType=RANGE \
        --global-secondary-indexes \
            'IndexName=bucket-index,KeySchema=[{AttributeName=bucket_name,KeyType=HASH},{AttributeName=first_observed_at,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
            'IndexName=severity-index,KeySchema=[{AttributeName=severity,KeyType=HASH},{AttributeName=first_observed_at,KeyType=RANGE}],Projection={ProjectionType=ALL}' \
        --billing-mode PAY_PER_REQUEST \
        --endpoint-url "$ENDPOINT"
    echo "Created: macie-findings (2 GSIs)"
fi

# Enable TTL on tables that need it
for TTL_TABLE in "event-correlation" "resource-inventory"; do
    aws dynamodb update-time-to-live \
        --table-name "$TTL_TABLE" \
        --time-to-live-specification Enabled=true,AttributeName=ttl \
        --endpoint-url "$ENDPOINT" 2>/dev/null || true
done

echo "All DynamoDB tables initialized."
