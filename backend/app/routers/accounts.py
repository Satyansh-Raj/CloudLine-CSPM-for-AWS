"""Accounts CRUD API — manage target AWS accounts
for multi-account scanning.

Endpoints:
  POST   /accounts/preflight — generate external_id + setup scripts
  POST   /accounts           — add a target account
  GET    /accounts           — list active accounts
  GET    /accounts/{id}      — get one account
  DELETE /accounts/{id}      — deactivate account
"""

import logging
import textwrap
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth.dependencies import (
    require_admin,
    require_any_authenticated,
)
from app.auth.models import User
from app.config import Settings
from app.dependencies import (
    get_account_store,
    get_session_factory,
    get_settings,
)
from app.models.account import TargetAccount
from app.pipeline.account_store import AccountStore
from app.pipeline.session_factory import (
    AWSSessionFactory,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["accounts"])


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class PreflightRequest(BaseModel):
    """Request body for the preflight endpoint."""

    account_id: str
    account_name: str


class PreflightResponse(BaseModel):
    """Response from the preflight endpoint.

    Contains the external_id to embed in the IAM trust
    policy plus ready-to-run setup scripts.
    """

    external_id: str
    bash_script: str
    cloudformation_template: str


class AccountCreateRequest(BaseModel):
    """Request body for creating a target account."""

    account_id: str
    account_name: str
    role_arn: str
    external_id: str | None = None
    regions: list[str] = ["us-east-1"]


class AccountUpdateRequest(BaseModel):
    """Request body for updating a target account."""

    account_name: str | None = None
    regions: list[str] | None = None


_SCANNER_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CloudLineScannerReadOnly",
            "Effect": "Allow",
            "Action": [
                "iam:Get*", "iam:List*",
                "ec2:Describe*",
                "s3:GetBucketAcl",
                "s3:GetBucketLocation",
                "s3:GetBucketLogging",
                "s3:GetBucketPolicy",
                "s3:GetBucketVersioning",
                "s3:GetEncryptionConfiguration",
                "s3:GetPublicAccessBlock",
                "s3:ListAllMyBuckets",
                "s3:ListBucket",
                "rds:Describe*",
                "lambda:GetFunction",
                "lambda:GetFunctionConfiguration",
                "lambda:GetPolicy",
                "lambda:ListFunctions",
                "lambda:ListTags",
                "guardduty:GetDetector",
                "guardduty:ListDetectors",
                "guardduty:ListFindings",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetEventSelectors",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:ListTrails",
                "kms:DescribeKey",
                "kms:GetKeyPolicy",
                "kms:GetKeyRotationStatus",
                "kms:ListAliases",
                "kms:ListKeys",
                "kms:ListResourceTags",
                "logs:DescribeLogGroups",
                "logs:DescribeMetricFilters",
                "logs:ListTagsLogGroup",
                "cloudwatch:DescribeAlarms",
                "cloudwatch:GetMetricStatistics",
                "cloudwatch:ListMetrics",
                "secretsmanager:DescribeSecret",
                "secretsmanager:ListSecrets",
                "config:DescribeConfigurationRecorders",
                "config:DescribeConfigurationRecorderStatus",
                "config:DescribeDeliveryChannels",
                "config:GetComplianceDetailsByConfigRule",
                "organizations:DescribeOrganization",
                "organizations:ListAccounts",
                "organizations:ListPolicies",
                "macie2:GetMacieSession",
                "macie2:ListFindings",
                "elasticloadbalancing:Describe*",
                "cloudfront:GetDistribution",
                "cloudfront:ListDistributions",
                "dynamodb:DescribeTable",
                "dynamodb:ListTables",
                "apigateway:GET",
                "ecs:Describe*", "ecs:List*",
                "ecr:DescribeRepositories",
                "ecr:GetRepositoryPolicy",
                "ecr:ListImages",
                "eks:DescribeCluster",
                "eks:ListClusters",
                "eks:ListNodegroups",
                "autoscaling:DescribeAutoScalingGroups",
                "backup:ListBackupPlans",
                "backup:ListBackupSelections",
                "backup:ListProtectedResources",
                "config:DescribeConfigRules",
                "config:DescribeConfigurationAggregators",
                "config:DescribeConfigurationRecorders",
                "config:DescribeConfigurationRecorderStatus",
                "config:DescribeConformancePacks",
                "config:DescribeDeliveryChannels",
                "config:GetComplianceDetailsByConfigRule",
                "route53:ListHostedZones",
                "route53:ListResourceRecordSets",
                "secretsmanager:GetResourcePolicy",
                "network-firewall:ListFirewalls",
                "network-firewall:DescribeFirewall",
                "wafv2:ListWebACLs",
                "wafv2:GetWebACL",
                "sts:GetCallerIdentity",
            ],
            "Resource": "*",
        }
    ],
}


def _build_bash_script(
    external_id: str,
    account_id: str,
    cloudline_account_id: str,
) -> str:
    import json as _json

    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": (
                        f"arn:aws:iam::"
                        f"{cloudline_account_id}:root"
                    )
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": external_id
                    }
                },
            }
        ],
    }
    policy_json = _json.dumps(
        _SCANNER_POLICY, indent=2
    )
    trust_json = _json.dumps(trust, indent=2)
    return textwrap.dedent(f"""\
        #!/bin/bash
        set -euo pipefail
        # CloudLine Scanner — IAM role setup
        # Target account : {account_id}
        # External ID    : {external_id}

        ROLE_NAME="CloudLineScanner"
        TRUST_POLICY='{trust_json}'
        SCANNER_POLICY='{policy_json}'

        if aws iam get-role --role-name "$ROLE_NAME" \\
             > /dev/null 2>&1; then
          echo "Role $ROLE_NAME already exists — updating trust policy ..."
          aws iam update-assume-role-policy \\
            --role-name "$ROLE_NAME" \\
            --policy-document "$TRUST_POLICY"
        else
          echo "Creating IAM role $ROLE_NAME ..."
          aws iam create-role \\
            --role-name "$ROLE_NAME" \\
            --assume-role-policy-document "$TRUST_POLICY"
        fi

        echo "Attaching inline policy ..."
        aws iam put-role-policy \\
          --role-name "$ROLE_NAME" \\
          --policy-name CloudLineScannerPolicy \\
          --policy-document "$SCANNER_POLICY"

        ACCOUNT=$(aws sts get-caller-identity \\
          --query Account --output text)
        echo ""
        echo "Done. Role ARN:"
        echo "  arn:aws:iam::${{ACCOUNT}}:role/$ROLE_NAME"
    """)


def _build_cf_template(
    external_id: str,
    account_id: str,
    cloudline_account_id: str,
) -> str:
    return textwrap.dedent(f"""\
        AWSTemplateFormatVersion: "2010-09-09"
        Description: >
          CloudLine Scanner cross-account IAM role.
          Target account : {account_id}
          External ID    : {external_id}

        Resources:
          CloudLineScannerRole:
            Type: AWS::IAM::Role
            Properties:
              RoleName: CloudLineScanner
              AssumeRolePolicyDocument:
                Version: "2012-10-17"
                Statement:
                  - Effect: Allow
                    Principal:
                      AWS: >-
                        arn:aws:iam::{cloudline_account_id}:root
                    Action: sts:AssumeRole
                    Condition:
                      StringEquals:
                        sts:ExternalId: "{external_id}"
              Policies:
                - PolicyName: CloudLineScannerPolicy
                  PolicyDocument:
                    Version: "2012-10-17"
                    Statement:
                      - Sid: CloudLineScannerReadOnly
                        Effect: Allow
                        Resource: "*"
                        Action:
                          - iam:Get*
                          - iam:List*
                          - ec2:Describe*
                          - s3:GetBucketAcl
                          - s3:GetBucketLocation
                          - s3:GetBucketLogging
                          - s3:GetBucketPolicy
                          - s3:GetBucketVersioning
                          - s3:GetEncryptionConfiguration
                          - s3:GetPublicAccessBlock
                          - s3:ListAllMyBuckets
                          - s3:ListBucket
                          - rds:Describe*
                          - lambda:GetFunction
                          - lambda:GetFunctionConfiguration
                          - lambda:GetPolicy
                          - lambda:ListFunctions
                          - lambda:ListTags
                          - guardduty:GetDetector
                          - guardduty:ListDetectors
                          - guardduty:ListFindings
                          - cloudtrail:DescribeTrails
                          - cloudtrail:GetEventSelectors
                          - cloudtrail:GetTrailStatus
                          - cloudtrail:ListTrails
                          - kms:DescribeKey
                          - kms:GetKeyPolicy
                          - kms:GetKeyRotationStatus
                          - kms:ListAliases
                          - kms:ListKeys
                          - kms:ListResourceTags
                          - logs:DescribeLogGroups
                          - logs:DescribeMetricFilters
                          - logs:ListTagsLogGroup
                          - cloudwatch:DescribeAlarms
                          - cloudwatch:GetMetricStatistics
                          - cloudwatch:ListMetrics
                          - secretsmanager:DescribeSecret
                          - secretsmanager:ListSecrets
                          - config:DescribeConfigurationRecorders
                          - config:DescribeConfigurationRecorderStatus
                          - config:DescribeDeliveryChannels
                          - config:GetComplianceDetailsByConfigRule
                          - organizations:DescribeOrganization
                          - organizations:ListAccounts
                          - organizations:ListPolicies
                          - macie2:GetMacieSession
                          - macie2:ListFindings
                          - elasticloadbalancing:Describe*
                          - cloudfront:GetDistribution
                          - cloudfront:ListDistributions
                          - dynamodb:DescribeTable
                          - dynamodb:ListTables
                          - apigateway:GET
                          - ecs:Describe*
                          - ecs:List*
                          - ecr:DescribeRepositories
                          - ecr:GetRepositoryPolicy
                          - ecr:ListImages
                          - eks:DescribeCluster
                          - eks:ListClusters
                          - eks:ListNodegroups
                          - autoscaling:DescribeAutoScalingGroups
                          - backup:ListBackupPlans
                          - backup:ListBackupSelections
                          - backup:ListProtectedResources
                          - config:DescribeConfigRules
                          - config:DescribeConfigurationAggregators
                          - config:DescribeConformancePacks
                          - route53:ListHostedZones
                          - route53:ListResourceRecordSets
                          - secretsmanager:GetResourcePolicy
                          - network-firewall:ListFirewalls
                          - network-firewall:DescribeFirewall
                          - wafv2:ListWebACLs
                          - wafv2:GetWebACL
                          - sts:GetCallerIdentity

        Outputs:
          RoleArn:
            Description: ARN of the CloudLine Scanner role
            Value: !GetAtt CloudLineScannerRole.Arn
    """)


def _account_to_dict(acc: TargetAccount) -> dict:
    """Serialize TargetAccount to API response dict."""
    return {
        "account_id": acc.account_id,
        "account_name": acc.account_name,
        "role_arn": acc.role_arn,
        "external_id": acc.external_id,
        "regions": acc.regions,
        "is_active": acc.is_active,
        "added_at": acc.added_at,
        "last_scanned": acc.last_scanned,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/accounts/preflight")
def preflight_account(
    req: PreflightRequest,
    cfg: Settings = Depends(get_settings),
    _user: User = Depends(require_admin),
) -> PreflightResponse:
    """Generate an external_id and setup scripts.

    Call this BEFORE creating the IAM role in the target
    account. Returns a UUID external_id that must be
    embedded in the trust policy, plus a bash script and
    CloudFormation template to automate the role setup.

    The external_id is NOT saved to the database. Pass it
    back via POST /accounts when submitting the role ARN.

    Returns:
        200 with external_id, bash_script, and
        cloudformation_template strings.
    """
    external_id = str(uuid.uuid4())
    cloudline_id = cfg.aws_account_id or "CLOUDLINE_ACCOUNT_ID"
    return PreflightResponse(
        external_id=external_id,
        bash_script=_build_bash_script(
            external_id=external_id,
            account_id=req.account_id,
            cloudline_account_id=cloudline_id,
        ),
        cloudformation_template=_build_cf_template(
            external_id=external_id,
            account_id=req.account_id,
            cloudline_account_id=cloudline_id,
        ),
    )


@router.post("/accounts", status_code=201)
def create_account(
    req: AccountCreateRequest,
    store: AccountStore = Depends(get_account_store),
    session_factory: AWSSessionFactory = Depends(
        get_session_factory
    ),
    _user: User = Depends(require_admin),
) -> dict:
    """Add a target account for cross-account scanning.

    Generates a unique External ID, validates the role
    via STS AssumeRole, then persists the account.

    Returns:
        201 with the created account data, including
        the generated external_id.

    Raises:
        400 if the role cannot be assumed.
        500 if the account cannot be persisted.
    """
    external_id = req.external_id or str(uuid.uuid4())
    now = (
        datetime.now(UTC)
        .isoformat()
        .replace("+00:00", "Z")
    )
    account = TargetAccount(
        pk="ACCOUNTS",
        sk=req.account_id,
        account_id=req.account_id,
        account_name=req.account_name,
        role_arn=req.role_arn,
        external_id=external_id,
        regions=req.regions,
        is_active=True,
        added_at=now,
    )
    # Validate the role is assumable before saving
    try:
        session_factory.get_session(account)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot assume role: {exc}",
        ) from exc
    ok = store.put_account(account)
    if not ok:
        raise HTTPException(
            status_code=500,
            detail="Failed to persist account",
        )
    return _account_to_dict(account)


@router.get("/accounts")
def list_accounts(
    store: AccountStore = Depends(get_account_store),
    _user: User = Depends(require_any_authenticated),
) -> list[dict]:
    """Return all active target accounts."""
    accounts = store.list_active()
    return [_account_to_dict(a) for a in accounts]


@router.get("/accounts/{account_id}")
def get_account(
    account_id: str,
    store: AccountStore = Depends(get_account_store),
    _user: User = Depends(require_any_authenticated),
) -> dict:
    """Return a single target account by ID.

    Raises:
        404 if the account does not exist.
    """
    account = store.get_account(account_id)
    if account is None:
        raise HTTPException(
            status_code=404,
            detail=f"Account {account_id} not found",
        )
    return _account_to_dict(account)


@router.put("/accounts/{account_id}")
def update_account(
    account_id: str,
    req: AccountUpdateRequest,
    store: AccountStore = Depends(get_account_store),
    _user: User = Depends(require_admin),
) -> dict:
    """Update alias and/or regions for a target account.

    Raises:
        404 if the account does not exist.
        500 if the update cannot be persisted.
    """
    if store.get_account(account_id) is None:
        raise HTTPException(
            status_code=404,
            detail=f"Account {account_id} not found",
        )
    ok = store.update_account(
        account_id,
        account_name=req.account_name,
        regions=req.regions,
    )
    if not ok:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Failed to update {account_id}"
            ),
        )
    account = store.get_account(account_id)
    return _account_to_dict(account)


@router.delete("/accounts/{account_id}")
def deactivate_account(
    account_id: str,
    store: AccountStore = Depends(get_account_store),
    _user: User = Depends(require_admin),
) -> dict:
    """Deactivate a target account (soft delete).

    Returns:
        200 with deactivated status.
    """
    ok = store.deactivate(account_id)
    if not ok:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Failed to deactivate {account_id}"
            ),
        )
    return {
        "account_id": account_id,
        "status": "deactivated",
    }
