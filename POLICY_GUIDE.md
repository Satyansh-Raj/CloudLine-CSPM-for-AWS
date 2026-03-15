# CloudLine Policy Writing Guide

How to add a new OPA/Rego security check to CloudLine.

## Overview

Each security check consists of 4 parts:

1. **Rego policy** — the detection logic
2. **Rego test** — unit tests for the policy
3. **Event mapping** — which CloudTrail events trigger re-evaluation
4. **Remediation template** — how to fix the issue

## Policy Organization

Policies are organized by AWS service domain:

```
policies/
├── identity/          # IAM, Cognito
├── compute/           # EC2, Lambda/Serverless
├── data_protection/   # S3, KMS, SecretsManager, Database, Storage
├── network/           # VPC, WAF, API Gateway
├── logging/           # CloudTrail, CloudWatch, Config
├── detection/         # GuardDuty, SecurityHub, etc.
├── cross_resource/    # Cross-service attack patterns
└── tests/             # All test files
```

Check IDs follow the pattern `{service}_{NN}` (e.g.,
`iam_01`, `s3_05`, `ec2_01`, `vpc_01`).

## Step 1: Write the Rego Policy

Add rules to the appropriate service module in `policies/`:

```rego
# policies/data_protection/s3.rego
package aws.data_protection.s3

import rego.v1

# Add a new rule to an existing service module.
# Each rule produces violations for a specific check.

violation contains result if {
    some bucket in input.buckets
    not bucket.example_setting
    result := {
        "check_id": "s3_21",
        "status": "alarm",
        "severity": "high",
        "reason": "S3 bucket missing example setting",
        "resource": bucket.arn,
        "domain": "data_protection",
        "compliance": {
            "cis_aws": ["2.1.5"],
            "nist_800_53": ["SC-13"],
            "pci_dss": [],
            "hipaa": [],
            "soc2": [],
        },
    }
}

compliant contains result if {
    some bucket in input.buckets
    bucket.example_setting
    result := {
        "check_id": "s3_21",
        "status": "ok",
        "severity": "high",
        "reason": "S3 bucket has example setting",
        "resource": bucket.arn,
        "domain": "data_protection",
        "compliance": {},
    }
}
```

### Conventions

- Package name: `aws.{domain}.{service}`
- Check ID: `{service}_{NN}` (sequential within module)
- Always include `check_id`, `status`, `severity`, `reason`,
  `resource`, `domain`
- Include both `violation` and `compliant` rules
- Map to at least one compliance framework
- Use `input.{resource_type}` for the resource data

## Step 2: Write Tests

Add tests to `policies/tests/{service}_test.rego`:

```rego
package aws.data_protection.s3_test

import rego.v1

import data.aws.data_protection.s3

test_s3_21_compliant if {
    results := s3.violation with input as {
        "buckets": [{
            "arn": "arn:aws:s3:::my-bucket",
            "example_setting": true,
        }],
    }
    # No violation for s3_21
    not any_s3_21(results)
}

test_s3_21_alarm if {
    results := s3.violation with input as {
        "buckets": [{
            "arn": "arn:aws:s3:::my-bucket",
            "example_setting": false,
        }],
    }
    some result in results
    result.check_id == "s3_21"
    result.severity == "high"
}

any_s3_21(results) if {
    some r in results
    r.check_id == "s3_21"
}
```

Run tests:

```bash
opa test policies/ -v
opa fmt -w policies/  # auto-format
```

## Step 3: Add Event Mapping

Edit `backend/app/pipeline/models.py` to add CloudTrail
events that should trigger this check:

```python
EVENT_POLICY_MAP: dict[str, list[str]] = {
    # ... existing mappings ...
    "PutBucketExampleSetting": [
        "aws.data_protection.s3"
    ],
}
```

This maps the CloudTrail `eventName` to the Rego
package(s) that should be re-evaluated when that event
fires.

## Step 4: Add Remediation Steps

Add entries to the frontend remediation constants in
`frontend/src/constants/remediationSteps.ts`:

```typescript
s3_21: {
  title: "Enable Example Setting on S3 Bucket",
  severity: "high",
  console: [
    "Open the S3 console",
    "Select the bucket",
    "Enable the example setting",
  ],
  cli: "aws s3api put-bucket-example ...",
  terraform: `resource "aws_s3_bucket" "main" {
  example_setting = true
}`,
},
```

### Tier Levels

| Tier | Type | Description |
|------|------|-------------|
| 1 | Suggestion | Console steps + CLI + Terraform (all checks) |
| 2 | One-Click | Automated boto3 execution (selected checks) |
| 3 | Auto | Runs automatically on new violations (configurable) |

To add Tier 2 (one-click) support, implement an executor
in `backend/app/pipeline/remediation/one_click.py` and a
rollback handler in `rollback.py`.

## Step 5: Add Risk Scoring (Optional)

The risk scorer uses 5 dimensions automatically:

1. **Severity** — from the policy metadata
2. **Exploitability** — service-specific (add to `risk_scorer.py`)
3. **Blast radius** — based on resource connectivity
4. **Data sensitivity** — from resource tags
5. **Compliance impact** — from mapped frameworks

To customize exploitability for a new service, add a case
to `_compute_exploitability()` in `risk_scorer.py`.

## Checklist

- [ ] Rego rules in `policies/{domain}/{service}.rego`
- [ ] Rego tests in `policies/tests/{service}_test.rego`
- [ ] `opa test policies/ -v` passes
- [ ] `opa fmt --diff policies/` clean
- [ ] Event mapping in `EVENT_POLICY_MAP`
- [ ] Remediation steps in `remediationSteps.ts`
- [ ] Compliance mapping in `complianceMappings.ts`
- [ ] Check name in `checkNames.ts`
- [ ] Backend tests updated if needed
- [ ] PR with description of what the check detects

## Policy Reference

### Identity & Access (39 checks)

| ID | Service | Severity | Description |
|----|---------|----------|-------------|
| iam_01–iam_20 | IAM | critical–low | Root MFA, password policy, access keys, MFA, roles, etc. |
| cognito_01–cognito_17 | Cognito | critical–low | User pool MFA, password policy, token validity, etc. |
| iam_09 | IAM | high | IAM User MFA Not Enabled |
| iam_14 | IAM | high | Inactive IAM User With Active Credentials |
| iam_15 | IAM | high | IAM Access Analyzer Not Enabled |

### Data Protection (88 checks)

| ID | Service | Severity | Description |
|----|---------|----------|-------------|
| s3_01–s3_20 | S3 | critical–low | Public access, encryption, versioning, lifecycle, etc. |
| kms_01–kms_15 | KMS | critical–low | Key rotation, policy, grants, etc. |
| secretsmanager_01–secretsmanager_13 | Secrets Manager | critical–low | Auto-rotation, encryption, replication, etc. |
| db_01–db_20 | RDS/Database | critical–low | Public access, encryption, multi-AZ, backups, etc. |
| storage_01–storage_20 | EBS/EFS | critical–low | Volume encryption, snapshots, lifecycle, etc. |

### Compute (40 checks)

| ID | Service | Severity | Description |
|----|---------|----------|-------------|
| ec2_01–ec2_20 | EC2 | critical–low | IMDSv2, security groups, SSH/RDP access, EBS defaults, etc. |
| serverless_01–serverless_20 | Lambda | critical–low | X-Ray tracing, VPC config, concurrency, DLQ, etc. |

### Network (54 checks)

| ID | Service | Severity | Description |
|----|---------|----------|-------------|
| vpc_01–vpc_20 | VPC | critical–low | Flow logs, NACLs, subnets, NAT gateways, etc. |
| waf_01–waf_14 | WAF | critical–low | Web ACL rules, logging, rate limiting, etc. |
| apigw_01–apigw_20 | API Gateway | critical–low | Authorization, throttling, logging, WAF, etc. |

### Logging & Monitoring (47 checks)

| ID | Service | Severity | Description |
|----|---------|----------|-------------|
| cloudtrail_01–cloudtrail_15 | CloudTrail | critical–low | Logging enabled, validation, encryption, etc. |
| cloudwatch_01–cloudwatch_20 | CloudWatch | critical–low | Root usage alarms, log retention, metrics, etc. |
| config_01–config_12 | AWS Config | critical–low | Recorder enabled, rules, delivery channel, etc. |

### Detection & Security (20 checks)

| ID | Service | Severity | Description |
|----|---------|----------|-------------|
| awssec_01–awssec_20 | GuardDuty/SecurityHub | critical–low | Detector enabled, findings, integrations, etc. |

### Cross-Resource (1 check)

| ID | Description |
|----|-------------|
| CROSS_01 | Capital One Attack Pattern (SSRF → IMDS → S3 exfiltration) |
