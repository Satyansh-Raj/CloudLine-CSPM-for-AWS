# CloudLine — CSPM for AWS

OPA-based Cloud Security Posture Management platform for AWS. Continuously scans your AWS environment against 289 built-in security checks, maps findings to compliance frameworks, and surfaces violations in a real-time dashboard.

---

## Features

- **289 security checks** across IAM, S3, EC2, VPC, Lambda, RDS, KMS, CloudTrail, and more
- **OPA/Rego policies** — human-readable, testable, extensible
- **Compliance mapping** — CIS AWS, NIST 800-53, PCI DSS, HIPAA, SOC2
- **Real-time scanning** — scheduled auto-scan + on-demand via WebSocket
- **Drift detection** — tracks config changes over time
- **Risk scoring** — 5-dimension score (severity, exploitability, blast radius, data sensitivity, compliance impact)
- **IAM graph** — visualize IAM relationships and permission paths
- **Resource inventory** — searchable catalog of all discovered resources
- **Multi-account / multi-region** — scan multiple AWS accounts via cross-account IAM roles
- **Jira integration** — create tickets directly from violations
- **SNS email alerts** — get notified on new violations
- **RBAC** — JWT-based auth with role management and force-password-change flow

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Browser (port 9710)                │
│   React + TypeScript + Tailwind (served by backend)  │
└───────────────────────┬─────────────────────────────┘
                        │ HTTP / WebSocket
┌───────────────────────▼─────────────────────────────┐
│              FastAPI Backend  (port 9710)            │
│  collectors → OPA evaluator → DynamoDB state store   │
└──────────┬──────────────────────────┬───────────────┘
           │                          │
┌──────────▼──────┐        ┌──────────▼──────────────┐
│  OPA Sidecar    │        │  DynamoDB Local          │
│  (port 9720)    │        │  (port 9730)             │
└─────────────────┘        └─────────────────────────┘
           │
┌──────────▼──────────────────────────────────────────┐
│                   AWS Account(s)                     │
│  IAM · S3 · EC2 · VPC · RDS · KMS · CloudTrail …   │
└─────────────────────────────────────────────────────┘
```

**Terraform deploys** (optional, for real-time event triggering):
- CloudTrail (multi-region)
- EventBridge rules → Lambda (re-evaluates affected policies on change)
- SNS topic + email subscribers
- DynamoDB tables (production)
- IAM scanner role (least-privilege)

---

## Security Checks

| Domain | Count | Services |
|--------|------:|---------|
| Identity & Access | 39 | IAM, Cognito |
| Data Protection | 88 | S3, KMS, Secrets Manager, RDS, EBS/EFS |
| Compute | 40 | EC2, Lambda |
| Network | 54 | VPC, WAF, API Gateway |
| Logging & Monitoring | 47 | CloudTrail, CloudWatch, AWS Config |
| Detection & Security | 20 | GuardDuty, Security Hub |
| Cross-Resource | 1 | Capital One SSRF → IMDS → S3 pattern |
| **Total** | **289** | |

---

## Prerequisites

| Tool | Version |
|------|---------|
| Docker + Docker Compose | Latest |
| AWS CLI | v2 |
| Python | 3.11+ |
| Node.js | 20+ |
| Terraform | 1.10+ (optional) |
| OPA binary | 0.68+ (auto-installed by setup) |

AWS CLI must be configured with credentials that have admin privileges for the initial setup.

---

## Quick Start

### One-command setup (recommended)

```bash
git clone https://github.com/Satyansh-Raj/CloudLine-CSPM-for-AWS.git
cd CloudLine-CSPM-for-AWS
chmod +x setup.sh && ./setup.sh
```

`setup.sh` does the following automatically:

1. Installs missing dependencies (Docker, Node.js, OPA, Terraform, AWS CLI)
2. Creates an IAM user `Cloudline_Scanner` with `SecurityAudit` + cross-account `sts:AssumeRole` policy
3. Prompts for admin email + password, generates `.env` with a random JWT secret
4. Optionally configures Jira integration
5. Optionally deploys Terraform infrastructure (CloudTrail, EventBridge, Lambda, SNS)
6. Builds the frontend, starts Docker containers

Dashboard: **http://localhost:9710**

---

### Manual setup

```bash
# 1. Copy and fill env file
cp .env.example .env
# Edit .env — fill AWS credentials, admin account, JWT secret

# 2. Build frontend
cd frontend && npm install && npm run build && cd ..

# 3. Start containers
docker compose up -d

# 4. Open dashboard
open http://localhost:9710
```

---

## Daily Usage

```bash
./start.sh              # start app
./start.sh --stop       # stop all containers
./start.sh --restart    # restart
./start.sh --rebuild    # rebuild frontend + restart
./start.sh --status     # check health
```

---

## Environment Variables

Copy `.env.example` to `.env` and fill in:

| Variable | Required | Description |
|----------|----------|-------------|
| `AWS_ACCESS_KEY_ID` | Yes | Scanner IAM credentials |
| `AWS_SECRET_ACCESS_KEY` | Yes | Scanner IAM credentials |
| `AWS_ACCOUNT_ID` | Yes | 12-digit AWS account ID |
| `AWS_REGION` | Yes | Primary region (e.g. `us-east-1`) |
| `AWS_REGIONS` | No | Comma-separated multi-region list |
| `AUTH_ENABLED` | Yes | `true` to enforce JWT auth |
| `JWT_SECRET` | Yes | Auto-generated by setup.sh |
| `ADMIN_BOOTSTRAP_EMAIL` | Yes | First admin account email |
| `ADMIN_BOOTSTRAP_PASSWORD` | Yes | Min 12 chars, 1 number, 1 special char |
| `OPA_MODE` | Yes | `cli` (local) or `http` (Docker sidecar) |
| `DYNAMODB_ENDPOINT` | No | Leave empty for real AWS DynamoDB |
| `SNS_ALERT_TOPIC_ARN` | No | Filled by Terraform after apply |
| `JIRA_URL` | No | `https://team.atlassian.net` |
| `JIRA_EMAIL` | No | Jira account email |
| `JIRA_API_TOKEN` | No | Jira API token |
| `JIRA_PROJECT_KEY` | No | e.g. `SEC` |
| `SCAN_INTERVAL_MINUTES` | No | Default `60` |

---

## Multi-Account Scanning

To scan additional AWS accounts:

1. In each target account, create a role named `CloudLineScanner` with `SecurityAudit` policy and a trust policy allowing the scanner account to assume it.
2. In the dashboard → **Accounts** page, add the target account ID and role ARN.
3. CloudLine automatically assumes the role during each scan.

---

## Development

### Backend

```bash
# Run tests
make test
# or inside container
make docker-test

# Lint
make lint
make lint-fix
```

### Frontend

```bash
make frontend-dev         # dev server (port 5173)
make frontend-build       # production build
make frontend-test        # unit tests
make frontend-test-coverage
```

### OPA Policies

```bash
make opa-test             # run all Rego tests
make opa-fmt              # format policies
```

### Docker

```bash
make docker-logs          # tail all container logs
make docker-shell         # shell into backend container
make docker-clean         # remove containers + volumes
```

---

## Writing Custom Policies

See [POLICY_GUIDE.md](POLICY_GUIDE.md) for the full guide.

Quick summary — each check requires:

1. **Rego rule** in `policies/{domain}/{service}.rego`
2. **Rego test** in `policies/tests/{service}_test.rego`
3. **Event mapping** in `backend/app/pipeline/models.py` (CloudTrail event → policy package)
4. **Remediation steps** in `frontend/src/constants/remediationSteps.ts`

```bash
# Verify your new policy
opa test policies/ -v
opa fmt --diff policies/
```

Custom policies can also be dropped into `policies/custom/` — they are picked up automatically without a restart (OPA watches the directory).

---

## Project Structure

```
CloudLine-CSPM-for-AWS/
├── backend/
│   ├── app/
│   │   ├── auth/          # JWT + RBAC
│   │   ├── collectors/    # boto3 AWS resource collectors
│   │   ├── compliance/    # framework mapping
│   │   ├── engine/        # OPA evaluator + risk scorer
│   │   ├── inventory/     # resource inventory store
│   │   ├── pipeline/      # event → policy trigger pipeline
│   │   ├── routers/       # FastAPI route handlers
│   │   └── main.py        # app entry point + scheduler
│   ├── config/            # compliance mapping JSON
│   └── tests/             # pytest test suite
├── frontend/
│   └── src/
│       ├── pages/         # Dashboard, Violations, Compliance,
│       │                  # Policies, IAM Graph, Inventory,
│       │                  # Trends, Accounts, Users, ...
│       ├── components/    # shared UI components
│       ├── api/           # API client
│       └── constants/     # remediation steps, check names
├── policies/
│   ├── identity/          # IAM, Cognito
│   ├── compute/           # EC2, Lambda
│   ├── data_protection/   # S3, KMS, Secrets Manager, RDS, EBS
│   ├── network/           # VPC, WAF, API Gateway
│   ├── logging/           # CloudTrail, CloudWatch, Config
│   ├── detection/         # GuardDuty, Security Hub
│   ├── cross_resource/    # cross-service attack patterns
│   ├── risk_scoring/      # risk score aggregation
│   ├── custom/            # drop your own policies here
│   └── tests/             # Rego unit tests
├── terraform/             # CloudTrail, Lambda, SNS, DynamoDB, IAM
├── lambda/                # EventBridge → backend trigger handler
├── scripts/
│   ├── init-dynamodb.sh   # DynamoDB table bootstrap
│   └── package_lambda.sh  # Lambda deployment zip builder
├── docker-compose.yml
├── setup.sh               # one-command setup
├── start.sh               # start / stop / rebuild helper
└── Makefile
```

---

## Ports

| Service | Port |
|---------|------|
| Dashboard + API | 9710 |
| OPA sidecar | 9720 |
| DynamoDB Local | 9730 |

---

## License

MIT
