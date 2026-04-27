#!/bin/bash
#
# CloudLine — One-Command Setup
# Prerequisites: AWS CLI configured with admin privileges.
#
# Usage:
#   chmod +x setup.sh && ./setup.sh
#

set -euo pipefail

# ── Colors ──────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$ROOT_DIR/.env"
TF_DIR="$ROOT_DIR/terraform"

info()    { echo -e "${CYAN}→${NC} $1"; }
success() { echo -e "${GREEN}✔${NC} $1"; }
warn()    { echo -e "${YELLOW}⚠${NC} $1"; }
fail()    { echo -e "${RED}✘${NC} $1"; }
banner()  {
  echo ""
  echo -e "${BOLD}════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  $1${NC}"
  echo -e "${BOLD}════════════════════════════════════════════${NC}"
  echo ""
}

OS=$(uname -s)

install_package() {
  if [[ "$OS" == "Linux" ]]; then
    sudo apt-get install -y "$1" >/dev/null 2>&1
  elif [[ "$OS" == "Darwin" ]]; then
    brew install "$1" >/dev/null 2>&1
  fi
}

# ── Resolve Docker-compatible distro and codename ─────
# Docker only publishes repos for specific Debian/Ubuntu
# codenames. Derivatives (Kali, Parrot, Mint, Pop!_OS,
# Zorin, MX, Deepin, elementary, etc.) must map to their
# upstream parent to avoid "no Release file" errors.
VALID_DOCKER_DEBIAN="bookworm bullseye buster trixie sid"
VALID_DOCKER_UBUNTU="noble jammy focal bionic"

resolve_docker_repo() {
  local distro_id codename

  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    distro_id="${ID:-}"
  fi

  case "${distro_id:-}" in
    ubuntu)
      DOCKER_DISTRO="ubuntu"
      codename="${UBUNTU_CODENAME:-$(
        lsb_release -cs 2>/dev/null || echo noble
      )}"
      if ! echo "$VALID_DOCKER_UBUNTU" \
           | grep -qw "$codename"; then
        codename="noble"
      fi
      ;;
    *)
      DOCKER_DISTRO="debian"
      codename="${VERSION_CODENAME:-}"
      if ! echo "$VALID_DOCKER_DEBIAN" \
           | grep -qw "$codename"; then
        codename="bookworm"
      fi
      ;;
  esac

  DOCKER_CODENAME="$codename"
}

# ═══════════════════════════════════════════════════
# PHASE 1 — Install System Dependencies
# ═══════════════════════════════════════════════════
banner "Phase 1 — Installing Dependencies"

# ── Fix broken Docker apt source on derivatives ───────
# Distros like Kali, Parrot, Mint, Zorin, MX, Deepin,
# Pop!_OS, elementary, etc. may have a docker.list with
# an unsupported codename from a prior install attempt.
if [[ "$OS" == "Linux" ]] \
   && [[ -f /etc/apt/sources.list.d/docker.list ]]; then
  resolve_docker_repo
  CURRENT_CODENAME=$(
    grep -oP \
      'download\.docker\.com/linux/\w+\s+\K\S+' \
      /etc/apt/sources.list.d/docker.list \
      2>/dev/null || echo ""
  )
  ALL_VALID="$VALID_DOCKER_DEBIAN $VALID_DOCKER_UBUNTU"
  if [[ -n "$CURRENT_CODENAME" ]] \
     && ! echo "$ALL_VALID" \
          | grep -qw "$CURRENT_CODENAME"; then
    sudo sed -i \
      "s|${CURRENT_CODENAME}|${DOCKER_CODENAME}|g" \
      /etc/apt/sources.list.d/docker.list
    sudo apt-get update -qq
  fi
fi

# ── Python 3.11+ ──
if command -v python3 &>/dev/null; then
  PY_VER=$(python3 --version 2>&1)
  success "Python found: $PY_VER"
else
  info "Installing Python..."
  if [[ "$OS" == "Linux" ]]; then
    sudo apt-get update -qq
    sudo apt-get install -y python3 python3-pip python3-venv
  elif [[ "$OS" == "Darwin" ]]; then
    brew install python@3.11
  fi
  success "Python installed: $(python3 --version)"
fi

# ── Node.js 20+ ──
if command -v node &>/dev/null; then
  success "Node.js found: $(node --version)"
else
  info "Installing Node.js 20..."
  if [[ "$OS" == "Linux" ]]; then
    curl -fsSL https://deb.nodesource.com/setup_20.x \
      | sudo -E bash - >/dev/null 2>&1
    sudo apt-get install -y nodejs >/dev/null 2>&1
  elif [[ "$OS" == "Darwin" ]]; then
    brew install node@20
  fi
  success "Node.js installed: $(node --version)"
fi

# ── npm ──
if command -v npm &>/dev/null; then
  success "npm found: $(npm --version)"
else
  info "Installing npm..."
  if [[ "$OS" == "Linux" ]]; then
    sudo apt-get update -qq
    sudo apt-get install -y npm >/dev/null 2>&1
  elif [[ "$OS" == "Darwin" ]]; then
    brew install npm >/dev/null 2>&1
  fi
  success "npm installed: $(npm --version)"
fi

# ── Docker / Podman ──
if command -v docker &>/dev/null; then
  success "Docker found: $(docker --version)"
  # Ensure current user can run Docker without sudo
  if ! docker info &>/dev/null 2>&1; then
    info "Adding $USER to docker group..."
    sudo usermod -aG docker "$USER"
    info "Re-launching setup with docker group active..."
    exec sg docker -c "$(printf '%q ' "$0" "$@")"
  fi
elif command -v podman &>/dev/null; then
  success "Podman found: $(podman --version)"
else
  info "Installing Docker..."
  if [[ "$OS" == "Linux" ]]; then
    # Works on all Debian-based distros (Debian, Ubuntu,
    # Kali, Pop!_OS, Mint, etc.)
    sudo apt-get update -qq
    sudo apt-get install -y \
      ca-certificates curl gnupg >/dev/null 2>&1

    # Resolve upstream distro + codename for Docker repo
    resolve_docker_repo

    # Add Docker's official GPG key
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL \
      "https://download.docker.com/linux/${DOCKER_DISTRO}/gpg" \
      | sudo gpg --dearmor --yes \
        -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg

    # Add the Docker repository
    echo \
      "deb [arch=$(dpkg --print-architecture) \
      signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/${DOCKER_DISTRO} \
      ${DOCKER_CODENAME} stable" \
      | sudo tee /etc/apt/sources.list.d/docker.list \
        >/dev/null

    sudo apt-get update -qq
    sudo apt-get install -y \
      docker-ce docker-ce-cli containerd.io \
      docker-buildx-plugin \
      docker-compose-plugin >/dev/null 2>&1

    sudo usermod -aG docker "$USER" 2>/dev/null || true
    success "Docker installed"
    info "Re-launching setup with docker group active..."
    exec sg docker -c "$(printf '%q ' "$0" "$@")"
  elif [[ "$OS" == "Darwin" ]]; then
    warn "Install Docker Desktop: https://docker.com/products/docker-desktop"
    exit 1
  fi
  success "Docker installed"
fi

# ── AWS CLI v2 ──
if command -v aws &>/dev/null; then
  success "AWS CLI found: $(aws --version 2>&1 | head -1)"
else
  info "Installing AWS CLI v2..."
  if [[ "$OS" == "Linux" ]]; then
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" \
      -o /tmp/awscliv2.zip
    unzip -q /tmp/awscliv2.zip -d /tmp
    sudo /tmp/aws/install >/dev/null 2>&1
    rm -rf /tmp/aws /tmp/awscliv2.zip
  elif [[ "$OS" == "Darwin" ]]; then
    curl -fsSL "https://awscli.amazonaws.com/AWSCLIV2.pkg" \
      -o /tmp/AWSCLIV2.pkg
    sudo installer -pkg /tmp/AWSCLIV2.pkg -target / >/dev/null 2>&1
    rm /tmp/AWSCLIV2.pkg
  fi
  success "AWS CLI installed"
fi

# ── Git ──
if command -v git &>/dev/null; then
  success "Git found: $(git --version)"
else
  info "Installing Git..."
  install_package git
  success "Git installed"
fi

# ── Terraform ──
if command -v terraform &>/dev/null; then
  success "Terraform found: $(terraform --version | head -1)"
else
  info "Installing Terraform..."
  TF_VER=$(curl -fsSL \
    "https://checkpoint-api.hashicorp.com/v1/check/terraform" \
    2>/dev/null | grep -oP '"current_version":"\K[^"]+' || true)
  [[ -z "$TF_VER" ]] && TF_VER="1.10.5"

  if [[ "$OS" == "Linux" ]]; then
    TF_ZIP="terraform_${TF_VER}_linux_amd64.zip"
  elif [[ "$OS" == "Darwin" ]]; then
    ARCH=$(uname -m)
    [[ "$ARCH" == "arm64" ]] \
      && TF_ARCH="darwin_arm64" \
      || TF_ARCH="darwin_amd64"
    TF_ZIP="terraform_${TF_VER}_${TF_ARCH}.zip"
  fi

  curl -fsSL \
    "https://releases.hashicorp.com/terraform/${TF_VER}/${TF_ZIP}" \
    -o /tmp/tf.zip
  sudo apt-get install -y unzip >/dev/null 2>&1 || true
  unzip -o /tmp/tf.zip -d /tmp/tf_bin >/dev/null 2>&1
  sudo mv /tmp/tf_bin/terraform /usr/local/bin/terraform
  sudo chmod +x /usr/local/bin/terraform
  rm -rf /tmp/tf.zip /tmp/tf_bin
  hash -r 2>/dev/null
  success "Terraform installed: $(terraform --version | head -1)"
fi

# ── OPA binary ──
if command -v opa &>/dev/null; then
  success "OPA found: $(opa version 2>&1 | head -1)"
else
  info "Installing OPA..."
  OPA_VER="v0.68.0"
  if [[ "$OS" == "Linux" ]]; then
    curl -fsSL \
      "https://openpolicyagent.org/downloads/${OPA_VER}/opa_linux_amd64_static" \
      -o /tmp/opa
  elif [[ "$OS" == "Darwin" ]]; then
    ARCH=$(uname -m)
    [[ "$ARCH" == "arm64" ]] \
      && OPA_ARCH="darwin_arm64" \
      || OPA_ARCH="darwin_amd64"
    curl -fsSL \
      "https://openpolicyagent.org/downloads/${OPA_VER}/opa_${OPA_ARCH}" \
      -o /tmp/opa
  fi
  chmod +x /tmp/opa
  mkdir -p "$HOME/.local/bin"
  mv /tmp/opa "$HOME/.local/bin/opa"
  success "OPA installed: $($HOME/.local/bin/opa version 2>&1 | head -1)"
fi
OPA_PATH="$(command -v opa 2>/dev/null || echo "$HOME/.local/bin/opa")"

# ═══════════════════════════════════════════════════
# PHASE 2 — Verify AWS CLI & Create Scanner IAM User
# ═══════════════════════════════════════════════════
banner "Phase 2 — AWS IAM Setup"

# Verify AWS CLI is configured
if ! aws sts get-caller-identity &>/dev/null; then
  fail "AWS CLI is not configured. Run 'aws configure' first."
  exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity \
  --query Account --output text)
AWS_REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")
success "AWS Account: $ACCOUNT_ID  Region: $AWS_REGION"

IAM_USER="Cloudline_Scanner"
POLICY_ARN="arn:aws:iam::aws:policy/SecurityAudit"

# Check if user already exists
if aws iam get-user --user-name "$IAM_USER" &>/dev/null; then
  success "IAM user '$IAM_USER' already exists"

  # Check for existing access key
  EXISTING_KEY=$(aws iam list-access-keys \
    --user-name "$IAM_USER" \
    --query 'AccessKeyMetadata[0].AccessKeyId' \
    --output text 2>/dev/null || echo "None")

  if [[ "$EXISTING_KEY" != "None" && "$EXISTING_KEY" != "" ]]; then
    info "Existing access key found: $EXISTING_KEY"

    # If .env already has this key, skip regeneration
    if grep -q "$EXISTING_KEY" "$ENV_FILE" 2>/dev/null; then
      success "Access key already configured in .env"
      ACCESS_KEY="$EXISTING_KEY"
      SECRET_KEY="(already in .env)"
      SKIP_ENV_CREDS=true
    else
      info "Rotating access key for fresh .env setup..."
      aws iam delete-access-key \
        --user-name "$IAM_USER" \
        --access-key-id "$EXISTING_KEY" 2>/dev/null || true
      KEY_JSON=$(aws iam create-access-key \
        --user-name "$IAM_USER" \
        --output json)
      ACCESS_KEY=$(echo "$KEY_JSON" | grep -oP '"AccessKeyId":\s*"\K[^"]+')
      SECRET_KEY=$(echo "$KEY_JSON" | grep -oP '"SecretAccessKey":\s*"\K[^"]+')
      SKIP_ENV_CREDS=false
    fi
  else
    KEY_JSON=$(aws iam create-access-key \
      --user-name "$IAM_USER" \
      --output json)
    ACCESS_KEY=$(echo "$KEY_JSON" | grep -oP '"AccessKeyId":\s*"\K[^"]+')
    SECRET_KEY=$(echo "$KEY_JSON" | grep -oP '"SecretAccessKey":\s*"\K[^"]+')
    SKIP_ENV_CREDS=false
  fi
else
  info "Creating IAM user '$IAM_USER'..."
  aws iam create-user --user-name "$IAM_USER" >/dev/null
  aws iam attach-user-policy \
    --user-name "$IAM_USER" \
    --policy-arn "$POLICY_ARN"
  success "Created '$IAM_USER' with SecurityAudit policy"

  KEY_JSON=$(aws iam create-access-key \
    --user-name "$IAM_USER" \
    --output json)
  ACCESS_KEY=$(echo "$KEY_JSON" | grep -oP '"AccessKeyId":\s*"\K[^"]+')
  SECRET_KEY=$(echo "$KEY_JSON" | grep -oP '"SecretAccessKey":\s*"\K[^"]+')
  SKIP_ENV_CREDS=false
  success "Access key generated: $ACCESS_KEY"
fi

# Always ensure cross-account AssumeRole policy is attached
# (idempotent — put-user-policy overwrites if already exists)
info "Ensuring cross-account AssumeRole policy on '$IAM_USER'..."
aws iam put-user-policy \
  --user-name "$IAM_USER" \
  --policy-name "CloudLineCrossAccountAssumeRole" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "CrossAccountScan",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/CloudLineScanner"
    }]
  }' >/dev/null
success "Cross-account AssumeRole policy applied"

# ═══════════════════════════════════════════════════
# PHASE 3 — Generate .env
# ═══════════════════════════════════════════════════
banner "Phase 3 — Configuring Environment"

# ── Admin account credentials ──
echo -e "${CYAN}Set up the admin account for the CloudLine dashboard.${NC}"
echo ""

while true; do
  read -rp "$(echo -e "${BOLD}Admin email [admin@cloudline.dev]:${NC} ")" ADMIN_EMAIL
  ADMIN_EMAIL="${ADMIN_EMAIL:-admin@cloudline.dev}"
  if [[ "$ADMIN_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    break
  fi
  warn "Invalid email format"
done

while true; do
  read -rsp "$(echo -e "${BOLD}Admin password (min 8 chars, 1 uppercase, 1 number, 1 special):${NC} ")" ADMIN_PASSWORD
  echo ""
  if [[ ${#ADMIN_PASSWORD} -ge 8 ]] \
     && [[ "$ADMIN_PASSWORD" =~ [A-Z] ]] \
     && [[ "$ADMIN_PASSWORD" =~ [0-9] ]] \
     && [[ "$ADMIN_PASSWORD" =~ [^a-zA-Z0-9] ]]; then
    read -rsp "$(echo -e "${BOLD}Confirm password:${NC} ")" ADMIN_PASSWORD_CONFIRM
    echo ""
    if [[ "$ADMIN_PASSWORD" == "$ADMIN_PASSWORD_CONFIRM" ]]; then
      break
    fi
    warn "Passwords do not match"
  else
    warn "Password too weak — need 8+ chars, uppercase, number, special character"
  fi
done
success "Admin account configured: $ADMIN_EMAIL"

# Auto-generate a secure JWT secret
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")

if [[ "${SKIP_ENV_CREDS:-false}" == "true" ]]; then
  info ".env already has valid credentials — skipping rewrite"
else
  cat > "$ENV_FILE" <<EOF
# CloudLine Environment — auto-generated by setup.sh

# AWS Credentials (Cloudline_Scanner)
AWS_ACCESS_KEY_ID=$ACCESS_KEY
AWS_SECRET_ACCESS_KEY=$SECRET_KEY

# AWS Configuration
AWS_REGION=$AWS_REGION
AWS_ACCOUNT_ID=$ACCOUNT_ID

# OPA Configuration
OPA_MODE=cli
OPA_BINARY_PATH=$OPA_PATH
OPA_POLICY_DIR=../policies
OPA_HTTP_URL=http://localhost:9720

# DynamoDB Configuration
DYNAMODB_ENDPOINT=http://localhost:9730
DYNAMODB_STATE_TABLE=violation-state
DYNAMODB_TRENDS_TABLE=compliance-trends
DYNAMODB_CORRELATION_TABLE=event-correlation
DYNAMODB_AUDIT_TABLE=remediation-audit
DYNAMODB_CONFIG_TABLE=auto-remediation-config

# SNS Configuration (filled after terraform apply)
SNS_ALERT_TOPIC_ARN=

# RBAC / JWT Auth
AUTH_ENABLED=true
JWT_SECRET=$JWT_SECRET
ADMIN_BOOTSTRAP_EMAIL=$ADMIN_EMAIL
ADMIN_BOOTSTRAP_PASSWORD=$ADMIN_PASSWORD

# Application Settings
APP_ENV=development
LOG_LEVEL=DEBUG
SCAN_INTERVAL_MINUTES=60
CORRELATION_WINDOW_MINUTES=5
DEFAULT_ROLLBACK_WINDOW_MINUTES=60
CORS_ORIGINS=http://localhost:5173

# Jira Integration (optional)
JIRA_URL=
JIRA_EMAIL=
JIRA_API_TOKEN=
JIRA_PROJECT_KEY=
EOF
  success ".env generated with scanner credentials"
fi

# Ensure auth vars exist (may be missing from older .env)
if ! grep -q "^ADMIN_BOOTSTRAP_EMAIL=" "$ENV_FILE" 2>/dev/null; then
  cat >> "$ENV_FILE" <<EOF

# RBAC / JWT Auth
AUTH_ENABLED=true
JWT_SECRET=$JWT_SECRET
ADMIN_BOOTSTRAP_EMAIL=$ADMIN_EMAIL
ADMIN_BOOTSTRAP_PASSWORD=$ADMIN_PASSWORD
EOF
  info "Added auth configuration to .env"
fi

# Ensure Jira vars exist (may be missing from older .env)
if ! grep -q "^JIRA_URL=" "$ENV_FILE" 2>/dev/null; then
  cat >> "$ENV_FILE" <<'EOF'

# Jira Integration (optional)
JIRA_URL=
JIRA_EMAIL=
JIRA_API_TOKEN=
JIRA_PROJECT_KEY=
EOF
  info "Added Jira configuration placeholders to .env"
fi

# ═══════════════════════════════════════════════════
# PHASE 4 — Email Notification Setup
# ═══════════════════════════════════════════════════
banner "Phase 4 — Email Notifications"

echo -e "${CYAN}Configure email addresses for security alerts.${NC}"
echo -e "${CYAN}Each subscriber receives SNS notifications for${NC}"
echo -e "${CYAN}new violations and resolutions.${NC}"
echo ""

ALERT_EMAILS=()
while true; do
  read -rp "$(echo -e "${BOLD}Enter email (or press Enter to finish):${NC} ")" email
  [[ -z "$email" ]] && break
  # Basic email validation
  if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    ALERT_EMAILS+=("$email")
    success "Added: $email"
  else
    warn "Invalid email format, skipping: $email"
  fi
done

if [[ ${#ALERT_EMAILS[@]} -eq 0 ]]; then
  warn "No emails configured — SNS alerts will be skipped"
  TF_EMAILS_VAR='[]'
else
  success "${#ALERT_EMAILS[@]} email(s) configured"
  # Build terraform list: ["a@b.com", "c@d.com"]
  TF_EMAILS_VAR='['
  for i in "${!ALERT_EMAILS[@]}"; do
    [[ $i -gt 0 ]] && TF_EMAILS_VAR+=', '
    TF_EMAILS_VAR+="\"${ALERT_EMAILS[$i]}\""
  done
  TF_EMAILS_VAR+=']'
fi

# ═══════════════════════════════════════════════════
# PHASE 5 — Jira Integration (Optional)
# ═══════════════════════════════════════════════════
banner "Phase 5 — Jira Integration (Optional)"

echo -e "${CYAN}Integrate with Jira Cloud to create tickets${NC}"
echo -e "${CYAN}directly from CloudLine violations.${NC}"
echo ""
echo -e "  You will need:"
echo -e "    1. Jira Cloud URL  (e.g. https://team.atlassian.net)"
echo -e "    2. Jira account email"
echo -e "    3. Jira API token  (generate at ${BOLD}https://id.atlassian.com/manage-profile/security/api-tokens${NC})"
echo -e "    4. Project key     (e.g. SEC, CLOUD)"
echo ""

read -rp "$(echo -e \
  "${BOLD}Configure Jira integration? (y/N):${NC} ")" jira_confirm

if [[ "$jira_confirm" =~ ^[Yy]$ ]]; then
  # ── Jira URL ──
  while true; do
    read -rp "$(echo -e \
      "${BOLD}Jira URL:${NC} ")" JIRA_URL
    if [[ "$JIRA_URL" =~ ^https://.+\.atlassian\.net/?$ ]]; then
      JIRA_URL="${JIRA_URL%/}"   # strip trailing slash
      break
    fi
    warn "URL must be https://<workspace>.atlassian.net"
  done

  # ── Jira Email ──
  while true; do
    read -rp "$(echo -e \
      "${BOLD}Jira email:${NC} ")" JIRA_EMAIL
    if [[ "$JIRA_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
      break
    fi
    warn "Invalid email format"
  done

  # ── Jira API Token (hidden input) ──
  while true; do
    read -rsp "$(echo -e \
      "${BOLD}Jira API token:${NC} ")" JIRA_API_TOKEN
    echo ""
    if [[ -n "$JIRA_API_TOKEN" ]]; then
      break
    fi
    warn "API token cannot be empty"
  done

  # ── Project Key ──
  read -rp "$(echo -e \
    "${BOLD}Jira project key [SEC]:${NC} ")" JIRA_PROJECT_KEY
  JIRA_PROJECT_KEY="${JIRA_PROJECT_KEY:-SEC}"

  # Write to .env
  sed -i "s|^JIRA_URL=.*|JIRA_URL=$JIRA_URL|" "$ENV_FILE"
  sed -i "s|^JIRA_EMAIL=.*|JIRA_EMAIL=$JIRA_EMAIL|" "$ENV_FILE"
  sed -i "s|^JIRA_API_TOKEN=.*|JIRA_API_TOKEN=$JIRA_API_TOKEN|" \
    "$ENV_FILE"
  sed -i "s|^JIRA_PROJECT_KEY=.*|JIRA_PROJECT_KEY=$JIRA_PROJECT_KEY|" \
    "$ENV_FILE"

  JIRA_CONFIGURED=true
  success "Jira configured → $JIRA_URL (project: $JIRA_PROJECT_KEY)"
else
  JIRA_CONFIGURED=false
  warn "Jira skipped — configure later in .env"
fi

# ═══════════════════════════════════════════════════
# PHASE 6 — Terraform Deploy
# ═══════════════════════════════════════════════════
banner "Phase 6 — Terraform Infrastructure"

# Write terraform.tfvars
cat > "$TF_DIR/terraform.tfvars" <<EOF
# Auto-generated by setup.sh
aws_account_id = "$ACCOUNT_ID"
aws_region     = "$AWS_REGION"
environment    = "production"
prefix         = "cloudline"
alert_emails   = $TF_EMAILS_VAR
alert_phone    = ""
EOF
success "terraform.tfvars generated"

# Build Lambda deployment zip (required by terraform plan)
if [[ ! -f "$ROOT_DIR/deployment.zip" ]]; then
  info "Building Lambda deployment package..."
  if ! bash "$ROOT_DIR/scripts/package_lambda.sh" \
       > /tmp/lambda_pkg.log 2>&1; then
    fail "Lambda packaging failed:"
    cat /tmp/lambda_pkg.log
    rm -f /tmp/lambda_pkg.log
    exit 1
  fi
  rm -f /tmp/lambda_pkg.log
  success "Lambda deployment.zip built"
else
  success "Lambda deployment.zip already exists"
fi

cd "$TF_DIR"

info "Running terraform init..."
if ! terraform init -input=false > /tmp/tf_init.log 2>&1; then
  fail "Terraform init failed:"
  cat /tmp/tf_init.log
  rm -f /tmp/tf_init.log
  exit 1
fi
rm -f /tmp/tf_init.log
success "Terraform initialized"

# Import the IAM user created by setup.sh so Terraform doesn't
# try to recreate it and hit EntityAlreadyExists.
info "Importing existing IAM user into Terraform state..."
terraform import \
  module.iam.aws_iam_user.cloudline_scanner \
  Cloudline_Scanner \
  > /tmp/tf_import.log 2>&1 || true   # no-op if already imported
terraform import \
  "module.iam.aws_iam_user_policy_attachment.security_audit" \
  "Cloudline_Scanner/arn:aws:iam::aws:policy/SecurityAudit" \
  >> /tmp/tf_import.log 2>&1 || true
terraform import \
  "module.iam.aws_iam_user_policy.cross_account_assume_role" \
  "Cloudline_Scanner:CloudLineCrossAccountAssumeRole" \
  >> /tmp/tf_import.log 2>&1 || true
rm -f /tmp/tf_import.log
success "IAM user imported into Terraform state"

info "Running terraform plan..."
if ! terraform plan -input=false -out=tfplan \
     > /tmp/tf_plan.log 2>&1; then
  fail "Terraform plan failed:"
  cat /tmp/tf_plan.log
  rm -f /tmp/tf_plan.log
  exit 1
fi
rm -f /tmp/tf_plan.log
success "Terraform plan ready"

echo ""
echo -e "${YELLOW}Terraform will create the following AWS resources:${NC}"
echo "  • CloudTrail trail (multi-region)"
echo "  • 7 EventBridge rules"
echo "  • Lambda function (event handler)"
echo "  • 5 DynamoDB tables"
echo "  • SNS alert topic + ${#ALERT_EMAILS[@]} email subscriber(s)"
echo "  • IAM role (least-privilege)"
echo ""

read -rp "$(echo -e "${BOLD}Apply infrastructure? (y/N):${NC} ")" confirm
if [[ "$confirm" =~ ^[Yy]$ ]]; then
  info "Applying terraform..."
  terraform apply -input=false tfplan
  success "Infrastructure deployed"

  # Capture SNS topic ARN and write it to .env
  SNS_ARN=$(terraform output -raw sns_topic_arn 2>/dev/null || echo "")
  if [[ -n "$SNS_ARN" ]]; then
    sed -i "s|^SNS_ALERT_TOPIC_ARN=.*|SNS_ALERT_TOPIC_ARN=$SNS_ARN|" \
      "$ENV_FILE"
    success "SNS topic ARN saved to .env: $SNS_ARN"
  fi

  if [[ ${#ALERT_EMAILS[@]} -gt 0 ]]; then
    echo ""
    warn "Each subscriber will receive a confirmation email from AWS."
    warn "They must click 'Confirm subscription' to start receiving alerts."
  fi
else
  warn "Terraform apply skipped — you can run it later:"
  echo "  cd $TF_DIR && terraform apply"
fi

rm -f tfplan
cd "$ROOT_DIR"

# ═══════════════════════════════════════════════════
# PHASE 7 — Build & Launch Application
# ═══════════════════════════════════════════════════
banner "Phase 7 — Building & Launching"

# Build frontend first (backend container serves dist/)
info "Installing frontend dependencies..."
cd "$ROOT_DIR/frontend"
npm install --silent 2>&1 | tail -3
success "Frontend dependencies installed"

info "Building frontend for production..."
npm run build 2>&1 | tail -5
success "Frontend built"
cd "$ROOT_DIR"

# Ensure custom policies dir is writable by container user (uid=999)
mkdir -p "$ROOT_DIR/policies/custom"
chmod o+w "$ROOT_DIR/policies/custom"

# Start Docker containers
info "Starting Docker containers..."
docker compose -f "$ROOT_DIR/docker-compose.yml" up -d --build 2>&1 \
  | tail -5
success "Containers running (backend:9710, OPA:9720, DynamoDB:9730)"

# Wait for backend health
info "Waiting for backend to be healthy..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:9710/health >/dev/null 2>&1; then
    success "Backend is healthy"
    break
  fi
  if [[ $i -eq 30 ]]; then
    warn "Backend not responding yet — check: docker compose logs backend"
  fi
  sleep 2
done

# ═══════════════════════════════════════════════════
# DONE
# ═══════════════════════════════════════════════════
banner "Setup Complete"

echo -e "${GREEN}${BOLD}CloudLine is running!${NC}"
echo ""
echo "  Dashboard:  http://localhost:9710"
echo ""
echo -e "  ${BOLD}Quick commands:${NC}"
echo "    ./start.sh          — Start app (skip setup)"
echo "    ./start.sh --stop   — Stop all containers"
echo "    ./start.sh --status — Check health"
echo "    make docker-logs    — View container logs"
echo ""

if [[ ${#ALERT_EMAILS[@]} -gt 0 ]]; then
  echo -e "  ${BOLD}Email subscribers:${NC}"
  for e in "${ALERT_EMAILS[@]}"; do
    echo "    • $e"
  done
  echo ""
  echo -e "  ${YELLOW}Remember: confirm the AWS subscription email!${NC}"
  echo ""
fi

if [[ "${JIRA_CONFIGURED:-false}" == "true" ]]; then
  echo -e "  ${BOLD}Jira integration:${NC}"
  echo "    URL:     $JIRA_URL"
  echo "    Email:   $JIRA_EMAIL"
  echo "    Project: $JIRA_PROJECT_KEY"
  echo ""
fi
