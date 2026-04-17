# CloudLine Multi-Account Setup

This guide explains how to connect additional AWS accounts to CloudLine so they
are scanned automatically and violations appear in the dashboard.

---

## How It Works

CloudLine's primary account (`832843292195`) assumes an IAM role in each target
account to collect data. When a scan runs, every connected account is scanned
and violations are displayed in the dashboard filtered by account. New violations
in any account trigger an SNS email notification to your subscribed address.

---

## Prerequisites

- CloudLine is running (`make docker-up`)
- You are logged in to the CloudLine dashboard as **Admin** or **Operator**
- You have AWS Console or CLI access to the target account you want to add

---

## Step 1 — Generate the Setup Script

1. Open the CloudLine dashboard and go to **Accounts**
2. Click **Add Account**
3. Enter:
   - **Account Name** — a friendly label (e.g. `Production`, `Staging`)
   - **AWS Account ID** — the 12-digit ID of the target account
4. Click **Generate Script**

CloudLine calls the preflight endpoint and returns:
- A unique **External ID** (UUID) tied to this account
- A **Bash script** (tab 1) — copy-paste into AWS CLI
- A **CloudFormation template** (tab 2) — deploy via AWS Console

---

## Step 2 — Create the IAM Role in the Target Account

Run **one** of the following options in the target account.

### Option A — Bash Script (AWS CLI)

```bash
# Run this in a terminal authenticated to the TARGET account
ROLE_NAME="CloudLineScanner"
ACCOUNT_ID="<target-account-id>"
EXTERNAL_ID="<generated-external-id>"
CLOUDLINE_ACCOUNT="832843292195"

aws iam create-role \
  --role-name "$ROLE_NAME" \
  --assume-role-policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Allow\",
      \"Principal\": { \"AWS\": \"arn:aws:iam::${CLOUDLINE_ACCOUNT}:root\" },
      \"Action\": \"sts:AssumeRole\",
      \"Condition\": { \"StringEquals\": { \"sts:ExternalId\": \"${EXTERNAL_ID}\" } }
    }]
  }"

aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "CloudLineScannerPolicy" \
  --policy-document file://policy.json
```

The dashboard shows the exact script with your values pre-filled — just copy and run it.

### Option B — CloudFormation

1. In the target account, go to **AWS Console → CloudFormation → Create Stack**
2. Choose **Upload a template file**
3. Paste the CloudFormation YAML shown in the dashboard (tab 2)
4. Deploy the stack — it creates the role automatically

---

## IAM Permissions Granted to the Role

The `CloudLineScannerPolicy` is **read-only**. It grants:

| Service | Permissions |
|---|---|
| IAM | `Get*`, `List*` |
| EC2 | `Describe*` |
| S3 | Bucket ACL, policy, versioning, encryption, public access block |
| RDS | `Describe*` |
| Lambda | List, get functions, policies, tags |
| GuardDuty | Get detector, list detectors and findings |
| CloudTrail | Describe, get event selectors and status |
| KMS | Describe, get key policy and rotation status, list |
| CloudWatch | Describe alarms, get metrics |
| Secrets Manager | Describe and list secrets |
| AWS Config | Describe recorders, delivery channels |
| Organizations | Describe org, list accounts |
| Macie | Get session, list findings |

No write, delete, or modify permissions are included.

---

## Step 3 — Connect the Account

1. Back in the CloudLine wizard, check **"I've run the script"**
2. Click **Next**
3. Enter the **Role ARN** of the role you just created:
   ```
   arn:aws:iam::<target-account-id>:role/CloudLineScanner
   ```
4. Click **Connect Account**

CloudLine verifies the role by calling `sts:AssumeRole`. If it succeeds the
account is saved and appears in the Accounts list.

---

## Step 4 — Trigger a Scan

After connecting, either:
- **Wait** for the auto-scan (runs every `SCAN_INTERVAL_MINUTES=5` minutes)
- **Manually trigger** a scan from the Dashboard → click **Scan Now**

The scan will cover all connected accounts. Progress is visible via the
WebSocket live updates on the dashboard.

---

## Viewing Per-Account Data

Use the **account selector** at the top of the Accounts page to switch context.
Every page — Dashboard, Violations, Inventory, Compliance, IAM Graph, Trends —
filters its data to the selected account.

To return to a view across all accounts, click **Deselect**.

---

## Email Notifications

All accounts share the same SNS topic (`cloudline-alerts`). When a violation is
detected or resolved in **any** connected account, an email is sent to all
subscribers. The email identifies the source account:

```
Account    : 111111111111
Region     : ap-south-1
```

To receive emails:
1. Go to **AWS Console → SNS → Topics → cloudline-alerts**
2. Click **Create subscription**
3. Protocol: **Email**
4. Endpoint: your email address
5. Confirm the subscription link AWS sends to your inbox

---

## Managing Connected Accounts

From the **Accounts** page you can:

| Action | How |
|---|---|
| View all accounts | Accounts list shows ID, name, role ARN, last scan time |
| Update name or regions | Click the account → Edit |
| Remove an account | Click the account → Delete |

Deleting an account from CloudLine does **not** remove the IAM role from the
target account. Delete the `CloudLineScanner` role manually in that account's
IAM console if no longer needed.

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| "Access denied" on connect | Role ARN wrong or External ID mismatch | Re-run the script with the correct External ID from the wizard |
| Account shows but no violations | Role created but scan not run yet | Click Scan Now on the Dashboard |
| No email notifications | Email not subscribed to SNS topic | Subscribe your email to `cloudline-alerts` in SNS Console |
| Scan skips an account | Account deactivated or role deleted | Reconnect the account via the wizard |
