"""Alert generator — publishes drift alerts to SNS.

Formats DriftAlert objects as plain-text and publishes
to an SNS topic for downstream consumers (Slack,
PagerDuty, email, WebSocket).
"""

import logging

import boto3

from app.pipeline.models import DriftAlert, DriftType

logger = logging.getLogger(__name__)

# Only these drift types trigger an SNS notification
_ALERTABLE_TYPES = {
    DriftType.NEW_VIOLATION,
    DriftType.RESOLUTION,
}


class AlertGenerator:
    """Publishes drift alerts to an SNS topic.

    Silently skips publishing when no topic ARN is
    configured, allowing local development without SNS.

    Example:
        >>> gen = AlertGenerator(
        ...     session=boto3.Session(),
        ...     topic_arn="arn:aws:sns:us-east-1:...",
        ... )
        >>> gen.publish(drift_alert)
        True
    """

    def __init__(
        self,
        session: boto3.Session,
        topic_arn: str = "",
        endpoint_url: str | None = None,
    ):
        self.topic_arn = topic_arn
        self._client = None
        self._session = session
        self._endpoint_url = endpoint_url

    @property
    def client(self):
        """Lazy-init SNS client."""
        if self._client is None:
            kwargs = {}
            if self._endpoint_url:
                kwargs["endpoint_url"] = (
                    self._endpoint_url
                )
            self._client = self._session.client(
                "sns", **kwargs
            )
        return self._client

    def publish(self, alert: DriftAlert) -> bool:
        """Publish a drift alert to SNS.

        Only publishes for new_violation and resolution
        drift types. Skips no_change and first_seen.

        Args:
            alert: The DriftAlert to publish.

        Returns:
            True if published (or skipped by design),
            False if publish failed.
        """
        if not self.topic_arn:
            logger.debug(
                "No SNS topic configured, skipping"
            )
            return False

        if alert.drift_type not in _ALERTABLE_TYPES:
            logger.debug(
                "Skipping non-alertable type: %s",
                alert.drift_type.value,
            )
            return False

        message = self._format_message(alert)
        subject = self._format_subject(alert)

        try:
            self.client.publish(
                TopicArn=self.topic_arn,
                Message=message,
                Subject=subject,
                MessageAttributes=self._attributes(
                    alert
                ),
            )
            logger.info(
                "Published %s alert for %s %s",
                alert.drift_type.value,
                alert.check_id,
                alert.resource_arn,
            )
            return True
        except Exception as e:
            logger.error(
                "SNS publish failed: %s", e
            )
            return False

    def publish_batch(
        self, alerts: list[DriftAlert]
    ) -> int:
        """Publish multiple alerts. Returns count of
        successfully published alerts."""
        count = 0
        for alert in alerts:
            if self.publish(alert):
                count += 1
        return count

    # Immediate actions per check_id
    _ACTIONS: dict[str, list[str]] = {
        "iam_root_mfa": [
            "1. Sign in to AWS as root",
            "2. Go to IAM > Security credentials",
            "3. Enable MFA under Multi-factor"
            " authentication",
            "4. Use a virtual or hardware MFA device",
        ],
        "iam_pwd_min_length": [
            "1. Go to IAM > Account settings",
            "2. Set minimum password length to 14+",
            "3. Enable complexity requirements",
            "4. Set password expiration to 90 days",
        ],
        "iam_user_mfa": [
            "1. Go to IAM > Users > select user",
            "2. Click Security credentials tab",
            "3. Assign a virtual MFA device",
            "4. Or disable the account if unused",
        ],
        "s3_block_public_acls": [
            "1. Go to S3 > select bucket > Permissions",
            "2. Click Edit under Block public access",
            "3. Enable all 4 checkboxes",
            "4. Save changes",
        ],
        "cloudtrail_enabled": [
            "1. Go to CloudTrail > Trails",
            "2. Edit the trail",
            "3. Enable multi-region trail",
            "4. Ensure log file validation is on",
        ],
        "ec2_no_open_ssh": [
            "1. Go to EC2 > Security Groups",
            "2. Find the rule allowing 0.0.0.0/0 on 22",
            "3. Remove or restrict to specific IPs",
            "4. Use a bastion host or VPN instead",
        ],
        "ec2_imdsv2": [
            "1. Go to EC2 > Instances > select instance",
            "2. Actions > Instance settings > Modify"
            " instance metadata options",
            "3. Set IMDSv2 to Required",
            "4. Verify applications support IMDSv2",
        ],
        "storage_ebs_encryption": [
            "1. Go to EC2 > Account Attributes"
            " > EBS encryption",
            "2. Click Manage > Enable encryption"
            " by default",
            "3. Select a KMS key",
            "4. New EBS volumes will be encrypted",
        ],
    }

    def _get_actions(
        self, check_id: str
    ) -> list[str]:
        """Return recommended actions for a check."""
        return self._ACTIONS.get(check_id, [
            "1. Review the affected resource in AWS"
            " Console",
            "2. Apply the remediation guidance for"
            f" {check_id}",
            "3. Re-run a scan to confirm resolution",
        ])

    def _format_message(
        self, alert: DriftAlert
    ) -> str:
        """Build a human-readable plain-text email."""
        div = "-" * 50
        sep = "=" * 50

        is_new = (
            alert.drift_type == DriftType.NEW_VIOLATION
        )
        banner = (
            "  *** NEW SECURITY VIOLATION DETECTED ***"
            if is_new
            else "  *** SECURITY VIOLATION RESOLVED ***"
        )

        severity = alert.severity.value.upper()
        sev_icons = {
            "CRITICAL": "[ !!! ] CRITICAL",
            "HIGH":     "[  !! ] HIGH",
            "MEDIUM":   "[   ! ] MEDIUM",
            "LOW":      "[     ] LOW",
        }
        sev_label = sev_icons.get(
            severity, f"[ ! ] {severity}"
        )

        ts = (
            str(alert.timestamp)
            .replace("T", " ")
            .replace("Z", " UTC")
        )

        # Resource — shorten long ARNs for readability
        resource = alert.resource_arn or "N/A"
        if len(resource) > 60:
            resource = "..." + resource[-57:]

        prev = alert.previous_status or "none"
        lines = [
            sep,
            banner,
            sep,
            "",
            f"  Severity   : {sev_label}",
            f"  Check      : {alert.check_id}",
            f"  Risk Score : {alert.risk_score} / 100",
            "",
            div,
            "  WHAT HAPPENED",
            div,
            f"  {alert.reason or 'No details available'}",
            "",
            f"  Resource   : {resource}",
            f"  Status     : {prev} --> "
            f"{alert.current_status}",
            "",
            div,
            "  ENVIRONMENT",
            div,
            f"  Account    : {alert.account_id}",
            f"  Region     : {alert.region}",
            f"  Detected   : {ts}",
            f"  Trigger    : {alert.trigger_event}",
            "",
        ]

        if is_new:
            actions = self._get_actions(alert.check_id)
            lines += [
                div,
                "  IMMEDIATE ACTIONS",
                div,
            ] + [f"  {a}" for a in actions] + [""]

        lines += [
            sep,
            "  CloudLine | AWS Misconfiguration"
            " Detection",
            sep,
        ]
        return "\n".join(lines)

    def _format_subject(
        self, alert: DriftAlert
    ) -> str:
        """Build a short SNS subject line (max 100)."""
        severity = alert.severity.value.upper()
        if alert.drift_type == DriftType.NEW_VIOLATION:
            prefix = f"[ALERT][{severity}]"
        else:
            prefix = f"[RESOLVED][{severity}]"

        subject = (
            f"{prefix} {alert.check_id} — "
            f"{alert.reason[:50] if alert.reason else 'Security violation'}"
        )
        return subject[:100]

    def _attributes(
        self, alert: DriftAlert
    ) -> dict:
        """Build SNS MessageAttributes for filtering."""
        return {
            "drift_type": {
                "DataType": "String",
                "StringValue": alert.drift_type.value,
            },
            "severity": {
                "DataType": "String",
                "StringValue": alert.severity.value,
            },
            "check_id": {
                "DataType": "String",
                "StringValue": alert.check_id,
            },
        }
