"""Event correlator — groups related events in a
time window to reduce alert noise.

Groups events by {account_id}#{service}#{resource_group}
within a configurable window (default 5 minutes).
Only one alert is sent per correlation group per window.
Records auto-expire via DynamoDB TTL after 24 hours.
"""

import logging
from datetime import UTC, datetime, timedelta

import boto3
from boto3.dynamodb.conditions import Key

from app.pipeline.models import DriftAlert

logger = logging.getLogger(__name__)

TTL_HOURS = 24


class EventCorrelator:
    """Groups related CloudTrail events by service
    and resource within a time window.

    Example:
        >>> correlator = EventCorrelator(
        ...     session=boto3.Session(),
        ...     table_name="event-correlation",
        ...     window_minutes=5,
        ... )
        >>> should_alert = correlator.correlate(alert)
    """

    def __init__(
        self,
        session: boto3.Session,
        table_name: str = "event-correlation",
        window_minutes: int = 5,
        endpoint_url: str | None = None,
    ):
        kwargs = {}
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url
        dynamo = session.resource(
            "dynamodb", **kwargs
        )
        self.table = dynamo.Table(table_name)
        self.table_name = table_name
        self.window_minutes = window_minutes

    def correlate(self, alert: DriftAlert) -> bool:
        """Process an alert through correlation.

        Returns True if this alert should trigger a
        notification (first in its window). Returns
        False if a prior alert in the same group
        already triggered a notification.

        Args:
            alert: The DriftAlert to correlate.

        Returns:
            True if alert should be sent, False if
            deduplicated.
        """
        group_key = self._group_key(alert)
        now = datetime.now(UTC)
        window_start = now - timedelta(
            minutes=self.window_minutes
        )

        # Look for existing open window
        existing = self._find_active_window(
            group_key, window_start
        )

        if existing is not None:
            # Append to existing window
            self._append_event(existing, alert)

            if existing.get("alert_sent", False):
                logger.debug(
                    "Dedup: alert already sent for "
                    "group %s",
                    group_key,
                )
                return False

            # Mark as alerted
            self._mark_alerted(existing)
            return True

        # New correlation window
        self._create_window(group_key, alert, now)
        return True

    def get_group(
        self, group_key: str, window_start: str
    ) -> dict | None:
        """Fetch a specific correlation group.

        Args:
            group_key: The partition key.
            window_start: The sort key (ISO timestamp).

        Returns:
            Item dict or None if not found.
        """
        try:
            resp = self.table.get_item(
                Key={
                    "pk": group_key,
                    "sk": window_start,
                },
            )
            return resp.get("Item")
        except Exception as e:
            logger.error(
                "Failed to get group %s: %s",
                group_key,
                e,
            )
            return None

    def _group_key(self, alert: DriftAlert) -> str:
        """Build the correlation group key.

        Format: {account_id}#{service}#{resource_group}
        where resource_group is derived from the
        check_id's domain prefix.
        """
        # Extract service from check_id or use
        # trigger_event prefix
        resource_group = alert.check_id
        return (
            f"{alert.account_id}"
            f"#{alert.region}"
            f"#{resource_group}"
        )

    def _find_active_window(
        self,
        group_key: str,
        window_start: datetime,
    ) -> dict | None:
        """Query for an active correlation window.

        Returns the most recent window item within
        the time range, or None.
        """
        try:
            resp = self.table.query(
                KeyConditionExpression=(
                    Key("pk").eq(group_key)
                    & Key("sk").gte(
                        window_start.isoformat()
                    )
                ),
                ScanIndexForward=False,
                Limit=1,
            )
            items = resp.get("Items", [])
            return items[0] if items else None
        except Exception as e:
            logger.error(
                "Correlation query failed for %s: %s",
                group_key,
                e,
            )
            return None

    def _create_window(
        self,
        group_key: str,
        alert: DriftAlert,
        now: datetime,
    ) -> bool:
        """Create a new correlation window record."""
        ttl_epoch = int(
            (now + timedelta(hours=TTL_HOURS))
            .timestamp()
        )
        item = {
            "pk": group_key,
            "sk": now.isoformat(),
            "events": [self._event_summary(alert)],
            "event_count": 1,
            "alert_sent": True,
            "ttl": ttl_epoch,
        }
        try:
            self.table.put_item(Item=item)
            logger.info(
                "New correlation window: %s",
                group_key,
            )
            return True
        except Exception as e:
            logger.error(
                "Failed to create window %s: %s",
                group_key,
                e,
            )
            return False

    def _append_event(
        self, window: dict, alert: DriftAlert
    ) -> bool:
        """Append an event to an existing window."""
        try:
            self.table.update_item(
                Key={
                    "pk": window["pk"],
                    "sk": window["sk"],
                },
                UpdateExpression=(
                    "SET events = list_append("
                    "events, :evt), "
                    "event_count = event_count + :one"
                ),
                ExpressionAttributeValues={
                    ":evt": [
                        self._event_summary(alert)
                    ],
                    ":one": 1,
                },
            )
            return True
        except Exception as e:
            logger.error(
                "Failed to append event: %s", e
            )
            return False

    def _mark_alerted(self, window: dict) -> bool:
        """Set alert_sent flag on a window."""
        try:
            self.table.update_item(
                Key={
                    "pk": window["pk"],
                    "sk": window["sk"],
                },
                UpdateExpression=(
                    "SET alert_sent = :val"
                ),
                ExpressionAttributeValues={
                    ":val": True,
                },
            )
            return True
        except Exception as e:
            logger.error(
                "Failed to mark alerted: %s", e
            )
            return False

    def _event_summary(
        self, alert: DriftAlert
    ) -> dict:
        """Build a compact event summary for storage."""
        return {
            "check_id": alert.check_id,
            "resource_arn": alert.resource_arn,
            "drift_type": alert.drift_type.value,
            "severity": alert.severity.value,
            "trigger_event": alert.trigger_event,
            "timestamp": alert.timestamp,
        }
