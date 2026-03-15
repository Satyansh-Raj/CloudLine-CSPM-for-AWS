"""Logging services collector (CloudTrail, Config,
CloudWatch, GuardDuty)."""

import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class LoggingCollector(BaseCollector):
    """Collects CloudTrail trails, AWS Config recorders,
    CloudWatch alarms, and GuardDuty detectors."""

    def collect(self) -> tuple[str, dict]:
        return "logging", {
            "cloudtrail_trails": (
                self._get_cloudtrail_trails()
            ),
            "config_recorders": (
                self._get_config_recorders()
            ),
            "cloudwatch_alarms": (
                self._get_cloudwatch_alarms()
            ),
            "guardduty_detectors": (
                self._get_guardduty_detectors()
            ),
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        # For logging, resource_id is the trail
        # name or detector id
        trails = self._get_cloudtrail_trails()
        for t in trails:
            if t["name"] == resource_id:
                return t
        return {}

    def _get_cloudtrail_trails(self) -> list[dict]:
        trails = []
        try:
            client = self.session.client(
                "cloudtrail"
            )
            resp = client.describe_trails()
            for t in resp.get("trailList", []):
                name = t.get("Name", "")
                is_logging = False
                log_validation = t.get(
                    "LogFileValidationEnabled",
                    False,
                )
                try:
                    status = (
                        client.get_trail_status(
                            Name=t.get(
                                "TrailARN",
                                name,
                            )
                        )
                    )
                    is_logging = status.get(
                        "IsLogging", False
                    )
                except Exception:
                    pass
                trails.append(
                    {
                        "name": name,
                        "arn": t.get(
                            "TrailARN", ""
                        ),
                        "is_multi_region": t.get(
                            "IsMultiRegionTrail",
                            False,
                        ),
                        "is_logging": is_logging,
                        "log_file_validation": (
                            log_validation
                        ),
                        "s3_bucket_name": t.get(
                            "S3BucketName", ""
                        ),
                        "kms_key_id": t.get(
                            "KmsKeyId"
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "CloudTrail describe_trails: %s", e
            )
        return trails

    def _get_config_recorders(self) -> list[dict]:
        recorders = []
        try:
            client = self.session.client("config")
            resp = (
                client.describe_configuration_recorders()
            )
            statuses = (
                client.describe_configuration_recorder_status()
            )
            status_map = {
                s["name"]: s.get(
                    "recording", False
                )
                for s in statuses.get(
                    "ConfigurationRecordersStatus",
                    [],
                )
            }
            for r in resp.get(
                "ConfigurationRecorders", []
            ):
                name = r.get("name", "")
                group = r.get(
                    "recordingGroup", {}
                )
                recorders.append(
                    {
                        "name": name,
                        "recording": status_map.get(
                            name, False
                        ),
                        "all_supported": group.get(
                            "allSupported", False
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "Config describe_recorders: %s", e
            )
        return recorders

    def _get_cloudwatch_alarms(self) -> list[dict]:
        alarms = []
        try:
            client = self.session.client(
                "cloudwatch"
            )
            paginator = client.get_paginator(
                "describe_alarms"
            )
            for page in paginator.paginate():
                for a in page.get(
                    "MetricAlarms", []
                ):
                    alarms.append(
                        {
                            "alarm_name": a[
                                "AlarmName"
                            ],
                            "metric_name": a.get(
                                "MetricName", ""
                            ),
                            "state": a.get(
                                "StateValue",
                                "OK",
                            ),
                        }
                    )
        except Exception as e:
            logger.error(
                "CloudWatch describe_alarms: %s", e
            )
        return alarms

    def _get_guardduty_detectors(self) -> list[dict]:
        detectors = []
        try:
            client = self.session.client(
                "guardduty"
            )
            resp = client.list_detectors()
            for did in resp.get(
                "DetectorIds", []
            ):
                detail = client.get_detector(
                    DetectorId=did
                )
                detectors.append(
                    {
                        "detector_id": did,
                        "status": detail.get(
                            "Status", "DISABLED"
                        ),
                        "finding_publishing_frequency": detail.get(
                            "FindingPublishingFrequency",
                            "SIX_HOURS",
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "GuardDuty list_detectors: %s", e
            )
        return detectors
