"""Logging services collector (CloudTrail, Config,
CloudWatch, GuardDuty).

The collect_full() method returns separate top-level
keys so that OPA/Rego policies can reference
input.cloudtrail, input.cloudwatch, input.aws_config,
and input.guardduty directly.
"""

import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class LoggingCollector(BaseCollector):
    """Collects CloudTrail trails, AWS Config recorders,
    CloudWatch alarms/log groups, and GuardDuty
    detectors."""

    # --------------------------------------------------
    # Legacy interface (backward-compatible)
    # --------------------------------------------------

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

    # --------------------------------------------------
    # New interface — separate top-level keys
    # --------------------------------------------------

    def collect_full(self) -> dict:
        """Returns cloudtrail, cloudwatch, aws_config,
        and guardduty as separate top-level keys for
        OPA/Rego policy consumption."""
        return {
            "cloudtrail": {
                "trails": (
                    self._get_cloudtrail_trails()
                ),
            },
            "cloudwatch": {
                "alarms": (
                    self._get_cloudwatch_alarms()
                ),
                "log_groups": (
                    self._get_cloudwatch_log_groups()
                ),
            },
            "aws_config": {
                "recorders": (
                    self._get_config_recorders()
                ),
                "recorder_statuses": (
                    self._get_config_recorder_statuses()
                ),
                "delivery_channels": (
                    self._get_config_delivery_channels()
                ),
                "rules": (
                    self._get_config_rules()
                ),
                "aggregators": (
                    self._get_config_aggregators()
                ),
                "conformance_packs": (
                    self._get_config_conformance_packs()
                ),
            },
            "guardduty": {
                "detectors": (
                    self._get_guardduty_detectors()
                ),
            },
        }

    # --------------------------------------------------
    # CloudTrail helpers
    # --------------------------------------------------

    def _get_cloudtrail_trails(
        self,
    ) -> list[dict]:
        trails = []
        try:
            ct = self.session.client("cloudtrail")
            s3_client = self.session.client("s3")
            resp = ct.describe_trails()
            for t in resp.get("trailList", []):
                name = t.get("Name", "")
                trail_arn = t.get("TrailARN", "")
                is_logging = False
                try:
                    status = ct.get_trail_status(
                        Name=trail_arn or name,
                    )
                    is_logging = status.get(
                        "IsLogging", False
                    )
                except Exception:
                    pass

                event_selectors = (
                    self._get_event_selectors(
                        ct, trail_arn or name
                    )
                )
                insight_selectors = (
                    self._get_insight_selectors(
                        ct, trail_arn or name
                    )
                )

                bucket = t.get("S3BucketName", "")
                s3_public = (
                    self._check_s3_public_access(
                        s3_client, bucket
                    )
                )
                mfa_delete = (
                    self._check_s3_mfa_delete(
                        s3_client, bucket
                    )
                )

                cw_log_group_arn = t.get(
                    "CloudWatchLogsLogGroupArn"
                )
                retention = (
                    self._get_trail_log_retention(
                        cw_log_group_arn
                    )
                )

                trails.append(
                    {
                        "name": name,
                        "trail_arn": trail_arn,
                        "is_logging": is_logging,
                        "is_multi_region_trail": t.get(
                            "IsMultiRegionTrail",
                            False,
                        ),
                        "log_file_validation_enabled": (
                            t.get(
                                "LogFileValidation"
                                "Enabled",
                                False,
                            )
                        ),
                        "s3_bucket_name": bucket,
                        "kms_key_id": t.get(
                            "KmsKeyId"
                        ),
                        "cloud_watch_logs_log_group_arn": (
                            cw_log_group_arn
                        ),
                        "sns_topic_arn": t.get(
                            "SnsTopicARN"
                        ),
                        "s3_bucket_public_access": (
                            s3_public
                        ),
                        "s3_bucket_mfa_delete_enabled": (
                            mfa_delete
                        ),
                        "event_selectors": (
                            event_selectors
                        ),
                        "insight_selectors": (
                            insight_selectors
                        ),
                        "include_global_service_events": (
                            t.get(
                                "IncludeGlobal"
                                "ServiceEvents",
                                True,
                            )
                        ),
                        "log_retention_days": (
                            retention
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "CloudTrail describe_trails: %s", e
            )
        return trails

    def _get_event_selectors(
        self, client, trail_name: str
    ) -> list[dict]:
        """Fetch event selectors for a trail."""
        selectors = []
        try:
            resp = client.get_event_selectors(
                TrailName=trail_name,
            )
            for es in resp.get(
                "EventSelectors", []
            ):
                data_resources = []
                for dr in es.get(
                    "DataResources", []
                ):
                    data_resources.append(
                        {
                            "type": dr.get(
                                "Type", ""
                            ),
                            "values": dr.get(
                                "Values", []
                            ),
                        }
                    )
                selectors.append(
                    {
                        "read_write_type": es.get(
                            "ReadWriteType", "All"
                        ),
                        "include_management_events": (
                            es.get(
                                "IncludeManagement"
                                "Events",
                                True,
                            )
                        ),
                        "data_resources": (
                            data_resources
                        ),
                    }
                )
        except Exception as e:
            logger.debug(
                "get_event_selectors %s: %s",
                trail_name,
                e,
            )
        return selectors

    def _get_insight_selectors(
        self, client, trail_name: str
    ) -> list[dict]:
        """Fetch insight selectors for a trail."""
        selectors = []
        try:
            resp = client.get_insight_selectors(
                TrailName=trail_name,
            )
            for ins in resp.get(
                "InsightSelectors", []
            ):
                selectors.append(
                    {
                        "insight_type": ins.get(
                            "InsightType", ""
                        ),
                    }
                )
        except Exception as e:
            # Insight selectors may not be enabled
            logger.debug(
                "get_insight_selectors %s: %s",
                trail_name,
                e,
            )
        return selectors

    def _check_s3_public_access(
        self, s3_client, bucket: str
    ) -> bool:
        """Check if an S3 bucket is publicly
        accessible."""
        if not bucket:
            return False
        try:
            resp = (
                s3_client
                .get_public_access_block(
                    Bucket=bucket,
                )
            )
            cfg = resp.get(
                "PublicAccessBlockConfiguration", {}
            )
            all_blocked = (
                cfg.get(
                    "BlockPublicAcls", False
                )
                and cfg.get(
                    "IgnorePublicAcls", False
                )
                and cfg.get(
                    "BlockPublicPolicy", False
                )
                and cfg.get(
                    "RestrictPublicBuckets", False
                )
            )
            return not all_blocked
        except Exception:
            # If we can't check, assume not public
            return False

    def _check_s3_mfa_delete(
        self, s3_client, bucket: str
    ) -> bool:
        """Check if MFA Delete is enabled on bucket
        versioning."""
        if not bucket:
            return False
        try:
            resp = s3_client.get_bucket_versioning(
                Bucket=bucket,
            )
            return (
                resp.get("MFADelete", "Disabled")
                == "Enabled"
            )
        except Exception:
            return False

    def _get_trail_log_retention(
        self, cw_log_group_arn: str | None
    ) -> int:
        """Get log retention days from the CloudWatch
        log group associated with a trail.

        Returns 0 when no log group is configured or
        when the retention is set to never expire."""
        if not cw_log_group_arn:
            return 0
        try:
            # ARN format:
            # arn:aws:logs:region:acct:log-group:NAME:*
            parts = cw_log_group_arn.split(":")
            lg_name = parts[6] if len(parts) > 6 else ""
            if not lg_name:
                return 0
            cw_logs = self.session.client("logs")
            resp = cw_logs.describe_log_groups(
                logGroupNamePrefix=lg_name,
            )
            for lg in resp.get("logGroups", []):
                if lg.get("logGroupName") == lg_name:
                    return lg.get(
                        "retentionInDays", 0
                    )
        except Exception as e:
            logger.debug(
                "Log retention lookup: %s", e
            )
        return 0

    # --------------------------------------------------
    # CloudWatch helpers
    # --------------------------------------------------

    def _get_cloudwatch_alarms(
        self,
    ) -> list[dict]:
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
                            "alarm_arn": a.get(
                                "AlarmArn", ""
                            ),
                            "metric_name": a.get(
                                "MetricName", ""
                            ),
                            "state_value": a.get(
                                "StateValue", "OK"
                            ),
                            "alarm_actions": a.get(
                                "AlarmActions", []
                            ),
                        }
                    )
        except Exception as e:
            logger.error(
                "CloudWatch describe_alarms: %s", e
            )
        return alarms

    def _get_cloudwatch_log_groups(
        self,
    ) -> list[dict]:
        """Fetch CloudWatch Log Groups with retention,
        KMS, and tags."""
        log_groups = []
        try:
            client = self.session.client("logs")
            paginator = client.get_paginator(
                "describe_log_groups"
            )
            for page in paginator.paginate():
                for lg in page.get(
                    "logGroups", []
                ):
                    lg_name = lg.get(
                        "logGroupName", ""
                    )
                    tags = self._get_log_group_tags(
                        client, lg_name
                    )
                    log_groups.append(
                        {
                            "log_group_name": (
                                lg_name
                            ),
                            "arn": lg.get("arn", ""),
                            "retention_in_days": (
                                lg.get(
                                    "retentionInDays"
                                )
                            ),
                            "kms_key_id": lg.get(
                                "kmsKeyId"
                            ),
                            "tags": tags,
                        }
                    )
        except Exception as e:
            logger.error(
                "CloudWatch describe_log_groups: %s",
                e,
            )
        return log_groups

    def _get_log_group_tags(
        self, client, log_group_name: str
    ) -> dict:
        """Return tags for a log group."""
        try:
            resp = client.list_tags_log_group(
                logGroupName=log_group_name,
            )
            return resp.get("tags", {})
        except Exception:
            return {}

    # --------------------------------------------------
    # AWS Config helpers
    # --------------------------------------------------

    def _get_config_recorders(
        self,
    ) -> list[dict]:
        recorders = []
        try:
            client = self.session.client("config")
            resp = (
                client
                .describe_configuration_recorders()
            )
            for r in resp.get(
                "ConfigurationRecorders", []
            ):
                group = r.get(
                    "recordingGroup", {}
                )
                recorders.append(
                    {
                        "name": r.get("name", ""),
                        "recording_group": {
                            "all_supported": (
                                group.get(
                                    "allSupported",
                                    False,
                                )
                            ),
                            "include_global_resource_types": (
                                group.get(
                                    "includeGlobal"
                                    "ResourceTypes",
                                    False,
                                )
                            ),
                        },
                    }
                )
        except Exception as e:
            logger.error(
                "Config describe_recorders: %s", e
            )
        return recorders

    def _get_config_recorder_statuses(
        self,
    ) -> list[dict]:
        """Fetch recording status for each Config
        recorder."""
        statuses = []
        try:
            client = self.session.client("config")
            resp = (
                client
                .describe_configuration_recorder_status()
            )
            for s in resp.get(
                "ConfigurationRecordersStatus", []
            ):
                statuses.append(
                    {
                        "name": s.get("name", ""),
                        "recording": s.get(
                            "recording", False
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "Config recorder_status: %s", e
            )
        return statuses

    def _get_config_delivery_channels(
        self,
    ) -> list[dict]:
        """Fetch Config delivery channels with S3
        public-access check."""
        channels = []
        try:
            client = self.session.client("config")
            s3_client = self.session.client("s3")
            resp = (
                client
                .describe_delivery_channels()
            )
            for ch in resp.get(
                "DeliveryChannels", []
            ):
                bucket = ch.get(
                    "s3BucketName", ""
                )
                s3_public = (
                    self._check_s3_public_access(
                        s3_client, bucket
                    )
                )
                snapshot_props = ch.get(
                    "configSnapshotDelivery"
                    "Properties",
                    {},
                )
                channels.append(
                    {
                        "name": ch.get(
                            "name", ""
                        ),
                        "s3_bucket_name": bucket,
                        "s3_bucket_public_access": (
                            s3_public
                        ),
                        "sns_topic_arn": ch.get(
                            "snsTopicARN"
                        ),
                        "config_snapshot_delivery_properties": {
                            "delivery_frequency": (
                                snapshot_props.get(
                                    "deliveryFrequency",
                                    "",
                                )
                            ),
                        },
                    }
                )
        except Exception as e:
            logger.error(
                "Config delivery_channels: %s", e
            )
        return channels

    def _get_config_rules(self) -> list[dict]:
        """Fetch Config rules with compliance and
        remediation status."""
        rules = []
        try:
            client = self.session.client("config")
            paginator = client.get_paginator(
                "describe_config_rules"
            )
            compliance_map = (
                self._get_config_compliance_map(
                    client
                )
            )
            remediation_map = (
                self._get_config_remediation_map(
                    client
                )
            )
            for page in paginator.paginate():
                for r in page.get(
                    "ConfigRules", []
                ):
                    rule_name = r.get(
                        "ConfigRuleName", ""
                    )
                    rules.append(
                        {
                            "config_rule_name": (
                                rule_name
                            ),
                            "config_rule_arn": (
                                r.get(
                                    "ConfigRuleArn",
                                    "",
                                )
                            ),
                            "config_rule_state": (
                                r.get(
                                    "ConfigRuleState",
                                    "ACTIVE",
                                )
                            ),
                            "compliance_type": (
                                compliance_map.get(
                                    rule_name,
                                    "NOT_DETERMINED",
                                )
                            ),
                            "remediation_configuration": (
                                remediation_map.get(
                                    rule_name
                                )
                            ),
                        }
                    )
        except Exception as e:
            logger.error(
                "Config describe_rules: %s", e
            )
        return rules

    def _get_config_compliance_map(
        self, client
    ) -> dict:
        """Build rule-name -> compliance_type map."""
        cmap: dict[str, str] = {}
        try:
            resp = (
                client
                .describe_compliance_by_config_rule()
            )
            for item in resp.get(
                "ComplianceByConfigRules", []
            ):
                name = item.get(
                    "ConfigRuleName", ""
                )
                comp = item.get("Compliance", {})
                cmap[name] = comp.get(
                    "ComplianceType",
                    "NOT_DETERMINED",
                )
        except Exception as e:
            logger.debug(
                "Config compliance map: %s", e
            )
        return cmap

    def _get_config_remediation_map(
        self, client
    ) -> dict:
        """Build rule-name -> remediation config map."""
        rmap: dict[str, dict | None] = {}
        try:
            resp = (
                client
                .describe_remediation_configurations(
                    ConfigRuleNames=[]
                )
            )
            for rc in resp.get(
                "RemediationConfigurations", []
            ):
                name = rc.get(
                    "ConfigRuleName", ""
                )
                rmap[name] = {
                    "target_id": rc.get(
                        "TargetId", ""
                    ),
                    "target_type": rc.get(
                        "TargetType", ""
                    ),
                }
        except Exception:
            pass
        return rmap

    def _get_config_aggregators(
        self,
    ) -> list[dict]:
        """Fetch Config aggregators."""
        aggregators = []
        try:
            client = self.session.client("config")
            resp = (
                client
                .describe_configuration_aggregators()
            )
            for agg in resp.get(
                "ConfigurationAggregators", []
            ):
                aggregators.append(
                    {
                        "name": agg.get(
                            "ConfigurationAggregator"
                            "Name",
                            "",
                        ),
                        "arn": agg.get(
                            "ConfigurationAggregator"
                            "Arn",
                            "",
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "Config aggregators: %s", e
            )
        return aggregators

    def _get_config_conformance_packs(
        self,
    ) -> list[dict]:
        """Fetch Config conformance packs."""
        packs = []
        try:
            client = self.session.client("config")
            resp = (
                client
                .describe_conformance_packs()
            )
            for cp in resp.get(
                "ConformancePackDetails", []
            ):
                packs.append(
                    {
                        "name": cp.get(
                            "ConformancePackName",
                            "",
                        ),
                        "arn": cp.get(
                            "ConformancePackArn",
                            "",
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "Config conformance_packs: %s", e
            )
        return packs

    # --------------------------------------------------
    # GuardDuty helpers
    # --------------------------------------------------

    def _get_guardduty_detectors(
        self,
    ) -> list[dict]:
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
                data_sources = (
                    self._parse_gd_data_sources(
                        detail
                    )
                )
                features = (
                    self._parse_gd_features(detail)
                )
                filters = (
                    self._get_gd_filters(
                        client, did
                    )
                )
                sns_arn = (
                    self._get_gd_sns_arn(did)
                )
                detectors.append(
                    {
                        "detector_id": did,
                        "status": detail.get(
                            "Status", "DISABLED"
                        ),
                        "finding_publishing_frequency": (
                            detail.get(
                                "FindingPublishing"
                                "Frequency",
                                "SIX_HOURS",
                            )
                        ),
                        "data_sources": (
                            data_sources
                        ),
                        "features": features,
                        "filters": filters,
                        "high_severity_sns_arn": (
                            sns_arn
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "GuardDuty list_detectors: %s", e
            )
        return detectors

    def _parse_gd_data_sources(
        self, detail: dict
    ) -> dict:
        """Extract data_sources from GuardDuty
        detector detail."""
        ds = detail.get("DataSources", {})
        s3_logs = ds.get("S3Logs", {})
        return {
            "s3_logs": {
                "status": s3_logs.get(
                    "Status", "DISABLED"
                ),
            },
        }

    def _parse_gd_features(
        self, detail: dict
    ) -> dict:
        """Extract features from GuardDuty detector
        detail."""
        features_list = detail.get(
            "Features", []
        )
        malware_status = "DISABLED"
        for f in features_list:
            if f.get("Name") == "EBS_MALWARE_PROTECTION":
                malware_status = f.get(
                    "Status", "DISABLED"
                )
                break
        return {
            "malware_protection": {
                "status": malware_status,
            },
        }

    def _get_gd_filters(
        self, client, detector_id: str
    ) -> list[dict]:
        """Fetch GuardDuty filters (suppression rules)
        for a detector."""
        filters = []
        try:
            resp = client.list_filters(
                DetectorId=detector_id,
            )
            for name in resp.get(
                "FilterNames", []
            ):
                try:
                    f = client.get_filter(
                        DetectorId=detector_id,
                        FilterName=name,
                    )
                    sev_threshold = (
                        self._extract_gd_severity(
                            f.get(
                                "FindingCriteria",
                                {},
                            )
                        )
                    )
                    filters.append(
                        {
                            "name": f.get(
                                "Name", name
                            ),
                            "action": f.get(
                                "Action",
                                "NOOP",
                            ),
                            "severity_threshold": (
                                sev_threshold
                            ),
                        }
                    )
                except Exception:
                    pass
        except Exception as e:
            logger.debug(
                "GuardDuty list_filters: %s", e
            )
        return filters

    def _extract_gd_severity(
        self, criteria: dict
    ) -> int:
        """Extract severity threshold from
        FindingCriteria."""
        criterion = criteria.get(
            "Criterion", {}
        )
        sev = criterion.get(
            "severity", {}
        )
        # LessThanOrEqual is the common filter form
        return sev.get(
            "LessThanOrEqual",
            sev.get("Eq", [10])[0]
            if isinstance(sev.get("Eq"), list)
            else sev.get("Eq", 10),
        )

    def _get_gd_sns_arn(
        self, detector_id: str
    ) -> str | None:
        """Check EventBridge rules for an SNS target
        tied to GuardDuty high-severity findings.

        Returns the SNS topic ARN if found, else
        None."""
        try:
            eb = self.session.client("events")
            resp = eb.list_rules(
                NamePrefix="guardduty",
            )
            for rule in resp.get("Rules", []):
                targets = eb.list_targets_by_rule(
                    Rule=rule["Name"],
                )
                for tgt in targets.get(
                    "Targets", []
                ):
                    arn = tgt.get("Arn", "")
                    if ":sns:" in arn:
                        return arn
        except Exception:
            pass
        return None
