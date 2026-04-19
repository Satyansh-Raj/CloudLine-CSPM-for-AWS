"""KMS and Secrets Manager collector."""

import json
import logging
from datetime import datetime, timezone

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class KMSCollector(BaseCollector):
    """Collects KMS keys, aliases, Secrets Manager
    secrets, and AWS Backup plans."""

    def collect(self) -> tuple[str, dict]:
        keys = self._get_kms_keys()
        return (
            "kms",
            {
                "keys": keys,
                "aliases": self._get_aliases(keys),
            },
        )

    def collect_full(self) -> dict:
        """Returns kms, secrets_manager, and backup
        sections for the unified JSON."""
        keys = self._get_kms_keys()
        return {
            "kms": {
                "keys": keys,
                "aliases": self._get_aliases(keys),
            },
            "secrets_manager": {
                "secrets": self._get_secrets(),
            },
            "backup": {
                "plans": self._get_backup_plans(),
                "protected_resources": (
                    self._get_protected_resources()
                ),
            },
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        kms = self.session.client("kms")
        try:
            resp = kms.describe_key(
                KeyId=resource_id
            )
            meta = resp["KeyMetadata"]
            key_id = meta["KeyId"]
            rotation = self._get_rotation(
                kms, key_id
            )
            tags = self._get_key_tags(
                kms, key_id
            )
            policy = self._get_key_policy(
                kms, key_id
            )
            grants = self._get_key_grants(
                kms, key_id
            )
            alarm = self._check_deletion_alarm(
                key_id
            )
            days_disabled = (
                self._calc_days_since_disabled(
                    meta
                )
            )
            return {
                "key_id": key_id,
                "arn": meta.get("Arn", ""),
                "key_state": meta.get(
                    "KeyState", "Enabled"
                ),
                "key_manager": meta.get(
                    "KeyManager", "AWS"
                ),
                "key_rotation_enabled": rotation,
                "tags": tags,
                "policy": policy,
                "description": meta.get(
                    "Description", ""
                ),
                "multi_region": meta.get(
                    "MultiRegion", False
                ),
                "origin": meta.get(
                    "Origin", "AWS_KMS"
                ),
                "key_spec": meta.get(
                    "KeySpec",
                    "SYMMETRIC_DEFAULT",
                ),
                "days_since_disabled": (
                    days_disabled
                ),
                "deletion_alarm_configured": (
                    alarm
                ),
                "grants": grants,
            }
        except Exception as e:
            logger.error(
                "KMS describe_key: %s", e
            )
        return {}

    # --------------------------------------------------
    # KMS key helpers
    # --------------------------------------------------

    def _get_kms_keys(self) -> list[dict]:
        keys = []
        try:
            kms = self.session.client("kms")
            paginator = kms.get_paginator(
                "list_keys"
            )
            for page in paginator.paginate():
                for k in page["Keys"]:
                    key_id = k["KeyId"]
                    try:
                        key = self._build_key(
                            kms, key_id
                        )
                        if key:
                            keys.append(key)
                    except Exception as e:
                        logger.warning(
                            "KMS key %s: %s",
                            key_id,
                            e,
                        )
        except Exception as e:
            logger.error(
                "KMS list_keys: %s", e
            )
        return keys

    def _build_key(
        self, kms, key_id: str
    ) -> dict | None:
        """Build a full key dict from AWS APIs.
        Returns None for AWS-managed keys."""
        meta = kms.describe_key(KeyId=key_id)[
            "KeyMetadata"
        ]
        key_manager = meta.get(
            "KeyManager", "AWS"
        )
        key_state = meta.get("KeyState", "Enabled")
        if key_manager == "AWS" or key_state in (
            "PendingDeletion",
            "PendingReplicaDeletion",
        ):
            return None
        rotation = self._get_rotation(
            kms, key_id
        )
        tags = self._get_key_tags(kms, key_id)
        policy = self._get_key_policy(
            kms, key_id
        )
        grants = self._get_key_grants(
            kms, key_id
        )
        alarm = self._check_deletion_alarm(
            key_id
        )
        days_disabled = (
            self._calc_days_since_disabled(meta)
        )
        return {
            "key_id": key_id,
            "arn": meta.get("Arn", ""),
            "key_state": meta.get(
                "KeyState", "Enabled"
            ),
            "key_manager": key_manager,
            "key_rotation_enabled": rotation,
            "tags": tags,
            "policy": policy,
            "description": meta.get(
                "Description", ""
            ),
            "multi_region": meta.get(
                "MultiRegion", False
            ),
            "origin": meta.get(
                "Origin", "AWS_KMS"
            ),
            "key_spec": meta.get(
                "KeySpec", "SYMMETRIC_DEFAULT"
            ),
            "days_since_disabled": (
                days_disabled
            ),
            "deletion_alarm_configured": alarm,
            "grants": grants,
        }

    def _get_rotation(
        self, kms, key_id: str
    ) -> bool:
        try:
            rot = kms.get_key_rotation_status(
                KeyId=key_id
            )
            return rot.get(
                "KeyRotationEnabled", False
            )
        except Exception:
            return False

    def _get_key_tags(
        self, kms, key_id: str
    ) -> dict:
        try:
            tr = kms.list_resource_tags(
                KeyId=key_id
            )
            return {
                t["TagKey"]: t["TagValue"]
                for t in tr.get("Tags", [])
            }
        except Exception:
            return {}

    def _get_key_policy(
        self, kms, key_id: str
    ) -> dict:
        """Fetch the default key policy and
        parse as JSON."""
        try:
            resp = kms.get_key_policy(
                KeyId=key_id,
                PolicyName="default",
            )
            raw = resp.get("Policy", "{}")
            return json.loads(raw)
        except Exception as e:
            logger.debug(
                "KMS get_key_policy %s: %s",
                key_id,
                e,
            )
            return {"Statement": []}

    def _get_key_grants(
        self, kms, key_id: str
    ) -> list[dict]:
        """List grants on a KMS key."""
        grants = []
        try:
            paginator = kms.get_paginator(
                "list_grants"
            )
            for page in paginator.paginate(
                KeyId=key_id
            ):
                for g in page.get(
                    "Grants", []
                ):
                    grants.append(
                        {
                            "grantee_principal": g.get(
                                "GranteePrincipal",
                                "",
                            ),
                            "operations": g.get(
                                "Operations",
                                [],
                            ),
                            "retiring_principal": g.get(
                                "RetiringPrincipal",
                                None,
                            ),
                        }
                    )
        except Exception as e:
            logger.debug(
                "KMS list_grants %s: %s",
                key_id,
                e,
            )
        return grants

    def _calc_days_since_disabled(
        self, meta: dict
    ) -> int:
        """Compute days since key was disabled.
        Returns 0 for non-disabled keys."""
        if meta.get("KeyState") != "Disabled":
            return 0
        # DeletionDate may be set if scheduled
        # for deletion; otherwise use Enabled
        # flag change (not directly available,
        # so fall back to creation date heuristic)
        now = datetime.now(timezone.utc)
        deletion_date = meta.get("DeletionDate")
        if deletion_date:
            if (
                not hasattr(
                    deletion_date, "tzinfo"
                )
                or deletion_date.tzinfo is None
            ):
                deletion_date = (
                    deletion_date.replace(
                        tzinfo=timezone.utc
                    )
                )
            delta = now - deletion_date
            return max(0, delta.days)
        # Fallback: no exact disable timestamp
        # available from the API; return 0 to
        # avoid false positives
        return 0

    def _check_deletion_alarm(
        self, key_id: str
    ) -> bool:
        """Check if a CloudWatch alarm exists
        for KMS deletion/disable events for
        this key."""
        try:
            cw = self.session.client(
                "cloudwatch"
            )
            resp = cw.describe_alarms(
                AlarmNamePrefix="kms-"
            )
            for alarm in resp.get(
                "MetricAlarms", []
            ):
                desc = alarm.get(
                    "AlarmDescription", ""
                )
                name = alarm.get(
                    "AlarmName", ""
                )
                if key_id in desc or (
                    key_id in name
                ):
                    return True
            return False
        except Exception as e:
            logger.debug(
                "CloudWatch alarm check "
                "for %s: %s",
                key_id,
                e,
            )
            return False

    # --------------------------------------------------
    # KMS aliases
    # --------------------------------------------------

    def _get_aliases(
        self, keys: list[dict]
    ) -> list[dict]:
        """Fetch all KMS aliases and enrich
        with key_manager from collected keys."""
        aliases = []
        key_manager_map = {
            k["key_id"]: k["key_manager"]
            for k in keys
        }
        try:
            kms = self.session.client("kms")
            paginator = kms.get_paginator(
                "list_aliases"
            )
            for page in paginator.paginate():
                for a in page.get(
                    "Aliases", []
                ):
                    target = a.get(
                        "TargetKeyId", ""
                    )
                    aliases.append(
                        {
                            "alias_name": a.get(
                                "AliasName",
                                "",
                            ),
                            "alias_arn": a.get(
                                "AliasArn",
                                "",
                            ),
                            "target_key_id": (
                                target
                            ),
                            "key_manager": (
                                key_manager_map.get(
                                    target,
                                    "AWS",
                                )
                            ),
                        }
                    )
        except Exception as e:
            logger.error(
                "KMS list_aliases: %s", e
            )
        return aliases

    # --------------------------------------------------
    # Secrets Manager helpers
    # --------------------------------------------------

    def _get_secrets(self) -> list[dict]:
        secrets = []
        try:
            sm = self.session.client(
                "secretsmanager"
            )
            paginator = sm.get_paginator(
                "list_secrets"
            )
            for page in paginator.paginate():
                for s in page["SecretList"]:
                    secret = (
                        self._build_secret(
                            sm, s
                        )
                    )
                    secrets.append(secret)
        except Exception as e:
            logger.error(
                "SecretsManager "
                "list_secrets: %s",
                e,
            )
        return secrets

    def _build_secret(
        self, sm, listing: dict
    ) -> dict:
        """Build a full secret dict by calling
        describe_secret and get_resource_policy
        for complete detail."""
        arn = listing.get("ARN", "")
        name = listing.get("Name", "")

        # Start with list_secrets data
        detail = self._describe_secret(
            sm, arn
        )

        rotation_rules_raw = detail.get(
            "RotationRules", {}
        )
        auto_days = rotation_rules_raw.get(
            "AutomaticallyAfterDays", 0
        )

        tags_list = detail.get("Tags", [])
        tags = {
            t["Key"]: t["Value"]
            for t in tags_list
        }

        resource_policy = (
            self._get_secret_policy(sm, arn)
        )

        last_accessed = detail.get(
            "LastAccessedDate"
        )
        days_since = (
            self._calc_days_since_accessed(
                last_accessed
            )
        )

        deleted_raw = detail.get("DeletedDate")
        deleted_date = (
            deleted_raw.isoformat()
            if deleted_raw
            else None
        )

        rotation_lambda = detail.get(
            "RotationLambdaARN", ""
        )
        fn_exists = (
            self._check_lambda_exists(
                rotation_lambda
            )
        )

        replication = detail.get(
            "ReplicationStatus", []
        )
        repl_out = [
            {
                "region": r.get("Region", ""),
                "status": r.get(
                    "Status", ""
                ),
            }
            for r in replication
        ]

        return {
            "name": name,
            "arn": arn,
            "rotation_enabled": detail.get(
                "RotationEnabled", False
            ),
            "rotation_rules": {
                "automatically_after_days": (
                    auto_days
                ),
            },
            "resource_policy": resource_policy,
            "kms_key_id": detail.get(
                "KmsKeyId", ""
            ),
            "tags": tags,
            "days_since_last_accessed": (
                days_since
            ),
            "deleted_date": deleted_date,
            "description": detail.get(
                "Description", ""
            ),
            "rotation_lambda_arn": (
                rotation_lambda
            ),
            "rotation_function_exists": (
                fn_exists
            ),
            "replication_status": repl_out,
        }

    def _describe_secret(
        self, sm, arn: str
    ) -> dict:
        """Call describe_secret for full detail
        on a single secret."""
        try:
            return sm.describe_secret(
                SecretId=arn
            )
        except Exception as e:
            logger.warning(
                "SecretsManager "
                "describe_secret %s: %s",
                arn,
                e,
            )
            return {}

    def _get_secret_policy(
        self, sm, arn: str
    ) -> dict:
        """Fetch the resource-based policy for
        a secret and parse as JSON."""
        try:
            resp = sm.get_resource_policy(
                SecretId=arn
            )
            raw = resp.get(
                "ResourcePolicy", ""
            )
            if not raw:
                return {"Statement": []}
            return json.loads(raw)
        except Exception as e:
            logger.debug(
                "SecretsManager "
                "get_resource_policy %s: %s",
                arn,
                e,
            )
            return {"Statement": []}

    def _calc_days_since_accessed(
        self, last_accessed
    ) -> int:
        """Compute days since a secret was last
        accessed. Returns 0 if unknown."""
        if not last_accessed:
            return 0
        try:
            now = datetime.now(timezone.utc)
            if not hasattr(
                last_accessed, "tzinfo"
            ) or last_accessed.tzinfo is None:
                last_accessed = (
                    last_accessed.replace(
                        tzinfo=timezone.utc
                    )
                )
            delta = now - last_accessed
            return max(0, delta.days)
        except Exception:
            return 0

    def _check_lambda_exists(
        self, lambda_arn: str
    ) -> bool:
        """Verify that a rotation Lambda
        function actually exists."""
        if not lambda_arn:
            return False
        try:
            lam = self.session.client("lambda")
            lam.get_function(
                FunctionName=lambda_arn
            )
            return True
        except Exception:
            return False

    # --------------------------------------------------
    # AWS Backup helpers
    # --------------------------------------------------

    def _get_backup_plans(self) -> list[dict]:
        plans = []
        try:
            backup = self.session.client(
                "backup"
            )
            resp = backup.list_backup_plans()
            for p in resp.get(
                "BackupPlansList", []
            ):
                plans.append(
                    {
                        "plan_id": p.get(
                            "BackupPlanId", ""
                        ),
                        "plan_name": p.get(
                            "BackupPlanName",
                            "",
                        ),
                        "arn": p.get(
                            "BackupPlanArn",
                            "",
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "Backup list_plans: %s", e
            )
        return plans

    def _get_protected_resources(
        self,
    ) -> list[dict]:
        resources = []
        try:
            backup = self.session.client(
                "backup"
            )
            resp = (
                backup.list_protected_resources()
            )
            for r in resp.get("Results", []):
                resources.append(
                    {
                        "resource_arn": r.get(
                            "ResourceArn", ""
                        ),
                        "resource_type": r.get(
                            "ResourceType",
                            "",
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "Backup list_protected: %s", e
            )
        return resources
