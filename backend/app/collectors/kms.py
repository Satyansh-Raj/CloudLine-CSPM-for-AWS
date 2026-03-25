"""KMS and Secrets Manager collector."""

import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class KMSCollector(BaseCollector):
    """Collects KMS keys and Secrets Manager secrets,
    plus AWS Backup plans."""

    def collect(self) -> tuple[str, dict]:
        return (
            "kms",
            {
                "keys": self._get_kms_keys(),
            },
        )

    def collect_full(self) -> dict:
        """Returns kms, secrets_manager, and backup
        sections for the unified JSON."""
        return {
            "kms": {"keys": self._get_kms_keys()},
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
            rotation = False
            try:
                rot = kms.get_key_rotation_status(
                    KeyId=meta["KeyId"]
                )
                rotation = rot.get(
                    "KeyRotationEnabled", False
                )
            except Exception:
                pass
            return {
                "key_id": meta["KeyId"],
                "arn": meta.get("Arn", ""),
                "key_state": meta.get(
                    "KeyState", "Enabled"
                ),
                "key_rotation_enabled": rotation,
            }
        except Exception as e:
            logger.error(
                "KMS describe_key: %s", e
            )
        return {}

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
                        meta = kms.describe_key(
                            KeyId=key_id
                        )["KeyMetadata"]
                        # Skip AWS-managed keys
                        if meta.get(
                            "KeyManager"
                        ) == "AWS":
                            continue
                        rotation = False
                        try:
                            rot = (
                                kms.get_key_rotation_status(
                                    KeyId=key_id
                                )
                            )
                            rotation = rot.get(
                                "KeyRotationEnabled",
                                False,
                            )
                        except Exception:
                            pass
                        tags = {}
                        try:
                            tr = (
                                kms.list_resource_tags(
                                    KeyId=key_id
                                )
                            )
                            tags = {
                                t["TagKey"]: (
                                    t["TagValue"]
                                )
                                for t in tr.get(
                                    "Tags", []
                                )
                            }
                        except Exception:
                            pass
                        keys.append(
                            {
                                "key_id": key_id,
                                "arn": meta.get(
                                    "Arn", ""
                                ),
                                "key_state": meta.get(
                                    "KeyState",
                                    "Enabled",
                                ),
                                "key_rotation_enabled": rotation,
                                "tags": tags,
                            }
                        )
                    except Exception:
                        pass
        except Exception as e:
            logger.error(
                "KMS list_keys: %s", e
            )
        return keys

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
                    secrets.append(
                        {
                            "name": s.get(
                                "Name", ""
                            ),
                            "arn": s.get(
                                "ARN", ""
                            ),
                            "rotation_enabled": s.get(
                                "RotationEnabled",
                                False,
                            ),
                            "rotation_interval_days": (
                                s.get(
                                    "RotationRules",
                                    {},
                                ).get(
                                    "AutomaticallyAfterDays",
                                    0,
                                )
                            ),
                        }
                    )
        except Exception as e:
            logger.error(
                "SecretsManager list_secrets: %s",
                e,
            )
        return secrets

    def _get_backup_plans(self) -> list[dict]:
        plans = []
        try:
            backup = self.session.client("backup")
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
                            "BackupPlanName", ""
                        ),
                        "arn": p.get(
                            "BackupPlanArn", ""
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
            backup = self.session.client("backup")
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
                            "ResourceType", ""
                        ),
                    }
                )
        except Exception as e:
            logger.error(
                "Backup list_protected: %s", e
            )
        return resources
