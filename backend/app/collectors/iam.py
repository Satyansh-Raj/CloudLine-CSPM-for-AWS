"""IAM service collector."""

import logging
from datetime import datetime, timezone

from botocore.config import Config

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)

_IAM_CONFIG = Config(
    retries={
        "max_attempts": 5,
        "mode": "adaptive",
    }
)


def summarize_permissions(
    policy_docs: list[dict],
) -> dict[str, list[str]]:
    """Parse policy documents into effective permissions.

    Returns:
        Dict of {service: [actions]}.
        {"*": ["*"]} means full admin access.
        {"s3": ["*"]} means full S3 access.
    """
    perms: dict[str, list[str]] = {}
    for doc in policy_docs:
        if not doc:
            continue
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                if action == "*":
                    return {"*": ["*"]}
                if ":" not in action:
                    continue
                svc, act = action.split(":", 1)
                svc = svc.lower()
                if svc not in perms:
                    perms[svc] = []
                if act == "*":
                    perms[svc] = ["*"]
                elif perms[svc] != ["*"]:
                    if act not in perms[svc]:
                        perms[svc].append(act)
    return perms


def summarize_resources(
    policy_docs: list[dict],
) -> dict[str, list[str]]:
    """Extract resource ARNs/names per service.

    Returns:
        Dict of {service: [resource_arns]}.
        {"*": ["*"]} means all resources.
    """
    resources: dict[str, list[str]] = {}
    for doc in policy_docs:
        if not doc:
            continue
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            if stmt.get("Effect") != "Allow":
                continue
            res = stmt.get("Resource", [])
            if isinstance(res, str):
                res = [res]
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            # Determine services from actions
            svcs = set()
            for action in actions:
                if action == "*":
                    svcs.add("*")
                elif ":" in action:
                    svcs.add(
                        action.split(":", 1)[0].lower()
                    )
            for r in res:
                if r == "*":
                    for s in svcs:
                        resources.setdefault(
                            s, []
                        )
                        if "*" not in resources[s]:
                            resources[s].append("*")
                    continue
                # Parse ARN to get resource name
                # arn:aws:s3:::bucket-name/*
                parts = r.split(":")
                if len(parts) >= 6:
                    svc = parts[2].lower()
                    res_name = ":".join(parts[5:])
                    if res_name:
                        resources.setdefault(
                            svc, []
                        )
                        if (
                            res_name
                            not in resources[svc]
                        ):
                            resources[svc].append(
                                res_name
                            )
    return resources


class IAMCollector(BaseCollector):
    """Collects IAM account summary, password policy,
    users with access keys/MFA, and Access Analyzer."""

    def collect(self) -> tuple[str, dict]:
        client = self.session.client(
            "iam", config=_IAM_CONFIG
        )
        return "iam", {
            "account_summary": self._get_account_summary(
                client
            ),
            "password_policy": self._get_password_policy(
                client
            ),
            "users": self._get_users(client),
            "access_analyzer": self._get_access_analyzer(),
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        client = self.session.client(
            "iam", config=_IAM_CONFIG
        )
        try:
            user = client.get_user(UserName=resource_id)
            return self._build_user_dict(
                client, user["User"]
            )
        except client.exceptions.NoSuchEntityException:
            return {}

    def _get_account_summary(self, client) -> dict:
        try:
            summary = client.get_account_summary()
            s = summary["SummaryMap"]
            return {
                "mfa_enabled": s.get(
                    "AccountMFAEnabled", 0
                )
                == 1,
                "users": s.get("Users", 0),
                "access_keys_active": s.get(
                    "AccessKeysActive", 0
                ),
            }
        except Exception:
            return {
                "mfa_enabled": False,
                "users": 0,
                "access_keys_active": 0,
            }

    def _get_password_policy(self, client) -> dict:
        try:
            pp = client.get_account_password_policy()
            policy = pp["PasswordPolicy"]
            return {
                "minimum_length": policy.get(
                    "MinimumPasswordLength", 8
                ),
                "require_symbols": policy.get(
                    "RequireSymbols", False
                ),
                "require_numbers": policy.get(
                    "RequireNumbers", False
                ),
                "require_uppercase": policy.get(
                    "RequireUppercaseCharacters", False
                ),
                "require_lowercase": policy.get(
                    "RequireLowercaseCharacters", False
                ),
                "max_age_days": policy.get(
                    "MaxPasswordAge", 0
                ),
                "password_reuse_prevention": policy.get(
                    "PasswordReusePrevention", 0
                ),
                "hard_expiry": policy.get(
                    "HardExpiry", False
                ),
            }
        except client.exceptions.NoSuchEntityException:
            return {
                "minimum_length": 8,
                "require_symbols": False,
                "require_numbers": False,
                "require_uppercase": False,
                "require_lowercase": False,
                "max_age_days": 0,
                "password_reuse_prevention": 0,
                "hard_expiry": False,
            }

    def _get_users(self, client) -> list[dict]:
        users = []
        paginator = client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                users.append(
                    self._build_user_dict(client, user)
                )
        return users

    def _build_user_dict(
        self, client, user: dict
    ) -> dict:
        username = user["UserName"]
        arn = user["Arn"]

        # MFA devices
        mfa_devices = client.list_mfa_devices(
            UserName=username
        )
        mfa_enabled = (
            len(mfa_devices["MFADevices"]) > 0
        )

        # Access keys
        keys = client.list_access_keys(
            UserName=username
        )
        access_keys = []
        for k in keys["AccessKeyMetadata"]:
            last_used_days = None
            try:
                lu = client.get_access_key_last_used(
                    AccessKeyId=k["AccessKeyId"]
                )
                last_used = lu.get(
                    "AccessKeyLastUsed", {}
                ).get("LastUsedDate")
                if last_used:
                    delta = (
                        datetime.now(timezone.utc)
                        - last_used
                    )
                    last_used_days = delta.days
            except Exception:
                pass
            access_keys.append(
                {
                    "key_id": k["AccessKeyId"],
                    "status": k["Status"],
                    "created_date": k[
                        "CreateDate"
                    ].isoformat(),
                    "last_used_days_ago": last_used_days,
                }
            )

        # Attached policies
        attached = client.list_attached_user_policies(
            UserName=username
        )
        policies = [
            {
                "policy_name": p["PolicyName"],
                "policy_arn": p["PolicyArn"],
            }
            for p in attached["AttachedPolicies"]
        ]

        # Last activity
        last_activity_days = None
        pwd_last_used = user.get("PasswordLastUsed")
        if pwd_last_used:
            delta = (
                datetime.now(timezone.utc)
                - pwd_last_used
            )
            last_activity_days = delta.days

        return {
            "name": username,
            "arn": arn,
            "mfa_enabled": mfa_enabled,
            "access_keys": access_keys,
            "last_activity_days_ago": last_activity_days,
            "attached_policies": policies,
        }

    # --- Graph-enriched collection ---

    def collect_graph_data(self) -> list[dict]:
        """Collect enriched IAM user data for the
        graph endpoint.

        Returns list of users with inline policies,
        managed policy details, groups, and effective
        permissions per service.
        """
        client = self.session.client(
            "iam", config=_IAM_CONFIG
        )
        users = []
        paginator = client.get_paginator(
            "list_users"
        )
        for page in paginator.paginate():
            for user in page["Users"]:
                users.append(
                    self._build_graph_user(
                        client, user
                    )
                )
        return users

    def _build_graph_user(
        self, client, user: dict
    ) -> dict:
        """Build enriched user dict with policies,
        groups, and effective permissions."""
        username = user["UserName"]
        arn = user["Arn"]

        # MFA
        mfa = client.list_mfa_devices(
            UserName=username
        )
        mfa_enabled = len(mfa["MFADevices"]) > 0

        # Inline policies
        inline = self._get_inline_policies(
            client, username
        )

        # Managed (attached) policies with docs
        attached = (
            client.list_attached_user_policies(
                UserName=username
            )
        )
        managed = []
        for p in attached["AttachedPolicies"]:
            doc = self._get_managed_policy_doc(
                client, p["PolicyArn"]
            )
            managed.append(
                {
                    "name": p["PolicyName"],
                    "arn": p["PolicyArn"],
                    "type": "managed",
                    "document": doc,
                }
            )

        # Groups with their policies
        groups = self._get_user_groups(
            client, username
        )

        # Summarize effective permissions
        all_docs = []
        for p in inline:
            all_docs.append(
                p.get("document", {})
            )
        for p in managed:
            all_docs.append(
                p.get("document", {})
            )
        for g in groups:
            for p in g.get("policies", []):
                all_docs.append(
                    p.get("document", {})
                )

        effective = summarize_permissions(all_docs)
        resources = summarize_resources(all_docs)

        # Strip policy documents from response
        for p in inline:
            p.pop("document", None)
        for p in managed:
            p.pop("document", None)
        for g in groups:
            for p in g.get("policies", []):
                p.pop("document", None)

        return {
            "name": username,
            "arn": arn,
            "mfa_enabled": mfa_enabled,
            "inline_policies": inline,
            "attached_policies": managed,
            "groups": groups,
            "effective_permissions": effective,
            "resources": resources,
        }

    def _get_inline_policies(
        self, client, username: str
    ) -> list[dict]:
        """Fetch inline policy names and documents
        for a user."""
        policies = []
        try:
            resp = client.list_user_policies(
                UserName=username
            )
            for name in resp.get(
                "PolicyNames", []
            ):
                doc_resp = client.get_user_policy(
                    UserName=username,
                    PolicyName=name,
                )
                policies.append(
                    {
                        "name": name,
                        "type": "inline",
                        "document": doc_resp.get(
                            "PolicyDocument", {}
                        ),
                    }
                )
        except Exception:
            logger.warning(
                "Failed to get inline policies "
                "for %s",
                username,
            )
        return policies

    def _get_managed_policy_doc(
        self, client, policy_arn: str
    ) -> dict:
        """Get the default version document for a
        managed policy."""
        try:
            pol = client.get_policy(
                PolicyArn=policy_arn
            )
            ver_id = pol["Policy"][
                "DefaultVersionId"
            ]
            ver = client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=ver_id,
            )
            return ver["PolicyVersion"]["Document"]
        except Exception:
            logger.warning(
                "Failed to get policy doc for %s",
                policy_arn,
            )
            return {}

    def _get_user_groups(
        self, client, username: str
    ) -> list[dict]:
        """Get groups for a user with their attached
        and inline policies."""
        groups = []
        try:
            resp = client.list_groups_for_user(
                UserName=username
            )
        except Exception:
            logger.warning(
                "Failed to get groups for %s",
                username,
            )
            return []

        for g in resp.get("Groups", []):
            gname = g["GroupName"]
            info = {
                "name": gname,
                "arn": g["Arn"],
                "policies": [],
            }

            # Group inline policies
            try:
                gp = client.list_group_policies(
                    GroupName=gname
                )
                for pname in gp.get(
                    "PolicyNames", []
                ):
                    doc = client.get_group_policy(
                        GroupName=gname,
                        PolicyName=pname,
                    )
                    info["policies"].append(
                        {
                            "name": pname,
                            "type": "inline",
                            "document": doc.get(
                                "PolicyDocument",
                                {},
                            ),
                        }
                    )
            except Exception:
                logger.warning(
                    "Failed to get inline policies"
                    " for group %s",
                    gname,
                )

            # Group managed policies
            try:
                gap = (
                    client
                    .list_attached_group_policies(
                        GroupName=gname
                    )
                )
                for p in gap.get(
                    "AttachedPolicies", []
                ):
                    doc = (
                        self
                        ._get_managed_policy_doc(
                            client, p["PolicyArn"]
                        )
                    )
                    info["policies"].append(
                        {
                            "name": p[
                                "PolicyName"
                            ],
                            "arn": p["PolicyArn"],
                            "type": "managed",
                            "document": doc,
                        }
                    )
            except Exception:
                logger.warning(
                    "Failed to get managed "
                    "policies for group %s",
                    gname,
                )

            groups.append(info)
        return groups

    def _get_access_analyzer(self) -> dict:
        try:
            client = self.session.client(
                "accessanalyzer"
            )
            resp = client.list_analyzers(
                Type="ACCOUNT"
            )
            analyzers = [
                {
                    "name": a["name"],
                    "arn": a["arn"],
                    "status": a["status"],
                }
                for a in resp.get("analyzers", [])
            ]
            return {"analyzers": analyzers}
        except Exception:
            return {"analyzers": []}
