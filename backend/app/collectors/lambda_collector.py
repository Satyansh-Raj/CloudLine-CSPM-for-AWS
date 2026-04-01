"""Lambda service collector."""

import json
import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class LambdaCollector(BaseCollector):
    """Collects Lambda function configurations."""

    def collect(self) -> tuple[str, list]:
        client = self.session.client("lambda")
        return (
            "lambda_functions",
            self._get_functions(client),
        )

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        client = self.session.client("lambda")
        try:
            resp = client.get_function(
                FunctionName=resource_id
            )
            cfg = resp.get("Configuration", {})
            return self._build_function(client, cfg)
        except Exception as e:
            logger.error(
                "Lambda get_function: %s", e
            )
        return {}

    def _get_functions(
        self, client
    ) -> list[dict]:
        functions = []
        try:
            paginator = client.get_paginator(
                "list_functions"
            )
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    func = self._build_function(
                        client, fn
                    )
                    func["tags"] = self._get_tags(
                        client,
                        fn.get(
                            "FunctionArn", ""
                        ),
                    )
                    functions.append(func)
        except Exception as e:
            logger.error(
                "Lambda list_functions: %s", e
            )
        return functions

    def _get_tags(
        self, client, arn: str
    ) -> dict:
        if not arn:
            return {}
        try:
            resp = client.list_tags(Resource=arn)
            return resp.get("Tags", {})
        except Exception:
            return {}

    def _get_function_policy(
        self, client, function_name: str
    ) -> dict:
        """Fetch resource-based policy."""
        try:
            resp = client.get_policy(
                FunctionName=function_name
            )
            return json.loads(
                resp.get("Policy", "{}")
            )
        except Exception:
            return {"Statement": []}

    def _get_role_policies(
        self, role_arn: str
    ) -> list[dict]:
        """List policies attached to the role."""
        role_name = role_arn.split("/")[-1]
        try:
            iam = self.session.client("iam")
            resp = (
                iam.list_attached_role_policies(
                    RoleName=role_name
                )
            )
            return [
                {
                    "policy_name": p[
                        "PolicyName"
                    ],
                    "policy_arn": p["PolicyArn"],
                }
                for p in resp.get(
                    "AttachedPolicies", []
                )
            ]
        except Exception:
            return []

    def _build_function(
        self, client, fn: dict
    ) -> dict:
        vpc_config = fn.get("VpcConfig", {})
        tracing_mode = fn.get(
            "TracingConfig", {}
        ).get("Mode", "PassThrough")
        role_arn = fn.get("Role", "")
        function_name = fn.get(
            "FunctionName", ""
        )

        return {
            "function_name": function_name,
            "function_arn": fn.get(
                "FunctionArn", ""
            ),
            "runtime": fn.get("Runtime", ""),
            "role": role_arn,
            "vpc_config": {
                "subnet_ids": vpc_config.get(
                    "SubnetIds", []
                ),
                "security_group_ids": (
                    vpc_config.get(
                        "SecurityGroupIds", []
                    )
                ),
            },
            "environment": {
                "variables": fn.get(
                    "Environment", {}
                ).get("Variables", {}),
            },
            "kms_key_arn": fn.get(
                "KMSKeyArn"
            ),
            "tracing_config": {
                "mode": tracing_mode,
            },
            "policy": self._get_function_policy(
                client, function_name
            ),
            "role_policies": (
                self._get_role_policies(
                    role_arn
                )
            ),
        }
