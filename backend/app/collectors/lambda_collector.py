"""Lambda service collector."""

import logging

from app.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class LambdaCollector(BaseCollector):
    """Collects Lambda function configurations."""

    def collect(self) -> tuple[str, dict]:
        client = self.session.client("lambda")
        return "lambda_functions", {
            "functions": self._get_functions(client),
        }

    def collect_resource(
        self, resource_id: str
    ) -> dict:
        client = self.session.client("lambda")
        try:
            resp = client.get_function(
                FunctionName=resource_id
            )
            cfg = resp.get("Configuration", {})
            return self._build_function(cfg)
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
                    func = self._build_function(fn)
                    func["tags"] = self._get_tags(
                        client,
                        fn.get("FunctionArn", ""),
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

    def _build_function(self, fn: dict) -> dict:
        vpc_config = fn.get("VpcConfig", {})
        # Check if KMS key is configured for env vars
        env_encryption = bool(
            fn.get("KMSKeyArn")
        )
        tracing = fn.get(
            "TracingConfig", {}
        ).get("Mode", "PassThrough")

        return {
            "function_name": fn.get(
                "FunctionName", ""
            ),
            "arn": fn.get("FunctionArn", ""),
            "runtime": fn.get("Runtime", ""),
            "role": fn.get("Role", ""),
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
            "environment_encryption": (
                env_encryption
            ),
            "tracing_config": tracing,
        }
