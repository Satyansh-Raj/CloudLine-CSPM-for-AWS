"""AWS session factory for cross-account scanning.

Creates boto3 sessions for target accounts by calling
STS AssumeRole, returning temporary credentials
wrapped in a new boto3.Session.
"""

import logging

import boto3
from botocore.exceptions import ClientError

from app.models.account import TargetAccount

logger = logging.getLogger(__name__)


class AWSSessionFactory:
    """Creates boto3 sessions for target accounts
    via STS AssumeRole.

    Attributes:
        _base: The base boto3 Session (calling account).
        _sts: STS client built from the base session.

    Example:
        >>> factory = AWSSessionFactory(boto3.Session())
        >>> session = factory.get_session(account)
    """

    def __init__(self, base_session: boto3.Session):
        self._base = base_session
        self._sts = base_session.client("sts")

    def get_session(
        self,
        account: TargetAccount,
        region: str | None = None,
    ) -> boto3.Session:
        """Assume role in target account and return a session.

        Builds the AssumeRole request from the account's
        role_arn and account_id. Passes ExternalId only
        when non-empty. Session name is
        "CloudLineScan-{account_id}".

        Args:
            account: TargetAccount with role_arn and
                optional external_id.
            region: Optional region name for the session.

        Returns:
            boto3.Session configured with temporary
            credentials from AssumeRole.

        Raises:
            RuntimeError: If AssumeRole fails (wraps
                the underlying ClientError).
        """
        session_name = (
            f"CloudLineScan-{account.account_id}"
        )
        kwargs: dict = {
            "RoleArn": account.role_arn,
            "RoleSessionName": session_name,
        }
        if account.external_id:
            kwargs["ExternalId"] = account.external_id

        try:
            resp = self._sts.assume_role(**kwargs)
        except ClientError as exc:
            raise RuntimeError(
                f"AssumeRole failed for account "
                f"{account.account_id}: {exc}"
            ) from exc

        creds = resp["Credentials"]
        session_kwargs: dict = {
            "aws_access_key_id": (
                creds["AccessKeyId"]
            ),
            "aws_secret_access_key": (
                creds["SecretAccessKey"]
            ),
            "aws_session_token": (
                creds["SessionToken"]
            ),
        }
        if region:
            session_kwargs["region_name"] = region

        return boto3.Session(**session_kwargs)

    def get_caller_identity(self) -> dict:
        """Return STS GetCallerIdentity for the base session.

        Returns:
            Dict with Account, UserId, and Arn keys.
        """
        return self._sts.get_caller_identity()
