"""Pydantic models for the unified AWS input JSON schema.

This is the data contract between Layer 1 (collectors) and
Layer 2 (OPA/Rego policy engine).
"""

from enum import Enum

from pydantic import BaseModel, Field

# --- IAM ---

class AccessKey(BaseModel):
    key_id: str
    status: str
    created_date: str
    last_used_days_ago: int | None = None


class AttachedPolicy(BaseModel):
    policy_name: str
    policy_arn: str


class IAMUser(BaseModel):
    name: str
    arn: str
    mfa_enabled: bool = False
    access_keys: list[AccessKey] = Field(default_factory=list)
    last_activity_days_ago: int | None = None
    attached_policies: list[AttachedPolicy] = Field(
        default_factory=list
    )


class AccountSummary(BaseModel):
    mfa_enabled: bool = False
    users: int = 0
    access_keys_active: int = 0


class PasswordPolicy(BaseModel):
    minimum_length: int = 8
    require_symbols: bool = False
    require_numbers: bool = False
    require_uppercase: bool = False
    require_lowercase: bool = False
    max_age_days: int = 0
    password_reuse_prevention: int = 0
    hard_expiry: bool = False


class AccessAnalyzer(BaseModel):
    analyzers: list[dict] = Field(default_factory=list)


class IAMData(BaseModel):
    account_summary: AccountSummary = Field(
        default_factory=AccountSummary
    )
    password_policy: PasswordPolicy = Field(
        default_factory=PasswordPolicy
    )
    users: list[IAMUser] = Field(default_factory=list)
    access_analyzer: AccessAnalyzer = Field(
        default_factory=AccessAnalyzer
    )


# --- S3 ---

class PublicAccessBlock(BaseModel):
    block_public_acls: bool = False
    block_public_policy: bool = False
    ignore_public_acls: bool = False
    restrict_public_buckets: bool = False


class BucketEncryption(BaseModel):
    enabled: bool = False
    type: str | None = None
    kms_key_id: str | None = None


class BucketLogging(BaseModel):
    enabled: bool = False
    target_bucket: str | None = None


class S3Bucket(BaseModel):
    name: str
    arn: str
    region: str = ""
    public_access_block: PublicAccessBlock = Field(
        default_factory=PublicAccessBlock
    )
    encryption: BucketEncryption = Field(
        default_factory=BucketEncryption
    )
    versioning: bool = False
    mfa_delete: bool = False
    logging: BucketLogging = Field(
        default_factory=BucketLogging
    )
    tags: dict = Field(default_factory=dict)


class S3Data(BaseModel):
    buckets: list[S3Bucket] = Field(default_factory=list)


# --- EC2 ---

class MetadataOptions(BaseModel):
    http_tokens: str = "optional"
    http_endpoint: str = "enabled"


class InstanceRole(BaseModel):
    role_name: str
    role_arn: str
    attached_policies: list[AttachedPolicy] = Field(
        default_factory=list
    )


class EC2Instance(BaseModel):
    instance_id: str
    arn: str = ""
    state: str = "running"
    public_ip: str | None = None
    private_ip: str | None = None
    subnet_id: str | None = None
    vpc_id: str | None = None
    security_groups: list[str] = Field(default_factory=list)
    iam_role: InstanceRole | None = None
    metadata_options: MetadataOptions = Field(
        default_factory=MetadataOptions
    )
    tags: dict = Field(default_factory=dict)


class IngressRule(BaseModel):
    from_port: int
    to_port: int
    protocol: str
    cidr: str = ""
    description: str = ""


class SecurityGroup(BaseModel):
    group_id: str
    group_name: str = ""
    arn: str = ""
    vpc_id: str = ""
    ingress_rules: list[IngressRule] = Field(
        default_factory=list
    )


class EBSVolume(BaseModel):
    volume_id: str
    arn: str = ""
    encrypted: bool = False
    size_gb: int = 0
    state: str = ""
    attached_instance: str | None = None
    tags: dict = Field(default_factory=dict)


class EC2Data(BaseModel):
    instances: list[EC2Instance] = Field(default_factory=list)
    security_groups: list[SecurityGroup] = Field(
        default_factory=list
    )
    ebs_volumes: list[EBSVolume] = Field(default_factory=list)


# --- VPC ---

class VPC(BaseModel):
    vpc_id: str
    cidr_block: str = ""
    is_default: bool = False


class FlowLog(BaseModel):
    flow_log_id: str
    resource_id: str
    traffic_type: str = "ALL"
    status: str = "ACTIVE"


class NACLEntry(BaseModel):
    rule_number: int
    protocol: str
    cidr_block: str = ""
    rule_action: str = "allow"
    egress: bool = False


class NACL(BaseModel):
    nacl_id: str
    vpc_id: str = ""
    entries: list[NACLEntry] = Field(default_factory=list)


class VPCData(BaseModel):
    vpcs: list[VPC] = Field(default_factory=list)
    flow_logs: list[FlowLog] = Field(default_factory=list)
    nacls: list[NACL] = Field(default_factory=list)


# --- RDS ---

class RDSInstance(BaseModel):
    db_instance_id: str
    arn: str = ""
    engine: str = ""
    publicly_accessible: bool = False
    storage_encrypted: bool = False
    multi_az: bool = False
    backup_retention_period: int = 0
    auto_minor_version_upgrade: bool = False
    tags: dict = Field(default_factory=dict)


class RDSData(BaseModel):
    db_instances: list[RDSInstance] = Field(
        default_factory=list
    )


# --- Lambda ---

class LambdaVPCConfig(BaseModel):
    subnet_ids: list[str] = Field(default_factory=list)
    security_group_ids: list[str] = Field(
        default_factory=list
    )


class LambdaFunction(BaseModel):
    function_name: str
    arn: str = ""
    runtime: str = ""
    role: str = ""
    vpc_config: LambdaVPCConfig = Field(
        default_factory=LambdaVPCConfig
    )
    environment_encryption: bool = False
    tracing_config: str = "PassThrough"
    tags: dict = Field(default_factory=dict)


class LambdaData(BaseModel):
    functions: list[LambdaFunction] = Field(
        default_factory=list
    )


# --- Logging ---

class CloudTrailTrail(BaseModel):
    name: str
    arn: str = ""
    is_multi_region: bool = False
    is_logging: bool = False
    log_file_validation: bool = False
    s3_bucket_name: str = ""
    kms_key_id: str | None = None


class ConfigRecorder(BaseModel):
    name: str
    recording: bool = False
    all_supported: bool = False


class CloudWatchAlarm(BaseModel):
    alarm_name: str
    metric_name: str = ""
    state: str = "OK"


class GuardDutyDetector(BaseModel):
    detector_id: str
    status: str = "DISABLED"
    finding_publishing_frequency: str = "SIX_HOURS"


class LoggingData(BaseModel):
    cloudtrail_trails: list[CloudTrailTrail] = Field(
        default_factory=list
    )
    config_recorders: list[ConfigRecorder] = Field(
        default_factory=list
    )
    cloudwatch_alarms: list[CloudWatchAlarm] = Field(
        default_factory=list
    )
    guardduty_detectors: list[GuardDutyDetector] = Field(
        default_factory=list
    )


# --- KMS ---

class KMSKey(BaseModel):
    key_id: str
    arn: str = ""
    key_state: str = "Enabled"
    key_rotation_enabled: bool = False
    tags: dict = Field(default_factory=dict)


class KMSData(BaseModel):
    keys: list[KMSKey] = Field(default_factory=list)


# --- Secrets Manager ---

class Secret(BaseModel):
    name: str
    arn: str = ""
    rotation_enabled: bool = False
    rotation_interval_days: int = 0


class SecretsManagerData(BaseModel):
    secrets: list[Secret] = Field(default_factory=list)


# --- Backup ---

class BackupData(BaseModel):
    plans: list[dict] = Field(default_factory=list)
    protected_resources: list[dict] = Field(
        default_factory=list
    )


# --- Collection Mode ---

class CollectionMode(str, Enum):
    FULL = "full"
    INCREMENTAL = "incremental"


# --- Unified Input (top-level) ---

class UnifiedAWSInput(BaseModel):
    """Complete unified JSON schema — the data contract
    between Layer 1 (collectors) and Layer 2 (OPA engine).
    """

    account_id: str
    region: str
    collection_timestamp: str
    collection_mode: str = "full"

    iam: IAMData = Field(default_factory=IAMData)
    s3: S3Data = Field(default_factory=S3Data)
    ec2: EC2Data = Field(default_factory=EC2Data)
    vpc: VPCData = Field(default_factory=VPCData)
    rds: RDSData = Field(default_factory=RDSData)
    lambda_functions: LambdaData = Field(
        default_factory=LambdaData
    )
    logging: LoggingData = Field(
        default_factory=LoggingData
    )
    kms: KMSData = Field(default_factory=KMSData)
    secrets_manager: SecretsManagerData = Field(
        default_factory=SecretsManagerData
    )
    backup: BackupData = Field(
        default_factory=BackupData
    )
