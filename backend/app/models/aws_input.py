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


class IAMGroup(BaseModel):
    group_name: str
    arn: str = ""
    group_id: str = ""
    attached_policies: list[AttachedPolicy] = Field(
        default_factory=list
    )


class IAMRole(BaseModel):
    role_name: str
    arn: str = ""
    role_id: str = ""
    assume_role_policy: dict = Field(
        default_factory=dict
    )
    attached_policies: list[AttachedPolicy] = Field(
        default_factory=list
    )
    tags: dict = Field(default_factory=dict)


class IAMPolicy(BaseModel):
    policy_name: str
    arn: str = ""
    policy_id: str = ""
    attachment_count: int = 0
    is_attachable: bool = True


class IAMData(BaseModel):
    account_summary: AccountSummary = Field(
        default_factory=AccountSummary
    )
    password_policy: PasswordPolicy = Field(
        default_factory=PasswordPolicy
    )
    users: list[IAMUser] = Field(default_factory=list)
    groups: list[IAMGroup] = Field(
        default_factory=list
    )
    roles: list[IAMRole] = Field(
        default_factory=list
    )
    policies: list[IAMPolicy] = Field(
        default_factory=list
    )
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


class AutoScalingGroup(BaseModel):
    asg_name: str
    arn: str = ""
    min_size: int = 0
    max_size: int = 0
    desired_capacity: int = 0
    launch_template: str = ""
    vpc_zone_ids: list[str] = Field(
        default_factory=list
    )
    tags: dict = Field(default_factory=dict)


class EBSSnapshot(BaseModel):
    snapshot_id: str
    arn: str = ""
    volume_id: str = ""
    encrypted: bool = False
    is_public: bool = False
    tags: dict = Field(default_factory=dict)


class EC2Data(BaseModel):
    instances: list[EC2Instance] = Field(default_factory=list)
    security_groups: list[SecurityGroup] = Field(
        default_factory=list
    )
    ebs_volumes: list[EBSVolume] = Field(default_factory=list)
    auto_scaling_groups: list[AutoScalingGroup] = (
        Field(default_factory=list)
    )
    ebs_snapshots: list[EBSSnapshot] = Field(
        default_factory=list
    )


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


class Subnet(BaseModel):
    subnet_id: str
    arn: str = ""
    vpc_id: str = ""
    cidr_block: str = ""
    availability_zone: str = ""
    map_public_ip_on_launch: bool = False
    tags: dict = Field(default_factory=dict)


class InternetGateway(BaseModel):
    igw_id: str
    arn: str = ""
    attached_vpcs: list[str] = Field(
        default_factory=list
    )
    tags: dict = Field(default_factory=dict)


class NATGateway(BaseModel):
    nat_gateway_id: str
    arn: str = ""
    vpc_id: str = ""
    subnet_id: str = ""
    state: str = "available"
    tags: dict = Field(default_factory=dict)


class NetworkFirewall(BaseModel):
    firewall_name: str
    arn: str = ""
    vpc_id: str = ""
    firewall_policy_arn: str = ""
    tags: dict = Field(default_factory=dict)


class WAFWebACL(BaseModel):
    name: str
    arn: str = ""
    web_acl_id: str = ""
    scope: str = "REGIONAL"
    tags: dict = Field(default_factory=dict)


class VPCData(BaseModel):
    vpcs: list[VPC] = Field(default_factory=list)
    flow_logs: list[FlowLog] = Field(default_factory=list)
    nacls: list[NACL] = Field(default_factory=list)
    subnets: list[Subnet] = Field(
        default_factory=list
    )
    internet_gateways: list[InternetGateway] = Field(
        default_factory=list
    )
    nat_gateways: list[NATGateway] = Field(
        default_factory=list
    )
    network_firewalls: list[NetworkFirewall] = Field(
        default_factory=list
    )
    waf_web_acls: list[WAFWebACL] = Field(
        default_factory=list
    )


# --- ELB / CDN / DNS ---

class LoadBalancer(BaseModel):
    lb_name: str
    arn: str = ""
    dns_name: str = ""
    scheme: str = "internal"
    lb_type: str = "application"
    vpc_id: str = ""
    tags: dict = Field(default_factory=dict)


class CloudFrontDistribution(BaseModel):
    distribution_id: str
    arn: str = ""
    domain_name: str = ""
    enabled: bool = True
    tags: dict = Field(default_factory=dict)


class Route53HostedZone(BaseModel):
    hosted_zone_id: str
    name: str = ""
    is_private: bool = False
    record_count: int = 0


class ELBData(BaseModel):
    load_balancers: list[LoadBalancer] = Field(
        default_factory=list
    )


class CDNData(BaseModel):
    distributions: list[CloudFrontDistribution] = (
        Field(default_factory=list)
    )
    hosted_zones: list[Route53HostedZone] = Field(
        default_factory=list
    )


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


class AuroraCluster(BaseModel):
    cluster_id: str
    arn: str = ""
    engine: str = ""
    storage_encrypted: bool = False
    multi_az: bool = False
    tags: dict = Field(default_factory=dict)


class RDSSnapshot(BaseModel):
    snapshot_id: str
    arn: str = ""
    db_instance_id: str = ""
    encrypted: bool = False
    is_public: bool = False
    tags: dict = Field(default_factory=dict)


class RDSData(BaseModel):
    db_instances: list[RDSInstance] = Field(
        default_factory=list
    )
    aurora_clusters: list[AuroraCluster] = Field(
        default_factory=list
    )
    snapshots: list[RDSSnapshot] = Field(
        default_factory=list
    )


# --- DynamoDB ---

class DynamoDBTable(BaseModel):
    table_name: str
    arn: str = ""
    table_status: str = "ACTIVE"
    billing_mode: str = "PROVISIONED"
    encryption_type: str = ""
    point_in_time_recovery: bool = False
    tags: dict = Field(default_factory=dict)


class DynamoDBData(BaseModel):
    tables: list[DynamoDBTable] = Field(
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


# --- API Gateway ---

class APIGateway(BaseModel):
    api_id: str
    name: str = ""
    arn: str = ""
    endpoint_type: str = "REGIONAL"
    protocol_type: str = "REST"
    tags: dict = Field(default_factory=dict)


class APIGatewayData(BaseModel):
    apis: list[APIGateway] = Field(
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


# --- Containers ---

class ECRRepository(BaseModel):
    repository_name: str
    arn: str = ""
    repository_uri: str = ""
    image_tag_mutability: str = "MUTABLE"
    scan_on_push: bool = False
    encryption_type: str = "AES256"
    tags: dict = Field(default_factory=dict)


class ECSCluster(BaseModel):
    cluster_name: str
    arn: str = ""
    status: str = "ACTIVE"
    running_tasks_count: int = 0
    active_services_count: int = 0
    tags: dict = Field(default_factory=dict)


class ECSTaskDefinition(BaseModel):
    family: str
    arn: str = ""
    revision: int = 0
    status: str = "ACTIVE"
    network_mode: str = ""
    requires_compatibilities: list[str] = Field(
        default_factory=list
    )
    tags: dict = Field(default_factory=dict)


class EKSCluster(BaseModel):
    cluster_name: str
    arn: str = ""
    status: str = "ACTIVE"
    kubernetes_version: str = ""
    endpoint_public_access: bool = True
    endpoint_private_access: bool = False
    tags: dict = Field(default_factory=dict)


class ContainerData(BaseModel):
    ecr_repositories: list[ECRRepository] = Field(
        default_factory=list
    )
    ecs_clusters: list[ECSCluster] = Field(
        default_factory=list
    )
    ecs_task_definitions: list[
        ECSTaskDefinition
    ] = Field(default_factory=list)
    eks_clusters: list[EKSCluster] = Field(
        default_factory=list
    )


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
    dynamodb: DynamoDBData = Field(
        default_factory=DynamoDBData
    )
    elb: ELBData = Field(default_factory=ELBData)
    cdn: CDNData = Field(default_factory=CDNData)
    lambda_functions: LambdaData = Field(
        default_factory=LambdaData
    )
    apigateway: APIGatewayData = Field(
        default_factory=APIGatewayData
    )
    logging: LoggingData = Field(
        default_factory=LoggingData
    )
    kms: KMSData = Field(default_factory=KMSData)
    secrets_manager: SecretsManagerData = Field(
        default_factory=SecretsManagerData
    )
    containers: ContainerData = Field(
        default_factory=ContainerData
    )
    backup: BackupData = Field(
        default_factory=BackupData
    )
