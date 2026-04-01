"""Pydantic models for the unified AWS input JSON
schema.

This is the data contract between Layer 1 (collectors)
and Layer 2 (OPA/Rego policy engine).

All sub-models use ``extra="allow"`` so that new
collector fields are accepted without requiring an
immediate model update.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class _Flex(BaseModel):
    """Base that silently accepts extra fields."""

    model_config = ConfigDict(extra="allow")


# --- IAM ---


class AccessKey(_Flex):
    access_key_id: str = ""
    status: str = ""
    created_date: str = ""
    last_used_days: int | None = None
    age_days: int = 0


class InlinePolicy(_Flex):
    policy_name: str = ""


class AttachedPolicy(_Flex):
    policy_name: str = ""
    policy_arn: str = ""


class IAMUser(_Flex):
    username: str = ""
    arn: str = ""
    mfa_enabled: bool = False
    password_enabled: bool = False
    access_keys: list[AccessKey] = Field(
        default_factory=list
    )
    days_since_last_use: int | None = None
    attached_policies: list[AttachedPolicy] = Field(
        default_factory=list
    )
    inline_policies: list[InlinePolicy] = Field(
        default_factory=list
    )


class AccountSummary(_Flex):
    mfa_enabled: bool = False
    users: int = 0
    access_keys_active: int = 0
    account_access_keys_present: int = 0


class PasswordPolicy(_Flex):
    minimum_password_length: int = 8
    require_symbols: bool = False
    require_numbers: bool = False
    require_uppercase_characters: bool = False
    require_lowercase_characters: bool = False
    max_password_age: int = 0
    password_reuse_prevention: int = 0
    hard_expiry: bool = False


class AccessAnalyzer(_Flex):
    analyzers: list[dict] = Field(
        default_factory=list
    )
    enabled: bool = False


class IAMGroup(_Flex):
    group_name: str = ""
    arn: str = ""
    group_id: str = ""
    attached_policies: list[AttachedPolicy] = Field(
        default_factory=list
    )


class IAMRole(_Flex):
    role_name: str = ""
    arn: str = ""
    role_id: str = ""
    trust_policy: dict = Field(
        default_factory=dict
    )
    tags: dict = Field(default_factory=dict)


class IAMPolicy(_Flex):
    policy_name: str = ""
    arn: str = ""
    policy_id: str = ""
    attachment_count: int = 0
    is_attachable: bool = True
    document: dict = Field(default_factory=dict)


class IAMData(_Flex):
    account_summary: AccountSummary = Field(
        default_factory=AccountSummary
    )
    password_policy: PasswordPolicy = Field(
        default_factory=PasswordPolicy
    )
    users: list[IAMUser] = Field(
        default_factory=list
    )
    groups: list[IAMGroup] = Field(
        default_factory=list
    )
    roles: list[IAMRole] = Field(
        default_factory=list
    )
    customer_managed_policies: list[IAMPolicy] = (
        Field(default_factory=list)
    )
    access_analyzer: AccessAnalyzer = Field(
        default_factory=AccessAnalyzer
    )


# --- S3 ---


class PublicAccessBlock(_Flex):
    block_public_acls: bool = False
    block_public_policy: bool = False
    ignore_public_acls: bool = False
    restrict_public_buckets: bool = False


class SSEDefault(_Flex):
    sse_algorithm: str = ""
    kms_master_key_id: str | None = None


class EncryptionRule(_Flex):
    apply_server_side_encryption_by_default: (
        SSEDefault
    ) = Field(default_factory=SSEDefault)


class BucketEncryption(_Flex):
    rules: list[EncryptionRule] = Field(
        default_factory=list
    )


class BucketVersioning(_Flex):
    status: str = "Suspended"
    mfa_delete: str = "Disabled"


class BucketLogging(_Flex):
    enabled: bool = False
    target_bucket: str | None = None


class ObjectLock(_Flex):
    enabled: bool = False


class S3Bucket(_Flex):
    name: str
    arn: str
    region: str = ""
    public_access_block: PublicAccessBlock = Field(
        default_factory=PublicAccessBlock
    )
    encryption: BucketEncryption = Field(
        default_factory=BucketEncryption
    )
    versioning: BucketVersioning = Field(
        default_factory=BucketVersioning
    )
    logging: BucketLogging = Field(
        default_factory=BucketLogging
    )
    tags: dict = Field(default_factory=dict)
    policy: dict = Field(default_factory=dict)
    policy_denies_http: bool = False
    acl: dict = Field(default_factory=dict)
    lifecycle_rules: list[dict] = Field(
        default_factory=list
    )
    object_lock: ObjectLock = Field(
        default_factory=ObjectLock
    )
    cors_rules: list[dict] = Field(
        default_factory=list
    )
    replication_configuration: dict = Field(
        default_factory=dict
    )
    notification_configuration: dict | None = None
    size_gb: int = 0
    intelligent_tiering_enabled: bool = False


class S3Data(_Flex):
    buckets: list[S3Bucket] = Field(
        default_factory=list
    )


# --- EC2 ---


class MetadataOptions(_Flex):
    http_tokens: str = "optional"
    http_endpoint: str = "enabled"


class InstanceState(_Flex):
    name: str = "running"
    code: int = 16


class InstanceRole(_Flex):
    role_name: str = ""
    role_arn: str = ""
    attached_policies: list[AttachedPolicy] = Field(
        default_factory=list
    )


class EC2Instance(_Flex):
    instance_id: str
    arn: str = ""
    state: InstanceState = Field(
        default_factory=InstanceState
    )
    public_ip_address: str | None = None
    private_ip_address: str | None = None
    subnet_id: str | None = None
    vpc_id: str | None = None
    security_groups: list[dict] = Field(
        default_factory=list
    )
    iam_role: InstanceRole | None = None
    metadata_options: MetadataOptions = Field(
        default_factory=MetadataOptions
    )
    tags: dict = Field(default_factory=dict)
    instance_type: str = ""
    key_name: str | None = None
    monitoring: dict = Field(default_factory=dict)


class SecurityGroup(_Flex):
    group_id: str
    group_name: str = ""
    arn: str = ""
    vpc_id: str = ""
    ip_permissions: list[dict] = Field(
        default_factory=list
    )
    ip_permissions_egress: list[dict] = Field(
        default_factory=list
    )
    tags: dict = Field(default_factory=dict)
    # backward-compat alias
    ingress_rules: list = Field(default_factory=list)


class EBSVolume(_Flex):
    volume_id: str
    arn: str = ""
    encrypted: bool = False
    size_gb: int = 0
    state: str = ""
    attached_instance: str | None = None
    tags: dict = Field(default_factory=dict)


class AutoScalingGroup(_Flex):
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


class EBSSnapshot(_Flex):
    snapshot_id: str
    arn: str = ""
    volume_id: str = ""
    encrypted: bool = False
    is_public: bool = False
    tags: dict = Field(default_factory=dict)


class EC2Data(_Flex):
    instances: list[EC2Instance] = Field(
        default_factory=list
    )
    security_groups: list[SecurityGroup] = Field(
        default_factory=list
    )
    ebs_volumes: list[EBSVolume] = Field(
        default_factory=list
    )
    auto_scaling_groups: list[
        AutoScalingGroup
    ] = Field(default_factory=list)
    ebs_snapshots: list[EBSSnapshot] = Field(
        default_factory=list
    )


# --- VPC ---


class VPC(_Flex):
    vpc_id: str
    cidr_block: str = ""
    is_default: bool = False
    flow_logs_enabled: bool = False
    tags: dict = Field(default_factory=dict)


class FlowLog(_Flex):
    flow_log_id: str
    resource_id: str
    traffic_type: str = "ALL"
    status: str = "ACTIVE"


class NACLEntry(_Flex):
    rule_number: int
    protocol: str
    cidr_block: str = ""
    rule_action: str = "allow"
    egress: bool = False
    port_range: dict | None = None


class NACL(_Flex):
    network_acl_id: str = ""
    vpc_id: str = ""
    entries: list[NACLEntry] = Field(
        default_factory=list
    )


class Subnet(_Flex):
    subnet_id: str
    arn: str = ""
    vpc_id: str = ""
    cidr_block: str = ""
    availability_zone: str = ""
    map_public_ip_on_launch: bool = False
    subnet_type: str = ""
    tags: dict = Field(default_factory=dict)


class InternetGateway(_Flex):
    igw_id: str
    arn: str = ""
    attached_vpcs: list[str] = Field(
        default_factory=list
    )
    tags: dict = Field(default_factory=dict)


class NATGateway(_Flex):
    nat_gateway_id: str
    arn: str = ""
    vpc_id: str = ""
    subnet_id: str = ""
    state: str = "available"
    tags: dict = Field(default_factory=dict)


class NetworkFirewall(_Flex):
    firewall_name: str
    arn: str = ""
    vpc_id: str = ""
    firewall_policy_arn: str = ""
    tags: dict = Field(default_factory=dict)


class WAFWebACL(_Flex):
    name: str
    arn: str = ""
    web_acl_id: str = ""
    scope: str = "REGIONAL"
    tags: dict = Field(default_factory=dict)


class VPCData(_Flex):
    vpcs: list[VPC] = Field(default_factory=list)
    flow_logs: list[FlowLog] = Field(
        default_factory=list
    )
    nacls: list[NACL] = Field(
        default_factory=list
    )
    subnets: list[Subnet] = Field(
        default_factory=list
    )
    internet_gateways: list[
        InternetGateway
    ] = Field(default_factory=list)
    nat_gateways: list[NATGateway] = Field(
        default_factory=list
    )
    network_firewalls: list[
        NetworkFirewall
    ] = Field(default_factory=list)
    waf_web_acls: list[WAFWebACL] = Field(
        default_factory=list
    )
    security_groups: list[dict] = Field(
        default_factory=list
    )
    route_tables: list[dict] = Field(
        default_factory=list
    )
    peering_connections: list[dict] = Field(
        default_factory=list
    )
    transit_gateways: list[dict] = Field(
        default_factory=list
    )


# --- ELB / CDN / DNS ---


class ListenerCert(_Flex):
    certificate_arn: str = ""
    days_until_expiry: int | None = None


class Listener(_Flex):
    protocol: str = ""
    ssl_policy: str = ""
    default_actions: list[dict] = Field(
        default_factory=list
    )
    certificates: list[ListenerCert] = Field(
        default_factory=list
    )


class LBAttributes(_Flex):
    access_logs_s3_enabled: bool = False
    deletion_protection_enabled: bool = False
    routing_http_drop_invalid_header_fields_enabled: (
        bool
    ) = False


class LoadBalancer(_Flex):
    load_balancer_name: str = ""
    load_balancer_arn: str = ""
    dns_name: str = ""
    scheme: str = "internal"
    type: str = "application"
    vpc_id: str = ""
    availability_zones: list[str] = Field(
        default_factory=list
    )
    listeners: list[Listener] = Field(
        default_factory=list
    )
    attributes: LBAttributes = Field(
        default_factory=LBAttributes
    )
    web_acl_arn: str | None = None
    tags: dict = Field(default_factory=dict)


class CloudFrontDistribution(_Flex):
    distribution_id: str
    arn: str = ""
    domain_name: str = ""
    enabled: bool = True
    tags: dict = Field(default_factory=dict)


class Route53HostedZone(_Flex):
    hosted_zone_id: str
    name: str = ""
    is_private: bool = False
    record_count: int = 0


class ELBData(_Flex):
    load_balancers: list[LoadBalancer] = Field(
        default_factory=list
    )


class CDNData(_Flex):
    distributions: list[
        CloudFrontDistribution
    ] = Field(default_factory=list)
    hosted_zones: list[Route53HostedZone] = Field(
        default_factory=list
    )


# --- RDS ---


class RDSInstance(_Flex):
    db_instance_identifier: str = ""
    db_instance_arn: str = ""
    engine: str = ""
    publicly_accessible: bool = False
    storage_encrypted: bool = False
    multi_az: bool = False
    backup_retention_period: int = 0
    auto_minor_version_upgrade: bool = False
    deletion_protection: bool = False
    iam_database_authentication_enabled: bool = (
        False
    )
    enabled_cloudwatch_logs_exports: list[str] = (
        Field(default_factory=list)
    )
    db_instance_port: int = 0
    tags: dict = Field(default_factory=dict)


class RDSSnapshot(_Flex):
    db_snapshot_identifier: str = ""
    db_snapshot_arn: str = ""
    attributes: dict = Field(default_factory=dict)


class RDSCluster(_Flex):
    db_cluster_identifier: str = ""
    db_cluster_arn: str = ""
    engine: str = ""
    publicly_accessible: bool = False
    storage_encrypted: bool = False
    deletion_protection: bool = False
    iam_database_authentication_enabled: bool = (
        False
    )
    backtrack_window: int = 0
    tags: dict = Field(default_factory=dict)


class RDSData(_Flex):
    db_instances: list[RDSInstance] = Field(
        default_factory=list
    )
    db_snapshots: list[RDSSnapshot] = Field(
        default_factory=list
    )
    db_clusters: list[RDSCluster] = Field(
        default_factory=list
    )
    # backward-compat aliases
    aurora_clusters: list = Field(default_factory=list)
    snapshots: list = Field(default_factory=list)


# --- DynamoDB ---


class SSEDescription(_Flex):
    status: str = "DISABLED"
    sse_type: str = "AES256"


class PITRDescription(_Flex):
    point_in_time_recovery_status: str = "DISABLED"


class ContinuousBackups(_Flex):
    point_in_time_recovery_description: (
        PITRDescription
    ) = Field(default_factory=PITRDescription)


class DynamoDBTable(_Flex):
    table_name: str
    table_arn: str = ""
    table_status: str = "ACTIVE"
    billing_mode: str = "PROVISIONED"
    sse_description: SSEDescription = Field(
        default_factory=SSEDescription
    )
    continuous_backups: ContinuousBackups = Field(
        default_factory=ContinuousBackups
    )
    deletion_protection_enabled: bool = False
    resource_policy: dict = Field(
        default_factory=dict
    )
    auto_scaling_enabled: bool = False
    tags: dict = Field(default_factory=dict)


class DynamoDBData(_Flex):
    tables: list[DynamoDBTable] = Field(
        default_factory=list
    )


# --- Lambda ---


class TracingConfig(_Flex):
    mode: str = "PassThrough"


class LambdaEnvironment(_Flex):
    variables: dict = Field(default_factory=dict)


class LambdaVPCConfig(_Flex):
    subnet_ids: list[str] = Field(
        default_factory=list
    )
    security_group_ids: list[str] = Field(
        default_factory=list
    )


class LambdaFunction(_Flex):
    function_name: str = ""
    function_arn: str = ""
    runtime: str = ""
    role: str = ""
    vpc_config: LambdaVPCConfig = Field(
        default_factory=LambdaVPCConfig
    )
    tracing_config: TracingConfig = Field(
        default_factory=TracingConfig
    )
    environment: LambdaEnvironment = Field(
        default_factory=LambdaEnvironment
    )
    kms_key_arn: str | None = None
    policy: dict = Field(default_factory=dict)
    role_policies: list[dict] = Field(
        default_factory=list
    )
    tags: dict = Field(default_factory=dict)


# --- API Gateway ---


class EndpointConfiguration(_Flex):
    types: list[str] = Field(
        default_factory=list
    )
    vpc_endpoint_ids: list[str] = Field(
        default_factory=list
    )


class CORSConfiguration(_Flex):
    allow_origins: list[str] = Field(
        default_factory=list
    )


class TLSConfig(_Flex):
    insecure_skip_verification: bool = False


class APIGatewayAPI(_Flex):
    id: str = ""
    name: str = ""
    arn: str = ""
    tags: dict = Field(default_factory=dict)
    endpoint_configuration: (
        EndpointConfiguration
    ) = Field(
        default_factory=EndpointConfiguration
    )
    cors_configuration: CORSConfiguration = Field(
        default_factory=CORSConfiguration
    )
    request_validator_id: str | None = None
    minimum_compression_size: int | None = None
    tls_config: TLSConfig = Field(
        default_factory=TLSConfig
    )


class AccessLogSettings(_Flex):
    destination_arn: str | None = None


class DefaultRouteSettings(_Flex):
    logging_level: str = "OFF"
    throttling_rate_limit: int = 0


class APIGatewayStage(_Flex):
    rest_api_id: str = ""
    stage_name: str = ""
    arn: str = ""
    access_log_settings: AccessLogSettings = Field(
        default_factory=AccessLogSettings
    )
    default_route_settings: (
        DefaultRouteSettings
    ) = Field(
        default_factory=DefaultRouteSettings
    )
    tags: dict = Field(default_factory=dict)
    web_acl_arn: str | None = None
    client_certificate_id: str | None = None


class UsagePlanThrottle(_Flex):
    rate_limit: int = 0


class UsagePlan(_Flex):
    id: str = ""
    tags: dict = Field(default_factory=dict)
    api_stages: list[dict] = Field(
        default_factory=list
    )
    throttle: UsagePlanThrottle = Field(
        default_factory=UsagePlanThrottle
    )


class APIGatewayData(_Flex):
    rest_apis: list[APIGatewayAPI] = Field(
        default_factory=list
    )
    stages: list[APIGatewayStage] = Field(
        default_factory=list
    )
    usage_plans: list[UsagePlan] = Field(
        default_factory=list
    )


# --- CloudTrail ---


class CloudTrailTrail(_Flex):
    name: str = ""
    arn: str = ""
    is_multi_region: bool = False
    is_logging: bool = False
    log_file_validation: bool = False
    s3_bucket_name: str = ""
    kms_key_id: str | None = None
    event_selectors: list[dict] = Field(
        default_factory=list
    )


class CloudTrailData(_Flex):
    trails: list[CloudTrailTrail] = Field(
        default_factory=list
    )


# --- CloudWatch ---


class CloudWatchAlarm(_Flex):
    alarm_name: str = ""
    metric_name: str = ""
    state: str = "OK"


class CloudWatchLogGroup(_Flex):
    log_group_name: str = ""
    arn: str = ""
    retention_in_days: int | None = None
    kms_key_id: str | None = None


class CloudWatchData(_Flex):
    alarms: list[CloudWatchAlarm] = Field(
        default_factory=list
    )
    log_groups: list[CloudWatchLogGroup] = Field(
        default_factory=list
    )


# --- AWS Config ---


class ConfigRecorder(_Flex):
    name: str = ""
    recording: bool = False
    all_supported: bool = False


class AWSConfigData(_Flex):
    recorders: list[ConfigRecorder] = Field(
        default_factory=list
    )


# --- GuardDuty ---


class GuardDutyDetector(_Flex):
    detector_id: str = ""
    status: str = "DISABLED"
    finding_publishing_frequency: str = "SIX_HOURS"


class GuardDutyData(_Flex):
    detectors: list[GuardDutyDetector] = Field(
        default_factory=list
    )


# --- KMS ---


class KMSKey(_Flex):
    key_id: str
    arn: str = ""
    key_state: str = "Enabled"
    key_manager: str = "CUSTOMER"
    key_rotation_enabled: bool = False
    policy: dict = Field(default_factory=dict)
    description: str = ""
    multi_region: bool = False
    origin: str = "AWS_KMS"
    key_spec: str = "SYMMETRIC_DEFAULT"
    days_since_disabled: int = 0
    deletion_alarm_configured: bool = False
    grants: list[dict] = Field(
        default_factory=list
    )
    tags: dict = Field(default_factory=dict)


class KMSData(_Flex):
    keys: list[KMSKey] = Field(
        default_factory=list
    )
    aliases: list[dict] = Field(
        default_factory=list
    )


# --- Secrets Manager ---


class RotationRules(_Flex):
    automatically_after_days: int = 0


class Secret(_Flex):
    name: str = ""
    arn: str = ""
    rotation_enabled: bool = False
    rotation_rules: RotationRules = Field(
        default_factory=RotationRules
    )
    resource_policy: dict = Field(
        default_factory=dict
    )
    kms_key_id: str = ""
    tags: dict = Field(default_factory=dict)
    days_since_last_accessed: int = 0
    deleted_date: str | None = None
    description: str = ""
    rotation_lambda_arn: str = ""
    rotation_function_exists: bool = False
    replication_status: list[dict] = Field(
        default_factory=list
    )


class SecretsManagerData(_Flex):
    secrets: list[Secret] = Field(
        default_factory=list
    )


# --- ECS ---


class ContainerDefinition(_Flex):
    name: str = ""
    privileged: bool = False
    readonly_root_filesystem: bool = False
    log_configuration: dict = Field(
        default_factory=dict
    )


class ECSTaskDefinition(_Flex):
    family: str = ""
    task_definition_arn: str = ""
    revision: int = 0
    status: str = "ACTIVE"
    network_mode: str = ""
    requires_compatibilities: list[str] = Field(
        default_factory=list
    )
    container_definitions: list[
        ContainerDefinition
    ] = Field(default_factory=list)
    tags: dict = Field(default_factory=dict)


class ECSCluster(_Flex):
    cluster_name: str = ""
    cluster_arn: str = ""
    status: str = "ACTIVE"
    running_tasks_count: int = 0
    active_services_count: int = 0
    settings: list[dict] = Field(
        default_factory=list
    )
    tags: dict = Field(default_factory=dict)


class ECSData(_Flex):
    clusters: list[ECSCluster] = Field(
        default_factory=list
    )
    task_definitions: list[
        ECSTaskDefinition
    ] = Field(default_factory=list)


# --- EKS ---


class ResourcesVpcConfig(_Flex):
    endpoint_public_access: bool = True
    endpoint_private_access: bool = False
    public_access_cidrs: list[str] = Field(
        default_factory=list
    )
    subnet_ids: list[str] = Field(
        default_factory=list
    )
    security_group_ids: list[str] = Field(
        default_factory=list
    )


class EKSCluster(_Flex):
    name: str = ""
    arn: str = ""
    status: str = "ACTIVE"
    version: str = ""
    resources_vpc_config: ResourcesVpcConfig = (
        Field(
            default_factory=ResourcesVpcConfig
        )
    )
    encryption_config: list[dict] = Field(
        default_factory=list
    )
    logging: dict = Field(default_factory=dict)
    tags: dict = Field(default_factory=dict)


class EKSNodeGroup(_Flex):
    node_group_name: str = ""
    node_group_arn: str = ""
    subnets: list[dict] = Field(
        default_factory=list
    )


class EKSData(_Flex):
    clusters: list[EKSCluster] = Field(
        default_factory=list
    )
    node_groups: list[EKSNodeGroup] = Field(
        default_factory=list
    )
    eol_versions: list[str] = Field(
        default_factory=list
    )


# --- ECR ---


class ImageScanningConfig(_Flex):
    scan_on_push: bool = False


class ECREncryptionConfig(_Flex):
    encryption_type: str = "AES256"
    kms_key: str | None = None


class ECRRepository(_Flex):
    repository_name: str = ""
    repository_arn: str = ""
    repository_uri: str = ""
    image_tag_mutability: str = "MUTABLE"
    image_scanning_configuration: (
        ImageScanningConfig
    ) = Field(
        default_factory=ImageScanningConfig
    )
    encryption_configuration: (
        ECREncryptionConfig
    ) = Field(
        default_factory=ECREncryptionConfig
    )
    repository_visibility: str = "private"
    lifecycle_policy: dict | None = None
    tags: dict = Field(default_factory=dict)


class ECRData(_Flex):
    repositories: list[ECRRepository] = Field(
        default_factory=list
    )


# --- Backup ---


class BackupData(_Flex):
    plans: list[dict] = Field(
        default_factory=list
    )
    protected_resources: list[dict] = Field(
        default_factory=list
    )


# --- Collection Mode ---


class CollectionMode(str, Enum):
    FULL = "full"
    INCREMENTAL = "incremental"


# --- Unified Input (top-level) ---


class UnifiedAWSInput(_Flex):
    """Complete unified JSON schema — the data
    contract between Layer 1 (collectors) and
    Layer 2 (OPA engine).
    """

    account_id: str
    region: str
    collection_timestamp: str
    collection_mode: str = "full"

    # Global
    iam: IAMData = Field(
        default_factory=IAMData
    )

    # Regional — standard collect() keys
    s3: S3Data = Field(default_factory=S3Data)
    ec2: EC2Data = Field(
        default_factory=EC2Data
    )
    vpc: VPCData = Field(
        default_factory=VPCData
    )
    rds: RDSData = Field(
        default_factory=RDSData
    )
    dynamodb: DynamoDBData = Field(
        default_factory=DynamoDBData
    )
    elb: ELBData = Field(
        default_factory=ELBData
    )
    cdn: CDNData = Field(
        default_factory=CDNData
    )
    apigateway: APIGatewayData = Field(
        default_factory=APIGatewayData
    )

    # Lambda returns list directly
    lambda_functions: list[LambdaFunction] = (
        Field(default_factory=list)
    )

    # Logging collector splits into 4 keys
    cloudtrail: CloudTrailData = Field(
        default_factory=CloudTrailData
    )
    cloudwatch: CloudWatchData = Field(
        default_factory=CloudWatchData
    )
    aws_config: AWSConfigData = Field(
        default_factory=AWSConfigData
    )
    guardduty: GuardDutyData = Field(
        default_factory=GuardDutyData
    )

    # KMS collector splits into 3 keys
    kms: KMSData = Field(
        default_factory=KMSData
    )
    secrets_manager: SecretsManagerData = Field(
        default_factory=SecretsManagerData
    )
    backup: BackupData = Field(
        default_factory=BackupData
    )

    # Container collector splits into 3 keys
    ecs: ECSData = Field(
        default_factory=ECSData
    )
    eks: EKSData = Field(
        default_factory=EKSData
    )
    ecr: ECRData = Field(
        default_factory=ECRData
    )

    # backward-compat: old field names accepted via
    # extra="allow" (logging, containers)


# --- Backward-compat aliases ---
# These classes were removed during the collector
# refactoring but are still referenced by tests.


class IngressRule(_Flex):
    """Backward-compat: replaced by raw
    ip_permissions dicts on SecurityGroup."""

    from_port: int = 0
    to_port: int = 0
    protocol: str = ""
    cidr: str = ""


class APIGateway(_Flex):
    """Backward-compat: renamed to APIGatewayAPI."""

    api_id: str = ""
    name: str = ""
    endpoint_type: str = "REGIONAL"
    protocol_type: str = "REST"
    arn: str = ""
    tags: dict = Field(default_factory=dict)


class AuroraCluster(_Flex):
    """Backward-compat: renamed to RDSCluster."""

    cluster_id: str = ""
    storage_encrypted: bool = False
    engine: str = ""
    arn: str = ""
    tags: dict = Field(default_factory=dict)


class LambdaData(_Flex):
    """Backward-compat: lambda_functions is now
    list[LambdaFunction] on UnifiedAWSInput."""

    functions: list[LambdaFunction] = Field(
        default_factory=list
    )


class LoggingData(_Flex):
    """Backward-compat: split into CloudTrailData,
    CloudWatchData, AWSConfigData, GuardDutyData."""

    cloudtrail_trails: list[CloudTrailTrail] = Field(
        default_factory=list
    )
    cloudwatch_alarms: list[CloudWatchAlarm] = Field(
        default_factory=list
    )
    guardduty_detectors: list[
        GuardDutyDetector
    ] = Field(default_factory=list)
    config_recorders: list[ConfigRecorder] = Field(
        default_factory=list
    )


class ContainerData(_Flex):
    """Backward-compat: split into ECSData,
    EKSData, ECRData."""

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
