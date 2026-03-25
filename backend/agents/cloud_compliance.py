"""Cloud Compliance Agent — Uses Playwright + Cloud APIs to verify security policies."""

import os
import json
import base64
import logging
import time
import uuid
import requests
import urllib.parse
from datetime import datetime

logger = logging.getLogger(__name__)

SCREENSHOTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

# ═══════════════════════════════════════════════════════
# AWS Service Registry — checks-based structure
# Each service has checks[]: {id, name, description, pages[], focus}
# ═══════════════════════════════════════════════════════

AWS_SERVICE_PAGES = {
    "ec2": {
        "name": "EC2",
        "description": "Elastic Compute Cloud",
        "checks": [
            {"id": "instance_inventory", "name": "Instance Inventory", "description": "All running and stopped instances",
             "pages": [{"label": "ec2_instances", "display": "Instances", "url": "https://{region}.console.aws.amazon.com/ec2/home?region={region}#Instances:"}],
             "focus": "List all EC2 instances — state (running/stopped/terminated), instance types, AMIs used, launch time, and public IPs"},
            {"id": "security_groups", "name": "Security Groups", "description": "Firewall rules and port access",
             "pages": [{"label": "ec2_security_groups", "display": "Security Groups", "url": "https://{region}.console.aws.amazon.com/ec2/home?region={region}#SecurityGroups:"}],
             "focus": "Audit inbound/outbound rules for overly permissive access (0.0.0.0/0), open sensitive ports (22, 3389, 3306), and unused groups"},
            {"id": "ebs_encryption", "name": "EBS Volumes & Encryption", "description": "Storage volumes and encryption status",
             "pages": [
                 {"label": "ec2_ebs_volumes", "display": "EBS Volumes", "url": "https://{region}.console.aws.amazon.com/ec2/home?region={region}#Volumes:"},
                 {"label": "ec2_ebs_settings", "display": "EBS Encryption Settings", "url": "https://{region}.console.aws.amazon.com/ec2/home?region={region}#Settings:"},
             ],
             "focus": "Check each volume's encryption status, the account-level default encryption toggle, and identify any unencrypted volumes"},
            {"id": "amis", "name": "AMI Inventory", "description": "Custom machine images (owned)",
             "pages": [{"label": "ec2_amis", "display": "My AMIs", "url": "https://{region}.console.aws.amazon.com/ec2/home?region={region}#Images:visibility=owned-by-me"}],
             "focus": "List owned AMIs, check public vs private visibility, age, snapshot encryption, and deprecation status"},
            {"id": "key_pairs", "name": "Key Pairs", "description": "SSH key pairs for instance access",
             "pages": [{"label": "ec2_key_pairs", "display": "Key Pairs", "url": "https://{region}.console.aws.amazon.com/ec2/home?region={region}#KeyPairs:"}],
             "focus": "Inventory all SSH key pairs, identify unused or very old key pairs that should be rotated or deleted"},
            {"id": "load_balancers", "name": "Load Balancers", "description": "ALB, NLB, and Classic load balancers",
             "pages": [{"label": "ec2_load_balancers", "display": "Load Balancers", "url": "https://{region}.console.aws.amazon.com/ec2/home?region={region}#LoadBalancers:"}],
             "focus": "Review listener protocols (HTTP vs HTTPS), SSL/TLS certificate status, idle timeout, and cross-zone load balancing settings"},
            {"id": "auto_scaling", "name": "Auto Scaling Groups", "description": "Automatic instance scaling",
             "pages": [{"label": "ec2_asg", "display": "Auto Scaling Groups", "url": "https://{region}.console.aws.amazon.com/ec2/home?region={region}#AutoScalingGroups:"}],
             "focus": "Review ASG desired/min/max capacity, scaling policies, health check types, and instance termination policies"},
            {"id": "snapshots", "name": "EBS Snapshots", "description": "Volume backup and recovery points",
             "pages": [{"label": "ec2_snapshots", "display": "Snapshots", "url": "https://{region}.console.aws.amazon.com/ec2/home?region={region}#Snapshots:visibility=owned-by-me"}],
             "focus": "Review snapshot encryption, public accessibility, age, and cost-saving opportunities for old snapshots"},
        ],
    },
    "s3": {
        "name": "S3",
        "description": "Simple Storage Service",
        "checks": [
            {"id": "bucket_inventory", "name": "Bucket Inventory", "description": "All S3 buckets overview",
             "pages": [{"label": "s3_buckets", "display": "S3 Buckets", "url": "https://s3.console.aws.amazon.com/s3/home?region={region}"}],
             "focus": "List all buckets, their regions, creation dates, and any public access indicators shown in the console"},
            {"id": "public_access", "name": "Public Access Block", "description": "Account-level public access settings",
             "pages": [{"label": "s3_public_access", "display": "Block Public Access Settings", "url": "https://s3.console.aws.amazon.com/s3/settings?region={region}"}],
             "focus": "Verify all four block public access settings are enabled at the account level to prevent accidental data exposure"},
            {"id": "storage_lens", "name": "Storage Lens", "description": "Usage, activity, and cost insights",
             "pages": [{"label": "s3_storage_lens", "display": "Storage Lens Dashboards", "url": "https://s3.console.aws.amazon.com/s3/lens?region={region}"}],
             "focus": "Review storage usage metrics, data access patterns, unencrypted or public buckets flagged in Storage Lens dashboards"},
            {"id": "access_points", "name": "Access Points", "description": "Per-application S3 access controls",
             "pages": [{"label": "s3_access_points", "display": "Access Points", "url": "https://s3.console.aws.amazon.com/s3/access-points?region={region}"}],
             "focus": "Review configured access points, their bucket associations, VPC restrictions, and any public policies"},
            {"id": "object_lambda", "name": "Object Lambda Access Points", "description": "Transform S3 objects on retrieval",
             "pages": [{"label": "s3_object_lambda", "display": "Object Lambda Access Points", "url": "https://s3.console.aws.amazon.com/s3/olap?region={region}"}],
             "focus": "Review Object Lambda configurations, Lambda functions used for transformation, and any security considerations"},
            {"id": "multi_region_ap", "name": "Multi-Region Access Points", "description": "Global S3 request routing",
             "pages": [{"label": "s3_multi_region_ap", "display": "Multi-Region Access Points", "url": "https://s3.console.aws.amazon.com/s3/mraps?region={region}"}],
             "focus": "Review multi-region access points, replication rules backing them, and failover policies"},
            {"id": "batch_operations", "name": "Batch Operations", "description": "Large-scale S3 object jobs",
             "pages": [{"label": "s3_batch_ops", "display": "Batch Operations Jobs", "url": "https://s3.console.aws.amazon.com/s3/jobs?region={region}"}],
             "focus": "Review batch jobs — status (active/completed/failed), types of operations, completion reports, and IAM roles used"},
            {"id": "s3_dashboard", "name": "S3 Service Overview", "description": "Top-level S3 account dashboard",
             "pages": [{"label": "s3_home", "display": "S3 Home", "url": "https://s3.console.aws.amazon.com/s3/home?region={region}"}],
             "focus": "Provide an overall assessment of the S3 environment — bucket count, any public buckets shown, and general posture"},
        ],
    },
    "iam": {
        "name": "IAM",
        "description": "Identity & Access Management",
        "checks": [
            {"id": "dashboard", "name": "Security Dashboard", "description": "IAM security status and recommendations",
             "pages": [{"label": "iam_dashboard", "display": "IAM Dashboard", "url": "https://us-east-1.console.aws.amazon.com/iam/home#/home"}],
             "focus": "Review security status indicators — root MFA, credential report, access key rotation, password policy, and any security warnings"},
            {"id": "users", "name": "User Inventory", "description": "All IAM users and credential status",
             "pages": [{"label": "iam_users", "display": "IAM Users", "url": "https://us-east-1.console.aws.amazon.com/iam/home#/users"}],
             "focus": "List users, check MFA status on each, last sign-in dates, access key age, and users with console access"},
            {"id": "roles", "name": "Roles Audit", "description": "IAM roles and trust relationships",
             "pages": [{"label": "iam_roles", "display": "IAM Roles", "url": "https://us-east-1.console.aws.amazon.com/iam/home#/roles"}],
             "focus": "Review role names, descriptions, trust policies, cross-account access, and service-linked vs customer-managed roles"},
            {"id": "policies", "name": "Managed Policies", "description": "Customer-managed IAM policies",
             "pages": [{"label": "iam_policies", "display": "IAM Policies", "url": "https://us-east-1.console.aws.amazon.com/iam/home#/policies"}],
             "focus": "Review customer-managed policies for overly permissive actions, wildcard resources, and unused policies"},
            {"id": "groups", "name": "Groups", "description": "User groups and attached permissions",
             "pages": [{"label": "iam_groups", "display": "IAM Groups", "url": "https://us-east-1.console.aws.amazon.com/iam/home#/groups"}],
             "focus": "Review groups, their attached policies, and whether permissions follow least-privilege principles"},
            {"id": "identity_providers", "name": "Identity Providers", "description": "SAML / OIDC federation config",
             "pages": [{"label": "iam_idp", "display": "Identity Providers", "url": "https://us-east-1.console.aws.amazon.com/iam/home#/providers"}],
             "focus": "Review configured SAML/OIDC providers, their metadata, and associated trust configurations for SSO"},
            {"id": "account_settings", "name": "Password Policy", "description": "Account-level password requirements",
             "pages": [{"label": "iam_account_settings", "display": "Account Settings", "url": "https://us-east-1.console.aws.amazon.com/iam/home#/account_settings"}],
             "focus": "Check password minimum length, complexity requirements, rotation period, reuse prevention, and MFA enforcement"},
            {"id": "access_analyzer", "name": "Access Analyzer", "description": "External access findings",
             "pages": [{"label": "iam_access_analyzer", "display": "Access Analyzer", "url": "https://us-east-1.console.aws.amazon.com/access-analyzer/home"}],
             "focus": "Review active findings from Access Analyzer — resources shared externally, their severity, and resolution status"},
        ],
    },
    "rds": {
        "name": "RDS",
        "description": "Relational Database Service",
        "checks": [
            {"id": "databases", "name": "Database Instances", "description": "All RDS DB instances",
             "pages": [{"label": "rds_databases", "display": "Databases", "url": "https://{region}.console.aws.amazon.com/rds/home?region={region}#databases:"}],
             "focus": "List all DB instances — engine type/version, status, Multi-AZ, storage encryption, and public accessibility"},
            {"id": "snapshots", "name": "Snapshots", "description": "Automated and manual DB snapshots",
             "pages": [{"label": "rds_snapshots", "display": "Snapshots", "url": "https://{region}.console.aws.amazon.com/rds/home?region={region}#snapshots-list:"}],
             "focus": "Review snapshot types (automated/manual), encryption status, age, and cross-region copy configurations"},
            {"id": "subnet_groups", "name": "Subnet Groups", "description": "DB subnet group configurations",
             "pages": [{"label": "rds_subnet_groups", "display": "Subnet Groups", "url": "https://{region}.console.aws.amazon.com/rds/home?region={region}#db-subnet-groups-list:"}],
             "focus": "Review subnet groups — associated VPCs, subnets across availability zones, and which DB instances use them"},
            {"id": "parameter_groups", "name": "Parameter Groups", "description": "DB engine configuration parameters",
             "pages": [{"label": "rds_param_groups", "display": "Parameter Groups", "url": "https://{region}.console.aws.amazon.com/rds/home?region={region}#parameter-groups-list:"}],
             "focus": "Review custom parameter groups — key security parameters like SSL enforcement, audit logging, and encryption settings"},
            {"id": "security_groups", "name": "Security Groups (VPC)", "description": "Network access rules for RDS",
             "pages": [{"label": "rds_sg", "display": "Security Groups", "url": "https://{region}.console.aws.amazon.com/rds/home?region={region}#db-security-groups:"}],
             "focus": "Review which security groups are attached to DB instances and whether they restrict access to known CIDRs/SGs only"},
            {"id": "automated_backups", "name": "Automated Backups", "description": "Automated backup retention settings",
             "pages": [{"label": "rds_automated_backups", "display": "Automated Backups", "url": "https://{region}.console.aws.amazon.com/rds/home?region={region}#automatedbackups:"}],
             "focus": "Review backup retention period, backup window, and whether all production databases have adequate backup coverage"},
            {"id": "events", "name": "Event Subscriptions", "description": "RDS event notifications",
             "pages": [{"label": "rds_events", "display": "Event Subscriptions", "url": "https://{region}.console.aws.amazon.com/rds/home?region={region}#event-subscriptions:"}],
             "focus": "Review configured event subscriptions for failure, maintenance, and security events — check notification targets"},
            {"id": "option_groups", "name": "Option Groups", "description": "DB engine optional feature configs",
             "pages": [{"label": "rds_option_groups", "display": "Option Groups", "url": "https://{region}.console.aws.amazon.com/rds/home?region={region}#option-groups-list:"}],
             "focus": "Review option groups — enabled options like SSL, audit plugins, timezone settings, and associated DB instances"},
        ],
    },
    "vpc": {
        "name": "VPC",
        "description": "Virtual Private Cloud",
        "checks": [
            {"id": "vpcs", "name": "VPC Inventory", "description": "All VPCs and their settings",
             "pages": [{"label": "vpc_list", "display": "Your VPCs", "url": "https://{region}.console.aws.amazon.com/vpcconsole/home?region={region}#vpcs:"}],
             "focus": "List all VPCs — CIDR blocks, whether they are default VPCs, DNS settings, and attached Internet Gateways"},
            {"id": "security_groups", "name": "Security Groups", "description": "VPC-level security group rules",
             "pages": [{"label": "vpc_security_groups", "display": "Security Groups", "url": "https://{region}.console.aws.amazon.com/vpcconsole/home?region={region}#SecurityGroups:"}],
             "focus": "Identify overly permissive rules — 0.0.0.0/0 ingress, open ports (22, 3389, 3306), and default security group misuse"},
            {"id": "subnets", "name": "Subnets", "description": "Public and private subnet configuration",
             "pages": [{"label": "vpc_subnets", "display": "Subnets", "url": "https://{region}.console.aws.amazon.com/vpcconsole/home?region={region}#subnets:"}],
             "focus": "Review subnet CIDR allocation, public vs private designation (auto-assign public IP), and AZ distribution"},
            {"id": "route_tables", "name": "Route Tables", "description": "Routing rules for subnets",
             "pages": [{"label": "vpc_route_tables", "display": "Route Tables", "url": "https://{region}.console.aws.amazon.com/vpcconsole/home?region={region}#RouteTables:"}],
             "focus": "Review routes — Internet Gateway associations, NAT Gateway routes, VPC peering routes, and overly broad routes"},
            {"id": "internet_gateways", "name": "Internet Gateways", "description": "Public internet access points",
             "pages": [{"label": "vpc_igw", "display": "Internet Gateways", "url": "https://{region}.console.aws.amazon.com/vpcconsole/home?region={region}#igws:"}],
             "focus": "Review which VPCs have Internet Gateways attached — verify that only intentionally public VPCs have IGW access"},
            {"id": "nacls", "name": "Network ACLs", "description": "Subnet-level stateless firewall rules",
             "pages": [{"label": "vpc_nacl", "display": "Network ACLs", "url": "https://{region}.console.aws.amazon.com/vpcconsole/home?region={region}#acls:"}],
             "focus": "Review NACL inbound/outbound rules — check if default NACL is being used (allow-all) and look for deny rules protecting sensitive subnets"},
            {"id": "nat_gateways", "name": "NAT Gateways", "description": "Outbound internet for private subnets",
             "pages": [{"label": "vpc_nat", "display": "NAT Gateways", "url": "https://{region}.console.aws.amazon.com/vpcconsole/home?region={region}#NatGateways:"}],
             "focus": "Review NAT Gateway placement (should be in public subnet), associated Elastic IPs, and status"},
            {"id": "vpc_peering", "name": "VPC Peering Connections", "description": "Cross-VPC network connections",
             "pages": [{"label": "vpc_peering", "display": "Peering Connections", "url": "https://{region}.console.aws.amazon.com/vpcconsole/home?region={region}#PeeringConnections:"}],
             "focus": "Review peering connections — which VPCs are connected, whether peering is intentional, and transitive routing risks"},
        ],
    },
    "lambda": {
        "name": "Lambda",
        "description": "Serverless Functions",
        "checks": [
            {"id": "functions", "name": "Function Inventory", "description": "All Lambda functions",
             "pages": [{"label": "lambda_functions", "display": "Functions", "url": "https://{region}.console.aws.amazon.com/lambda/home?region={region}#/functions"}],
             "focus": "List all functions — runtime versions (check for deprecated runtimes), memory, timeout, package size, and last modified"},
            {"id": "function_urls", "name": "Function URLs", "description": "Public HTTP endpoints for Lambda",
             "pages": [{"label": "lambda_functions_url", "display": "Functions (URL check)", "url": "https://{region}.console.aws.amazon.com/lambda/home?region={region}#/functions"}],
             "focus": "Identify functions with Function URLs exposed — check auth type (NONE vs AWS_IAM) and CORS configuration"},
            {"id": "event_sources", "name": "Event Source Mappings", "description": "Triggers and event sources",
             "pages": [{"label": "lambda_event_sources", "display": "Event Source Mappings", "url": "https://{region}.console.aws.amazon.com/lambda/home?region={region}#/event-source-mappings"}],
             "focus": "Review all event source mappings — SQS, Kinesis, DynamoDB streams — check batch sizes, error handling, and DLQ configuration"},
            {"id": "layers", "name": "Lambda Layers", "description": "Shared code and dependency layers",
             "pages": [{"label": "lambda_layers", "display": "Layers", "url": "https://{region}.console.aws.amazon.com/lambda/home?region={region}#/layers"}],
             "focus": "Review Lambda layers — version count, compatible runtimes, and whether layers are publicly shared (security risk)"},
            {"id": "applications", "name": "Applications", "description": "SAM / Serverless Application Manager deployments",
             "pages": [{"label": "lambda_applications", "display": "Applications", "url": "https://{region}.console.aws.amazon.com/lambda/home?region={region}#/applications"}],
             "focus": "Review deployed serverless applications, their source (SAR vs custom), deployment status, and linked resources"},
            {"id": "code_signing", "name": "Code Signing", "description": "Code integrity verification",
             "pages": [{"label": "lambda_code_signing", "display": "Code Signing Configs", "url": "https://{region}.console.aws.amazon.com/lambda/home?region={region}#/code-signing"}],
             "focus": "Check if code signing is configured — identifies which functions enforce code signature validation for deployment security"},
            {"id": "aliases_versions", "name": "Aliases & Versions", "description": "Deployment versioning and aliases",
             "pages": [{"label": "lambda_functions_v", "display": "Functions", "url": "https://{region}.console.aws.amazon.com/lambda/home?region={region}#/functions"}],
             "focus": "Review version count and alias usage — identify functions without versioning (using $LATEST only) which is a deployment risk"},
            {"id": "monitoring", "name": "CloudWatch Monitoring", "description": "Lambda metrics and error rates",
             "pages": [{"label": "lambda_monitoring", "display": "Functions (monitoring)", "url": "https://{region}.console.aws.amazon.com/lambda/home?region={region}#/functions"}],
             "focus": "Review Lambda function error rates, throttling counts, and duration metrics for performance and reliability issues"},
        ],
    },
    "cloudwatch": {
        "name": "CloudWatch",
        "description": "Monitoring & Observability",
        "checks": [
            {"id": "alarms", "name": "Alarms", "description": "Metric alarms and notification status",
             "pages": [{"label": "cloudwatch_alarms", "display": "Alarms", "url": "https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#alarmsV2:"}],
             "focus": "Review alarm states (OK/ALARM/INSUFFICIENT_DATA), alarm names, thresholds, and associated SNS actions for notification"},
            {"id": "dashboards", "name": "Dashboards", "description": "Monitoring and observability dashboards",
             "pages": [{"label": "cloudwatch_dashboards", "display": "Dashboards", "url": "https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#dashboards:"}],
             "focus": "Review existing dashboards — names, sharing settings (public vs private), and whether key services have monitoring coverage"},
            {"id": "log_groups", "name": "Log Groups", "description": "CloudWatch log group inventory",
             "pages": [{"label": "cloudwatch_log_groups", "display": "Log Groups", "url": "https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#logsV2:log-groups"}],
             "focus": "Review log groups — retention periods (look for 'Never expire'), encryption with KMS, and storage size"},
            {"id": "metrics_explorer", "name": "Metrics Explorer", "description": "Custom and service metrics",
             "pages": [{"label": "cloudwatch_metrics", "display": "Metrics", "url": "https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#metricsV2:"}],
             "focus": "Review available metric namespaces — which services are emitting metrics and any gaps in monitoring coverage"},
            {"id": "synthetics", "name": "Synthetics Canaries", "description": "Automated availability monitoring",
             "pages": [{"label": "cloudwatch_synthetics", "display": "Synthetics Canaries", "url": "https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#synthetics:canary/list"}],
             "focus": "Review synthetic canaries — status (running/stopped), success rate, schedule, and S3 artifact storage configuration"},
            {"id": "insights", "name": "Contributor Insights", "description": "High-cardinality traffic analysis",
             "pages": [{"label": "cloudwatch_insights", "display": "Contributor Insights", "url": "https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#contributorinsights:rules"}],
             "focus": "Review Contributor Insights rules — active/inactive status, log group source, and report field configurations"},
            {"id": "anomaly_detection", "name": "Anomaly Detection", "description": "ML-powered metric anomalies",
             "pages": [{"label": "cloudwatch_anomaly", "display": "Anomaly Detection", "url": "https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#alarmsV2:withAnomalyDetection"}],
             "focus": "Review anomaly detection models — configured metrics, bands, and any associated alarms for automated alerting"},
            {"id": "events", "name": "EventBridge Rules", "description": "Event-driven automation rules",
             "pages": [{"label": "cloudwatch_events", "display": "EventBridge Rules", "url": "https://{region}.console.aws.amazon.com/events/home?region={region}#/rules"}],
             "focus": "Review EventBridge rules — event patterns, scheduled expressions, targets, and enabled/disabled status"},
        ],
    },
    "kms": {
        "name": "KMS",
        "description": "Key Management Service",
        "checks": [
            {"id": "customer_keys", "name": "Customer Managed Keys", "description": "Keys you create and manage",
             "pages": [{"label": "kms_cmk", "display": "Customer Managed Keys", "url": "https://{region}.console.aws.amazon.com/kms/home?region={region}#/kms/keys"}],
             "focus": "List CMKs — status (enabled/disabled/pending deletion), key rotation enabled, creation date, and associated aliases"},
            {"id": "aws_managed_keys", "name": "AWS Managed Keys", "description": "Keys managed by AWS services",
             "pages": [{"label": "kms_aws_managed", "display": "AWS Managed Keys", "url": "https://{region}.console.aws.amazon.com/kms/home?region={region}#/kms/defaultKeys"}],
             "focus": "Review which AWS services have created managed keys — verify expected services are using KMS encryption"},
            {"id": "key_policies", "name": "Key Policies Review", "description": "Access control policies on keys",
             "pages": [{"label": "kms_key_policies", "display": "Customer Keys (policy view)", "url": "https://{region}.console.aws.amazon.com/kms/home?region={region}#/kms/keys"}],
             "focus": "Review key policies for cross-account access, overly permissive allow-all statements, and least privilege issues"},
            {"id": "key_rotation", "name": "Key Rotation Status", "description": "Automatic key material rotation",
             "pages": [{"label": "kms_rotation", "display": "Customer Keys (rotation view)", "url": "https://{region}.console.aws.amazon.com/kms/home?region={region}#/kms/keys"}],
             "focus": "Check which CMKs have automatic rotation enabled — keys without rotation are a compliance risk for PCI/HIPAA/SOC2"},
            {"id": "custom_key_stores", "name": "Custom Key Stores", "description": "CloudHSM-backed key stores",
             "pages": [{"label": "kms_custom_stores", "display": "Custom Key Stores", "url": "https://{region}.console.aws.amazon.com/kms/home?region={region}#/kms/customKeyStores"}],
             "focus": "Review custom key stores — connected CloudHSM clusters, connection status, and associated keys"},
            {"id": "key_aliases", "name": "Key Aliases", "description": "Friendly names for KMS keys",
             "pages": [{"label": "kms_aliases", "display": "Customer Keys (aliases)", "url": "https://{region}.console.aws.amazon.com/kms/home?region={region}#/kms/keys"}],
             "focus": "Review key aliases — which keys have aliases, whether aliases follow naming conventions, and orphaned aliases"},
            {"id": "grants", "name": "Key Grants", "description": "Temporary key usage permissions",
             "pages": [{"label": "kms_grants", "display": "Customer Keys (grants)", "url": "https://{region}.console.aws.amazon.com/kms/home?region={region}#/kms/keys"}],
             "focus": "Check for active key grants — grantee principals, allowed operations, and grants that may no longer be needed"},
            {"id": "key_usage_metrics", "name": "Key Usage & Requests", "description": "Key operation metrics",
             "pages": [{"label": "kms_metrics", "display": "Customer Keys (monitoring)", "url": "https://{region}.console.aws.amazon.com/kms/home?region={region}#/kms/keys"}],
             "focus": "Review key usage frequency — identify unused keys, keys nearing deletion, and high-volume keys needing review"},
        ],
    },
    "secretsmanager": {
        "name": "Secrets Manager",
        "description": "Secret Storage & Rotation",
        "checks": [
            {"id": "secrets_inventory", "name": "Secrets Inventory", "description": "All stored secrets",
             "pages": [{"label": "secrets_list", "display": "Secrets", "url": "https://{region}.console.aws.amazon.com/secretsmanager/home?region={region}#!/listSecrets"}],
             "focus": "List all secrets — names/descriptions, last changed date, rotation status (enabled/disabled), and last accessed date"},
            {"id": "rotation_status", "name": "Rotation Configuration", "description": "Automatic secret rotation",
             "pages": [{"label": "secrets_rotation", "display": "Secrets (rotation view)", "url": "https://{region}.console.aws.amazon.com/secretsmanager/home?region={region}#!/listSecrets"}],
             "focus": "Identify secrets without automatic rotation enabled — especially database credentials and API keys that should rotate regularly"},
            {"id": "encryption", "name": "Encryption Settings", "description": "KMS key usage for secrets",
             "pages": [{"label": "secrets_encryption", "display": "Secrets (encryption view)", "url": "https://{region}.console.aws.amazon.com/secretsmanager/home?region={region}#!/listSecrets"}],
             "focus": "Check whether secrets use the default AWS managed KMS key or customer managed keys for encryption at rest"},
            {"id": "resource_policies", "name": "Resource Policies", "description": "Cross-account access policies",
             "pages": [{"label": "secrets_policies", "display": "Secrets (policy view)", "url": "https://{region}.console.aws.amazon.com/secretsmanager/home?region={region}#!/listSecrets"}],
             "focus": "Identify secrets with resource-based policies — review cross-account principals and overly permissive access"},
            {"id": "stale_secrets", "name": "Stale & Unused Secrets", "description": "Old or never-accessed secrets",
             "pages": [{"label": "secrets_stale", "display": "Secrets (last used)", "url": "https://{region}.console.aws.amazon.com/secretsmanager/home?region={region}#!/listSecrets"}],
             "focus": "Identify secrets never accessed or not accessed for 90+ days — candidates for deletion to reduce attack surface"},
            {"id": "tags", "name": "Secret Tagging", "description": "Resource tagging and cost allocation",
             "pages": [{"label": "secrets_tags", "display": "Secrets (tags view)", "url": "https://{region}.console.aws.amazon.com/secretsmanager/home?region={region}#!/listSecrets"}],
             "focus": "Check tagging consistency — environment, owner, application tags help with cost allocation and access control policies"},
            {"id": "replication", "name": "Multi-Region Replication", "description": "Secret replication to other regions",
             "pages": [{"label": "secrets_replication", "display": "Secrets (replication view)", "url": "https://{region}.console.aws.amazon.com/secretsmanager/home?region={region}#!/listSecrets"}],
             "focus": "Review which secrets are replicated to other regions for DR — verify replication status and replica KMS key configuration"},
            {"id": "lambda_rotation", "name": "Rotation Lambda Functions", "description": "Lambda functions that rotate secrets",
             "pages": [{"label": "secrets_rotation_fn", "display": "Secrets (rotation functions)", "url": "https://{region}.console.aws.amazon.com/secretsmanager/home?region={region}#!/listSecrets"}],
             "focus": "Review the Lambda functions configured for secret rotation — check their runtime, last invocation, and error rates"},
        ],
    },
    "guardduty": {
        "name": "GuardDuty",
        "description": "Threat Detection",
        "checks": [
            {"id": "summary", "name": "Findings Summary", "description": "Overall threat detection summary",
             "pages": [{"label": "guardduty_summary", "display": "Summary", "url": "https://{region}.console.aws.amazon.com/guardduty/home?region={region}#/summary"}],
             "focus": "Review GuardDuty status — enabled/disabled, total finding counts, and high severity finding summary"},
            {"id": "findings", "name": "Active Findings", "description": "Current threat and anomaly findings",
             "pages": [{"label": "guardduty_findings", "display": "Findings", "url": "https://{region}.console.aws.amazon.com/guardduty/home?region={region}#/findings"}],
             "focus": "List active findings — severity (HIGH/MEDIUM/LOW), finding types, affected resources, and when last seen"},
            {"id": "accounts", "name": "Member Accounts", "description": "GuardDuty organization member accounts",
             "pages": [{"label": "guardduty_accounts", "display": "Accounts", "url": "https://{region}.console.aws.amazon.com/guardduty/home?region={region}#/linked-accounts"}],
             "focus": "Review member account enrollment status, GuardDuty enabled/disabled per account, and invitation status"},
            {"id": "s3_protection", "name": "S3 Protection", "description": "S3 malicious activity monitoring",
             "pages": [{"label": "guardduty_s3", "display": "S3 Protection", "url": "https://{region}.console.aws.amazon.com/guardduty/home?region={region}#/protection-plans/s3"}],
             "focus": "Check if S3 protection plan is enabled — identifies malicious access, data exfiltration, and bucket policy changes"},
            {"id": "eks_protection", "name": "EKS Protection", "description": "Kubernetes audit log monitoring",
             "pages": [{"label": "guardduty_eks", "display": "EKS Protection", "url": "https://{region}.console.aws.amazon.com/guardduty/home?region={region}#/protection-plans/eks"}],
             "focus": "Check EKS audit log monitoring and EKS runtime monitoring enrollment status"},
            {"id": "malware_protection", "name": "Malware Protection", "description": "EBS volume malware scanning",
             "pages": [{"label": "guardduty_malware", "display": "Malware Protection", "url": "https://{region}.console.aws.amazon.com/guardduty/home?region={region}#/protection-plans/malware"}],
             "focus": "Check malware protection plan status — on-demand and automated scanning of EC2 EBS volumes"},
            {"id": "ipsets", "name": "IP Sets & Threat Lists", "description": "Custom trusted and threat IP lists",
             "pages": [{"label": "guardduty_ipsets", "display": "Lists", "url": "https://{region}.console.aws.amazon.com/guardduty/home?region={region}#/lists"}],
             "focus": "Review trusted IP sets and threat intelligence lists — custom IP whitelists and threat feed configurations"},
            {"id": "filters", "name": "Suppression Rules", "description": "Finding filters and suppression rules",
             "pages": [{"label": "guardduty_filters", "display": "Suppression Rules", "url": "https://{region}.console.aws.amazon.com/guardduty/home?region={region}#/filters"}],
             "focus": "Review active suppression rules — ensure no rules are hiding important findings, check rule criteria"},
        ],
    },
    "securityhub": {
        "name": "Security Hub",
        "description": "Security Posture Management",
        "checks": [
            {"id": "summary", "name": "Security Score", "description": "Overall security posture score",
             "pages": [{"label": "securityhub_summary", "display": "Summary", "url": "https://{region}.console.aws.amazon.com/securityhub/home?region={region}#/summary"}],
             "focus": "Review the overall security score, score breakdown by standard, and critical/high finding counts"},
            {"id": "findings", "name": "Active Findings", "description": "All security findings",
             "pages": [{"label": "securityhub_findings", "display": "Findings", "url": "https://{region}.console.aws.amazon.com/securityhub/home?region={region}#/findings"}],
             "focus": "List findings — severity (CRITICAL/HIGH/MEDIUM/LOW), compliance status, workflow status, and affected resources"},
            {"id": "standards", "name": "Security Standards", "description": "Enabled compliance standards and scores",
             "pages": [{"label": "securityhub_standards", "display": "Standards", "url": "https://{region}.console.aws.amazon.com/securityhub/home?region={region}#/standards"}],
             "focus": "Review enabled standards (CIS, PCI DSS, AWS FSBP, NIST), their scores, and failed control counts"},
            {"id": "controls", "name": "Security Controls", "description": "Individual control statuses",
             "pages": [{"label": "securityhub_controls", "display": "Controls", "url": "https://{region}.console.aws.amazon.com/securityhub/home?region={region}#/controls"}],
             "focus": "Review failed controls — identify CRITICAL and HIGH severity controls that need immediate remediation"},
            {"id": "integrations", "name": "Integrations", "description": "Third-party integration status",
             "pages": [{"label": "securityhub_integrations", "display": "Integrations", "url": "https://{region}.console.aws.amazon.com/securityhub/home?region={region}#/integrations"}],
             "focus": "Review enabled integrations — GuardDuty, Inspector, Macie, IAM Access Analyzer, and third-party tools"},
            {"id": "insights", "name": "Insights", "description": "Pre-built and custom security insights",
             "pages": [{"label": "securityhub_insights", "display": "Insights", "url": "https://{region}.console.aws.amazon.com/securityhub/home?region={region}#/insights"}],
             "focus": "Review Security Hub insights — focus on top-failing resources and most failed security controls insights"},
            {"id": "automation_rules", "name": "Automation Rules", "description": "Automated finding management rules",
             "pages": [{"label": "securityhub_automation", "display": "Automation Rules", "url": "https://{region}.console.aws.amazon.com/securityhub/home?region={region}#/automation-rules"}],
             "focus": "Review automation rules — criteria, actions (suppress/update), and whether rules may be hiding important findings"},
            {"id": "accounts", "name": "Accounts", "description": "Organization member account enrollment",
             "pages": [{"label": "securityhub_accounts", "display": "Accounts", "url": "https://{region}.console.aws.amazon.com/securityhub/home?region={region}#/accounts"}],
             "focus": "Review member accounts — enrollment status, delegated admin account, and accounts not yet enrolled in Security Hub"},
        ],
    },
    "dynamodb": {
        "name": "DynamoDB",
        "description": "NoSQL Database",
        "checks": [
            {"id": "tables", "name": "Table Inventory", "description": "All DynamoDB tables",
             "pages": [{"label": "dynamodb_tables", "display": "Tables", "url": "https://{region}.console.aws.amazon.com/dynamodbv2/home?region={region}#tables"}],
             "focus": "List tables — status, item count, size, billing mode (on-demand vs provisioned), and whether encryption is shown"},
            {"id": "backups", "name": "Backups", "description": "On-demand and PITR backups",
             "pages": [{"label": "dynamodb_backups", "display": "Backups", "url": "https://{region}.console.aws.amazon.com/dynamodbv2/home?region={region}#backups"}],
             "focus": "Review backup status — on-demand backup count, Point-in-Time Recovery (PITR) enabled/disabled per table"},
            {"id": "global_tables", "name": "Global Tables", "description": "Multi-region replicated tables",
             "pages": [{"label": "dynamodb_global", "display": "Global Tables", "url": "https://{region}.console.aws.amazon.com/dynamodbv2/home?region={region}#global-tables"}],
             "focus": "Review global table configurations — replicated regions, replication latency, and conflict resolution settings"},
            {"id": "imports", "name": "Imports from S3", "description": "S3 data import jobs",
             "pages": [{"label": "dynamodb_imports", "display": "Imports from S3", "url": "https://{region}.console.aws.amazon.com/dynamodbv2/home?region={region}#imports"}],
             "focus": "Review import jobs — status, source S3 bucket, table destination, and any failed imports"},
            {"id": "exports", "name": "Exports to S3", "description": "Table data export jobs",
             "pages": [{"label": "dynamodb_exports", "display": "Exports to S3", "url": "https://{region}.console.aws.amazon.com/dynamodbv2/home?region={region}#exports"}],
             "focus": "Review export jobs — destination S3 bucket, export format, status, and whether exports are encrypted"},
            {"id": "streams", "name": "Streams", "description": "DynamoDB change data streams",
             "pages": [{"label": "dynamodb_streams", "display": "Tables (streams view)", "url": "https://{region}.console.aws.amazon.com/dynamodbv2/home?region={region}#tables"}],
             "focus": "Identify which tables have DynamoDB Streams enabled — stream view type and downstream Lambda consumers"},
            {"id": "reserved_capacity", "name": "Reserved Capacity", "description": "Reserved read/write capacity purchases",
             "pages": [{"label": "dynamodb_reserved", "display": "Reserved Capacity", "url": "https://{region}.console.aws.amazon.com/dynamodbv2/home?region={region}#reserved-capacity"}],
             "focus": "Review reserved capacity purchases — region, capacity type, count, and utilization for cost optimization"},
            {"id": "monitoring", "name": "CloudWatch Metrics", "description": "Performance and error metrics",
             "pages": [{"label": "dynamodb_metrics", "display": "Tables (monitoring)", "url": "https://{region}.console.aws.amazon.com/dynamodbv2/home?region={region}#tables"}],
             "focus": "Review table-level metrics — throttled requests, system errors, consumed capacity, and latency trends"},
        ],
    },
    "cloudtrail": {
        "name": "CloudTrail",
        "description": "API Activity Logging",
        "checks": [
            {"id": "trails", "name": "Trail Configuration", "description": "Active CloudTrail trails",
             "pages": [{"label": "cloudtrail_trails", "display": "Trails", "url": "https://{region}.console.aws.amazon.com/cloudtrail/home?region={region}#/trails"}],
             "focus": "Review trails — multi-region coverage, S3 bucket destination, log file validation, KMS encryption, and SNS notifications"},
            {"id": "event_history", "name": "Event History", "description": "Recent API activity (last 90 days)",
             "pages": [{"label": "cloudtrail_events", "display": "Event History", "url": "https://{region}.console.aws.amazon.com/cloudtrail/home?region={region}#/events"}],
             "focus": "Review recent API events — look for unusual access patterns, root account usage, or failed authentication attempts"},
            {"id": "insights", "name": "CloudTrail Insights", "description": "Anomalous API activity detection",
             "pages": [{"label": "cloudtrail_insights", "display": "Insights", "url": "https://{region}.console.aws.amazon.com/cloudtrail/home?region={region}#/insights"}],
             "focus": "Review Insights findings — unusual API call rates or error rates that may indicate a security incident or misconfiguration"},
            {"id": "lake", "name": "CloudTrail Lake", "description": "SQL-based event data store",
             "pages": [{"label": "cloudtrail_lake", "display": "Lake", "url": "https://{region}.console.aws.amazon.com/cloudtrail/home?region={region}#/lake"}],
             "focus": "Review event data stores — retention period, KMS encryption, and whether Lake is configured for long-term retention"},
            {"id": "dashboard", "name": "Dashboard", "description": "CloudTrail overview dashboard",
             "pages": [{"label": "cloudtrail_dashboard", "display": "Dashboard", "url": "https://{region}.console.aws.amazon.com/cloudtrail/home?region={region}#/dashboard"}],
             "focus": "Review the CloudTrail dashboard — trail health status, recent activity summary, and top API callers"},
            {"id": "channels", "name": "Channels", "description": "External event integration channels",
             "pages": [{"label": "cloudtrail_channels", "display": "Channels", "url": "https://{region}.console.aws.amazon.com/cloudtrail/home?region={region}#/channels"}],
             "focus": "Review CloudTrail channels for partner event source integrations — channel configurations and destinations"},
            {"id": "s3_logging", "name": "S3 Data Events", "description": "S3 object-level logging",
             "pages": [{"label": "cloudtrail_trails_data", "display": "Trails (data events)", "url": "https://{region}.console.aws.amazon.com/cloudtrail/home?region={region}#/trails"}],
             "focus": "Identify if S3 data event logging is enabled on trails — critical for auditing S3 GetObject/PutObject on sensitive buckets"},
            {"id": "lambda_logging", "name": "Lambda Data Events", "description": "Lambda function invocation logging",
             "pages": [{"label": "cloudtrail_trails_lambda", "display": "Trails (Lambda events)", "url": "https://{region}.console.aws.amazon.com/cloudtrail/home?region={region}#/trails"}],
             "focus": "Identify if Lambda data event logging is configured — important for auditing serverless function invocations"},
        ],
    },
    "config": {
        "name": "AWS Config",
        "description": "Resource Configuration Tracking",
        "checks": [
            {"id": "dashboard", "name": "Compliance Dashboard", "description": "Overall Config compliance overview",
             "pages": [{"label": "config_dashboard", "display": "Dashboard", "url": "https://{region}.console.aws.amazon.com/config/home?region={region}#/dashboard"}],
             "focus": "Review Config compliance status — total rules, compliant vs non-compliant resources, and recording status"},
            {"id": "rules", "name": "Config Rules", "description": "Managed and custom compliance rules",
             "pages": [{"label": "config_rules", "display": "Rules", "url": "https://{region}.console.aws.amazon.com/config/home?region={region}#/rules/view"}],
             "focus": "Review Config rules — compliance status per rule, remediation actions, and identify NONCOMPLIANT rules needing attention"},
            {"id": "resources", "name": "Resource Inventory", "description": "All tracked AWS resources",
             "pages": [{"label": "config_resources", "display": "Resources", "url": "https://{region}.console.aws.amazon.com/config/home?region={region}#/resources"}],
             "focus": "Review resource inventory — resource types tracked, configuration timeline availability, and compliance states"},
            {"id": "conformance_packs", "name": "Conformance Packs", "description": "Pre-built compliance frameworks",
             "pages": [{"label": "config_conformance", "display": "Conformance Packs", "url": "https://{region}.console.aws.amazon.com/config/home?region={region}#/conformance-packs"}],
             "focus": "Review deployed conformance packs (CIS, PCI, HIPAA) — pack-level compliance scores and non-compliant resource counts"},
            {"id": "aggregators", "name": "Aggregators", "description": "Multi-account/region Config data",
             "pages": [{"label": "config_aggregators", "display": "Aggregators", "url": "https://{region}.console.aws.amazon.com/config/home?region={region}#/aggregator/dashboards"}],
             "focus": "Review aggregator configurations — source accounts/regions, authorization status, and aggregate compliance dashboard"},
            {"id": "remediation", "name": "Remediation", "description": "Automated remediation actions",
             "pages": [{"label": "config_remediation", "display": "Rules (remediation)", "url": "https://{region}.console.aws.amazon.com/config/home?region={region}#/rules/view"}],
             "focus": "Identify rules with automatic remediation configured — SSM Automation documents used, retry attempts, and execution status"},
            {"id": "recorders", "name": "Recorders", "description": "Configuration recording settings",
             "pages": [{"label": "config_recorders", "display": "Settings", "url": "https://{region}.console.aws.amazon.com/config/home?region={region}#/settings"}],
             "focus": "Review recorder configuration — which resource types are recorded, delivery channel S3 bucket, and SNS topic settings"},
            {"id": "advanced_queries", "name": "Advanced Queries", "description": "SQL queries on config data",
             "pages": [{"label": "config_queries", "display": "Advanced Queries", "url": "https://{region}.console.aws.amazon.com/config/home?region={region}#/queries"}],
             "focus": "Review saved advanced queries — useful for identifying compliance posture across resource types using SQL syntax"},
        ],
    },
    "sns": {
        "name": "SNS",
        "description": "Simple Notification Service",
        "checks": [
            {"id": "topics", "name": "Topics", "description": "All SNS topics and configurations",
             "pages": [{"label": "sns_topics", "display": "Topics", "url": "https://{region}.console.aws.amazon.com/sns/v3/home?region={region}#/topics"}],
             "focus": "List SNS topics — encryption (KMS), access policies, delivery retry policies, and whether topics are public"},
            {"id": "subscriptions", "name": "Subscriptions", "description": "Topic subscriptions and endpoints",
             "pages": [{"label": "sns_subscriptions", "display": "Subscriptions", "url": "https://{region}.console.aws.amazon.com/sns/v3/home?region={region}#/subscriptions"}],
             "focus": "Review subscriptions — protocol (email/HTTP/SQS/Lambda), confirmation status, and filter policies"},
            {"id": "mobile_push", "name": "Mobile Push Notifications", "description": "Push notification platform apps",
             "pages": [{"label": "sns_push", "display": "Mobile Push", "url": "https://{region}.console.aws.amazon.com/sns/v3/home?region={region}#/mobile/push-notifications"}],
             "focus": "Review mobile push platform applications — certificate expiry, enabled/disabled status, and failure feedback"},
            {"id": "text_messaging", "name": "Text Messaging (SMS)", "description": "SMS messaging preferences",
             "pages": [{"label": "sns_sms", "display": "Text Messaging", "url": "https://{region}.console.aws.amazon.com/sns/v3/home?region={region}#/mobile/text-messaging"}],
             "focus": "Review SMS account settings — spending limit, default message type (Transactional vs Promotional), and sandbox status"},
            {"id": "data_protection", "name": "Data Protection Policies", "description": "PII detection in messages",
             "pages": [{"label": "sns_data_protection", "display": "Data Protection", "url": "https://{region}.console.aws.amazon.com/sns/v3/home?region={region}#/mobile/data-protection"}],
             "focus": "Review data protection policies — which PII data identifiers are configured, audit/deny actions for sensitive data"},
            {"id": "fifo_topics", "name": "FIFO Topics", "description": "Ordered message delivery topics",
             "pages": [{"label": "sns_fifo", "display": "Topics (FIFO)", "url": "https://{region}.console.aws.amazon.com/sns/v3/home?region={region}#/topics"}],
             "focus": "Identify FIFO topics — content-based deduplication settings, message ordering guarantees, and SQS FIFO subscribers"},
            {"id": "dead_letter", "name": "Dead-Letter Queues", "description": "Failed delivery message capture",
             "pages": [{"label": "sns_dlq", "display": "Subscriptions (DLQ)", "url": "https://{region}.console.aws.amazon.com/sns/v3/home?region={region}#/subscriptions"}],
             "focus": "Identify subscriptions with DLQ configured — check DLQ ARN, retention period, and unprocessed message counts"},
            {"id": "access_policies", "name": "Topic Access Policies", "description": "IAM and resource-based policies",
             "pages": [{"label": "sns_policies", "display": "Topics (policies)", "url": "https://{region}.console.aws.amazon.com/sns/v3/home?region={region}#/topics"}],
             "focus": "Review topic access policies for public access — check for overly permissive Principal:* Allow statements"},
        ],
    },
    "sqs": {
        "name": "SQS",
        "description": "Simple Queue Service",
        "checks": [
            {"id": "queues", "name": "Queue Inventory", "description": "All SQS queues",
             "pages": [{"label": "sqs_queues", "display": "Queues", "url": "https://{region}.console.aws.amazon.com/sqs/v2/home?region={region}#/queues"}],
             "focus": "List queues — type (Standard/FIFO), message count, in-flight messages, encryption (SSE/KMS), and visibility timeout"},
            {"id": "dlq", "name": "Dead-Letter Queues", "description": "Failed message retention queues",
             "pages": [{"label": "sqs_dlq", "display": "Queues (DLQ)", "url": "https://{region}.console.aws.amazon.com/sqs/v2/home?region={region}#/queues"}],
             "focus": "Identify queues configured as dead-letter queues — message retention periods and source queues that route to them"},
            {"id": "encryption", "name": "Encryption Settings", "description": "Queue encryption configuration",
             "pages": [{"label": "sqs_encryption", "display": "Queues (encryption)", "url": "https://{region}.console.aws.amazon.com/sqs/v2/home?region={region}#/queues"}],
             "focus": "Check encryption status per queue — SSE-SQS (AWS managed) vs SSE-KMS (customer managed), KMS key IDs"},
            {"id": "access_policies", "name": "Access Policies", "description": "Queue access control policies",
             "pages": [{"label": "sqs_access", "display": "Queues (access policies)", "url": "https://{region}.console.aws.amazon.com/sqs/v2/home?region={region}#/queues"}],
             "focus": "Review queue access policies — identify public access (Principal:*), cross-account access, and service-linked access"},
            {"id": "fifo_queues", "name": "FIFO Queue Settings", "description": "Ordered and exactly-once delivery",
             "pages": [{"label": "sqs_fifo", "display": "Queues (FIFO)", "url": "https://{region}.console.aws.amazon.com/sqs/v2/home?region={region}#/queues"}],
             "focus": "Identify FIFO queues — deduplication settings, throughput mode (basic/high), and content-based deduplication"},
            {"id": "message_retention", "name": "Message Retention", "description": "Message lifetime and visibility settings",
             "pages": [{"label": "sqs_retention", "display": "Queues (retention)", "url": "https://{region}.console.aws.amazon.com/sqs/v2/home?region={region}#/queues"}],
             "focus": "Review retention periods (max 14 days), visibility timeout values, and receive message wait time (long polling)"},
            {"id": "lambda_triggers", "name": "Lambda Event Sources", "description": "Lambda triggers from SQS",
             "pages": [{"label": "sqs_lambda", "display": "Queues (lambda triggers)", "url": "https://{region}.console.aws.amazon.com/sqs/v2/home?region={region}#/queues"}],
             "focus": "Identify queues used as Lambda event sources — batch size, batch window, function ARN, and error handling"},
            {"id": "monitoring", "name": "CloudWatch Metrics", "description": "Queue performance and depth metrics",
             "pages": [{"label": "sqs_metrics", "display": "Queues (monitoring)", "url": "https://{region}.console.aws.amazon.com/sqs/v2/home?region={region}#/queues"}],
             "focus": "Review queue metrics — messages sent/received/deleted, approximate age of oldest message, and DLQ message counts"},
        ],
    },
    "ecs": {
        "name": "ECS",
        "description": "Elastic Container Service",
        "checks": [
            {"id": "clusters", "name": "Cluster Inventory", "description": "All ECS clusters",
             "pages": [{"label": "ecs_clusters", "display": "Clusters", "url": "https://{region}.console.aws.amazon.com/ecs/v2/clusters?region={region}"}],
             "focus": "List clusters — status, number of services/tasks, container insights enabled, capacity providers (Fargate/EC2)"},
            {"id": "services", "name": "Services", "description": "Running ECS services",
             "pages": [{"label": "ecs_services", "display": "Clusters (services)", "url": "https://{region}.console.aws.amazon.com/ecs/v2/clusters?region={region}"}],
             "focus": "Review services — desired vs running task count, launch type, deployment configuration, and auto-scaling policies"},
            {"id": "task_definitions", "name": "Task Definitions", "description": "Container task definitions",
             "pages": [{"label": "ecs_task_defs", "display": "Task Definitions", "url": "https://{region}.console.aws.amazon.com/ecs/v2/task-definitions?region={region}"}],
             "focus": "Review task definitions — container image sources, CPU/memory allocation, network mode, IAM task roles, and secrets management"},
            {"id": "capacity_providers", "name": "Capacity Providers", "description": "Infrastructure capacity providers",
             "pages": [{"label": "ecs_capacity", "display": "Cluster Capacity Providers", "url": "https://{region}.console.aws.amazon.com/ecs/v2/clusters?region={region}"}],
             "focus": "Review capacity provider configurations — Fargate vs EC2, managed scaling settings, base and weight values"},
            {"id": "container_insights", "name": "Container Insights", "description": "Performance monitoring",
             "pages": [{"label": "ecs_insights", "display": "Clusters (insights)", "url": "https://{region}.console.aws.amazon.com/ecs/v2/clusters?region={region}"}],
             "focus": "Check Container Insights enablement per cluster — critical for monitoring CPU/memory and container health"},
            {"id": "service_discovery", "name": "Service Discovery", "description": "Cloud Map service namespaces",
             "pages": [{"label": "ecs_discovery", "display": "Service Discovery", "url": "https://{region}.console.aws.amazon.com/ecs/v2/service-discovery?region={region}"}],
             "focus": "Review service discovery namespaces — DNS-based vs API-based, associated services, and health check configurations"},
            {"id": "account_settings", "name": "Account Settings", "description": "ECS feature opt-ins",
             "pages": [{"label": "ecs_account_settings", "display": "Account Settings", "url": "https://{region}.console.aws.amazon.com/ecs/v2/account-settings?region={region}"}],
             "focus": "Review ECS account settings — new ARN format, container instance long ARN, and ECS Anywhere settings"},
            {"id": "registries", "name": "Container Registries (ECR)", "description": "ECR private repositories",
             "pages": [{"label": "ecr_repositories", "display": "ECR Repositories", "url": "https://{region}.console.aws.amazon.com/ecr/repositories?region={region}"}],
             "focus": "Review ECR repositories — image scan settings (enhanced/basic/none), encryption, lifecycle policies, and public access"},
        ],
    },
    "eks": {
        "name": "EKS",
        "description": "Elastic Kubernetes Service",
        "checks": [
            {"id": "clusters", "name": "Cluster Inventory", "description": "All EKS clusters",
             "pages": [{"label": "eks_clusters", "display": "Clusters", "url": "https://{region}.console.aws.amazon.com/eks/home?region={region}#/clusters"}],
             "focus": "List clusters — Kubernetes version, status, platform version, and whether version is up-to-date"},
            {"id": "node_groups", "name": "Node Groups", "description": "Managed node groups",
             "pages": [{"label": "eks_node_groups", "display": "Clusters (node groups)", "url": "https://{region}.console.aws.amazon.com/eks/home?region={region}#/clusters"}],
             "focus": "Review managed node groups — instance types, min/max/desired size, AMI type, node update strategy"},
            {"id": "fargate_profiles", "name": "Fargate Profiles", "description": "Serverless pod execution profiles",
             "pages": [{"label": "eks_fargate", "display": "Clusters (Fargate profiles)", "url": "https://{region}.console.aws.amazon.com/eks/home?region={region}#/clusters"}],
             "focus": "Review Fargate profiles — namespaces and label selectors, pod execution role, and associated subnets"},
            {"id": "add_ons", "name": "Add-ons", "description": "Managed Kubernetes add-ons",
             "pages": [{"label": "eks_addons", "display": "Clusters (add-ons)", "url": "https://{region}.console.aws.amazon.com/eks/home?region={region}#/clusters"}],
             "focus": "Review installed add-ons — versions (check for update availability), VPC CNI, CoreDNS, kube-proxy, EBS CSI driver"},
            {"id": "networking", "name": "Networking", "description": "Cluster VPC and networking config",
             "pages": [{"label": "eks_networking", "display": "Clusters (networking)", "url": "https://{region}.console.aws.amazon.com/eks/home?region={region}#/clusters"}],
             "focus": "Review cluster networking — VPC, subnets, security groups, endpoint access (public/private), and service IP range"},
            {"id": "logging", "name": "Control Plane Logging", "description": "Kubernetes API server logs",
             "pages": [{"label": "eks_logging", "display": "Clusters (logging)", "url": "https://{region}.console.aws.amazon.com/eks/home?region={region}#/clusters"}],
             "focus": "Check which control plane log types are enabled — API server, audit, authenticator, controller manager, scheduler"},
            {"id": "access_entries", "name": "Access Entries", "description": "IAM principal cluster access",
             "pages": [{"label": "eks_access", "display": "Clusters (access)", "url": "https://{region}.console.aws.amazon.com/eks/home?region={region}#/clusters"}],
             "focus": "Review access entries — IAM principals with cluster access, associated access policies, and cluster-admin bindings"},
            {"id": "insights", "name": "Upgrade Insights", "description": "Cluster upgrade readiness",
             "pages": [{"label": "eks_insights", "display": "Clusters (insights)", "url": "https://{region}.console.aws.amazon.com/eks/home?region={region}#/clusters"}],
             "focus": "Review upgrade insights — deprecated API usage, add-on compatibility, and issues blocking the next Kubernetes version upgrade"},
        ],
    },
    "route53": {
        "name": "Route 53",
        "description": "DNS & Traffic Management",
        "checks": [
            {"id": "hosted_zones", "name": "Hosted Zones", "description": "All DNS hosted zones",
             "pages": [{"label": "route53_zones", "display": "Hosted Zones", "url": "https://us-east-1.console.aws.amazon.com/route53/v2/hostedzones"}],
             "focus": "List hosted zones — public vs private, record count, associated VPCs for private zones, and DNSSEC status"},
            {"id": "health_checks", "name": "Health Checks", "description": "Endpoint health monitoring",
             "pages": [{"label": "route53_health", "display": "Health Checks", "url": "https://us-east-1.console.aws.amazon.com/route53/v2/healthchecks"}],
             "focus": "Review health checks — endpoint type (HTTP/HTTPS/TCP), interval, failure threshold, and current status (healthy/unhealthy)"},
            {"id": "traffic_policies", "name": "Traffic Policies", "description": "Complex routing policy templates",
             "pages": [{"label": "route53_traffic", "display": "Traffic Policies", "url": "https://us-east-1.console.aws.amazon.com/route53/v2/trafficpolicies"}],
             "focus": "Review traffic policies — policy types (latency/weighted/failover), associated policy instances, and configuration"},
            {"id": "resolver", "name": "Resolver", "description": "Hybrid DNS resolution rules",
             "pages": [{"label": "route53_resolver", "display": "Resolver", "url": "https://us-east-1.console.aws.amazon.com/route53resolver/home?region=us-east-1#/endpoints"}],
             "focus": "Review Resolver inbound/outbound endpoints — IP addresses, VPC associations, and forwarding rules for hybrid DNS"},
            {"id": "domains", "name": "Registered Domains", "description": "Route 53 registered domain names",
             "pages": [{"label": "route53_domains", "display": "Registered Domains", "url": "https://us-east-1.console.aws.amazon.com/route53/domains/home#/ListDomains"}],
             "focus": "Review registered domains — expiration dates, auto-renew settings, DNSSEC configuration, and transfer lock status"},
            {"id": "cidr_collections", "name": "CIDR Collections", "description": "IP-based routing groups",
             "pages": [{"label": "route53_cidr", "display": "CIDR Collections", "url": "https://us-east-1.console.aws.amazon.com/route53/v2/cidrcollections"}],
             "focus": "Review CIDR collections and their location groups — used for geographic or IP-based routing policies"},
            {"id": "dnssec", "name": "DNSSEC Signing", "description": "DNS Security Extensions",
             "pages": [{"label": "route53_dnssec", "display": "Hosted Zones (DNSSEC)", "url": "https://us-east-1.console.aws.amazon.com/route53/v2/hostedzones"}],
             "focus": "Identify hosted zones with DNSSEC enabled or disabled — DNSSEC prevents DNS spoofing and cache poisoning attacks"},
            {"id": "query_logging", "name": "Query Logging", "description": "DNS query audit logs",
             "pages": [{"label": "route53_query_log", "display": "Query Logging", "url": "https://us-east-1.console.aws.amazon.com/route53/v2/querylogging"}],
             "focus": "Review query logging configurations — which hosted zones have query logging enabled and CloudWatch log group destinations"},
        ],
    },
    "cloudfront": {
        "name": "CloudFront",
        "description": "Content Delivery Network",
        "checks": [
            {"id": "distributions", "name": "Distributions", "description": "All CloudFront distributions",
             "pages": [{"label": "cloudfront_distributions", "display": "Distributions", "url": "https://us-east-1.console.aws.amazon.com/cloudfront/v4/home#/distributions"}],
             "focus": "List distributions — status (deployed/in-progress), domain name, origins, price class, and WAF association"},
            {"id": "security_policies", "name": "Security Policies", "description": "TLS and HTTP security settings",
             "pages": [{"label": "cloudfront_security", "display": "Distributions (security)", "url": "https://us-east-1.console.aws.amazon.com/cloudfront/v4/home#/distributions"}],
             "focus": "Review TLS minimum protocol version (should be TLS 1.2), HTTP→HTTPS redirect enforcement, and HTTPS-only viewer policies"},
            {"id": "origins", "name": "Origin Configurations", "description": "Distribution origin settings",
             "pages": [{"label": "cloudfront_origins", "display": "Distributions (origins)", "url": "https://us-east-1.console.aws.amazon.com/cloudfront/v4/home#/distributions"}],
             "focus": "Review origin protocols (HTTP/HTTPS), origin shield enablement, connection timeout/retries, and custom headers"},
            {"id": "waf_integration", "name": "WAF & Shield", "description": "Web application firewall protection",
             "pages": [{"label": "cloudfront_waf", "display": "Distributions (WAF)", "url": "https://us-east-1.console.aws.amazon.com/cloudfront/v4/home#/distributions"}],
             "focus": "Identify distributions with WAF ACL attached — distributions without WAF are exposed to SQL injection and XSS attacks"},
            {"id": "cache_policies", "name": "Cache Policies", "description": "Caching behavior configurations",
             "pages": [{"label": "cloudfront_cache", "display": "Cache Policies", "url": "https://us-east-1.console.aws.amazon.com/cloudfront/v4/home#/policies/cache"}],
             "focus": "Review cache policies — TTL settings, cache key parameters, and whether sensitive headers are being cached"},
            {"id": "origin_request_policies", "name": "Origin Request Policies", "description": "Headers forwarded to origin",
             "pages": [{"label": "cloudfront_origin_policies", "display": "Origin Request Policies", "url": "https://us-east-1.console.aws.amazon.com/cloudfront/v4/home#/policies/origin-request"}],
             "focus": "Review what headers, query strings, and cookies are forwarded to origin — check for sensitive data forwarding"},
            {"id": "functions", "name": "CloudFront Functions", "description": "Edge compute functions",
             "pages": [{"label": "cloudfront_functions", "display": "Functions", "url": "https://us-east-1.console.aws.amazon.com/cloudfront/v4/home#/functions"}],
             "focus": "Review CloudFront Functions — runtime, associated distributions, and function code for security headers injection"},
            {"id": "access_logs", "name": "Access Logs & Reports", "description": "Distribution traffic logs",
             "pages": [{"label": "cloudfront_logs", "display": "Distributions (logging)", "url": "https://us-east-1.console.aws.amazon.com/cloudfront/v4/home#/distributions"}],
             "focus": "Check access logging configuration per distribution — S3 bucket destination, prefix, and cookie logging settings"},
        ],
    },
}


# ═══════════════════════════════════════════════════════
# AWS Generic Service Compliance Check
# ═══════════════════════════════════════════════════════

def check_aws_service(account_id, iam_username, iam_password, region, service, check_id=None):
    """Browse to the console pages for the requested AWS service check and screenshot + AI-analyze each.

    If check_id is provided, only that specific check's pages are captured and its focus is used
    to tailor the AI prompt. If check_id is None the first check in the service is used.
    """
    service_info = AWS_SERVICE_PAGES.get(service)
    if not service_info:
        return {
            "provider": "aws",
            "service": service,
            "service_name": service,
            "error": f"Unknown service: {service}",
            "screenshots": [],
            "vision_analysis": {},
            "status": "error",
        }

    checks = service_info.get("checks", [])

    # Resolve the specific check to run
    check_info = None
    if check_id:
        for c in checks:
            if c["id"] == check_id:
                check_info = c
                break
    if check_info is None and checks:
        check_info = checks[0]

    if check_info is None:
        return {
            "provider": "aws",
            "service": service,
            "service_name": service_info["name"],
            "error": "No checks defined for this service",
            "screenshots": [],
            "vision_analysis": {},
            "status": "error",
        }

    pages = check_info["pages"]
    focus = check_info.get("focus", "Provide a thorough analysis of everything visible on this page")

    results = {
        "provider": "aws",
        "service": service,
        "service_name": service_info["name"],
        "service_description": service_info["description"],
        "check": check_info["name"],
        "check_description": check_info["description"],
        "timestamp": datetime.utcnow().isoformat(),
        "screenshots": [],
        "vision_analysis": {},
        "status": "completed",
    }

    screenshots = _take_aws_service_screenshots(account_id, iam_username, iam_password, region, pages)
    results["screenshots"] = screenshots

    # If no real screenshots were captured, the login likely failed
    real_screenshots = [s for s in screenshots if not s["label"].startswith("debug_")]
    if not real_screenshots:
        results["status"] = "error"
        results["error"] = "AWS console login failed or timed out. Please verify your Account ID, IAM username, and password are correct."
        logger.warning("No screenshots captured — marking result as error")
        return results

    # AI-analyze each real screenshot
    for ss in screenshots:
        if ss["label"].startswith("debug_"):
            continue
        if not os.path.exists(ss["path"]):
            continue

        prompt = f"""You are an AWS cloud security and infrastructure auditor reviewing the AWS Management Console.

This screenshot shows the "{service_info['name']} — {ss['description']}" page.

Your analysis focus for this check: {focus}

Provide a thorough, comprehensive analysis of everything visible, guided by the focus above. Cover:
1. What resources and configurations are shown
2. Security posture — both positive findings and potential risks
3. Key configuration details and settings visible
4. Specific, actionable recommendations

Respond ONLY with this JSON (no markdown, no extra text):
{{
    "page_summary": "One sentence describing what this page shows",
    "resources_found": ["resource or item 1", "resource or item 2"],
    "security_observations": ["observation 1 (positive or negative)"],
    "configuration_details": ["key detail 1"],
    "recommendations": ["actionable recommendation 1"],
    "risk_level": "low|medium|high|critical|unknown",
    "confidence": 0.90
}}"""
        try:
            analysis = _analyze_screenshot_with_vision(ss["path"], prompt)
            results["vision_analysis"][ss["label"]] = analysis
        except Exception as e:
            logger.error(f"Vision analysis failed for {ss['label']}: {e}")
            results["vision_analysis"][ss["label"]] = {"error": str(e)}

    return results


def _take_aws_service_screenshots(account_id, iam_username, iam_password, region, pages):
    """Log in via IAM browser login, then navigate to each page in the list and screenshot."""
    screenshots = []
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
    except ImportError:
        logger.warning("Playwright not available — cannot take service screenshots")
        return screenshots

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        )
        page = context.new_page()
        _apply_stealth(page)

        # ── Step 1: IAM console login ──────────────────────────────────────
        signin_url = f"https://{account_id}.signin.aws.amazon.com/console"
        try:
            page.goto(signin_url, wait_until="commit", timeout=60000)
            page.wait_for_timeout(3000)  # let sign-in page JS render
        except PlaywrightTimeout:
            logger.error("Timed out loading AWS sign-in page")
            browser.close()
            return screenshots

        # Fill Account ID radio / field
        try:
            iam_radio = page.locator('input[type="radio"][value="iam"]')
            if iam_radio.count() > 0:
                iam_radio.first.click()
                page.wait_for_timeout(500)
        except Exception:
            pass

        for selector in ['#account', '#resolving_input', 'input[name="account"]', 'input[type="text"]']:
            try:
                el = page.locator(selector)
                if el.count() > 0:
                    el.first.click()
                    page.wait_for_timeout(200)
                    el.first.type(account_id, delay=60)
                    break
            except Exception:
                continue

        # Submit account step
        for selector in ['#next_button', 'button[type="submit"]', 'input[type="submit"]']:
            try:
                el = page.locator(selector)
                if el.count() > 0:
                    el.first.click()
                    page.wait_for_timeout(1000)
                    break
            except Exception:
                continue

        # Fill username
        for selector in ['#username', 'input[name="username"]', 'input[type="text"]']:
            try:
                el = page.locator(selector)
                if el.count() > 0:
                    el.first.click()
                    page.wait_for_timeout(200)
                    el.first.type(iam_username, delay=60)
                    break
            except Exception:
                continue

        # Fill password
        for selector in ['#password', 'input[name="password"]', 'input[type="password"]']:
            try:
                el = page.locator(selector)
                if el.count() > 0:
                    el.first.click()
                    page.wait_for_timeout(200)
                    el.first.type(iam_password, delay=60)
                    break
            except Exception:
                continue

        # Submit login
        for selector in ['#signin_button', 'button[type="submit"]', 'input[type="submit"]']:
            try:
                el = page.locator(selector)
                if el.count() > 0:
                    el.first.click()
                    break
            except Exception:
                continue

        # Wait for redirect to console
        try:
            page.wait_for_url("**/console.aws.amazon.com/**", timeout=25000)
        except PlaywrightTimeout:
            try:
                raw = page.screenshot(full_page=False)
                file_id, filepath, filename = _save_screenshot(raw, "aws", "debug_service_login_failed")
                screenshots.append({
                    "file_id": file_id,
                    "path": filepath,
                    "filename": filename,
                    "label": "debug_service_login_failed",
                    "description": "Login failure — this is what the browser showed when login timed out",
                    "url": page.url,
                })
            except Exception:
                pass
            logger.error("AWS service scan: login timed out")
            browser.close()
            return screenshots

        logger.info("AWS service scan: logged in successfully, navigating to pages")

        # ── Step 2: Navigate to each page and screenshot ─────────────────────
        for page_def in pages:
            label = page_def["label"]
            display = page_def["display"]
            url = page_def["url"].replace("{region}", region)

            try:
                page.goto(url, wait_until="commit", timeout=60000)
                page.wait_for_timeout(5000)  # let dynamic content load

                raw = page.screenshot(full_page=False)
                file_id, filepath, filename = _save_screenshot(raw, "aws", label)
                screenshots.append({
                    "file_id": file_id,
                    "path": filepath,
                    "filename": filename,
                    "label": label,
                    "description": display,
                    "url": page.url,
                })
                logger.info(f"AWS service screenshot captured: {label} ({page.url})")
            except PlaywrightTimeout:
                logger.warning(f"Timeout navigating to {label} ({url}) — skipping")
            except Exception as ex:
                logger.warning(f"Error capturing {label}: {ex}")

        browser.close()

    return screenshots


def _apply_stealth(page):
    """Apply anti-detection patches to a Playwright page.

    Uses playwright-stealth if available, otherwise falls back to manual JS patches.
    Patches: webdriver flag, navigator properties, chrome runtime, canvas/WebGL fingerprints.
    """
    try:
        from playwright_stealth import stealth_sync
        stealth_sync(page)
        logger.info("Stealth mode applied via playwright-stealth")
    except ImportError:
        # Manual fallback patches
        page.add_init_script("""
            // Remove webdriver flag
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            // Realistic language/plugin fingerprint
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            Object.defineProperty(navigator, 'plugins', { get: () => [
                { name: 'Chrome PDF Plugin' }, { name: 'Chrome PDF Viewer' },
                { name: 'Native Client' }
            ]});
            // Add chrome runtime object
            window.chrome = { runtime: {}, loadTimes: function(){}, csi: function(){}, app: {} };
            // Realistic permissions
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (params) =>
                params.name === 'notifications'
                    ? Promise.resolve({ state: Notification.permission })
                    : originalQuery(params);
        """)
        logger.info("Stealth mode applied via manual JS patches")


def _save_screenshot(screenshot_bytes, provider, label):
    """Save a screenshot and return its file ID and path."""
    file_id = str(uuid.uuid4())
    filename = f"{provider}_{label}_{file_id}.png"
    filepath = os.path.join(SCREENSHOTS_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(screenshot_bytes)
    return file_id, filepath, filename


def _analyze_screenshot_with_vision(screenshot_path, analysis_prompt):
    """Send a screenshot to the vision model for compliance analysis."""
    from utils.bedrock_client import get_llm
    from langchain_core.messages import HumanMessage

    with open(screenshot_path, "rb") as f:
        image_data = base64.b64encode(f.read()).decode("utf-8")

    llm = get_llm(temperature=0, max_tokens=2000)

    message = HumanMessage(
        content=[
            {"type": "text", "text": analysis_prompt},
            {
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": "image/png",
                    "data": image_data,
                },
            },
        ]
    )

    response = llm.invoke([message])
    content = response.content.strip()
    if content.startswith("```"):
        content = content.split("\n", 1)[1].rsplit("```", 1)[0]
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return {"raw_analysis": content}


# ═══════════════════════════════════════════════════════
# AWS EBS Encryption Compliance
# ═══════════════════════════════════════════════════════

def check_aws_ebs_encryption(access_key=None, secret_key=None, region="us-east-1",
                              account_id=None, iam_username=None, iam_password=None):
    """Check AWS EBS volume encryption using boto3 and/or Playwright screenshots.

    - access_key + secret_key → boto3 API compliance check + optional STS federation screenshots
    - account_id + iam_username + iam_password → real browser console login screenshots
    - Both can be provided together for full coverage.
    """
    results = {
        "provider": "aws",
        "check": "EBS Volume Encryption",
        "timestamp": datetime.utcnow().isoformat(),
        "screenshots": [],
        "api_findings": {},
        "vision_analysis": {},
        "status": "completed",
        "encryption_enabled": None,
    }

    # ── API checks (only if API keys provided) ──────────────────────────────
    if access_key and secret_key:
        import boto3
        from botocore.exceptions import ClientError

        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )

        # Step 1: Check EBS encryption default setting
        try:
            ec2_client = session.client("ec2", region_name=region)
            enc_response = ec2_client.get_ebs_encryption_by_default()
            ebs_encrypted = enc_response.get("EbsEncryptionByDefault", False)
            results["api_findings"]["ebs_encryption_by_default"] = ebs_encrypted
            results["encryption_enabled"] = ebs_encrypted
        except ClientError as e:
            results["api_findings"]["ebs_encryption_error"] = str(e)

        # Step 3: List EBS volumes
        try:
            ec2_client = session.client("ec2", region_name=region)
            volumes = ec2_client.describe_volumes(MaxResults=50)
            vol_list = volumes.get("Volumes", [])
            encrypted_count = sum(1 for v in vol_list if v.get("Encrypted"))
            total_count = len(vol_list)
            results["api_findings"]["volumes"] = {
                "total": total_count,
                "encrypted": encrypted_count,
                "unencrypted": total_count - encrypted_count,
            }
            if total_count > 0 and encrypted_count == total_count:
                results["encryption_enabled"] = True
            elif total_count > 0 and encrypted_count < total_count:
                results["encryption_enabled"] = False
        except ClientError as e:
            results["api_findings"]["volumes_error"] = str(e)
    else:
        results["api_findings"]["note"] = "No API keys provided — skipping boto3 checks. Compliance determined from screenshots."

    # Step 3: Take screenshots via Playwright
    screenshots = _take_aws_screenshots(
        access_key, secret_key, region,
        account_id=account_id, iam_username=iam_username, iam_password=iam_password,
    )
    results["screenshots"] = screenshots

    # Step 4: Analyze only real (non-debug) screenshots with vision model
    for ss in screenshots:
        if ss["label"].startswith("debug_"):
            continue
        if os.path.exists(ss["path"]):
            prompt = f"""You are a cloud security compliance auditor. Analyze this screenshot from the AWS Console.

This screenshot shows the {ss['label']} page in AWS.

Determine:
1. Is EBS volume encryption enabled by default?
2. Are there any unencrypted EBS volumes visible?
3. What is the overall encryption compliance status?

Respond in this JSON format:
{{
    "encryption_status": "enabled|disabled|partial|unknown",
    "findings": ["list of specific observations from the screenshot"],
    "compliance_assessment": "A clear statement about whether EBS encryption policy is properly configured",
    "confidence": 0.85
}}

Respond ONLY with JSON."""
            try:
                analysis = _analyze_screenshot_with_vision(ss["path"], prompt)
                results["vision_analysis"][ss["label"]] = analysis
            except Exception as e:
                logger.error(f"Vision analysis failed for {ss['label']}: {e}")
                results["vision_analysis"][ss["label"]] = {"error": str(e)}

    # Step 5: Derive encryption_enabled from vision analysis if API checks didn't set it
    if results["encryption_enabled"] is None and results["vision_analysis"]:
        statuses = [
            v.get("encryption_status", "unknown")
            for v in results["vision_analysis"].values()
            if isinstance(v, dict) and "encryption_status" in v
        ]
        if statuses:
            if all(s == "enabled" for s in statuses):
                results["encryption_enabled"] = True
            elif any(s in ("disabled", "partial") for s in statuses):
                results["encryption_enabled"] = False

    return results


def _take_aws_screenshots(access_key, secret_key, region,
                           account_id=None, iam_username=None, iam_password=None):
    """Take real AWS Console screenshots.

    If account_id + iam_username + iam_password are provided, logs in via
    the IAM console sign-in page (real browser login).
    Falls back to STS federation token approach if console credentials absent.
    """
    screenshots = []

    if account_id and iam_username and iam_password:
        screenshots = _take_aws_screenshots_browser(
            account_id, iam_username, iam_password, region
        )
        if screenshots:
            return screenshots
        logger.warning("Browser login failed or returned no screenshots, falling back to federation")

    # Fallback: STS federation token (only if API keys available)
    if not access_key or not secret_key:
        logger.info("No API keys provided and browser login returned no screenshots — no screenshots available")
        return screenshots

    try:
        from playwright.sync_api import sync_playwright
        import boto3

        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )
        sts_client = session.client("sts")

        fed_response = sts_client.get_federation_token(
            Name="compliance-checker",
            Policy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                        "ec2:Describe*",
                        "ec2:GetEbsEncryptionByDefault",
                        "cloudtrail:Describe*",
                        "cloudtrail:LookupEvents",
                    ],
                    "Resource": "*",
                }],
            }),
            DurationSeconds=900,
        )

        credentials = fed_response["Credentials"]
        session_json = json.dumps({
            "sessionId": credentials["AccessKeyId"],
            "sessionKey": credentials["SecretAccessKey"],
            "sessionToken": credentials["SessionToken"],
        })

        signin_token_url = (
            "https://signin.aws.amazon.com/federation"
            f"?Action=getSigninToken&SessionDuration=900"
            f"&Session={urllib.parse.quote(session_json)}"
        )
        token_response = requests.get(signin_token_url, timeout=10)
        signin_token = token_response.json().get("SigninToken")

        if not signin_token:
            logger.warning("Could not get AWS federation sign-in token")
            return screenshots

        ec2_settings_url = f"https://{region}.console.aws.amazon.com/ec2/home?region={region}#Settings:tab=ebsEncryption"
        ec2_ebs_url = f"https://{region}.console.aws.amazon.com/ec2/home?region={region}#Volumes:"
        urls_to_capture = [
            ("ebs_encryption_settings", ec2_settings_url, "EBS Encryption Settings"),
            ("ebs_volumes", ec2_ebs_url, "EBS Volumes List"),
        ]
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = browser.new_context(viewport={"width": 1440, "height": 900})
            page = context.new_page()

            for label, target_url, description in urls_to_capture:
                try:
                    login_url = (
                        "https://signin.aws.amazon.com/federation"
                        f"?Action=login&Issuer=EvidenceIntegrityAgent"
                        f"&Destination={urllib.parse.quote(target_url)}"
                        f"&SigninToken={signin_token}"
                    )
                    page.goto(login_url, wait_until="networkidle", timeout=30000)
                    time.sleep(3)
                    screenshot_bytes = page.screenshot(full_page=False)
                    file_id, filepath, filename = _save_screenshot(screenshot_bytes, "aws", label)
                    screenshots.append({
                        "file_id": file_id, "path": filepath, "filename": filename,
                        "label": label, "description": description, "url": target_url,
                    })
                    logger.info(f"AWS screenshot (federation) captured: {label}")
                except Exception as e:
                    logger.error(f"Failed AWS federation screenshot '{label}': {e}")

            browser.close()

    except ImportError:
        logger.warning("Playwright not installed. Skipping browser screenshots.")
    except Exception as e:
        logger.error(f"AWS federation screenshot error: {e}")

    return screenshots


def _take_aws_screenshots_browser(account_id, iam_username, iam_password, region):
    """Log into AWS Console with IAM username/password and take real screenshots."""
    screenshots = []

    def _debug_screenshot(page, label):
        """Save a debug screenshot and return it as a result screenshot so it shows up in the UI."""
        try:
            raw = page.screenshot(full_page=False)
            file_id, filepath, filename = _save_screenshot(raw, "aws", f"debug_{label}")
            logger.info(f"AWS debug screenshot saved: {label} (URL: {page.url})")
            return {"file_id": file_id, "path": filepath, "filename": filename,
                    "label": f"debug_{label}", "description": f"[DEBUG] {label}", "url": page.url}
        except Exception as ex:
            logger.warning(f"Could not save debug screenshot {label}: {ex}")
            return None

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-blink-features=AutomationControlled"],
            )
            context = browser.new_context(
                viewport={"width": 1440, "height": 900},
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            )
            page = context.new_page()

            # ── Step 1: Navigate to IAM sign-in page ──
            signin_url = f"https://{account_id}.signin.aws.amazon.com/console"
            logger.info(f"AWS browser login: navigating to {signin_url}")
            page.goto(signin_url, wait_until="commit", timeout=60000)
            time.sleep(5)

            logger.info(f"AWS browser login: landed on {page.url}, title: {page.title()}")

            # Debug screenshot: saved to disk for diagnosis only (not shown in results)
            _debug_screenshot(page, "1_signin_page")

            # ── Step 2: Handle possible "Root / IAM user" selector step ──
            # Some accounts show a radio button to choose sign-in type before showing credentials
            try:
                iam_radio = page.query_selector("#iam_user_radio_button, input[value='iam_user'], input[name='signin_type'][value='iam']")
                if iam_radio and not iam_radio.is_checked():
                    logger.info("AWS login: found IAM user radio button, clicking it")
                    iam_radio.click()
                    time.sleep(1)
            except Exception:
                pass

            # ── Step 3: Fill credentials ──
            # AWS OAuth sign-in (eu-north-1.signin.aws.amazon.com/oauth) still uses
            # #username / #password / #signin_button, but we also try role/label selectors.
            filled = False
            try:
                page.wait_for_selector("#username", timeout=15000)
                logger.info("AWS login: found #username field")
                page.fill("#username", iam_username)
                time.sleep(0.5)

                # Check if #password is on the same page or hidden (two-step flow)
                pwd_el = page.query_selector("#password")
                if pwd_el and pwd_el.is_visible():
                    page.fill("#password", iam_password)
                    time.sleep(0.3)
                    filled = True
                    logger.info("AWS login: filled #username and #password on same page")
                else:
                    # Two-step: click Next, wait for password field
                    logger.info("AWS login: #password not visible, looking for Next button")
                    for next_sel in ["#next_button", "button#next_button", "button:has-text('Next')", "input[type='submit']"]:
                        try:
                            next_el = page.query_selector(next_sel)
                            if next_el and next_el.is_visible():
                                next_el.click()
                                time.sleep(2)
                                page.wait_for_selector("#password", timeout=10000)
                                page.fill("#password", iam_password)
                                time.sleep(0.3)
                                filled = True
                                logger.info(f"AWS login: two-step flow — filled password after Next ({next_sel})")
                                break
                        except Exception:
                            continue

            except PlaywrightTimeout:
                logger.warning("AWS login: #username not found, trying label/role-based selectors")

            if not filled:
                # Fallback: try by label or name attributes
                for u_sel, p_sel in [
                    ("input[name='username']", "input[name='password']"),
                    ("input[autocomplete='username']", "input[autocomplete='current-password']"),
                ]:
                    try:
                        page.wait_for_selector(u_sel, timeout=5000)
                        page.fill(u_sel, iam_username)
                        time.sleep(0.3)
                        page.fill(p_sel, iam_password)
                        time.sleep(0.3)
                        filled = True
                        logger.info(f"AWS login: filled via fallback selectors {u_sel}, {p_sel}")
                        break
                    except Exception:
                        continue

            if not filled:
                logger.error("AWS login: could not fill credentials — no matching form fields found")
                _debug_screenshot(page, "2_fill_failed")
                browser.close()
                return screenshots

            # Debug screenshot: after filling, before clicking submit (saved to disk only)
            _debug_screenshot(page, "2_before_submit")

            # ── Step 4: Submit ──
            # Try button click first; fall back to Enter key (more reliable across form variations)
            submitted = False
            for submit_sel in ["#signin_button", "button[type='submit']", "input[type='submit']"]:
                try:
                    el = page.query_selector(submit_sel)
                    if el and el.is_visible():
                        el.click()
                        submitted = True
                        logger.info(f"AWS login: clicked submit via {submit_sel}")
                        break
                except Exception:
                    continue

            if not submitted:
                logger.info("AWS login: no submit button found, pressing Enter on password field")
                try:
                    page.locator("#password").press("Enter")
                    submitted = True
                except Exception:
                    page.keyboard.press("Enter")
                    submitted = True

            logger.info("AWS browser login: credentials submitted, waiting for navigation...")
            time.sleep(3)

            # Debug screenshot: saved to disk only
            _debug_screenshot(page, "3_after_submit")
            logger.info(f"AWS browser login: after submit URL: {page.url}, title: {page.title()}")

            # Check for visible inline errors (wrong password, account locked, etc.)
            for err_sel in ["#error_msg", "#alert_msg", ".error-text", "[id*='error']", "[class*='error']", "p.error", "span.error"]:
                try:
                    el = page.query_selector(err_sel)
                    if el and el.is_visible():
                        err_text = el.inner_text().strip()
                        if err_text:
                            logger.error(f"AWS login: inline error visible — '{err_text}'")
                            break
                except Exception:
                    continue

            # ── Step 5: Wait for the OAuth redirect chain to reach the console ──
            # IMPORTANT: the sign-in URL contains "console.aws.amazon.com" URL-encoded in its
            # redirect_uri query param — check the base URL only (before '?').
            def _is_console_url(url):
                base = url.split("?")[0]
                return (
                    "console.aws.amazon.com" in base
                    and "signin.aws.amazon.com" not in base
                )

            try:
                page.wait_for_url(_is_console_url, timeout=60000)
                try:
                    page.wait_for_load_state("networkidle", timeout=15000)
                except PlaywrightTimeout:
                    pass
                time.sleep(3)
                logger.info(f"AWS browser login: SUCCESS — reached console at {page.url}")
            except PlaywrightTimeout:
                current_url = page.url
                logger.error(f"AWS login: timed out waiting for console redirect. Stuck at: {current_url}")
                page_content = page.content()
                # Debug screenshot at failure point
                _debug_screenshot(page, "4_login_failed")
                if "mfa" in current_url.lower() or "multi-factor" in page_content.lower() or "authenticator" in page_content.lower():
                    logger.warning("AWS MFA required — cannot automate browser login with MFA enabled")
                elif "captcha" in page_content.lower() or "verify" in page_content.lower():
                    logger.error("AWS login: CAPTCHA or human verification challenge detected")
                elif "incorrect" in page_content.lower() or "invalid" in page_content.lower():
                    logger.error("AWS login: incorrect credentials reported by AWS")
                else:
                    logger.error("AWS login: unknown failure — check debug screenshots")
                browser.close()
                return screenshots

            # ── Step 5: Navigate to target pages and screenshot ──
            ec2_settings_url = f"https://{region}.console.aws.amazon.com/ec2/home?region={region}#Settings:"
            ec2_volumes_url = f"https://{region}.console.aws.amazon.com/ec2/home?region={region}#Volumes:"

            pages_to_capture = [
                ("ebs_encryption_settings", ec2_settings_url, "EBS Encryption Settings"),
                ("ebs_volumes", ec2_volumes_url, "EBS Volumes List"),
            ]
            for label, target_url, description in pages_to_capture:
                try:
                    page.goto(target_url, wait_until="commit", timeout=60000)
                    # Wait for React/Angular to render
                    try:
                        page.wait_for_load_state("networkidle", timeout=10000)
                    except PlaywrightTimeout:
                        pass
                    time.sleep(4)
                    screenshot_bytes = page.screenshot(full_page=False)
                    file_id, filepath, filename = _save_screenshot(screenshot_bytes, "aws", label)
                    screenshots.append({
                        "file_id": file_id, "path": filepath, "filename": filename,
                        "label": label, "description": description, "url": target_url,
                    })
                    logger.info(f"AWS browser screenshot captured: {label} (URL: {page.url})")
                except Exception as e:
                    logger.error(f"Failed AWS browser screenshot '{label}': {e}")

            browser.close()

    except ImportError:
        logger.warning("Playwright not installed — cannot take browser screenshots.")
    except Exception as e:
        logger.error(f"AWS browser login error: {e}", exc_info=True)

    return screenshots


# ═══════════════════════════════════════════════════════
# Azure SQL Database & Data Warehouse Encryption
# ═══════════════════════════════════════════════════════

def check_azure_sql_encryption(tenant_id, client_id, client_secret, access_token=None):
    """Check Azure SQL Database and Data Warehouse Transparent Data Encryption."""
    results = {
        "provider": "azure",
        "check": "SQL Database & Data Warehouse Encryption (TDE)",
        "timestamp": datetime.utcnow().isoformat(),
        "screenshots": [],
        "api_findings": {},
        "vision_analysis": {},
        "status": "completed",
        "encryption_enabled": None,
    }

    # Step 1: Get Azure access token
    token = access_token
    if token:
        results["api_findings"]["authentication"] = "success (access token)"
    else:
        try:
            token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            token_data = {
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://management.azure.com/.default",
                "grant_type": "client_credentials",
            }
            token_response = requests.post(token_url, data=token_data, timeout=15)
            token_response.raise_for_status()
            token = token_response.json().get("access_token")
            results["api_findings"]["authentication"] = "success"
        except Exception as e:
            results["api_findings"]["authentication"] = f"failed: {str(e)}"
            results["status"] = "error"
            return results

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Step 2: Check Activity Logs for TDE events
    activity_logs_available = False
    try:
        # Get subscriptions
        subs_url = "https://management.azure.com/subscriptions?api-version=2022-12-01"
        subs_response = requests.get(subs_url, headers=headers, timeout=15)
        subs_response.raise_for_status()
        subscriptions = subs_response.json().get("value", [])

        results["api_findings"]["subscriptions"] = [
            {"id": s["subscriptionId"], "name": s.get("displayName")}
            for s in subscriptions
        ]

        for sub in subscriptions:
            sub_id = sub["subscriptionId"]

            # Check Activity Logs for TDE events
            filter_str = "eventTimestamp ge '2024-01-01' and resourceType eq 'Microsoft.Sql/servers/databases/transparentDataEncryption'"
            logs_url = (
                f"https://management.azure.com/subscriptions/{sub_id}"
                f"/providers/Microsoft.Insights/eventtypes/management/values"
                f"?api-version=2015-04-01&$filter={urllib.parse.quote(filter_str)}"
            )
            try:
                logs_response = requests.get(logs_url, headers=headers, timeout=15)
                if logs_response.status_code == 200:
                    log_entries = logs_response.json().get("value", [])
                    activity_logs_available = len(log_entries) > 0
                    results["api_findings"]["activity_logs"] = {
                        "available": activity_logs_available,
                        "tde_events_count": len(log_entries),
                        "events": [
                            {
                                "operation": e.get("operationName", {}).get("value"),
                                "status": e.get("status", {}).get("value"),
                                "timestamp": e.get("eventTimestamp"),
                            }
                            for e in log_entries[:10]
                        ],
                    }
            except Exception as e:
                results["api_findings"]["activity_logs_error"] = str(e)

            # Step 3: Check SQL Servers and TDE status directly
            sql_servers_url = (
                f"https://management.azure.com/subscriptions/{sub_id}"
                f"/providers/Microsoft.Sql/servers?api-version=2023-05-01-preview"
            )
            try:
                servers_response = requests.get(sql_servers_url, headers=headers, timeout=15)
                if servers_response.status_code == 200:
                    servers = servers_response.json().get("value", [])
                    server_findings = []

                    for server in servers:
                        server_name = server.get("name")
                        server_rg = server.get("id", "").split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in server.get("id", "") else ""

                        # Get databases for this server
                        dbs_url = (
                            f"https://management.azure.com/subscriptions/{sub_id}"
                            f"/resourceGroups/{server_rg}/providers/Microsoft.Sql/servers/{server_name}"
                            f"/databases?api-version=2023-05-01-preview"
                        )
                        dbs_response = requests.get(dbs_url, headers=headers, timeout=15)
                        if dbs_response.status_code == 200:
                            databases = dbs_response.json().get("value", [])

                            for db in databases:
                                db_name = db.get("name")
                                if db_name == "master":
                                    continue

                                # Check TDE status
                                tde_url = (
                                    f"https://management.azure.com/subscriptions/{sub_id}"
                                    f"/resourceGroups/{server_rg}/providers/Microsoft.Sql/servers/{server_name}"
                                    f"/databases/{db_name}/transparentDataEncryption/current"
                                    f"?api-version=2023-05-01-preview"
                                )
                                tde_response = requests.get(tde_url, headers=headers, timeout=15)
                                tde_enabled = False
                                if tde_response.status_code == 200:
                                    tde_state = tde_response.json().get("properties", {}).get("state", "")
                                    tde_enabled = tde_state.lower() == "enabled"

                                server_findings.append({
                                    "server": server_name,
                                    "database": db_name,
                                    "tde_enabled": tde_enabled,
                                })

                    results["api_findings"]["sql_servers"] = server_findings
                    if server_findings:
                        all_encrypted = all(s["tde_enabled"] for s in server_findings)
                        results["encryption_enabled"] = all_encrypted
                    else:
                        results["api_findings"]["sql_servers_note"] = "No SQL databases found"
            except Exception as e:
                results["api_findings"]["sql_servers_error"] = str(e)

    except Exception as e:
        results["api_findings"]["subscription_error"] = str(e)

    # Step 4: Take screenshots via Playwright (render API data as visual reports)
    screenshots = _take_azure_screenshots(results["api_findings"])
    results["screenshots"] = screenshots

    # Step 5: Analyze screenshots
    for ss in screenshots:
        if os.path.exists(ss["path"]):
            prompt = f"""You are a cloud security compliance auditor. Analyze this screenshot from the Azure Portal.

This screenshot shows the {ss['label']} page in Azure.

Determine:
1. Is Transparent Data Encryption (TDE) enabled for Azure SQL Databases?
2. Is encryption enabled for Azure SQL Data Warehouse (Synapse Analytics)?
3. What is the overall encryption compliance status?

Respond in this JSON format:
{{
    "encryption_status": "enabled|disabled|partial|unknown",
    "findings": ["list of specific observations from the screenshot"],
    "compliance_assessment": "A clear statement about the TDE encryption status",
    "confidence": 0.85
}}

Respond ONLY with JSON."""
            try:
                analysis = _analyze_screenshot_with_vision(ss["path"], prompt)
                results["vision_analysis"][ss["label"]] = analysis
            except Exception as e:
                results["vision_analysis"][ss["label"]] = {"error": str(e)}

    return results


def _take_azure_screenshots(api_findings):
    """Render Azure compliance data as Azure Portal-style dark theme HTML and screenshot them."""
    screenshots = []

    try:
        from playwright.sync_api import sync_playwright

        subscriptions = api_findings.get("subscriptions", [])
        sql_servers = api_findings.get("sql_servers", [])
        sql_note = api_findings.get("sql_servers_note", "")
        activity_logs = api_findings.get("activity_logs", {})
        auth_status = api_findings.get("authentication", "unknown")

        auth_ok = auth_status.startswith("success") if auth_status else False
        any_found = len(sql_servers) > 0
        all_encrypted = all(s.get("tde_enabled") for s in sql_servers) if any_found else False
        sub_name = subscriptions[0].get("name", "N/A") if subscriptions else "N/A"
        sub_id = subscriptions[0].get("id", "") if subscriptions else ""

        # Azure Portal Fluent UI dark theme CSS (shared)
        azure_css = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif; background: #1b1a19; color: #d4d4d4; margin: 0; }
.az-topbar { height: 40px; background: #1b1a19; display: flex; align-items: center; padding: 0 16px; border-bottom: 1px solid #323130; }
.az-topbar-logo { color: #fff; font-size: 14px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
.az-topbar-logo svg { width: 18px; height: 18px; flex-shrink: 0; }
.az-topbar-search { margin-left: 24px; background: #323130; border: 1px solid #484644; border-radius: 4px; padding: 4px 12px; color: #a19f9d; font-size: 13px; width: 340px; }
.az-topbar-right { margin-left: auto; display: flex; align-items: center; gap: 16px; }
.az-topbar-icon { width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; color: #a19f9d; cursor: pointer; border-radius: 2px; }
.az-topbar-icon:hover { background: #323130; }
.az-layout { display: flex; min-height: 660px; }
.az-sidebar { width: 220px; background: #252423; border-right: 1px solid #323130; padding: 8px 0; flex-shrink: 0; }
.az-sidebar-item { display: flex; align-items: center; gap: 10px; padding: 8px 16px; color: #d4d4d4; font-size: 13px; cursor: pointer; border-left: 3px solid transparent; }
.az-sidebar-item:hover { background: #323130; }
.az-sidebar-item.active { background: #323130; border-left-color: #0078d4; color: #ffffff; }
.az-sidebar-item svg { width: 16px; height: 16px; flex-shrink: 0; }
.az-sidebar-divider { height: 1px; background: #323130; margin: 8px 16px; }
.az-main { flex: 1; background: #1b1a19; padding: 0; }
.az-breadcrumb { padding: 12px 24px 0; font-size: 12px; color: #a19f9d; }
.az-breadcrumb a { color: #6cb6ff; text-decoration: none; }
.az-breadcrumb span { margin: 0 6px; }
.az-page-title { padding: 8px 24px 4px; font-size: 20px; font-weight: 600; color: #ffffff; }
.az-page-desc { padding: 0 24px 16px; font-size: 13px; color: #a19f9d; }
.az-content { padding: 0 24px 24px; }
.az-card { background: #292827; border: 1px solid #323130; border-radius: 4px; margin-bottom: 16px; }
.az-card-header { padding: 12px 16px; border-bottom: 1px solid #323130; font-size: 14px; font-weight: 600; color: #ffffff; display: flex; align-items: center; gap: 8px; }
.az-card-header svg { width: 16px; height: 16px; flex-shrink: 0; }
.az-card-body { padding: 16px; }
.az-table { width: 100%; border-collapse: collapse; }
.az-table th { text-align: left; font-size: 12px; font-weight: 600; color: #a19f9d; padding: 8px 12px; border-bottom: 1px solid #484644; background: #252423; }
.az-table td { font-size: 13px; color: #d4d4d4; padding: 10px 12px; border-bottom: 1px solid #323130; }
.az-table tr:hover td { background: #323130; }
.az-badge { display: inline-flex; align-items: center; gap: 4px; padding: 2px 10px; border-radius: 2px; font-size: 12px; font-weight: 600; }
.az-badge-success { background: #0e700e; color: #92c353; }
.az-badge-danger { background: #6e0811; color: #f1707b; }
.az-badge-warning { background: #4a3600; color: #f7c948; }
.az-badge-info { background: #003b5c; color: #6cb6ff; }
.az-info-bar { display: flex; align-items: center; gap: 10px; padding: 10px 16px; border-radius: 4px; margin-bottom: 16px; font-size: 13px; }
.az-info-bar-success { background: #052505; border: 1px solid #0e700e; color: #92c353; }
.az-info-bar-warning { background: #2d1f00; border: 1px solid #4a3600; color: #f7c948; }
.az-info-bar-danger { background: #3b0509; border: 1px solid #6e0811; color: #f1707b; }
.az-info-icon { width: 20px; height: 20px; flex-shrink: 0; }
.az-stat-row { display: flex; gap: 16px; margin-bottom: 16px; }
.az-stat { flex: 1; background: #292827; border: 1px solid #323130; border-radius: 4px; padding: 16px; text-align: center; }
.az-stat-value { font-size: 28px; font-weight: 700; color: #ffffff; }
.az-stat-label { font-size: 12px; color: #a19f9d; margin-top: 4px; }
.az-empty { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 40px; color: #a19f9d; }
.az-empty svg { width: 48px; height: 48px; margin-bottom: 12px; color: #484644; }
.az-empty p { font-size: 14px; }
"""

        # ── Azure sidebar SVG icons ──
        icon_home = '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1L1 7h2v7h4V9h2v5h4V7h2L8 1z"/></svg>'
        icon_sql = '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1C5.2 1 3 1.9 3 3v10c0 1.1 2.2 2 5 2s5-.9 5-2V3c0-1.1-2.2-2-5-2zm0 1.5c2.5 0 3.5.7 3.5 1s-1 1-3.5 1-3.5-.7-3.5-1 1-1 3.5-1zM4.5 5.4C5.4 5.8 6.6 6 8 6s2.6-.2 3.5-.6V7.5c0 .3-1 1-3.5 1s-3.5-.7-3.5-1V5.4zm0 4C5.4 9.8 6.6 10 8 10s2.6-.2 3.5-.6v2.1c0 .3-1 1-3.5 1s-3.5-.7-3.5-1V9.4z"/></svg>'
        icon_shield = '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1L2 3.5v4c0 3.6 2.5 6.8 6 8 3.5-1.2 6-4.4 6-8v-4L8 1zm-1 10.6L4.5 9l1-1L7 9.5l3.5-3.5 1 1L7 11.6z"/></svg>'
        icon_key = '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M10.5 1a4.5 4.5 0 00-3.6 7.2L2 13.1V15h2v-1.5h1.5V12H7v-1.5l1.8-1.8A4.5 4.5 0 1010.5 1zm1 3a1 1 0 110-2 1 1 0 010 2z"/></svg>'
        icon_log = '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M2 3h12v1H2V3zm0 3h12v1H2V6zm0 3h8v1H2V9zm0 3h10v1H2v-1z"/></svg>'
        icon_sub = '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zM2.5 8a5.5 5.5 0 0110.7-1.5H9v3h4.2A5.5 5.5 0 012.5 8z"/></svg>'

        # ── Report 1: SQL Databases page ──
        # Build table rows
        db_table_rows = ""
        if any_found:
            for srv in sql_servers:
                tde = srv.get("tde_enabled", False)
                badge_class = "az-badge-success" if tde else "az-badge-danger"
                badge_text = "Enabled" if tde else "Disabled"
                db_table_rows += f"""
                <tr>
                    <td><span style="color:#6cb6ff">{srv.get('database', 'N/A')}</span></td>
                    <td>{srv.get('server', 'N/A')}</td>
                    <td>{sub_name}</td>
                    <td><span class="az-badge {badge_class}">{badge_text}</span></td>
                    <td>SQL database</td>
                </tr>"""

        if any_found:
            info_class = "az-info-bar-success" if all_encrypted else "az-info-bar-danger"
            info_text = f"All {len(sql_servers)} database(s) have Transparent Data Encryption enabled." if all_encrypted else f"Warning: {sum(1 for s in sql_servers if not s.get('tde_enabled'))} of {len(sql_servers)} database(s) do not have TDE enabled."
            info_icon_svg = '<svg class="az-info-icon" viewBox="0 0 20 20" fill="currentColor"><path d="M10 2a8 8 0 100 16 8 8 0 000-16zm1 11H9V9h2v4zm0-6H9V5h2v2z"/></svg>'
            table_html = f"""
            <div class="az-info-bar {info_class}">{info_icon_svg}{info_text}</div>
            <table class="az-table">
                <thead><tr><th>Name</th><th>Server</th><th>Subscription</th><th>TDE Status</th><th>Type</th></tr></thead>
                <tbody>{db_table_rows}</tbody>
            </table>"""
        else:
            table_html = f"""
            <div class="az-info-bar az-info-bar-warning">
                <svg class="az-info-icon" viewBox="0 0 20 20" fill="currentColor"><path d="M10 2a8 8 0 100 16 8 8 0 000-16zm1 11H9V9h2v4zm0-6H9V5h2v2z"/></svg>
                {sql_note or 'No SQL databases found in this subscription.'}
            </div>
            <div class="az-empty">
                <svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="8" y="6" width="32" height="36" rx="3"/><path d="M16 16h16M16 22h16M16 28h10"/></svg>
                <p>No SQL databases to display</p>
                <p style="font-size:12px;margin-top:4px;color:#605e5c">Create a SQL database to get started with encryption monitoring.</p>
            </div>"""

        sql_html = f"""<!DOCTYPE html><html><head><style>{azure_css}</style></head><body>
<div class="az-topbar">
    <div class="az-topbar-logo">
        <span style="color:#0078d4;font-weight:800;font-size:15px;margin-right:2px">&#9650;</span>
        Microsoft Azure
    </div>
    <div class="az-topbar-search">Search resources, services, and docs (G+/)</div>
    <div class="az-topbar-right">
        <div class="az-topbar-icon"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1.5a1 1 0 011 1v5a1 1 0 01-2 0v-5a1 1 0 011-1zm0 10a1.25 1.25 0 100 2.5 1.25 1.25 0 000-2.5z"/></svg></div>
        <div class="az-topbar-icon"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a2.5 2.5 0 012.5 2.5V5h.5A1.5 1.5 0 0112.5 6.5v5a1.5 1.5 0 01-1.5 1.5h-6A1.5 1.5 0 013.5 11.5v-5A1.5 1.5 0 015 5h.5V3.5A2.5 2.5 0 018 1z"/></svg></div>
    </div>
</div>
<div class="az-layout">
    <div class="az-sidebar">
        <div class="az-sidebar-item">{icon_home} Home</div>
        <div class="az-sidebar-item">{icon_sub} Subscriptions</div>
        <div class="az-sidebar-divider"></div>
        <div class="az-sidebar-item active">{icon_sql} SQL databases</div>
        <div class="az-sidebar-item">{icon_shield} Security Center</div>
        <div class="az-sidebar-item">{icon_key} Encryption</div>
        <div class="az-sidebar-item">{icon_log} Activity log</div>
    </div>
    <div class="az-main">
        <div class="az-breadcrumb"><a href="#">Home</a><span>&gt;</span><a href="#">SQL databases</a></div>
        <div class="az-page-title">SQL databases</div>
        <div class="az-page-desc">Subscription: {sub_name} ({sub_id[:8]}...)</div>
        <div class="az-content">
            {table_html}
        </div>
    </div>
</div>
</body></html>"""

        # ── Report 2: Transparent Data Encryption page ──
        # Activity log section
        activity_rows = ""
        if activity_logs:
            events = activity_logs.get("events", [])
            for ev in events[:8]:
                op = ev.get("operation", "N/A")
                st = ev.get("status", "N/A")
                ts = ev.get("timestamp", "N/A")[:19] if ev.get("timestamp") else "N/A"
                st_class = "az-badge-success" if st.lower() in ("succeeded", "success") else "az-badge-warning"
                activity_rows += f"""
                <tr>
                    <td>{op}</td>
                    <td><span class="az-badge {st_class}">{st}</span></td>
                    <td>{ts}</td>
                </tr>"""

        activity_section = ""
        if activity_logs:
            tde_count = activity_logs.get("tde_events_count", 0)
            if activity_rows:
                activity_section = f"""
                <div class="az-card">
                    <div class="az-card-header">{icon_log} Activity Log &mdash; TDE Events ({tde_count})</div>
                    <div class="az-card-body" style="padding:0">
                        <table class="az-table">
                            <thead><tr><th>Operation</th><th>Status</th><th>Timestamp</th></tr></thead>
                            <tbody>{activity_rows}</tbody>
                        </table>
                    </div>
                </div>"""
            else:
                activity_section = f"""
                <div class="az-card">
                    <div class="az-card-header">{icon_log} Activity Log &mdash; TDE Events</div>
                    <div class="az-card-body">
                        <div class="az-info-bar az-info-bar-warning">
                            <svg class="az-info-icon" viewBox="0 0 20 20" fill="currentColor"><path d="M10 2a8 8 0 100 16 8 8 0 000-16zm1 11H9V9h2v4zm0-6H9V5h2v2z"/></svg>
                            No TDE-related events found in the activity log.
                        </div>
                    </div>
                </div>"""

        enc_html = f"""<!DOCTYPE html><html><head><style>{azure_css}</style></head><body>
<div class="az-topbar">
    <div class="az-topbar-logo">
        <span style="color:#0078d4;font-weight:800;font-size:15px;margin-right:2px">&#9650;</span>
        Microsoft Azure
    </div>
    <div class="az-topbar-search">Search resources, services, and docs (G+/)</div>
    <div class="az-topbar-right">
        <div class="az-topbar-icon"><svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 1.5a1 1 0 011 1v5a1 1 0 01-2 0v-5a1 1 0 011-1zm0 10a1.25 1.25 0 100 2.5 1.25 1.25 0 000-2.5z"/></svg></div>
    </div>
</div>
<div class="az-layout">
    <div class="az-sidebar">
        <div class="az-sidebar-item">{icon_home} Home</div>
        <div class="az-sidebar-item">{icon_sub} Subscriptions</div>
        <div class="az-sidebar-divider"></div>
        <div class="az-sidebar-item">{icon_sql} SQL databases</div>
        <div class="az-sidebar-item">{icon_shield} Security Center</div>
        <div class="az-sidebar-item active">{icon_key} Encryption</div>
        <div class="az-sidebar-item">{icon_log} Activity log</div>
    </div>
    <div class="az-main">
        <div class="az-breadcrumb"><a href="#">Home</a><span>&gt;</span><a href="#">Security</a><span>&gt;</span><a href="#">Transparent Data Encryption</a></div>
        <div class="az-page-title">Transparent Data Encryption (TDE)</div>
        <div class="az-page-desc">Overview of SQL database encryption across your subscriptions</div>
        <div class="az-content">
            <div class="az-stat-row">
                <div class="az-stat">
                    <div class="az-stat-value" style="color:#6cb6ff">{len(subscriptions)}</div>
                    <div class="az-stat-label">Subscriptions</div>
                </div>
                <div class="az-stat">
                    <div class="az-stat-value">{len(sql_servers)}</div>
                    <div class="az-stat-label">SQL Databases</div>
                </div>
                <div class="az-stat">
                    <div class="az-stat-value" style="color:{'#92c353' if all_encrypted and any_found else '#f7c948' if not any_found else '#f1707b'}">{sum(1 for s in sql_servers if s.get('tde_enabled'))}</div>
                    <div class="az-stat-label">TDE Enabled</div>
                </div>
                <div class="az-stat">
                    <div class="az-stat-value" style="font-size:16px;color:{'#92c353' if auth_ok else '#f1707b'}">{'OK' if auth_ok else 'FAIL'}</div>
                    <div class="az-stat-label">Authentication</div>
                </div>
            </div>

            <div class="az-card">
                <div class="az-card-header">{icon_sub} Subscriptions</div>
                <div class="az-card-body" style="padding:0">
                    <table class="az-table">
                        <thead><tr><th>Subscription Name</th><th>Subscription ID</th><th>SQL Databases</th></tr></thead>
                        <tbody>{''.join(f'<tr><td><span style="color:#6cb6ff">{s.get("name","N/A")}</span></td><td style="font-family:monospace;font-size:12px">{s.get("id","N/A")}</td><td>{len(sql_servers)}</td></tr>' for s in subscriptions) if subscriptions else '<tr><td colspan="3" style="color:#a19f9d">No subscriptions</td></tr>'}</tbody>
                    </table>
                </div>
            </div>

            {activity_section}
        </div>
    </div>
</div>
</body></html>"""

        reports = [
            ("sql_databases", sql_html, "SQL Databases"),
            ("sql_encryption", enc_html, "SQL Encryption Overview"),
        ]

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = browser.new_context(viewport={"width": 1366, "height": 768})
            page = context.new_page()

            for label, content, description in reports:
                try:
                    page.set_content(content, wait_until="networkidle")
                    time.sleep(1)
                    screenshot_bytes = page.screenshot(full_page=False)
                    file_id, filepath, filename = _save_screenshot(screenshot_bytes, "azure", label)
                    screenshots.append({
                        "file_id": file_id,
                        "path": filepath,
                        "filename": filename,
                        "label": label,
                        "description": description,
                        "url": "rendered-from-api-data",
                    })
                    logger.info(f"Azure screenshot captured: {label}")
                except Exception as e:
                    logger.error(f"Failed to capture Azure screenshot '{label}': {e}")

            browser.close()

    except ImportError:
        logger.warning("Playwright not installed. Skipping browser screenshots.")
    except Exception as e:
        logger.error(f"Azure screenshot capture error: {e}")

    return screenshots


# ═══════════════════════════════════════════════════════
# GitHub MFA Verification
# ═══════════════════════════════════════════════════════

def check_github_mfa(api_token):
    """Check GitHub MFA (Two-Factor Authentication) status."""
    results = {
        "provider": "github",
        "check": "Multi-Factor Authentication (MFA)",
        "timestamp": datetime.utcnow().isoformat(),
        "screenshots": [],
        "api_findings": {},
        "vision_analysis": {},
        "status": "completed",
        "mfa_enabled": None,
    }

    headers = {
        "Authorization": f"token {api_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Step 1: Get authenticated user info
    try:
        user_response = requests.get("https://api.github.com/user", headers=headers, timeout=15)
        user_response.raise_for_status()
        user_data = user_response.json()
        results["api_findings"]["user"] = {
            "login": user_data.get("login"),
            "name": user_data.get("name"),
            "email": user_data.get("email"),
            "two_factor_authentication": user_data.get("two_factor_authentication"),
        }

        mfa_status = user_data.get("two_factor_authentication")
        if mfa_status is not None:
            results["mfa_enabled"] = mfa_status
        results["api_findings"]["authentication"] = "success"
    except Exception as e:
        results["api_findings"]["authentication"] = f"failed: {str(e)}"
        results["status"] = "error"
        return results

    # Step 2: Check organization MFA requirements (if user is in orgs)
    try:
        orgs_response = requests.get("https://api.github.com/user/orgs", headers=headers, timeout=15)
        if orgs_response.status_code == 200:
            orgs = orgs_response.json()
            org_findings = []
            for org in orgs:
                org_name = org.get("login")
                # Check org MFA requirement
                org_detail_response = requests.get(
                    f"https://api.github.com/orgs/{org_name}",
                    headers=headers, timeout=15,
                )
                if org_detail_response.status_code == 200:
                    org_data = org_detail_response.json()
                    org_findings.append({
                        "name": org_name,
                        "two_factor_requirement_enabled": org_data.get("two_factor_requirement_enabled"),
                    })

                # List members without 2FA (requires admin)
                no_2fa_url = f"https://api.github.com/orgs/{org_name}/members?filter=2fa_disabled"
                no_2fa_response = requests.get(no_2fa_url, headers=headers, timeout=15)
                if no_2fa_response.status_code == 200:
                    members_without_2fa = no_2fa_response.json()
                    org_findings[-1]["members_without_2fa"] = len(members_without_2fa)

            results["api_findings"]["organizations"] = org_findings
    except Exception as e:
        results["api_findings"]["organizations_error"] = str(e)

    # Step 3: Take screenshots via Playwright
    screenshots = _take_github_screenshots(api_token, user_data.get("login", ""))
    results["screenshots"] = screenshots

    # Step 4: Analyze screenshots with vision model
    for ss in screenshots:
        if os.path.exists(ss["path"]):
            prompt = f"""You are a security compliance auditor. Analyze this screenshot from GitHub.

This screenshot shows the {ss['label']} page on GitHub.

Determine:
1. Is Multi-Factor Authentication (MFA / 2FA) enabled for this account?
2. What security settings are visible?
3. What is the overall MFA compliance status?

Respond in this JSON format:
{{
    "mfa_status": "enabled|disabled|unknown",
    "findings": ["list of specific observations from the screenshot"],
    "compliance_assessment": "A clear statement about whether MFA is properly configured",
    "confidence": 0.85
}}

Respond ONLY with JSON."""
            try:
                analysis = _analyze_screenshot_with_vision(ss["path"], prompt)
                results["vision_analysis"][ss["label"]] = analysis
            except Exception as e:
                results["vision_analysis"][ss["label"]] = {"error": str(e)}

    return results


def _take_github_screenshots(api_token, username):
    """Render GitHub security data as visual reports and screenshot them."""
    screenshots = []

    headers = {
        "Authorization": f"token {api_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Fetch data via API
    user_data = {}
    try:
        resp = requests.get("https://api.github.com/user", headers=headers, timeout=15)
        if resp.status_code == 200:
            user_data = resp.json()
    except Exception:
        pass

    org_data = []
    try:
        resp = requests.get("https://api.github.com/user/orgs", headers=headers, timeout=15)
        if resp.status_code == 200:
            for org in resp.json():
                org_detail = requests.get(f"https://api.github.com/orgs/{org['login']}", headers=headers, timeout=15)
                if org_detail.status_code == 200:
                    org_data.append(org_detail.json())
    except Exception:
        pass

    # Fetch user's public profile page screenshot
    try:
        from playwright.sync_api import sync_playwright

        mfa_enabled = user_data.get("two_factor_authentication", False)

        # Build HTML reports from API data
        reports = []

        # Report 1: User Security Overview
        mfa_badge_color = "#2ea043" if mfa_enabled else "#da3633"
        mfa_badge_text = "ENABLED" if mfa_enabled else "DISABLED"
        mfa_icon = "&#x2713;" if mfa_enabled else "&#x2717;"

        orgs_html = ""
        if org_data:
            org_rows = ""
            for org in org_data:
                org_2fa = org.get("two_factor_requirement_enabled", False)
                org_color = "#2ea043" if org_2fa else "#da3633"
                org_status = "Required" if org_2fa else "Not Required"
                org_rows += f"""
                <tr>
                    <td><img src="{org.get('avatar_url', '')}" width="24" height="24" style="border-radius:50%;vertical-align:middle;margin-right:8px">{org.get('login', 'N/A')}</td>
                    <td><span style="color:{org_color};font-weight:600">{org_status}</span></td>
                </tr>"""
            orgs_html = f"""
            <div style="margin-top:24px">
                <h3 style="color:#e6edf3;font-size:16px;margin-bottom:12px;border-bottom:1px solid #30363d;padding-bottom:8px">Organization 2FA Requirements</h3>
                <table style="width:100%;border-collapse:collapse">
                    <tr><th style="text-align:left;color:#8b949e;font-size:12px;padding:8px 0;border-bottom:1px solid #21262d">Organization</th><th style="text-align:left;color:#8b949e;font-size:12px;padding:8px 0;border-bottom:1px solid #21262d">2FA Policy</th></tr>
                    {org_rows}
                </table>
            </div>"""

        security_html = f"""<!DOCTYPE html>
<html><head><style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Noto Sans, Helvetica, Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 32px; }}
.container {{ max-width: 800px; margin: 0 auto; }}
.header {{ display: flex; align-items: center; gap: 16px; margin-bottom: 32px; padding-bottom: 16px; border-bottom: 1px solid #30363d; }}
.avatar {{ width: 64px; height: 64px; border-radius: 50%; border: 2px solid #30363d; }}
.user-info h1 {{ font-size: 24px; color: #e6edf3; margin: 0 0 4px; }}
.user-info p {{ font-size: 14px; color: #8b949e; margin: 0; }}
.badge {{ display: inline-flex; align-items: center; gap: 6px; padding: 6px 16px; border-radius: 20px; font-size: 13px; font-weight: 600; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 24px; margin-bottom: 16px; }}
.status-row {{ display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid #21262d; }}
.status-row:last-child {{ border-bottom: none; }}
.status-label {{ color: #c9d1d9; font-size: 14px; }}
.status-value {{ font-weight: 600; font-size: 14px; }}
.section-title {{ color: #e6edf3; font-size: 20px; font-weight: 600; margin: 0 0 16px; display: flex; align-items: center; gap: 8px; }}
.github-logo {{ color: #e6edf3; }}
</style></head><body>
<div class="container">
    <div class="header">
        <img class="avatar" src="{user_data.get('avatar_url', 'https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png')}" alt="avatar">
        <div class="user-info">
            <h1>{user_data.get('name', user_data.get('login', 'Unknown'))}</h1>
            <p>@{user_data.get('login', 'unknown')} &middot; {user_data.get('email') or 'No public email'}</p>
        </div>
    </div>
    <h2 class="section-title">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#e6edf3" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        Security Settings &mdash; Two-Factor Authentication
    </h2>
    <div class="card">
        <div class="status-row">
            <span class="status-label">Two-Factor Authentication (2FA)</span>
            <span class="badge" style="background:{mfa_badge_color}22;color:{mfa_badge_color};border:1px solid {mfa_badge_color}44">{mfa_icon} {mfa_badge_text}</span>
        </div>
        <div class="status-row">
            <span class="status-label">Account Type</span>
            <span class="status-value" style="color:#8b949e">{user_data.get('type', 'User')}</span>
        </div>
        <div class="status-row">
            <span class="status-label">Public Repos</span>
            <span class="status-value" style="color:#8b949e">{user_data.get('public_repos', 0)}</span>
        </div>
        <div class="status-row">
            <span class="status-label">Account Created</span>
            <span class="status-value" style="color:#8b949e">{user_data.get('created_at', 'N/A')[:10]}</span>
        </div>
        <div class="status-row">
            <span class="status-label">Profile URL</span>
            <span class="status-value" style="color:#58a6ff">{user_data.get('html_url', 'N/A')}</span>
        </div>
        {orgs_html}
    </div>
    <p style="color:#484f58;font-size:12px;text-align:center;margin-top:24px">
        Data retrieved via GitHub REST API &middot; GET /user &middot; Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
    </p>
</div>
</body></html>"""

        reports.append(("mfa_status", security_html, "GitHub MFA Security Report"))

        # Report 2: User's public profile page
        profile_url = user_data.get("html_url", f"https://github.com/{username}")
        reports.append(("public_profile", profile_url, "GitHub Public Profile"))

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = browser.new_context(viewport={"width": 1024, "height": 900})
            page = context.new_page()

            for label, content, description in reports:
                try:
                    if content.startswith("http"):
                        page.goto(content, wait_until="networkidle", timeout=20000)
                        time.sleep(2)
                    else:
                        page.set_content(content, wait_until="networkidle")
                        time.sleep(1)

                    screenshot_bytes = page.screenshot(full_page=True)
                    file_id, filepath, filename = _save_screenshot(screenshot_bytes, "github", label)
                    screenshots.append({
                        "file_id": file_id,
                        "path": filepath,
                        "filename": filename,
                        "label": label,
                        "description": description,
                        "url": content if content.startswith("http") else "rendered-from-api-data",
                    })
                    logger.info(f"GitHub screenshot captured: {label}")
                except Exception as e:
                    logger.error(f"Failed to capture GitHub screenshot '{label}': {e}")

            browser.close()

    except ImportError:
        logger.warning("Playwright not installed. Skipping browser screenshots.")
    except Exception as e:
        logger.error(f"GitHub screenshot capture error: {e}")

    return screenshots



# ═══════════════════════════════════════════════════════
# Datadog Service Registry
# ═══════════════════════════════════════════════════════

DATADOG_SERVICE_PAGES = {
    "monitors_alerts": {
        "name": "Monitors & Alerts",
        "description": "Alert monitors, SLOs, and notification policies",
        "checks": [
            {"id": "monitors_overview", "name": "Monitor Overview", "description": "All configured monitors and their status",
             "pages": [{"label": "dd_monitors", "display": "Monitors", "url": "/monitors/manage"}],
             "focus": "List all monitors — their status (OK/Alert/Warn/No Data), type (metric/log/APM/composite), and identify monitors in alert state or with no data"},
            {"id": "triggered_alerts", "name": "Triggered Alerts", "description": "Currently firing alerts",
             "pages": [{"label": "dd_triggered", "display": "Triggered Monitors", "url": "/monitors/triggered"}],
             "focus": "Review all currently triggered monitors — severity, duration, affected services/hosts, and any monitors that have been alerting for an extended period"},
            {"id": "slos", "name": "Service Level Objectives", "description": "SLO status and error budgets",
             "pages": [{"label": "dd_slos", "display": "SLOs", "url": "/slo"}],
             "focus": "Review SLO compliance — which SLOs are on track vs breaching, error budget remaining, and SLOs at risk of failing within the next 7 days"},
            {"id": "downtime", "name": "Scheduled Downtimes", "description": "Maintenance windows and alert suppressions",
             "pages": [{"label": "dd_downtime", "display": "Downtimes", "url": "/monitors/downtimes"}],
             "focus": "Review scheduled downtimes — scope, duration, which monitors are silenced, and identify any permanent or overly broad downtimes masking real issues"},
            {"id": "monitor_settings", "name": "Monitor Settings & Policies", "description": "Notification channels and escalation policies",
             "pages": [{"label": "dd_monitor_settings", "display": "Monitor Settings", "url": "/monitors/settings"}],
             "focus": "Review monitor notification settings — default routing, escalation policies, and whether critical monitors have proper alert recipients configured"},
            {"id": "composite_monitors", "name": "Composite Monitors", "description": "Multi-condition combined monitors",
             "pages": [{"label": "dd_composite", "display": "Composite Monitors", "url": "/monitors/manage?q=type%3Acomposite"}],
             "focus": "Review composite monitor logic — which sub-monitors are combined, the boolean expression used, and whether the composite conditions make security sense"},
            {"id": "synthetics", "name": "Synthetic Tests", "description": "Uptime and browser synthetic tests",
             "pages": [{"label": "dd_synthetics", "display": "Synthetic Tests", "url": "/synthetics/list"}],
             "focus": "List synthetic tests — API tests, browser tests, their locations, frequency, alert thresholds, and tests that are failing or have recent failures"},
            {"id": "alerts_history", "name": "Alert History", "description": "Recent alert events and resolutions",
             "pages": [{"label": "dd_alert_history", "display": "Alert History", "url": "/monitors/manage?q=status%3Aalert"}],
             "focus": "Review monitors currently in alert — how long they have been alerting, affected resources, and whether appropriate responders are notified"},
        ],
    },
    "infrastructure": {
        "name": "Infrastructure",
        "description": "Hosts, containers, processes, and network monitoring",
        "checks": [
            {"id": "host_map", "name": "Host Map", "description": "All monitored hosts and their health",
             "pages": [{"label": "dd_hostmap", "display": "Host Map", "url": "/infrastructure/map"}],
             "focus": "Review the host map — total host count, health distribution (green/yellow/red), host groups, and any hosts reporting issues or going silent"},
            {"id": "host_list", "name": "Host List", "description": "Infrastructure host inventory",
             "pages": [{"label": "dd_hosts", "display": "Host List", "url": "/infrastructure"}],
             "focus": "List all hosts — their agent version, platform, CPU/memory usage, last reported time, and identify hosts with outdated agents or high resource utilization"},
            {"id": "containers", "name": "Containers", "description": "Running containers and resource usage",
             "pages": [{"label": "dd_containers", "display": "Containers", "url": "/containers"}],
             "focus": "Review container inventory — container status, image names, resource consumption (CPU/memory), and containers with excessive resource usage or frequent restarts"},
            {"id": "processes", "name": "Live Processes", "description": "Running processes across infrastructure",
             "pages": [{"label": "dd_processes", "display": "Live Processes", "url": "/process"}],
             "focus": "Review live processes — top CPU/memory consumers, unusual process names, and processes running as root or with elevated privileges"},
            {"id": "network", "name": "Network Performance", "description": "Service-to-service network flows",
             "pages": [{"label": "dd_network", "display": "Network", "url": "/network"}],
             "focus": "Analyze network flows — top talkers, unexpected connections, high error-rate flows, and services with unusual outbound traffic patterns"},
            {"id": "serverless", "name": "Serverless Functions", "description": "Lambda and serverless monitoring",
             "pages": [{"label": "dd_serverless", "display": "Serverless", "url": "/functions"}],
             "focus": "Review serverless functions — invocation counts, error rates, cold start frequency, and functions with high duration or memory usage"},
            {"id": "cloud_cost", "name": "Cloud Cost Management", "description": "Cloud spend analysis and optimization",
             "pages": [{"label": "dd_cloud_cost", "display": "Cloud Cost", "url": "/cost-management"}],
             "focus": "Review cloud cost breakdown — top cost services, anomalous spend increases, cost by tag/team, and optimization recommendations"},
            {"id": "agent_status", "name": "Agent Health", "description": "Datadog agent deployment status",
             "pages": [{"label": "dd_agent", "display": "Agent Status", "url": "/infrastructure"}],
             "focus": "Review Datadog agent deployment — agent versions deployed, hosts missing agents, agent connectivity issues, and integration check failures"},
        ],
    },
    "apm_traces": {
        "name": "APM & Tracing",
        "description": "Application performance, service map, and error tracking",
        "checks": [
            {"id": "service_map", "name": "Service Map", "description": "Service dependency topology",
             "pages": [{"label": "dd_service_map", "display": "Service Map", "url": "/apm/map"}],
             "focus": "Review the service dependency map — service connections, latency between services, error rates on edges, and any unexpected external connections"},
            {"id": "services_list", "name": "Services List", "description": "All APM-instrumented services",
             "pages": [{"label": "dd_services", "display": "Services", "url": "/apm/services"}],
             "focus": "List all APM services — request rate, error rate (p99 latency), and identify services with elevated error rates or degraded performance"},
            {"id": "traces", "name": "Trace Explorer", "description": "Distributed traces and spans",
             "pages": [{"label": "dd_traces", "display": "Traces", "url": "/apm/traces"}],
             "focus": "Review recent traces — identify high-latency traces, error traces, and traces showing unusual service call patterns or excessive downstream calls"},
            {"id": "error_tracking", "name": "Error Tracking", "description": "Application error groups and trends",
             "pages": [{"label": "dd_errors", "display": "Error Tracking", "url": "/apm/error-tracking"}],
             "focus": "Review error groups — error frequency, first/last seen, affected users, and unhandled errors that should be prioritized for investigation"},
            {"id": "profiling", "name": "Continuous Profiler", "description": "CPU and memory profiling data",
             "pages": [{"label": "dd_profiling", "display": "Profiling", "url": "/profiling"}],
             "focus": "Review profiling data — top CPU consumers, memory allocation hotspots, lock contention, and functions consuming disproportionate resources"},
            {"id": "rum", "name": "Real User Monitoring", "description": "Frontend user experience metrics",
             "pages": [{"label": "dd_rum", "display": "RUM", "url": "/rum/explorer"}],
             "focus": "Review RUM data — page load times, Core Web Vitals, session replay errors, and user sessions with poor experience scores"},
            {"id": "slo_apm", "name": "APM SLOs", "description": "SLOs based on APM service health",
             "pages": [{"label": "dd_apm_slos", "display": "APM SLOs", "url": "/slo?q=type%3Aservice"}],
             "focus": "Review APM-based SLOs — service availability and latency SLOs, error budget consumption rate, and SLOs approaching breach"},
            {"id": "deployment_tracking", "name": "Deployment Tracking", "description": "Code deployment impact on performance",
             "pages": [{"label": "dd_deployments", "display": "Deployments", "url": "/apm/deployment-tracking"}],
             "focus": "Review recent deployments — performance changes post-deploy, error rate increases, and deployments that introduced regressions"},
        ],
    },
    "security": {
        "name": "Security",
        "description": "Security signals, threats, vulnerabilities, and compliance",
        "checks": [
            {"id": "security_signals", "name": "Security Signals", "description": "Active security threats and detections",
             "pages": [{"label": "dd_sec_signals", "display": "Security Signals", "url": "/security/threats/signals"}],
             "focus": "Review security signals — severity (critical/high/medium), threat type, affected resources, and signals that have been open for extended periods without review"},
            {"id": "cloud_security", "name": "Cloud Security Posture", "description": "CSM misconfigurations and compliance",
             "pages": [{"label": "dd_csm", "display": "Cloud Security", "url": "/security/csm"}],
             "focus": "Review cloud security posture — misconfiguration findings by severity, affected resources, compliance framework coverage, and high-severity findings requiring immediate remediation"},
            {"id": "vulnerabilities", "name": "Vulnerability Management", "description": "CVE findings in infrastructure and code",
             "pages": [{"label": "dd_vulns", "display": "Vulnerabilities", "url": "/security/vulnerabilities"}],
             "focus": "Review vulnerability findings — critical/high CVEs, exploitability score, affected services, and vulnerabilities that have been open past SLA"},
            {"id": "identity_risks", "name": "Identity & Access Risks", "description": "IAM misconfigurations and risky permissions",
             "pages": [{"label": "dd_identity", "display": "Identity Risks", "url": "/security/identities"}],
             "focus": "Review identity risk findings — over-privileged roles, unused permissions, publicly exposed credentials, and IAM configuration violations"},
            {"id": "threat_detection", "name": "Threat Detection Rules", "description": "SIEM detection rule configurations",
             "pages": [{"label": "dd_threat_rules", "display": "Detection Rules", "url": "/security/configuration/workload-rules"}],
             "focus": "Review threat detection rules — enabled/disabled rules, rule coverage by MITRE ATT&CK category, custom rules, and rules with no recent matches (potential dead rules)"},
            {"id": "compliance_posture", "name": "Compliance Posture", "description": "CIS, SOC2, PCI-DSS compliance coverage",
             "pages": [{"label": "dd_compliance", "display": "Compliance", "url": "/security/compliance"}],
             "focus": "Review compliance posture — passing/failing checks per framework (CIS, SOC2, PCI-DSS, HIPAA), overall score, and highest-impact failing controls"},
            {"id": "audit_trail", "name": "Audit Trail", "description": "User activity and configuration changes",
             "pages": [{"label": "dd_audit", "display": "Audit Trail", "url": "/audit-trail"}],
             "focus": "Review audit trail events — user login events, configuration changes, API key usage, dashboard modifications, and any events from unrecognized users or IPs"},
            {"id": "api_keys", "name": "API & Application Keys", "description": "API keys and application key management",
             "pages": [{"label": "dd_api_keys", "display": "API Keys", "url": "/organization-settings/api-keys"}],
             "focus": "List all API keys — their names, creators, last used date, and identify keys that are unused (candidates for rotation or deletion)"},
        ],
    },
    "logs": {
        "name": "Log Management",
        "description": "Log ingestion, pipelines, indexes, and archives",
        "checks": [
            {"id": "log_explorer", "name": "Log Explorer", "description": "Live log stream and search",
             "pages": [{"label": "dd_logs", "display": "Log Explorer", "url": "/logs"}],
             "focus": "Review the log stream — error log rate, top log sources, unusual log volumes, and error patterns that indicate application issues"},
            {"id": "log_pipelines", "name": "Log Pipelines", "description": "Log processing and parsing rules",
             "pages": [{"label": "dd_log_pipelines", "display": "Pipelines", "url": "/logs/pipelines"}],
             "focus": "Review log pipelines — enabled/disabled pipelines, processor types, parsing rules, and pipelines processing sensitive data (PII handling)"},
            {"id": "log_indexes", "name": "Log Indexes", "description": "Log retention and sampling configuration",
             "pages": [{"label": "dd_log_indexes", "display": "Indexes", "url": "/logs/pipelines/indexes"}],
             "focus": "Review log indexes — daily log volume per index, retention period (days), sampling rules, and indexes approaching quota limits"},
            {"id": "log_archives", "name": "Log Archives", "description": "Long-term log storage configuration",
             "pages": [{"label": "dd_log_archives", "display": "Archives", "url": "/logs/pipelines/archives"}],
             "focus": "Review log archive configurations — destination (S3/GCS/Azure Blob), encryption, filter rules, and whether all required log types are archived for compliance"},
            {"id": "log_metrics", "name": "Log-Based Metrics", "description": "Custom metrics derived from logs",
             "pages": [{"label": "dd_log_metrics", "display": "Log Metrics", "url": "/logs/pipelines/generate-metrics"}],
             "focus": "Review log-based metrics — metric names, query filters, group-by tags, and metrics that may have high cardinality causing cost issues"},
            {"id": "sensitive_data", "name": "Sensitive Data Scanner", "description": "PII and secret detection in logs",
             "pages": [{"label": "dd_sds", "display": "Sensitive Data Scanner", "url": "/logs/pipelines/sensitive-data-scanner"}],
             "focus": "Review Sensitive Data Scanner rules — which data types are scanned (SSN, credit cards, API keys), redaction vs tagging action, and scanning groups"},
            {"id": "log_patterns", "name": "Log Patterns", "description": "Automated log clustering and anomalies",
             "pages": [{"label": "dd_log_patterns", "display": "Log Patterns", "url": "/logs?live=true&cols=host%2Cservice"}],
             "focus": "Review log volume trends — identify spikes in error logs, new log sources that appeared recently, and services with zero logs (potential monitoring gap)"},
            {"id": "exclusion_filters", "name": "Exclusion Filters", "description": "Log sampling and exclusion rules",
             "pages": [{"label": "dd_exclusion", "display": "Exclusion Filters", "url": "/logs/pipelines/indexes"}],
             "focus": "Review exclusion filters — which log queries are sampled or excluded, sampling rate percentages, and whether critical security logs are accidentally excluded"},
        ],
    },
    "organization": {
        "name": "Organization Settings",
        "description": "Users, roles, teams, SSO, and account configuration",
        "checks": [
            {"id": "users", "name": "Users & Roles", "description": "User accounts and role assignments",
             "pages": [{"label": "dd_users", "display": "Users", "url": "/organization-settings/users"}],
             "focus": "List all users — their roles (Admin/Standard/Read-Only), status (active/pending/disabled), last login date, and users with Admin role who may not need it"},
            {"id": "roles", "name": "Custom Roles", "description": "Permission sets and role definitions",
             "pages": [{"label": "dd_roles", "display": "Roles", "url": "/organization-settings/roles"}],
             "focus": "Review custom role definitions — permissions granted, number of users assigned, and roles with overly broad permissions like manage_all or dashboards_write"},
            {"id": "teams", "name": "Teams", "description": "Team structure and membership",
             "pages": [{"label": "dd_teams", "display": "Teams", "url": "/organization-settings/teams"}],
             "focus": "Review team structure — team names, member counts, and whether teams are properly scoped for resource access control"},
            {"id": "saml_sso", "name": "SSO & SAML Configuration", "description": "Single sign-on settings",
             "pages": [{"label": "dd_saml", "display": "SSO / SAML", "url": "/organization-settings/sso"}],
             "focus": "Review SSO configuration — SAML enablement, IdP provider, strict mode (prevent non-SSO login), and whether SSO is the only allowed login method"},
            {"id": "service_accounts", "name": "Service Accounts", "description": "Non-human service account keys",
             "pages": [{"label": "dd_svc_accts", "display": "Service Accounts", "url": "/organization-settings/service-accounts"}],
             "focus": "List service accounts — their assigned roles, associated API keys, last activity, and service accounts with Admin or overly broad permissions"},
            {"id": "oauth_apps", "name": "OAuth Applications", "description": "Third-party OAuth integrations",
             "pages": [{"label": "dd_oauth", "display": "OAuth Apps", "url": "/organization-settings/oauth-applications"}],
             "focus": "Review OAuth applications — connected apps, permissions granted, and whether any apps have broader access than required"},
            {"id": "ip_allowlist", "name": "IP Allowlist", "description": "IP-based access restrictions",
             "pages": [{"label": "dd_ip_allowlist", "display": "IP Allowlist", "url": "/organization-settings/ip-allowlist"}],
             "focus": "Review IP allowlist configuration — whether it is enabled, allowed CIDR ranges, and whether the allowlist is narrow enough to prevent unauthorized access"},
            {"id": "sensitive_settings", "name": "Data Access & Sharing", "description": "Data sharing and privacy controls",
             "pages": [{"label": "dd_sharing", "display": "Data Sharing", "url": "/organization-settings/sensitive-data"}],
             "focus": "Review data sharing settings — public dashboard sharing, sensitive data access controls, and whether external sharing is restricted appropriately"},
        ],
    },
    "dashboards": {
        "name": "Dashboards",
        "description": "Dashboard inventory, sharing settings, and key metrics",
        "checks": [
            {"id": "dashboard_list", "name": "Dashboard List", "description": "All created dashboards",
             "pages": [{"label": "dd_dashboards", "display": "Dashboards", "url": "/dashboard/lists"}],
             "focus": "Review dashboard inventory — total count, public vs private dashboards, recently created/modified dashboards, and dashboards shared publicly without authentication"},
            {"id": "home_dashboard", "name": "Home / Overview Dashboard", "description": "Main overview health dashboard",
             "pages": [{"label": "dd_home", "display": "Home Dashboard", "url": "/"}],
             "focus": "Review the home dashboard — infrastructure health summary, active monitors, recent events, and overall system health indicators"},
            {"id": "integrations", "name": "Integrations", "description": "Installed third-party integrations",
             "pages": [{"label": "dd_integrations", "display": "Integrations", "url": "/integrations"}],
             "focus": "Review installed integrations — which cloud providers, services, and tools are connected, and identify integrations that may be unused or have overly broad permissions"},
            {"id": "events", "name": "Event Stream", "description": "Infrastructure and application events",
             "pages": [{"label": "dd_events", "display": "Events", "url": "/event/stream"}],
             "focus": "Review the event stream — recent deployment events, configuration changes, alert state changes, and any unusual events from the past 24 hours"},
            {"id": "notebook", "name": "Notebooks", "description": "Incident and analysis notebooks",
             "pages": [{"label": "dd_notebooks", "display": "Notebooks", "url": "/notebook/list"}],
             "focus": "Review notebooks — their names, sharing status (private/public/org), and notebooks that may contain sensitive data visible to all org members"},
            {"id": "incidents", "name": "Incident Management", "description": "Active and recent incidents",
             "pages": [{"label": "dd_incidents", "display": "Incidents", "url": "/incidents"}],
             "focus": "Review incident list — active incidents, severity, duration, responders assigned, and resolved incidents to assess MTTD and MTTR trends"},
            {"id": "metrics_explorer", "name": "Metrics Explorer", "description": "Custom metric inventory",
             "pages": [{"label": "dd_metrics", "display": "Metrics Explorer", "url": "/metric/explorer"}],
             "focus": "Review metrics — custom metric count vs plan limits, high-cardinality metrics, and metrics not queried recently that may be incurring unnecessary cost"},
            {"id": "powerpack", "name": "Workflow Automation", "description": "Automated response workflows",
             "pages": [{"label": "dd_workflows", "display": "Workflows", "url": "/workflow"}],
             "focus": "Review automated workflows — trigger conditions, actions taken (create ticket, send alert, remediate), and workflows that run with elevated permissions"},
        ],
    },
}


# ═══════════════════════════════════════════════════════
# Datadog Compliance Check
# ═══════════════════════════════════════════════════════

def check_datadog_service(email, password, service, check_id=None, site="datadoghq.com"):
    """Log in to Datadog dashboard via Playwright and screenshot + AI-analyze the requested check."""
    service_info = DATADOG_SERVICE_PAGES.get(service)
    if not service_info:
        return {
            "provider": "datadog",
            "service": service,
            "service_name": service,
            "error": f"Unknown service: {service}",
            "screenshots": [],
            "vision_analysis": {},
            "status": "error",
        }

    checks = service_info.get("checks", [])
    check_info = None
    if check_id:
        for c in checks:
            if c["id"] == check_id:
                check_info = c
                break
    if check_info is None and checks:
        check_info = checks[0]

    if check_info is None:
        return {
            "provider": "datadog",
            "service": service,
            "service_name": service_info["name"],
            "error": "No checks defined for this service",
            "screenshots": [],
            "vision_analysis": {},
            "status": "error",
        }

    pages = check_info["pages"]
    focus = check_info.get("focus", "Provide a thorough analysis of everything visible on this page")

    results = {
        "provider": "datadog",
        "service": service,
        "service_name": service_info["name"],
        "service_description": service_info["description"],
        "check": check_info["name"],
        "check_description": check_info["description"],
        "timestamp": datetime.utcnow().isoformat(),
        "screenshots": [],
        "vision_analysis": {},
        "status": "completed",
    }

    screenshots = _take_datadog_screenshots(email, password, pages, site=site)
    results["screenshots"] = screenshots

    for ss in screenshots:
        if ss["label"].startswith("debug_"):
            continue
        if not os.path.exists(ss["path"]):
            continue

        prompt = f"""You are a Datadog observability and security auditor reviewing the Datadog dashboard.

This screenshot shows the "{service_info['name']} — {ss['description']}" page.

Your analysis focus for this check: {focus}

Provide a thorough, comprehensive analysis of everything visible, guided by the focus above. Cover:
1. What resources and configurations are shown
2. Security and operational posture — both positive findings and potential risks
3. Key configuration details and settings visible
4. Specific, actionable recommendations

Respond ONLY with this JSON (no markdown, no extra text):
{{
    "page_summary": "One sentence describing what this page shows",
    "resources_found": ["resource or item 1", "resource or item 2"],
    "security_observations": ["observation 1 (positive or negative)"],
    "configuration_details": ["key detail 1"],
    "recommendations": ["actionable recommendation 1"],
    "risk_level": "low|medium|high|critical|unknown",
    "confidence": 0.90
}}"""
        try:
            analysis = _analyze_screenshot_with_vision(ss["path"], prompt)
            results["vision_analysis"][ss["label"]] = analysis
        except Exception as e:
            logger.error(f"Vision analysis failed for {ss['label']}: {e}")
            results["vision_analysis"][ss["label"]] = {"error": str(e)}

    return results


def _take_datadog_screenshots(email, password, pages, site="datadoghq.com"):
    """Log in to Datadog via Playwright, then navigate and screenshot each page."""
    screenshots = []
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
    except ImportError:
        logger.warning("Playwright not available — cannot take Datadog screenshots")
        return screenshots

    base_url = f"https://app.{site}"

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        )
        page = context.new_page()
        _apply_stealth(page)

        # ── Step 1: Navigate to Datadog login ─────────────────────────────────
        try:
            page.goto(f"{base_url}/account/login", wait_until="commit", timeout=60000)
            page.wait_for_timeout(2000)
        except PlaywrightTimeout:
            logger.error("Datadog: timed out loading login page")
            browser.close()
            return screenshots

        try:
            raw = page.screenshot()
            _save_screenshot(raw, "datadog", "debug_login_page")
        except Exception:
            pass

        # ── Step 2: Fill email ─────────────────────────────────────────────────
        email_filled = False
        for selector in ['input[name="email"]', 'input[type="email"]', '#email', 'input[placeholder*="email" i]']:
            try:
                el = page.locator(selector)
                if el.count() > 0:
                    el.first.click()
                    page.wait_for_timeout(300)
                    el.first.type(email, delay=80)  # human-like typing
                    email_filled = True
                    logger.info("Datadog: email filled")
                    break
            except Exception:
                continue

        if not email_filled:
            logger.error("Datadog: could not find email field")
            browser.close()
            return screenshots

        page.wait_for_timeout(1000)

        # ── Step 3: Click Next if email-first flow ─────────────────────────────
        for btn_sel in ['button:has-text("Next")', 'button:has-text("Continue")', 'input[type="submit"]']:
            try:
                btn = page.locator(btn_sel)
                if btn.count() > 0:
                    btn.first.click()
                    page.wait_for_timeout(2000)
                    break
            except Exception:
                continue

        # ── Step 4: Fill password ──────────────────────────────────────────────
        password_filled = False
        for selector in ['input[name="password"]', 'input[type="password"]', '#password']:
            try:
                el = page.locator(selector)
                if el.count() > 0:
                    el.first.click()
                    page.wait_for_timeout(300)
                    el.first.type(password, delay=80)  # human-like typing
                    password_filled = True
                    logger.info("Datadog: password filled")
                    break
            except Exception:
                continue

        if not password_filled:
            logger.error("Datadog: could not find password field")
            try:
                raw = page.screenshot()
                _save_screenshot(raw, "datadog", "debug_no_password_field")
            except Exception:
                pass
            browser.close()
            return screenshots

        # ── Step 5: Submit login ───────────────────────────────────────────────
        submitted = False
        for selector in ['button[type="submit"]', 'button:has-text("Log in")', 'button:has-text("Sign in")', 'input[type="submit"]']:
            try:
                btn = page.locator(selector)
                if btn.count() > 0:
                    btn.first.click()
                    submitted = True
                    logger.info("Datadog: login submitted")
                    break
            except Exception:
                continue

        if not submitted:
            page.keyboard.press("Enter")

        # ── Step 6: Wait for dashboard ─────────────────────────────────────────
        try:
            page.wait_for_url(
                lambda url: f"app.{site}" in url and "/account/login" not in url,
                timeout=30000,
            )
            page.wait_for_timeout(4000)
            logger.info(f"Datadog: logged in, URL: {page.url}")
        except PlaywrightTimeout:
            logger.error("Datadog: timed out waiting for post-login redirect")
            try:
                raw = page.screenshot()
                _save_screenshot(raw, "datadog", "debug_login_failed")
            except Exception:
                pass
            browser.close()
            return screenshots

        # ── Step 7: Screenshot each page ──────────────────────────────────────
        for page_info in pages:
            label = page_info["label"]
            display = page_info["display"]
            url = base_url + page_info["url"]

            try:
                page.goto(url, wait_until="commit", timeout=60000)
                page.wait_for_timeout(4000)

                screenshot_bytes = page.screenshot(full_page=False)
                file_id, filepath, filename = _save_screenshot(screenshot_bytes, "datadog", label)
                screenshots.append({
                    "file_id": file_id,
                    "path": filepath,
                    "filename": filename,
                    "label": label,
                    "description": display,
                    "url": url,
                })
                logger.info(f"Datadog: captured {label}")
            except Exception as e:
                logger.error(f"Datadog: failed to capture {label}: {e}")
                try:
                    raw = page.screenshot()
                    _save_screenshot(raw, "datadog", f"debug_{label}_error")
                except Exception:
                    pass

        browser.close()

    return screenshots
