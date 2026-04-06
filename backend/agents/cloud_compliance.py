"""Cloud Compliance Agent — Uses Playwright + Cloud APIs to verify security policies."""

import os
import json
import base64
import logging
import time
import uuid
import requests
import urllib.parse
from datetime import datetime, timedelta

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
        # The account-specific URL redirects through OAuth. The React SPA
        # login form takes ~45-50 seconds to render in headless Docker Chromium.
        signin_url = f"https://{account_id}.signin.aws.amazon.com/console"
        try:
            page.goto(signin_url, wait_until="commit", timeout=60000)
        except PlaywrightTimeout:
            logger.error("Timed out loading AWS sign-in page")
            browser.close()
            return screenshots

        # Wait for the React SPA login form to render (can take 45-60s in Docker)
        try:
            page.wait_for_selector(
                'input#username, input#password',
                state="visible", timeout=90000
            )
            logger.info("AWS sign-in form rendered")
            page.wait_for_timeout(1000)  # small settle time
        except PlaywrightTimeout:
            logger.error("AWS sign-in form never rendered after 90s")
            try:
                raw = page.screenshot(full_page=False)
                file_id, filepath, filename = _save_screenshot(raw, "aws", "debug_form_not_rendered")
                screenshots.append({
                    "file_id": file_id,
                    "path": filepath,
                    "filename": filename,
                    "label": "debug_form_not_rendered",
                    "description": "Sign-in form did not render",
                    "url": page.url,
                })
            except Exception:
                pass
            browser.close()
            return screenshots

        # Fill username (account ID is pre-filled from the URL)
        try:
            page.locator('#username').fill(iam_username)
            logger.info("Filled username")
        except Exception as e:
            logger.error(f"Could not fill username: {e}")

        # Fill password
        try:
            page.locator('#password').fill(iam_password)
            logger.info("Filled password")
        except Exception as e:
            logger.error(f"Could not fill password: {e}")

        # Submit login
        try:
            page.locator('#signin_button').click()
            logger.info("Clicked sign-in button")
        except Exception:
            # Fallback to generic submit
            for selector in ['button[type="submit"]', 'input[type="submit"]']:
                try:
                    el = page.locator(selector)
                    if el.count() > 0:
                        el.first.click()
                        logger.info(f"Clicked submit via fallback: {selector}")
                        break
                except Exception:
                    continue

        # Wait for redirect to console
        try:
            page.wait_for_url("**/console.aws.amazon.com/**", timeout=45000)
            logger.info("Login successful — redirected to console")
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
                logger.error(f"Login failed — browser URL: {page.url}")
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


# Azure service registry for env-backed navigation
AZURE_SERVICE_PAGES = {
    "subscriptions": {"name": "Subscriptions", "description": "Tenant subscriptions and access scope"},
    "sql": {"name": "SQL Databases", "description": "SQL servers, databases, and TDE posture"},
    "storage": {"name": "Storage Accounts", "description": "Storage account encryption and replication settings"},
    "key_vault": {"name": "Key Vault", "description": "Vault inventory, purge protection, and soft delete"},
    "activity_logs": {"name": "Activity Logs", "description": "Management activity and security-relevant events"},
}


def _azure_get_token(tenant_id, client_id, client_secret, access_token=None):
    if access_token:
        return access_token

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://management.azure.com/.default",
        "grant_type": "client_credentials",
    }
    token_response = requests.post(token_url, data=token_data, timeout=15)
    token_response.raise_for_status()
    return token_response.json().get("access_token")


def _azure_headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _azure_list_subscriptions(headers):
    subs_url = "https://management.azure.com/subscriptions?api-version=2022-12-01"
    subs_response = requests.get(subs_url, headers=headers, timeout=15)
    subs_response.raise_for_status()
    return subs_response.json().get("value", [])


def _azure_rg_from_id(resource_id):
    if "/resourceGroups/" not in resource_id:
        return ""
    return resource_id.split("/resourceGroups/")[1].split("/")[0]


def check_azure_service(tenant_id, client_id, client_secret, service, access_token=None):
    """Run a focused Azure service inventory suitable for provider-side navigation."""
    if service == "sql":
        result = check_azure_sql_encryption(tenant_id, client_id, client_secret, access_token=access_token)
        result["service"] = "sql"
        result["service_name"] = AZURE_SERVICE_PAGES["sql"]["name"]
        result["service_description"] = AZURE_SERVICE_PAGES["sql"]["description"]
        return result

    result = {
        "provider": "azure",
        "service": service,
        "service_name": AZURE_SERVICE_PAGES.get(service, {}).get("name", service),
        "service_description": AZURE_SERVICE_PAGES.get(service, {}).get("description", ""),
        "timestamp": datetime.utcnow().isoformat(),
        "screenshots": [],
        "api_findings": {},
        "vision_analysis": {},
        "status": "completed",
    }

    try:
        token = _azure_get_token(tenant_id, client_id, client_secret, access_token=access_token)
        headers = _azure_headers(token)
        subscriptions = _azure_list_subscriptions(headers)
        result["api_findings"]["authentication"] = "success"
        result["api_findings"]["subscriptions"] = [
            {"id": sub["subscriptionId"], "name": sub.get("displayName")}
            for sub in subscriptions
        ]
    except Exception as exc:
        result["status"] = "error"
        result["api_findings"]["authentication"] = f"failed: {exc}"
        return result

    try:
        if service == "subscriptions":
            result["api_findings"]["inventory"] = result["api_findings"]["subscriptions"]
        elif service == "storage":
            accounts = []
            for sub in subscriptions:
                resp = requests.get(
                    f"https://management.azure.com/subscriptions/{sub['subscriptionId']}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01",
                    headers=headers,
                    timeout=20,
                )
                if resp.status_code != 200:
                    continue
                for item in resp.json().get("value", []):
                    props = item.get("properties", {})
                    encryption = props.get("encryption", {})
                    accounts.append({
                        "name": item.get("name"),
                        "resource_group": _azure_rg_from_id(item.get("id", "")),
                        "location": item.get("location"),
                        "kind": item.get("kind"),
                        "sku": (item.get("sku") or {}).get("name"),
                        "blob_encryption": ((encryption.get("services") or {}).get("blob") or {}).get("enabled"),
                        "file_encryption": ((encryption.get("services") or {}).get("file") or {}).get("enabled"),
                        "key_source": encryption.get("keySource"),
                    })
            result["api_findings"]["storage_accounts"] = accounts
        elif service == "key_vault":
            vaults = []
            for sub in subscriptions:
                resp = requests.get(
                    f"https://management.azure.com/subscriptions/{sub['subscriptionId']}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01",
                    headers=headers,
                    timeout=20,
                )
                if resp.status_code != 200:
                    continue
                for item in resp.json().get("value", []):
                    props = item.get("properties", {})
                    vaults.append({
                        "name": item.get("name"),
                        "resource_group": _azure_rg_from_id(item.get("id", "")),
                        "location": item.get("location"),
                        "sku": (props.get("sku") or {}).get("name"),
                        "soft_delete_retention_in_days": props.get("softDeleteRetentionInDays"),
                        "enable_purge_protection": props.get("enablePurgeProtection"),
                        "enable_rbac_authorization": props.get("enableRbacAuthorization"),
                        "vault_uri": props.get("vaultUri"),
                    })
            result["api_findings"]["vaults"] = vaults
        elif service == "activity_logs":
            events = []
            for sub in subscriptions:
                filter_str = "eventTimestamp ge '2024-01-01'"
                resp = requests.get(
                    f"https://management.azure.com/subscriptions/{sub['subscriptionId']}/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&$filter={urllib.parse.quote(filter_str)}",
                    headers=headers,
                    timeout=20,
                )
                if resp.status_code != 200:
                    continue
                for event in resp.json().get("value", [])[:30]:
                    events.append({
                        "subscription_id": sub["subscriptionId"],
                        "operation": (event.get("operationName") or {}).get("value"),
                        "status": (event.get("status") or {}).get("value"),
                        "resource_group": event.get("resourceGroupName"),
                        "timestamp": event.get("eventTimestamp"),
                        "caller": event.get("caller"),
                    })
            result["api_findings"]["activity_logs"] = events
    except Exception as exc:
        result["status"] = "error"
        result["api_findings"]["service_error"] = str(exc)

    return result


# ═══════════════════════════════════════════════════════
# GitHub Posture Verification
# ═══════════════════════════════════════════════════════

def _github_headers(api_token):
    return {
        "Authorization": f"token {api_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _github_paginated_get(url, headers, params=None, max_pages=3):
    items = []
    current_params = dict(params or {})
    current_params.setdefault("per_page", 100)

    for page_num in range(1, max_pages + 1):
        current_params["page"] = page_num
        response = requests.get(url, headers=headers, params=current_params, timeout=20)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, list):
            return data
        items.extend(data)
        if len(data) < current_params["per_page"]:
            break

    return items


def _github_status_severity(status):
    return {"pass": 0, "warn": 1, "unknown": 2, "fail": 3}.get(status, 2)


def _github_pick_worst_status(statuses):
    valid = [status for status in statuses if status]
    if not valid:
        return "unknown"
    return max(valid, key=_github_status_severity)


def _github_numeric_score(status):
    return {"pass": 100, "warn": 62, "fail": 22, "unknown": 40}.get(status, 40)


def _github_build_service(key, name, status, summary, metrics, highlights, metadata):
    return {
        "key": key,
        "name": name,
        "status": status,
        "score": _github_numeric_score(status),
        "summary": summary,
        "metrics": metrics,
        "highlights": highlights,
        "metadata": metadata,
    }


def _github_fetch_repo_branches(headers, repo_full_name, limit=10):
    try:
        response = requests.get(
            f"https://api.github.com/repos/{repo_full_name}/branches",
            headers=headers,
            params={"per_page": limit},
            timeout=20,
        )
        if response.status_code != 200:
            return {"error": f"{response.status_code}: {response.text[:160]}", "branches": []}
        data = response.json()
        return {
            "branches": [
                {
                    "name": branch.get("name"),
                    "protected": branch.get("protected"),
                    "commit_sha": (branch.get("commit") or {}).get("sha"),
                }
                for branch in data
            ]
        }
    except Exception as exc:
        return {"error": str(exc), "branches": []}


def _github_analyze_repositories(headers, repos):
    total_repos = len(repos)
    active_repos = [repo for repo in repos if not repo.get("archived")]
    private_repos = len([repo for repo in repos if repo.get("private")])
    public_repos = total_repos - private_repos
    archived_repos = total_repos - len(active_repos)
    disabled_issues = len([repo for repo in active_repos if not repo.get("has_issues", True)])
    disabled_projects = len([repo for repo in active_repos if not repo.get("has_projects", False)])
    disabled_wiki = len([repo for repo in active_repos if not repo.get("has_wiki", False)])

    if total_repos == 0:
        status = "unknown"
        summary = "No accessible repositories were returned by the token."
    elif archived_repos == total_repos:
        status = "warn"
        summary = "All accessible repositories are archived; active repository posture could not be fully assessed."
    else:
        status = "pass"
        summary = f"{len(active_repos)} active repositories were discovered across private and public scopes."

    detailed_repositories = []
    for repo in repos[:30]:
        branch_data = _github_fetch_repo_branches(headers, repo.get("full_name"), limit=12)
        detailed_repositories.append({
            "full_name": repo.get("full_name"),
            "name": repo.get("name"),
            "visibility": repo.get("visibility"),
            "private": repo.get("private"),
            "archived": repo.get("archived"),
            "default_branch": repo.get("default_branch"),
            "open_issues_count": repo.get("open_issues_count"),
            "forks_count": repo.get("forks_count"),
            "stargazers_count": repo.get("stargazers_count"),
            "watchers_count": repo.get("watchers_count"),
            "language": repo.get("language"),
            "has_issues": repo.get("has_issues"),
            "has_projects": repo.get("has_projects"),
            "has_wiki": repo.get("has_wiki"),
            "updated_at": repo.get("updated_at"),
            "pushed_at": repo.get("pushed_at"),
            "html_url": repo.get("html_url"),
            "branches": branch_data.get("branches", []),
            "branches_error": branch_data.get("error"),
        })

    metadata = {
        "total_repositories": total_repos,
        "active_repositories": len(active_repos),
        "private_repositories": private_repos,
        "public_repositories": public_repos,
        "archived_repositories": archived_repos,
        "repositories": detailed_repositories,
    }

    return _github_build_service(
        "repositories",
        "Repositories",
        status,
        summary,
        {
            "total": total_repos,
            "active": len(active_repos),
            "private": private_repos,
            "public": public_repos,
        },
        [
            f"{archived_repos} archived repositories",
            f"{disabled_issues} active repositories with issues disabled",
            f"{disabled_projects} active repositories with projects disabled",
            f"{disabled_wiki} active repositories with wiki disabled",
        ],
        metadata,
    )


def _github_analyze_pull_requests(headers, username):
    query = f"is:pr involves:{username}"
    open_resp = requests.get(
        "https://api.github.com/search/issues",
        headers=headers,
        params={"q": f"{query} state:open", "per_page": 30},
        timeout=20,
    )
    open_resp.raise_for_status()
    open_data = open_resp.json()

    merged_resp = requests.get(
        "https://api.github.com/search/issues",
        headers=headers,
        params={"q": f"{query} is:merged", "per_page": 30},
        timeout=20,
    )
    merged_resp.raise_for_status()
    merged_data = merged_resp.json()

    stale_cutoff = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    stale_open = [
        item for item in open_data.get("items", [])
        if item.get("updated_at", "") < stale_cutoff
    ]
    open_total = open_data.get("total_count", 0)

    if open_total >= 15:
        status = "warn"
        summary = f"{open_total} open pull requests need attention across accessible repositories."
    else:
        status = "pass"
        summary = f"{open_total} open pull requests and {merged_data.get('total_count', 0)} merged pull requests were found."

    return _github_build_service(
        "pull_requests",
        "Pull Requests",
        status,
        summary,
        {
            "open": open_total,
            "merged": merged_data.get("total_count", 0),
            "sampled_stale": len(stale_open),
            "sampled": len(open_data.get("items", [])),
        },
        [
            f"{len(stale_open)} sampled pull requests have not moved recently",
            f"Search scope: PRs involving {username}",
        ],
        {
            "query_scope": f"PRs involving {username}",
            "open_results": open_data,
            "merged_results": merged_data,
        },
    )


def _github_analyze_settings(user_data, org_details, repos):
    mfa_enabled = user_data.get("two_factor_authentication")
    orgs_with_required_2fa = len([org for org in org_details if org.get("two_factor_requirement_enabled")])
    org_total = len(org_details)

    security_enabled = 0
    security_partial = 0
    for repo in repos:
        security = repo.get("security_and_analysis") or {}
        statuses = [
            (security.get("dependabot_security_updates") or {}).get("status"),
            (security.get("secret_scanning") or {}).get("status"),
            (security.get("secret_scanning_push_protection") or {}).get("status"),
            (security.get("code_scanning") or {}).get("status"),
        ]
        enabled = len([status for status in statuses if status == "enabled"])
        if enabled == len([status for status in statuses if status is not None]) and enabled > 0:
            security_enabled += 1
        elif enabled > 0:
            security_partial += 1

    if mfa_enabled is False:
        status = "fail"
        summary = "Account-level 2FA is disabled on the authenticated GitHub user."
    elif org_total and orgs_with_required_2fa < org_total:
        status = "warn"
        summary = f"{org_total - orgs_with_required_2fa} organizations do not enforce 2FA."
    else:
        status = "pass"
        summary = "GitHub account and organization security settings look broadly healthy."

    return _github_build_service(
        "settings",
        "Settings",
        status,
        summary,
        {
            "mfa_enabled": bool(mfa_enabled),
            "organizations": org_total,
            "orgs_with_2fa_required": orgs_with_required_2fa,
            "repos_with_full_security_features": security_enabled,
            "repos_with_partial_security_features": security_partial,
        },
        [
            f"Authenticated user 2FA: {'enabled' if mfa_enabled else 'disabled'}",
            f"{orgs_with_required_2fa}/{org_total} organizations require 2FA",
            f"{security_enabled} repositories expose all returned security feature toggles as enabled",
        ],
        {
            "user": {
                "login": user_data.get("login"),
                "name": user_data.get("name"),
                "email": user_data.get("email"),
                "two_factor_authentication": user_data.get("two_factor_authentication"),
                "created_at": user_data.get("created_at"),
                "html_url": user_data.get("html_url"),
            },
            "organizations": org_details,
            "repository_security": [
                {
                    "full_name": repo.get("full_name"),
                    "security_and_analysis": repo.get("security_and_analysis"),
                }
                for repo in repos[:50]
            ],
        },
    )


def _github_analyze_vulnerabilities(headers, repos):
    scanned_repos = []
    open_alerts = 0
    alerts_unavailable = 0
    coverage_gaps = 0

    for repo in repos[:15]:
        repo_name = repo.get("full_name")
        security = repo.get("security_and_analysis") or {}
        feature_states = {
            "dependabot_security_updates": (security.get("dependabot_security_updates") or {}).get("status"),
            "secret_scanning": (security.get("secret_scanning") or {}).get("status"),
            "push_protection": (security.get("secret_scanning_push_protection") or {}).get("status"),
            "code_scanning": (security.get("code_scanning") or {}).get("status"),
        }
        if any(state in (None, "disabled") for state in feature_states.values()):
            coverage_gaps += 1

        alert_summary = {"full_name": repo_name, "feature_states": feature_states}
        try:
            resp = requests.get(
                f"https://api.github.com/repos/{repo_name}/dependabot/alerts",
                headers=headers,
                params={"state": "open", "per_page": 100},
                timeout=20,
            )
            if resp.status_code == 200:
                alerts = resp.json()
                open_alerts += len(alerts)
                alert_summary["open_dependabot_alerts"] = len(alerts)
                alert_summary["dependabot_alerts"] = alerts[:20]
            else:
                alerts_unavailable += 1
                alert_summary["dependabot_alerts_error"] = f"{resp.status_code}: {resp.text[:200]}"
        except Exception as exc:
            alerts_unavailable += 1
            alert_summary["dependabot_alerts_error"] = str(exc)

        scanned_repos.append(alert_summary)

    if open_alerts > 0:
        status = "fail"
        summary = f"{open_alerts} open Dependabot alerts were found in sampled repositories."
    elif coverage_gaps > 0 or alerts_unavailable > 0:
        status = "warn"
        summary = "Vulnerability coverage is partial due to disabled features or unavailable alert scopes."
    else:
        status = "pass"
        summary = "No open Dependabot alerts were found in the sampled repositories."

    return _github_build_service(
        "vulnerabilities",
        "Vulnerabilities",
        status,
        summary,
        {
            "sampled_repositories": len(scanned_repos),
            "open_dependabot_alerts": open_alerts,
            "coverage_gaps": coverage_gaps,
            "alert_queries_unavailable": alerts_unavailable,
        },
        [
            f"{open_alerts} open Dependabot alerts across sampled repositories",
            f"{coverage_gaps} repositories with security coverage gaps",
            f"{alerts_unavailable} repositories where alert data was unavailable",
        ],
        {
            "sample_scope": "first 15 accessible repositories",
            "repositories": scanned_repos,
        },
    )


def _github_analyze_issues(headers, username, repos):
    issues_resp = requests.get(
        "https://api.github.com/search/issues",
        headers=headers,
        params={"q": f"is:issue user:{username} state:open", "per_page": 30},
        timeout=20,
    )
    issues_resp.raise_for_status()
    issues_data = issues_resp.json()

    open_issues_total = issues_data.get("total_count", 0)
    repo_issue_total = sum(repo.get("open_issues_count", 0) for repo in repos)

    if open_issues_total >= 20:
        status = "warn"
        summary = f"{open_issues_total} open issues are currently visible for user scope {username}."
    else:
        status = "pass"
        summary = f"{open_issues_total} open issues were found in search results."

    return _github_build_service(
        "issues",
        "Issues",
        status,
        summary,
        {
            "open_issue_search_results": open_issues_total,
            "aggregate_open_issue_counts": repo_issue_total,
            "sampled_results": len(issues_data.get("items", [])),
        },
        [
            f"Search scope: issues under user/org namespace {username}",
            f"Repository aggregate open issues count: {repo_issue_total}",
        ],
        {
            "query_scope": f"is:issue user:{username} state:open",
            "search_results": issues_data,
        },
    )


def check_github_posture(api_token, include_visuals=True):
    """Build a GitHub integration view across repositories, PRs, settings, vulnerabilities, and issues."""
    results = {
        "provider": "github",
        "check": "GitHub Posture Overview",
        "timestamp": datetime.utcnow().isoformat(),
        "screenshots": [],
        "api_findings": {},
        "vision_analysis": {},
        "status": "completed",
        "services": {},
        "github_summary": {},
    }

    headers = _github_headers(api_token)

    try:
        user_response = requests.get("https://api.github.com/user", headers=headers, timeout=20)
        user_response.raise_for_status()
        user_data = user_response.json()
    except Exception as exc:
        results["status"] = "error"
        results["api_findings"]["authentication"] = f"failed: {exc}"
        return results

    username = user_data.get("login")
    results["api_findings"]["authentication"] = "success"
    results["api_findings"]["user"] = {
        "login": user_data.get("login"),
        "name": user_data.get("name"),
        "email": user_data.get("email"),
        "two_factor_authentication": user_data.get("two_factor_authentication"),
    }

    repos = []
    org_details = []
    errors = []

    try:
        repos = _github_paginated_get(
            "https://api.github.com/user/repos",
            headers,
            params={"sort": "updated", "affiliation": "owner,collaborator,organization_member"},
            max_pages=3,
        )
    except Exception as exc:
        errors.append(f"repositories: {exc}")

    try:
        orgs = _github_paginated_get("https://api.github.com/user/orgs", headers, max_pages=2)
        for org in orgs[:25]:
            try:
                detail_resp = requests.get(f"https://api.github.com/orgs/{org['login']}", headers=headers, timeout=20)
                if detail_resp.status_code == 200:
                    org_details.append(detail_resp.json())
            except Exception as exc:
                org_details.append({"login": org.get("login"), "error": str(exc)})
    except Exception as exc:
        errors.append(f"organizations: {exc}")

    def _safe_service(key, name, fn):
        try:
            return fn()
        except Exception as exc:
            errors.append(f"{key}: {exc}")
            return _github_build_service(
                key,
                name,
                "unknown",
                f"{name} could not be fully assessed with the current token scope.",
                {},
                [str(exc)],
                {"error": str(exc)},
            )

    services = {
        "repositories": _safe_service("repositories", "Repositories", lambda: _github_analyze_repositories(headers, repos)),
        "pull_requests": _safe_service("pull_requests", "Pull Requests", lambda: _github_analyze_pull_requests(headers, username)),
        "settings": _safe_service("settings", "Settings", lambda: _github_analyze_settings(user_data, org_details, repos)),
        "vulnerabilities": _safe_service("vulnerabilities", "Vulnerabilities", lambda: _github_analyze_vulnerabilities(headers, repos)),
        "issues": _safe_service("issues", "Issues", lambda: _github_analyze_issues(headers, username, repos)),
    }
    results["services"] = services

    status_counts = {"pass": 0, "warn": 0, "fail": 0, "unknown": 0}
    for service in services.values():
        status_counts[service["status"]] = status_counts.get(service["status"], 0) + 1

    overall_status = _github_pick_worst_status([service["status"] for service in services.values()])
    overall_score = round(sum(service["score"] for service in services.values()) / max(len(services), 1))

    results["api_findings"]["organizations"] = [
        {
            "login": org.get("login"),
            "name": org.get("name"),
            "two_factor_requirement_enabled": org.get("two_factor_requirement_enabled"),
        }
        for org in org_details
    ]
    results["api_findings"]["summary"] = {
        "score": overall_score,
        "overall_status": overall_status,
        "services": {
            key: {
                "status": service["status"],
                "summary": service["summary"],
                "metrics": service["metrics"],
            }
            for key, service in services.items()
        },
    }
    if errors:
        results["api_findings"]["warnings"] = errors

    results["github_summary"] = {
        "overall_status": overall_status,
        "score": overall_score,
        "status_counts": status_counts,
        "service_order": list(services.keys()),
        "bar_graph": [
            {"key": key, "label": service["name"], "score": service["score"], "status": service["status"]}
            for key, service in services.items()
        ],
    }

    if include_visuals:
        screenshots = _take_github_screenshots(results)
        results["screenshots"] = screenshots

        for ss in screenshots:
            if not os.path.exists(ss["path"]):
                continue
            prompt = f"""You are a security compliance auditor. Analyze this GitHub posture screenshot.

This screenshot shows the {ss['label']} view from a GitHub integration dashboard.

Respond in JSON with:
{{
  "page_summary": "brief summary",
  "risk_level": "low|medium|high|critical|unknown",
  "security_observations": ["specific observations"],
  "configuration_details": ["specific details"],
  "recommendations": ["recommended actions"],
  "confidence": 0.85
}}

Respond ONLY with JSON."""
            try:
                results["vision_analysis"][ss["label"]] = _analyze_screenshot_with_vision(ss["path"], prompt)
            except Exception as exc:
                results["vision_analysis"][ss["label"]] = {"error": str(exc)}

    return results


def _take_github_screenshots(results):
    """Render GitHub posture summary as polished dashboard screenshots."""
    screenshots = []
    user_data = (results.get("services", {}).get("settings", {}).get("metadata", {}) or {}).get("user", {})
    services = results.get("services", {})
    summary = results.get("github_summary", {})

    try:
        from playwright.sync_api import sync_playwright

        status_palette = {
            "pass": ("#34d399", "#062b23"),
            "warn": ("#fbbf24", "#2f2102"),
            "fail": ("#fb7185", "#350814"),
            "unknown": ("#93c5fd", "#091629"),
        }

        service_cards = ""
        for service in services.values():
            accent, tint = status_palette.get(service["status"], status_palette["unknown"])
            service_cards += f"""
            <div class="service-card">
                <div class="service-top">
                    <span class="service-name">{service['name']}</span>
                    <span class="service-badge" style="color:{accent};background:{tint};border-color:{accent}44">{service['status'].upper()}</span>
                </div>
                <div class="service-score">{service['score']}</div>
                <p>{service['summary']}</p>
            </div>"""

        bars = ""
        for item in summary.get("bar_graph", []):
            accent, _ = status_palette.get(item["status"], status_palette["unknown"])
            bars += f"""
            <div class="bar-row">
                <div class="bar-label"><span>{item['label']}</span><strong>{item['score']}</strong></div>
                <div class="bar-track"><div class="bar-fill" style="width:{item['score']}%;background:{accent}"></div></div>
            </div>"""

        overview_html = f"""<!DOCTYPE html>
<html>
<head>
<style>
body {{ margin:0; padding:40px; font-family:'Segoe UI',sans-serif; background:radial-gradient(circle at top, #172554 0%, #09090f 46%, #05070c 100%); color:#eef2ff; }}
.shell {{ max-width:1240px; margin:0 auto; background:linear-gradient(180deg, rgba(15,23,42,0.92), rgba(6,10,18,0.95)); border:1px solid rgba(148,163,184,0.18); border-radius:28px; overflow:hidden; box-shadow:0 30px 80px rgba(0,0,0,0.45); }}
.hero {{ padding:32px 36px 24px; background:linear-gradient(135deg, rgba(56,189,248,0.18), rgba(168,85,247,0.12), rgba(244,114,182,0.08)); }}
.eyebrow {{ display:inline-flex; padding:8px 12px; border-radius:999px; background:rgba(255,255,255,0.08); font-size:12px; letter-spacing:0.12em; text-transform:uppercase; }}
.hero h1 {{ font-size:38px; margin:16px 0 8px; }}
.hero p {{ margin:0; color:#cbd5e1; font-size:16px; }}
.grid {{ display:grid; grid-template-columns:1.2fr 0.8fr; gap:24px; padding:28px 36px 36px; }}
.panel {{ background:rgba(15,23,42,0.72); border:1px solid rgba(148,163,184,0.16); border-radius:24px; padding:24px; }}
.stats {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin:18px 0 0; }}
.stat {{ padding:16px; border-radius:18px; background:rgba(255,255,255,0.04); }}
.stat strong {{ display:block; font-size:26px; margin-top:6px; }}
.services {{ display:grid; grid-template-columns:repeat(2,1fr); gap:14px; }}
.service-card {{ padding:18px; border-radius:18px; background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.06); min-height:150px; }}
.service-top {{ display:flex; justify-content:space-between; gap:12px; align-items:center; }}
.service-name {{ font-size:15px; font-weight:700; }}
.service-badge {{ border:1px solid; border-radius:999px; padding:6px 10px; font-size:11px; letter-spacing:0.08em; }}
.service-score {{ font-size:36px; font-weight:800; margin:14px 0 6px; }}
.service-card p {{ color:#cbd5e1; line-height:1.5; font-size:14px; margin:0; }}
.bar-row {{ margin-bottom:14px; }}
.bar-label {{ display:flex; justify-content:space-between; margin-bottom:8px; font-size:13px; color:#cbd5e1; }}
.bar-track {{ height:12px; border-radius:999px; background:rgba(148,163,184,0.12); overflow:hidden; }}
.bar-fill {{ height:100%; border-radius:999px; }}
</style>
</head>
<body>
    <div class="shell">
        <div class="hero">
            <span class="eyebrow">GitHub Integration Overview</span>
            <h1>{user_data.get('name') or user_data.get('login') or 'GitHub Account'}</h1>
            <p>@{user_data.get('login', 'unknown')} · Overall score {summary.get('score', 0)} · Status {summary.get('overall_status', 'unknown').upper()}</p>
            <div class="stats">
                <div class="stat"><span>Passed</span><strong>{summary.get('status_counts', {}).get('pass', 0)}</strong></div>
                <div class="stat"><span>Warnings</span><strong>{summary.get('status_counts', {}).get('warn', 0)}</strong></div>
                <div class="stat"><span>Failures</span><strong>{summary.get('status_counts', {}).get('fail', 0)}</strong></div>
                <div class="stat"><span>Unknown</span><strong>{summary.get('status_counts', {}).get('unknown', 0)}</strong></div>
            </div>
        </div>
        <div class="grid">
            <div class="panel">
                <h2>Service Status</h2>
                <div class="services">{service_cards}</div>
            </div>
            <div class="panel">
                <h2>Score Graph</h2>
                {bars}
            </div>
        </div>
    </div>
</body>
</html>"""

        profile_url = user_data.get("html_url", f"https://github.com/{user_data.get('login', '')}")
        reports = [
            ("posture_overview", overview_html, "GitHub posture overview dashboard"),
            ("public_profile", profile_url, "GitHub public profile"),
        ]

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = browser.new_context(viewport={"width": 1440, "height": 1200}, device_scale_factor=1)
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
                except Exception as exc:
                    logger.error(f"Failed to capture GitHub screenshot '{label}': {exc}")

            browser.close()
    except ImportError:
        logger.warning("Playwright not installed. Skipping browser screenshots.")
    except Exception as exc:
        logger.error(f"GitHub screenshot capture error: {exc}")

    return screenshots


# ═══════════════════════════════════════════════════════
# Snowflake Service Registry
# ═══════════════════════════════════════════════════════

SNOWFLAKE_SERVICE_PAGES = {
    "warehouses": {
        "name": "Warehouses",
        "description": "Compute warehouse management",
        "checks": [
            {"id": "warehouse_list", "name": "Warehouse Inventory", "description": "All warehouses and their configuration",
             "pages": [{"label": "sf_warehouses", "display": "Warehouses", "path": "/compute/history/warehouses"}],
             "focus": "List all warehouses — name, size (XS to 6XL), state (running/suspended), auto-suspend/resume settings, and cluster count"},
        ],
    },
    "databases": {
        "name": "Databases",
        "description": "Database and schema management",
        "checks": [
            {"id": "database_list", "name": "Database Inventory", "description": "All databases and schemas",
             "pages": [{"label": "sf_databases", "display": "Databases", "path": "/data/databases"}],
             "focus": "List all databases — name, owner, creation date, retention time, and schema count"},
        ],
    },
    "users": {
        "name": "Users & Roles",
        "description": "Identity and access management",
        "checks": [
            {"id": "user_list", "name": "User Inventory", "description": "All user accounts and their status",
             "pages": [{"label": "sf_users", "display": "Users", "path": "/admin/users-and-roles"}],
             "focus": "List all users — name, login name, default role, MFA status, last login, disabled status, and whether password is expired"},
            {"id": "role_list", "name": "Role Hierarchy", "description": "All roles and privilege grants",
             "pages": [{"label": "sf_roles", "display": "Roles", "path": "/admin/roles"}],
             "focus": "List all roles — name, type (system/custom), granted-to count, and privilege hierarchy"},
        ],
    },
    "security": {
        "name": "Governance & Security",
        "description": "Network policies and security settings",
        "checks": [
            {"id": "network_policies", "name": "Network Policies", "description": "IP allow/block lists and access rules",
             "pages": [{"label": "sf_governance_security", "display": "Governance & Security", "path": "/governance-security"}],
             "focus": "Review security settings — network policies, access history, data masking policies, row-level security, and any governance rules configured"},
        ],
    },
    "monitoring": {
        "name": "Monitoring",
        "description": "Query and warehouse performance monitoring",
        "checks": [
            {"id": "query_history", "name": "Query History", "description": "Recent query activity and performance",
             "pages": [{"label": "sf_query_history", "display": "Query History", "path": "/monitoring/queries"}],
             "focus": "Review recent query activity — query count, execution times, error rates, warehouse usage, and any long-running or failed queries"},
            {"id": "warehouse_activity", "name": "Warehouse Activity", "description": "Warehouse load and credit usage",
             "pages": [{"label": "sf_warehouse_activity", "display": "Warehouse Activity", "path": "/monitoring/warehouses"}],
             "focus": "Review warehouse activity — credit consumption, load patterns, auto-suspend utilization, and idle time"},
        ],
    },
    "admin": {
        "name": "Admin",
        "description": "Account and cost management",
        "checks": [
            {"id": "cost_management", "name": "Cost Management", "description": "Credit usage and billing overview",
             "pages": [{"label": "sf_cost_management", "display": "Cost Management", "path": "/admin/billing"}],
             "focus": "Review cost management — credit consumption trends, warehouse-level spending, storage costs, and resource monitors configured"},
        ],
    },
}


# ═══════════════════════════════════════════════════════
# Snowflake Compliance Check
# ═══════════════════════════════════════════════════════

def check_snowflake_service(account_url, username, password, service, check_id=None):
    """Log into Snowflake via Playwright and capture screenshots for the requested service check."""
    service_info = SNOWFLAKE_SERVICE_PAGES.get(service)
    if not service_info:
        return {
            "provider": "snowflake",
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
            "provider": "snowflake",
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
        "provider": "snowflake",
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

    screenshots = _take_snowflake_screenshots(account_url, username, password, pages)
    results["screenshots"] = screenshots

    real_screenshots = [s for s in screenshots if not s["label"].startswith("debug_")]
    if not real_screenshots:
        results["status"] = "error"
        results["error"] = "Snowflake login failed or timed out. Please verify your account URL, username, and password."
        logger.warning("Snowflake: No screenshots captured — marking result as error")
        return results

    for ss in screenshots:
        if ss["label"].startswith("debug_"):
            continue
        if not os.path.exists(ss["path"]):
            continue

        prompt = f"""You are a Snowflake cloud data platform auditor reviewing the Snowflake web console (Snowsight).

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
            logger.error(f"Snowflake vision analysis failed for {ss['label']}: {e}")
            results["vision_analysis"][ss["label"]] = {"error": str(e)}

    return results


def _take_snowflake_screenshots(account_url, username, password, pages):
    """Log into Snowflake Snowsight and capture screenshots."""
    screenshots = []
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
    except ImportError:
        logger.warning("Playwright not available — cannot take Snowflake screenshots")
        return screenshots

    account_url = account_url.strip().rstrip("/")
    if not account_url.startswith("http"):
        account_url = f"https://{account_url}"
    base_url = account_url

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

        # ── Step 1: Navigate to Snowflake login ──
        try:
            page.goto(base_url, wait_until="commit", timeout=60000)
        except PlaywrightTimeout:
            logger.error("Snowflake: timed out loading login page")
            browser.close()
            return screenshots

        # Wait for login form
        try:
            page.wait_for_selector(
                'input[name="username"], input#username, input[type="text"]',
                state="visible", timeout=30000
            )
            logger.info("Snowflake: login form rendered")
            page.wait_for_timeout(1000)
        except PlaywrightTimeout:
            logger.error("Snowflake: login form never rendered")
            try:
                raw = page.screenshot(full_page=False)
                file_id, filepath, filename = _save_screenshot(raw, "snowflake", "debug_login_not_rendered")
                screenshots.append({"file_id": file_id, "path": filepath, "filename": filename,
                                    "label": "debug_login_not_rendered", "description": "Login form did not render", "url": page.url})
            except Exception:
                pass
            browser.close()
            return screenshots

        # Fill username
        for selector in ['input[name="username"]', 'input#username', 'input[autocomplete="username"]']:
            try:
                el = page.locator(selector)
                if el.count() > 0 and el.first.is_visible():
                    el.first.fill(username)
                    logger.info(f"Snowflake: filled username via {selector}")
                    break
            except Exception:
                continue

        # Fill password
        for selector in ['input[name="password"]', 'input#password', 'input[type="password"]']:
            try:
                el = page.locator(selector)
                if el.count() > 0 and el.first.is_visible():
                    el.first.fill(password)
                    logger.info(f"Snowflake: filled password via {selector}")
                    break
            except Exception:
                continue

        # Click sign in
        for selector in ['button[type="submit"]', 'button:has-text("Sign in")', 'button:has-text("Log In")']:
            try:
                el = page.locator(selector)
                if el.count() > 0 and el.first.is_visible():
                    el.first.click()
                    logger.info(f"Snowflake: clicked login via {selector}")
                    break
            except Exception:
                continue

        # Wait for Snowsight to load — try multiple indicators
        logged_in = False
        try:
            # First: wait for URL to change away from the login page
            page.wait_for_url("**/app.snowflake.com/**", timeout=60000)
            logged_in = True
            logger.info(f"Snowflake: redirected to app.snowflake.com — URL: {page.url}")
        except PlaywrightTimeout:
            # Fallback: check if URL changed from the login page at all
            if "app.snowflake.com" in page.url or "snowsight" in page.url:
                logged_in = True
                logger.info(f"Snowflake: detected app URL: {page.url}")

        if logged_in:
            # Wait for the SPA to render any navigation/content
            page.wait_for_timeout(5000)
            logger.info("Snowflake: logged in successfully")
        else:
            try:
                raw = page.screenshot(full_page=False)
                file_id, filepath, filename = _save_screenshot(raw, "snowflake", "debug_login_failed")
                screenshots.append({"file_id": file_id, "path": filepath, "filename": filename,
                                    "label": "debug_login_failed", "description": "Login timed out", "url": page.url})
            except Exception:
                pass
            logger.error(f"Snowflake: login timed out — URL: {page.url}")
            browser.close()
            return screenshots

        # Capture the post-login base URL (Snowflake redirects to app.snowflake.com/<org>/<account>)
        post_login_url = page.url.rstrip("/")
        # Strip any hash/fragment and trailing path segments like /worksheets
        if "#" in post_login_url:
            post_login_url = post_login_url.split("#")[0].rstrip("/")
        # Remove known landing paths
        for suffix in ["/worksheets", "/worksheet", "/dashboard", "/home"]:
            if post_login_url.endswith(suffix):
                post_login_url = post_login_url[:-len(suffix)].rstrip("/")
                break
        logger.info(f"Snowflake: post-login base URL: {post_login_url}")

        # ── Step 2: Navigate to each page and screenshot ──
        for page_def in pages:
            label = page_def["label"]
            display = page_def["display"]
            target_url = post_login_url + page_def["path"]

            try:
                page.goto(target_url, wait_until="commit", timeout=60000)
                page.wait_for_timeout(3000)

                # Wait for Snowsight SPA content to finish loading:
                # 1. Wait for skeleton loaders to disappear
                # 2. Wait for spinners to disappear
                # 3. Poll until no loading indicators remain (up to 30s)
                for attempt in range(15):
                    loading = page.locator('[class*="skeleton"], [class*="Skeleton"], [class*="loading"], [class*="spinner"], [role="progressbar"], svg[class*="spin"]')
                    count = loading.count()
                    if count == 0:
                        logger.info(f"Snowflake: content loaded for {label} after {(attempt+1)*2}s")
                        break
                    page.wait_for_timeout(2000)
                else:
                    logger.warning(f"Snowflake: content still loading after 30s for {label}, capturing anyway")

                page.wait_for_timeout(2000)  # final settle

                raw = page.screenshot(full_page=False)
                file_id, filepath, filename = _save_screenshot(raw, "snowflake", label)
                screenshots.append({
                    "file_id": file_id,
                    "path": filepath,
                    "filename": filename,
                    "label": label,
                    "description": display,
                    "url": page.url,
                })
                logger.info(f"Snowflake screenshot captured: {label}")
            except PlaywrightTimeout:
                logger.warning(f"Snowflake: timeout navigating to {label}")
            except Exception as ex:
                logger.warning(f"Snowflake: error capturing {label}: {ex}")

        browser.close()

    return screenshots


# ═══════════════════════════════════════════════════════
# SendGrid Service Registry
# ═══════════════════════════════════════════════════════

SENDGRID_SERVICE_PAGES = {
    "api_keys": {
        "name": "API Keys",
        "description": "API key management and permissions",
        "checks": [
            {"id": "api_key_list", "name": "API Key Inventory", "description": "All API keys and their permissions",
             "pages": [{"label": "sg_api_keys", "display": "API Keys", "path": "/settings/api_keys"}],
             "focus": "List all API keys — name, permissions (Full Access, Restricted, Billing), creation date, and last used. Flag any full-access keys or unused keys"},
        ],
    },
    "sender_auth": {
        "name": "Sender Authentication",
        "description": "Domain and email authentication",
        "checks": [
            {"id": "domain_auth", "name": "Domain Authentication", "description": "DNS records and domain verification status",
             "pages": [{"label": "sg_sender_auth", "display": "Sender Authentication", "path": "/settings/sender_auth"}],
             "focus": "Review authenticated domains — SPF, DKIM, and DMARC status. Identify any unauthenticated senders or pending verifications"},
        ],
    },
    "teammates": {
        "name": "Teammates",
        "description": "Team member access and roles",
        "checks": [
            {"id": "teammate_list", "name": "Teammate Inventory", "description": "All team members and their access levels",
             "pages": [{"label": "sg_teammates", "display": "Teammates", "path": "/settings/teammates"}],
             "focus": "List all teammates — email, role (Admin, Developer, Analyst, etc.), invitation status, and 2FA status. Flag any inactive users or overly permissive roles"},
        ],
    },
    "ip_access": {
        "name": "IP Access Management",
        "description": "IP allowlisting and access controls",
        "checks": [
            {"id": "ip_access_list", "name": "IP Access List", "description": "Allowed IPs for account access",
             "pages": [{"label": "sg_ip_access", "display": "IP Access Management", "path": "/settings/access"}],
             "focus": "Review IP access restrictions — allowed IP ranges, whether IP access management is enabled, and any overly broad CIDR blocks"},
        ],
    },
    "two_factor": {
        "name": "Two-Factor Auth",
        "description": "Account-level 2FA enforcement",
        "checks": [
            {"id": "two_factor_status", "name": "2FA Status", "description": "Two-factor authentication settings",
             "pages": [{"label": "sg_two_factor", "display": "Two-Factor Authentication", "path": "/settings/auth"}],
             "focus": "Check if two-factor authentication is enforced for all teammates, and identify any accounts without 2FA enabled"},
        ],
    },
    "email_activity": {
        "name": "Email Activity",
        "description": "Recent email sending activity",
        "checks": [
            {"id": "activity_feed", "name": "Activity Feed", "description": "Recent email events and delivery status",
             "pages": [{"label": "sg_activity", "display": "Email Activity", "path": "/email_activity"}],
             "focus": "Review recent email activity — delivery rates, bounces, blocks, spam reports, and any unusual sending patterns that might indicate compromise"},
        ],
    },
}


# ═══════════════════════════════════════════════════════
# SendGrid Compliance Check
# ═══════════════════════════════════════════════════════

def check_sendgrid_service(username, password, service, check_id=None):
    """Log into SendGrid via Playwright and capture screenshots for the requested service check."""
    service_info = SENDGRID_SERVICE_PAGES.get(service)
    if not service_info:
        return {
            "provider": "sendgrid",
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
            "provider": "sendgrid",
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
        "provider": "sendgrid",
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

    screenshots = _take_sendgrid_screenshots(username, password, pages)
    results["screenshots"] = screenshots

    real_screenshots = [s for s in screenshots if not s["label"].startswith("debug_")]
    if not real_screenshots:
        results["status"] = "error"
        results["error"] = "SendGrid login failed or timed out. Please verify your username and password."
        logger.warning("SendGrid: No screenshots captured — marking result as error")
        return results

    for ss in screenshots:
        if ss["label"].startswith("debug_"):
            continue
        if not os.path.exists(ss["path"]):
            continue

        prompt = f"""You are a SendGrid email platform security auditor reviewing the SendGrid web console.

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
            logger.error(f"SendGrid vision analysis failed for {ss['label']}: {e}")
            results["vision_analysis"][ss["label"]] = {"error": str(e)}

    return results


def _take_sendgrid_screenshots(username, password, pages):
    """Log into SendGrid and capture screenshots."""
    screenshots = []
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
    except ImportError:
        logger.warning("Playwright not available — cannot take SendGrid screenshots")
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

        # ── Step 1: Navigate to SendGrid login ──
        try:
            page.goto("https://app.sendgrid.com/login", wait_until="commit", timeout=60000)
        except PlaywrightTimeout:
            logger.error("SendGrid: timed out loading login page")
            browser.close()
            return screenshots

        # Wait for login form
        try:
            page.wait_for_selector(
                'input[name="username"], input#username, input[type="email"], input[placeholder*="email" i]',
                state="visible", timeout=30000
            )
            logger.info("SendGrid: login form rendered")
            page.wait_for_timeout(1000)
        except PlaywrightTimeout:
            logger.error("SendGrid: login form never rendered")
            try:
                raw = page.screenshot(full_page=False)
                file_id, filepath, filename = _save_screenshot(raw, "sendgrid", "debug_login_not_rendered")
                screenshots.append({"file_id": file_id, "path": filepath, "filename": filename,
                                    "label": "debug_login_not_rendered", "description": "Login form did not render", "url": page.url})
            except Exception:
                pass
            browser.close()
            return screenshots

        # Fill username/email
        for selector in ['input[name="username"]', 'input#username', 'input[type="email"]', 'input[placeholder*="email" i]']:
            try:
                el = page.locator(selector)
                if el.count() > 0 and el.first.is_visible():
                    el.first.fill(username)
                    logger.info(f"SendGrid: filled username via {selector}")
                    break
            except Exception:
                continue

        # Fill password
        for selector in ['input[name="password"]', 'input#password', 'input[type="password"]']:
            try:
                el = page.locator(selector)
                if el.count() > 0 and el.first.is_visible():
                    el.first.fill(password)
                    logger.info(f"SendGrid: filled password via {selector}")
                    break
            except Exception:
                continue

        # Click sign in
        for selector in ['button[type="submit"]', 'button:has-text("Log In")', 'button:has-text("Sign In")', 'input[type="submit"]']:
            try:
                el = page.locator(selector)
                if el.count() > 0 and el.first.is_visible():
                    el.first.click()
                    logger.info(f"SendGrid: clicked login via {selector}")
                    break
            except Exception:
                continue

        # Wait for post-login redirect
        logged_in = False
        try:
            page.wait_for_url("**/app.sendgrid.com/**", timeout=60000)
            # Make sure we're not still on the login page
            if "/login" not in page.url:
                logged_in = True
                logger.info(f"SendGrid: logged in — URL: {page.url}")
            else:
                # Wait a bit more — might be redirecting
                page.wait_for_timeout(5000)
                if "/login" not in page.url:
                    logged_in = True
                    logger.info(f"SendGrid: logged in after extra wait — URL: {page.url}")
        except PlaywrightTimeout:
            if "app.sendgrid.com" in page.url and "/login" not in page.url:
                logged_in = True
                logger.info(f"SendGrid: detected logged-in URL: {page.url}")

        if logged_in:
            page.wait_for_timeout(3000)
            logger.info("SendGrid: login successful")
        else:
            try:
                raw = page.screenshot(full_page=False)
                file_id, filepath, filename = _save_screenshot(raw, "sendgrid", "debug_login_failed")
                screenshots.append({"file_id": file_id, "path": filepath, "filename": filename,
                                    "label": "debug_login_failed", "description": "Login timed out", "url": page.url})
            except Exception:
                pass
            logger.error(f"SendGrid: login timed out — URL: {page.url}")
            browser.close()
            return screenshots

        # ── Step 2: Navigate to each page and screenshot ──
        base_url = "https://app.sendgrid.com"
        for page_def in pages:
            label = page_def["label"]
            display = page_def["display"]
            target_url = base_url + page_def["path"]

            try:
                page.goto(target_url, wait_until="commit", timeout=60000)
                page.wait_for_timeout(3000)

                # Wait for content to load (poll for loading indicators)
                for attempt in range(15):
                    loading = page.locator('[class*="skeleton"], [class*="Skeleton"], [class*="loading"], [class*="spinner"], [role="progressbar"], svg[class*="spin"], [class*="Loader"]')
                    count = loading.count()
                    if count == 0:
                        logger.info(f"SendGrid: content loaded for {label} after {(attempt+1)*2}s")
                        break
                    page.wait_for_timeout(2000)
                else:
                    logger.warning(f"SendGrid: content still loading after 30s for {label}, capturing anyway")

                page.wait_for_timeout(2000)  # final settle

                raw = page.screenshot(full_page=False)
                file_id, filepath, filename = _save_screenshot(raw, "sendgrid", label)
                screenshots.append({
                    "file_id": file_id,
                    "path": filepath,
                    "filename": filename,
                    "label": label,
                    "description": display,
                    "url": page.url,
                })
                logger.info(f"SendGrid screenshot captured: {label}")
            except PlaywrightTimeout:
                logger.warning(f"SendGrid: timeout navigating to {label}")
            except Exception as ex:
                logger.warning(f"SendGrid: error capturing {label}: {ex}")

        browser.close()

    return screenshots
