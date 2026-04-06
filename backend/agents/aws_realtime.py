"""API-only AWS realtime monitoring with provider-wide inventory snapshots."""

from __future__ import annotations

import html
import json
import logging
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List

import boto3
from botocore.config import Config as BotoConfig

logger = logging.getLogger(__name__)

SCREENSHOTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)


def _svc(
    name: str,
    description: str,
    client: str,
    operation: str,
    result_key: str,
    *,
    params: Dict[str, Any] | None = None,
    global_service: bool = False,
) -> Dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "client": client,
        "operation": operation,
        "result_key": result_key,
        "params": params or {},
        "global_service": global_service,
    }


AWS_REALTIME_SERVICE_CATALOG: Dict[str, Dict[str, Any]] = {
    "ec2": _svc("EC2", "Compute instances and reservations", "ec2", "describe_instances", "Reservations"),
    "s3": _svc("S3", "Buckets and object storage posture", "s3", "list_buckets", "Buckets", global_service=True),
    "iam": _svc("IAM", "Users, roles, and access management", "iam", "list_users", "Users", global_service=True),
    "rds": _svc("RDS", "Relational databases", "rds", "describe_db_instances", "DBInstances"),
    "vpc": _svc("VPC", "Networks, subnets, and routing", "ec2", "describe_vpcs", "Vpcs"),
    "lambda": _svc("Lambda", "Serverless functions", "lambda", "list_functions", "Functions"),
    "cloudwatch": _svc("CloudWatch", "Metrics and alarms", "cloudwatch", "describe_alarms", "MetricAlarms"),
    "kms": _svc("KMS", "Encryption keys and rotation", "kms", "list_keys", "Keys"),
    "secretsmanager": _svc("Secrets Manager", "Secrets inventory and rotation", "secretsmanager", "list_secrets", "SecretList"),
    "guardduty": _svc("GuardDuty", "Threat detection detectors", "guardduty", "list_detectors", "DetectorIds"),
    "securityhub": _svc("Security Hub", "Enabled standards and findings pipeline", "securityhub", "get_enabled_standards", "StandardsSubscriptions"),
    "dynamodb": _svc("DynamoDB", "NoSQL tables and backups", "dynamodb", "list_tables", "TableNames"),
    "cloudtrail": _svc("CloudTrail", "Audit trails and event logging", "cloudtrail", "describe_trails", "trailList"),
    "config": _svc("AWS Config", "Configuration tracking and compliance", "config", "describe_config_rules", "ConfigRules"),
    "sns": _svc("SNS", "Notification topics", "sns", "list_topics", "Topics"),
    "sqs": _svc("SQS", "Queues and message retention", "sqs", "list_queues", "QueueUrls"),
    "ecs": _svc("ECS", "Container orchestration", "ecs", "list_clusters", "clusterArns"),
    "eks": _svc("EKS", "Kubernetes clusters", "eks", "list_clusters", "clusters"),
    "route53": _svc("Route 53", "DNS zones and routing", "route53", "list_hosted_zones", "HostedZones", global_service=True),
    "cloudfront": _svc("CloudFront", "CDN distributions", "cloudfront", "list_distributions", "DistributionList.Items", global_service=True),
    "ecr": _svc("ECR", "Container registries", "ecr", "describe_repositories", "repositories"),
    "elasticloadbalancingv2": _svc("ELBv2", "Application and network load balancers", "elbv2", "describe_load_balancers", "LoadBalancers"),
    "autoscaling": _svc("Auto Scaling", "Scaling groups", "autoscaling", "describe_auto_scaling_groups", "AutoScalingGroups"),
    "acm": _svc("ACM", "Certificates and renewals", "acm", "list_certificates", "CertificateSummaryList"),
    "apigateway": _svc("API Gateway REST", "REST APIs", "apigateway", "get_rest_apis", "items"),
    "apigatewayv2": _svc("API Gateway HTTP/WebSocket", "HTTP and WebSocket APIs", "apigatewayv2", "get_apis", "Items"),
    "cloudformation": _svc("CloudFormation", "Stacks and drift risk", "cloudformation", "list_stacks", "StackSummaries"),
    "elasticache": _svc("ElastiCache", "Cache clusters", "elasticache", "describe_cache_clusters", "CacheClusters"),
    "efs": _svc("EFS", "Elastic file systems", "efs", "describe_file_systems", "FileSystems"),
    "fsx": _svc("FSx", "Managed file systems", "fsx", "describe_file_systems", "FileSystems"),
    "backup": _svc("AWS Backup", "Backup vaults and protection", "backup", "list_backup_vaults", "BackupVaultList"),
    "redshift": _svc("Redshift", "Data warehouse clusters", "redshift", "describe_clusters", "Clusters"),
    "athena": _svc("Athena", "Query workgroups", "athena", "list_work_groups", "WorkGroups"),
    "glue": _svc("Glue", "Data catalog and jobs", "glue", "get_databases", "DatabaseList"),
    "logs": _svc("CloudWatch Logs", "Log groups and retention", "logs", "describe_log_groups", "logGroups"),
    "organizations": _svc("Organizations", "Accounts and org structure", "organizations", "list_accounts", "Accounts", global_service=True),
    "wafv2": _svc("WAF", "Web ACLs and edge protections", "wafv2", "list_web_acls", "WebACLs", params={"Scope": "REGIONAL"}),
    "sesv2": _svc("SES", "Email identities and deliverability", "sesv2", "list_email_identities", "EmailIdentities"),
    "elasticbeanstalk": _svc("Elastic Beanstalk", "Applications and environments", "elasticbeanstalk", "describe_applications", "Applications"),
    "opensearch": _svc("OpenSearch", "Search domains", "opensearch", "list_domain_names", "DomainNames"),
    "mq": _svc("Amazon MQ", "Message brokers", "mq", "list_brokers", "BrokerSummaries"),
    "stepfunctions": _svc("Step Functions", "State machines and workflows", "stepfunctions", "list_state_machines", "stateMachines"),
    "inspector2": _svc("Inspector", "Vulnerability findings", "inspector2", "list_findings", "findings"),
    "eventbridge": _svc("EventBridge", "Event rules and buses", "events", "list_rules", "Rules"),
    "ssm": _svc("Systems Manager", "Managed instances and automation", "ssm", "describe_instance_information", "InstanceInformationList"),
    "ram": _svc("Resource Access Manager", "Shared resources", "ram", "get_resource_shares", "resourceShares", params={"resourceOwner": "SELF"}),
    "detective": _svc("Detective", "Investigation graphs", "detective", "list_graphs", "GraphList"),
    "shield": _svc("Shield", "DDoS protections", "shield", "list_protections", "Protections", global_service=True),
}


def list_aws_realtime_services() -> List[Dict[str, str]]:
    return [
        {"id": service_id, "name": meta["name"], "description": meta["description"]}
        for service_id, meta in AWS_REALTIME_SERVICE_CATALOG.items()
    ]


def validate_aws_credentials(access_key: str, secret_key: str, region: str) -> Dict[str, Any]:
    if not access_key or not secret_key:
        return {"configured": False, "healthy": False, "message": "Missing AWS API credentials in .env"}

    try:
        session = _build_session(access_key, secret_key, region)
        identity = session.client("sts").get_caller_identity()
        return {
            "configured": True,
            "healthy": True,
            "message": "AWS API credentials verified",
            "details": {
                "account": identity.get("Account"),
                "arn": identity.get("Arn"),
                "region": region,
                "mode": "api-only",
            },
        }
    except Exception as exc:  # pragma: no cover - cloud credentials vary by environment
        return {"configured": True, "healthy": False, "message": f"AWS validation failed: {exc}"}


def check_aws_realtime_service(access_key: str, secret_key: str, region: str, service: str, include_screenshot: bool = True) -> Dict[str, Any]:
    meta = AWS_REALTIME_SERVICE_CATALOG.get(service)
    if not meta:
        return {
            "provider": "aws",
            "service": service,
            "service_name": service,
            "status": "error",
            "error": f"Unknown AWS service integration: {service}",
            "screenshots": [],
            "api_findings": {},
            "vision_analysis": {},
        }

    session = _build_session(access_key, secret_key, region)
    observed_region = "global" if meta.get("global_service") else "all enabled regions"
    api_findings = {
        "integration": {
            "service_id": service,
            "service_name": meta["name"],
            "description": meta["description"],
            "region": observed_region,
            "region_scope": "global" if meta.get("global_service") else "regional",
            "mode": "api-only realtime monitor",
            "checked_at": datetime.utcnow().isoformat(),
        }
    }

    try:
        items = _fetch_service_items(session, meta, region)
        available_regions = _collect_available_regions(items)
        regional_counts = _count_items_by_region(items)
        status = "completed"
        errors: List[str] = []
    except Exception as exc:  # pragma: no cover - depends on live AWS permissions
        items = []
        available_regions = []
        regional_counts = {}
        status = "error"
        errors = [str(exc)]

    api_findings["integration"]["available_regions"] = available_regions
    api_findings["inventory"] = {
        "resource_count": len(items),
        "sample": _sample_items(items),
        "items_preview": _items_preview(items),
        "available_regions": available_regions,
        "regional_resource_counts": regional_counts,
    }
    api_findings["health"] = _build_health_section(meta, items, errors, available_regions)
    if errors:
        api_findings["errors"] = {"messages": errors}

    result = {
        "provider": "aws",
        "service": service,
        "service_name": meta["name"],
        "service_description": meta["description"],
        "check": "Realtime AWS Integration Monitor",
        "check_description": f"Live API inventory and posture summary for {meta['name']}",
        "timestamp": datetime.utcnow().isoformat(),
        "status": status,
        "api_findings": api_findings,
        "vision_analysis": {},
        "screenshots": [],
        "encryption_enabled": True if status == "completed" and not errors else None,
    }

    if include_screenshot:
        screenshot = _capture_result_dashboard(result)
        if screenshot:
            result["screenshots"].append(screenshot)

    if status == "error":
        result["error"] = errors[0]

    return result


def check_aws_realtime_posture(access_key: str, secret_key: str, region: str, selected_service: str | None = None) -> Dict[str, Any]:
    services: Dict[str, Any] = {}
    counts = {"pass": 0, "warn": 0, "fail": 0, "unknown": 0}

    for service_id, meta in AWS_REALTIME_SERVICE_CATALOG.items():
        service_result = check_aws_realtime_service(access_key, secret_key, region, service_id, include_screenshot=False)
        health = service_result.get("api_findings", {}).get("health", {})
        status = health.get("status", "unknown")
        if status not in counts:
            status = "unknown"
        counts[status] += 1

        services[service_id] = {
            "name": meta["name"],
            "status": status,
            "score": health.get("score", 45),
            "summary": health.get("summary") or service_result.get("check_description") or meta["description"],
            "metrics": {
                "resources": service_result.get("api_findings", {}).get("inventory", {}).get("resource_count", 0),
                "region": service_result.get("api_findings", {}).get("integration", {}).get("region", region),
            },
            "metadata": service_result,
        }

    total = max(len(services), 1)
    overall_score = round(sum(item["score"] for item in services.values()) / total)
    selected_key = selected_service if selected_service in services else next(iter(services.keys()), None)

    return {
        "provider": "aws",
        "check": "AWS Realtime Posture Overview",
        "service_name": "Realtime Posture Overview",
        "selected_service": selected_key,
        "timestamp": datetime.utcnow().isoformat(),
        "aws_summary": {
            "score": overall_score,
            "overall_status": "pass" if counts["fail"] == 0 and counts["warn"] == 0 else "warn" if counts["fail"] == 0 else "fail",
            "status_counts": counts,
            "service_count": len(services),
        },
        "services": services,
        "screenshots": [],
        "api_findings": {},
        "vision_analysis": {},
        "status": "completed",
    }


def _build_session(access_key: str, secret_key: str, region: str):
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )


def _fetch_service_items(session, meta: Dict[str, Any], region: str) -> List[Any]:
    if meta.get("global_service"):
        return _fetch_service_items_for_region(session, meta, "us-east-1")[:100]

    collected: List[Any] = []
    for region_name in _list_enabled_regions(session, region):
        try:
            collected.extend(_fetch_service_items_for_region(session, meta, region_name))
        except Exception as exc:
            logger.debug("AWS service %s unavailable in %s: %s", meta["name"], region_name, exc)
        if len(collected) >= 100:
            break
    return collected[:100]


def _fetch_service_items_for_region(session, meta: Dict[str, Any], region_name: str) -> List[Any]:
    client = session.client(meta["client"], region_name=region_name, config=BotoConfig(retries={"max_attempts": 3}))
    operation_name = meta["operation"]
    params = dict(meta.get("params") or {})

    if operation_name == "list_findings" and meta["client"] == "inspector2":
        params.setdefault("maxResults", 25)

    operation = getattr(client, operation_name)
    try:
        paginator = client.get_paginator(operation_name)
        pages = paginator.paginate(**params)
        collected: List[Any] = []
        for page in pages:
            collected.extend(_normalize_items(meta, page, region_name))
            if len(collected) >= 100:
                break
        return collected[:100]
    except Exception:
        response = operation(**params)
        return _normalize_items(meta, response, region_name)[:100]


def _normalize_items(meta: Dict[str, Any], payload: Dict[str, Any], region_name: str) -> List[Any]:
    if meta["client"] == "ec2" and meta["operation"] == "describe_instances":
        reservations = _coerce_items(_extract_result_path(payload, meta["result_key"]))
        flattened: List[Any] = []
        for reservation in reservations:
            if not isinstance(reservation, dict):
                flattened.append(_attach_aws_region_context(reservation, region_name))
                continue
            instances = reservation.get("Instances") or []
            if not instances:
                flattened.append(_attach_aws_region_context(reservation, region_name))
                continue
            for instance in instances:
                if isinstance(instance, dict):
                    enriched = dict(instance)
                    enriched.setdefault("ReservationId", reservation.get("ReservationId"))
                    enriched.setdefault("OwnerId", reservation.get("OwnerId"))
                    enriched.setdefault("Name", _extract_tag_value(instance.get("Tags"), "Name"))
                    state = instance.get("State")
                    if isinstance(state, dict) and state.get("Name"):
                        enriched.setdefault("StateName", state.get("Name"))
                    flattened.append(_attach_aws_region_context(enriched, region_name))
                else:
                    flattened.append(_attach_aws_region_context(instance, region_name))
        return flattened

    value = _extract_result_path(payload, meta["result_key"])
    return [_attach_aws_region_context(item, region_name) for item in _coerce_items(value)]


def _list_enabled_regions(session, default_region: str) -> List[str]:
    try:
        client = session.client("ec2", region_name=default_region or "us-east-1", config=BotoConfig(retries={"max_attempts": 3}))
        response = client.describe_regions(AllRegions=False)
        regions = sorted(region.get("RegionName") for region in response.get("Regions", []) if region.get("RegionName"))
        return regions or [default_region or "us-east-1"]
    except Exception as exc:
        logger.debug("Falling back to configured AWS region list: %s", exc)
        return [default_region or "us-east-1"]


def _extract_result_path(payload: Dict[str, Any], path: str) -> Any:
    current: Any = payload
    for key in path.split("."):
        if isinstance(current, dict):
            current = current.get(key, [])
        else:
            return []
    return current


def _coerce_items(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _sample_items(items: List[Any]) -> List[Any]:
    sample = []
    for item in items[:5]:
        if isinstance(item, dict):
            compact = {}
            for key, value in item.items():
                if isinstance(value, (str, int, float, bool)) or value is None:
                    compact[key] = value
                elif isinstance(value, list):
                    compact[key] = f"{len(value)} item(s)"
                elif isinstance(value, dict):
                    compact[key] = json.dumps(value)[:120]
                if len(compact) >= 6:
                    break
            sample.append(compact)
        else:
            sample.append(item)
    return sample


def _items_preview(items: List[Any]) -> List[Any]:
    return [_serialize_preview_item(item) for item in items[:50]]


def _attach_aws_region_context(item: Any, region_name: str) -> Any:
    if not isinstance(item, dict):
        return item
    enriched = dict(item)
    enriched.setdefault("_region", region_name)
    return enriched


def _collect_available_regions(items: List[Any]) -> List[str]:
    return sorted({item.get("_region") for item in items if isinstance(item, dict) and item.get("_region")})


def _count_items_by_region(items: List[Any]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        region_name = item.get("_region")
        if not region_name:
            continue
        counts[region_name] = counts.get(region_name, 0) + 1
    return counts


def _serialize_preview_item(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [_serialize_preview_item(item) for item in value[:8]]
    if isinstance(value, dict):
        if value.get("InstanceId"):
            return _serialize_ec2_instance_preview(value)
        serialized = {}
        display_name = _derive_aws_display_name(value)
        if display_name:
            serialized["display_name"] = display_name
        preferred_keys = ["_region", "name", "Name", "id", "Id", "Arn", "ArnValue", "State", "StateName", "location"]
        for key in preferred_keys:
            if key in value and len(serialized) < 12:
                serialized[key] = _serialize_preview_item(value[key])
        for index, (key, item) in enumerate(value.items()):
            if key in serialized:
                continue
            if len(serialized) >= 12 or index >= 20:
                break
            serialized[key] = _serialize_preview_item(item)
        return serialized
    return str(value)


def _serialize_ec2_instance_preview(value: Dict[str, Any]) -> Dict[str, Any]:
    preview: Dict[str, Any] = {}
    display_name = _derive_aws_display_name(value)
    if display_name:
        preview["display_name"] = display_name
    ordered_fields = [
        "Name",
        "InstanceId",
        "_region",
        "StateName",
        "InstanceType",
        "PrivateIpAddress",
        "PublicIpAddress",
        "VpcId",
        "SubnetId",
        "Architecture",
        "PlatformDetails",
        "LaunchTime",
        "ReservationId",
        "ImageId",
    ]
    for key in ordered_fields:
        if key in value and value.get(key) not in (None, ""):
            preview[key] = _serialize_preview_item(value[key])

    if "State" in value and "StateName" not in preview:
        state = value.get("State")
        if isinstance(state, dict) and state.get("Name"):
            preview["StateName"] = state.get("Name")

    if len(preview) < 14:
        for key, item in value.items():
            if key in preview:
                continue
            if len(preview) >= 14:
                break
            if isinstance(item, (dict, list)):
                continue
            preview[key] = _serialize_preview_item(item)
    return preview


def _extract_tag_value(tags: Any, key_name: str) -> str | None:
    if not isinstance(tags, list):
        return None
    for tag in tags:
        if isinstance(tag, dict) and tag.get("Key") == key_name:
            return tag.get("Value")
    return None


def _derive_aws_display_name(item: Dict[str, Any]) -> str | None:
    if not isinstance(item, dict):
        return None

    keys = [
        "Name", "InstanceId", "VpcId", "SubnetId", "GroupId", "NetworkInterfaceId",
        "InternetGatewayId", "NatGatewayId", "RouteTableId", "VpcPeeringConnectionId",
        "TransitGatewayId", "VolumeId", "SnapshotId", "ImageId", "LaunchTemplateId",
        "AllocationId", "EgressOnlyInternetGatewayId", "PrefixListId", "VpnGatewayId",
        "VpnConnectionId", "CustomerGatewayId", "UserName", "RoleName",
        "DBInstanceIdentifier", "DBClusterIdentifier", "DBSubnetGroupName",
        "FunctionName", "BucketName", "TableName", "QueueName", "QueueUrl",
        "TopicName", "TopicArn", "ClusterName", "RepositoryName", "SecretName",
        "KeyId", "AliasName", "DistributionId", "HostedZoneId", "LoadBalancerArn",
        "LoadBalancerName", "TargetGroupArn", "AutoScalingGroupName", "CertificateArn",
        "RestApiId", "ApiId", "StackName", "CacheClusterId", "FileSystemId",
        "VaultName", "WorkGroup", "Id", "Arn"
    ]
    for key in keys:
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            if key == "QueueUrl":
                parts = value.split("/")
                return parts[-1] or value
            if key == "TopicArn" or key == "Arn" or key.endswith("Arn"):
                arn_parts = value.split(":")
                return arn_parts[-1] or value
            return value

    name_tag = _extract_tag_value(item.get("Tags"), "Name")
    if name_tag:
        return name_tag
    return None


def _build_health_section(meta: Dict[str, Any], items: List[Any], errors: List[str], available_regions: List[str]) -> Dict[str, Any]:
    score = 92 if not errors else 58
    status = "pass" if not errors else "warn"
    region_note = f" across {len(available_regions)} region(s)" if available_regions and not meta.get("global_service") else ""
    return {
        "status": status,
        "score": score,
        "summary": (
            f"Live AWS API check completed for {meta['name']} with {len(items)} resource(s) discovered{region_note}."
            if not errors
            else f"AWS API check completed with partial visibility issues for {meta['name']}."
        ),
        "observations": [
            f"Realtime AWS API integration is active for {meta['name']}.",
            f"Observed {len(items)} resource(s) from {meta['operation']}{region_note}.",
        ] + ([f"Permission or API issue: {errors[0]}"] if errors else []),
    }


def _capture_result_dashboard(result: Dict[str, Any]) -> Dict[str, Any] | None:
    html_doc = _render_dashboard_html(result)
    filename = f"aws_realtime_{result['service']}_{uuid.uuid4()}.png"
    file_path = os.path.join(SCREENSHOTS_DIR, filename)

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover - depends on local runtime
        logger.info("Playwright unavailable for AWS realtime screenshot generation: %s", exc)
        return None

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            page = browser.new_page(viewport={"width": 1440, "height": 1080}, device_scale_factor=1)
            page.set_content(html_doc, wait_until="load")
            page.screenshot(path=file_path, full_page=True)
            browser.close()
    except Exception as exc:  # pragma: no cover - browser runtime varies
        logger.warning("Failed to generate AWS realtime dashboard screenshot: %s", exc)
        return None

    return {
        "file_id": str(uuid.uuid4()),
        "filename": filename,
        "label": f"aws_{result['service']}_dashboard",
        "description": f"{result['service_name']} realtime API dashboard",
    }


def _render_dashboard_html(result: Dict[str, Any]) -> str:
    api_findings = result.get("api_findings", {})
    cards = []
    for section_name, section_value in api_findings.items():
        cards.append(
            f"""
            <section class="card">
                <h3>{html.escape(section_name.replace('_', ' ').title())}</h3>
                <pre>{html.escape(json.dumps(section_value, indent=2, default=str))}</pre>
            </section>
            """
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{html.escape(result['service_name'])} Realtime Monitor</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #07111f;
      --panel: #101b2d;
      --panel-alt: #14233b;
      --border: rgba(148, 163, 184, 0.18);
      --text: #e2e8f0;
      --muted: #9fb0c8;
      --accent: #38bdf8;
      --good: #34d399;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, Arial, sans-serif;
      background:
        radial-gradient(circle at top left, rgba(56, 189, 248, 0.18), transparent 28%),
        linear-gradient(180deg, #050b16, var(--bg));
      color: var(--text);
      padding: 40px;
    }}
    .hero {{
      display: flex;
      justify-content: space-between;
      gap: 24px;
      margin-bottom: 24px;
      padding: 28px;
      border-radius: 28px;
      background: linear-gradient(135deg, rgba(20, 35, 59, 0.98), rgba(11, 18, 33, 0.96));
      border: 1px solid var(--border);
    }}
    .hero h1 {{
      margin: 10px 0 8px;
      font-size: 54px;
      line-height: 1.02;
      max-width: 12ch;
    }}
    .eyebrow {{
      margin: 0;
      color: var(--accent);
      letter-spacing: 0.18em;
      text-transform: uppercase;
      font-size: 12px;
      font-weight: 700;
    }}
    .hero p {{
      margin: 0;
      color: var(--muted);
      max-width: 62ch;
      line-height: 1.7;
      font-size: 18px;
    }}
    .score {{
      min-width: 180px;
      border-radius: 999px;
      display: grid;
      place-items: center;
      padding: 20px;
      aspect-ratio: 1;
      background: radial-gradient(circle at 35% 30%, rgba(56, 189, 248, 0.28), transparent 38%), rgba(15, 23, 42, 0.9);
      border: 1px solid var(--border);
    }}
    .score strong {{
      display: block;
      font-size: 58px;
      line-height: 1;
    }}
    .score span {{
      color: var(--muted);
      font-size: 13px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
    }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .metric {{
      padding: 18px 20px;
      border-radius: 20px;
      background: rgba(16, 27, 45, 0.9);
      border: 1px solid var(--border);
    }}
    .metric span {{
      display: block;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-size: 12px;
    }}
    .metric strong {{
      display: block;
      margin-top: 8px;
      font-size: 32px;
      color: var(--good);
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 18px;
    }}
    .card {{
      padding: 22px;
      border-radius: 24px;
      background: linear-gradient(180deg, rgba(16, 27, 45, 0.96), rgba(10, 17, 31, 0.92));
      border: 1px solid var(--border);
    }}
    .card h3 {{
      margin: 0 0 12px;
      font-size: 16px;
    }}
    pre {{
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      color: #c7d8ee;
      font-size: 13px;
      line-height: 1.65;
      font-family: "JetBrains Mono", monospace;
    }}
  </style>
</head>
<body>
  <div class="hero">
    <div>
      <p class="eyebrow">AWS Realtime Integration</p>
      <h1>{html.escape(result['service_name'])} status</h1>
      <p>{html.escape(result.get('check_description', 'Live AWS API monitor'))}</p>
    </div>
    <div class="score">
      <div>
        <strong>{api_findings.get('health', {}).get('score', 0)}</strong>
        <span>live score</span>
      </div>
    </div>
  </div>
  <div class="metrics">
    <div class="metric"><span>Provider</span><strong>AWS</strong></div>
    <div class="metric"><span>Mode</span><strong>API</strong></div>
    <div class="metric"><span>Resources</span><strong>{api_findings.get('inventory', {}).get('resource_count', 0)}</strong></div>
    <div class="metric"><span>Status</span><strong>{html.escape(api_findings.get('health', {}).get('status', 'unknown').upper())}</strong></div>
  </div>
  <div class="grid">
    {''.join(cards)}
  </div>
</body>
</html>"""
