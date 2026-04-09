"""API-only IBM Cloud realtime monitoring backed by IBM IAM and Resource Controller."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List
from urllib.parse import urljoin

import requests

IAM_TOKEN_URL = "https://iam.cloud.ibm.com/identity/token"
RESOURCE_GROUPS_URL = "https://resource-controller.cloud.ibm.com/v2/resource_groups"
RESOURCE_INSTANCES_URL = "https://resource-controller.cloud.ibm.com/v2/resource_instances"
REQUEST_TIMEOUT = 30
PAGE_SIZE = 100
MAX_GROUP_PAGES = 3
MAX_INSTANCE_PAGES = 8
MAX_SERVICE_PREVIEW = 50


def _svc(
    name: str,
    description: str,
    patterns: List[str],
    *,
    category: str,
    global_service: bool = False,
    special_source: str | None = None,
) -> Dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "patterns": patterns,
        "category": category,
        "global_service": global_service,
        "special_source": special_source,
    }


IBM_REALTIME_SERVICE_CATALOG: Dict[str, Dict[str, Any]] = {
    "resource_groups": _svc("Resource Groups", "Account-level resource group boundaries and tenancy segmentation", [], category="Foundation", global_service=True, special_source="resource_groups"),
    "resource_instances": _svc("Resource Instances", "All billable IBM Cloud resource instances discovered for the account", [], category="Foundation", global_service=True, special_source="resource_instances"),
    "virtual_private_cloud": _svc("Virtual Private Cloud", "IBM Cloud VPC service footprint across account regions", [r"service:is\b", r"service:vpc\b"], category="Networking"),
    "transit_gateway": _svc("Transit Gateway", "Cross-network transit connectivity footprint", [r"service:transit\b", r"service:transit-gateway\b"], category="Networking"),
    "direct_link": _svc("Direct Link", "Dedicated private connectivity to IBM Cloud", [r"service:directlink\b", r"service:direct-link\b"], category="Networking"),
    "internet_services": _svc("Internet Services", "Edge acceleration, DNS, and WAF controls", [r"service:internet-svcs\b", r"service:internet-services\b"], category="Networking", global_service=True),
    "dns_services": _svc("DNS Services", "Managed DNS zones and resolution surfaces", [r"service:dns-svcs\b", r"service:dns-services\b"], category="Networking", global_service=True),
    "load_balancer_service": _svc("Load Balancer Service", "Managed load balancing service instances", [r"service:load-balancer\b", r"service:loadbalancer\b"], category="Networking"),
    "virtual_private_endpoints": _svc("Virtual Private Endpoints", "Private service endpoint connectivity", [r"service:vpe\b", r"service:private-endpoint\b"], category="Networking"),
    "service_endpoints": _svc("Service Endpoints", "Private service networking perimeter", [r"service:service-endpoints\b", r"service:serviceendpoint\b"], category="Networking", global_service=True),
    "kubernetes_service": _svc("Kubernetes Service", "Managed Kubernetes cluster footprint", [r"service:containers-kubernetes\b", r"service:kubernetes-service\b", r"service:ks\b"], category="Containers"),
    "red_hat_openshift": _svc("Red Hat OpenShift", "OpenShift cluster service instances", [r"service:openshift\b", r"service:openshift-container-platform\b"], category="Containers"),
    "satellite": _svc("Satellite", "Distributed IBM Cloud Satellite locations and configs", [r"service:satellite\b"], category="Containers"),
    "code_engine": _svc("Code Engine", "Serverless apps, jobs, and project environments", [r"service:codeengine\b", r"service:code-engine\b"], category="Compute"),
    "cloud_functions": _svc("Cloud Functions", "Event-driven function and namespace services", [r"service:functions\b", r"service:cloud-functions\b"], category="Compute"),
    "container_registry": _svc("Container Registry", "Container image registry inventory", [r"service:container-registry\b", r"service:cr\b"], category="Compute"),
    "continuous_delivery": _svc("Continuous Delivery", "Toolchains and delivery pipeline services", [r"service:continuous-delivery\b", r"service:toolchain\b"], category="DevOps"),
    "schematics": _svc("Schematics", "Terraform and IaC workspace services", [r"service:schematics\b"], category="DevOps"),
    "api_connect": _svc("API Connect", "API management platform instances", [r"service:apiconnect\b", r"service:api-connect\b"], category="Integration"),
    "app_connect": _svc("App Connect", "Application and data integration services", [r"service:app-connect\b", r"service:appconnect\b"], category="Integration"),
    "event_notifications": _svc("Event Notifications", "Notification topics and destination services", [r"service:event-notifications\b", r"service:eventnotifications\b"], category="Integration"),
    "event_streams": _svc("Event Streams", "Kafka-compatible streaming service instances", [r"service:eventstreams\b", r"service:event-streams\b", r"service:messagehub\b"], category="Integration"),
    "mq": _svc("IBM MQ", "Managed messaging queue instances", [r"service:mq\b", r"service:ibm-mq\b"], category="Integration"),
    "messages_for_rabbitmq": _svc("Messages for RabbitMQ", "Managed RabbitMQ service instances", [r"service:messages-for-rabbitmq\b", r"service:rabbitmq\b"], category="Integration"),
    "cloud_object_storage": _svc("Cloud Object Storage", "Bucket-oriented object storage services", [r"service:cloud-object-storage\b", r"service:cos\b"], category="Storage", global_service=True),
    "file_storage": _svc("File Storage", "Managed file storage service instances", [r"service:file-storage\b", r"service:file-storage-v2\b"], category="Storage"),
    "block_storage": _svc("Block Storage", "Managed block storage service instances", [r"service:block-storage\b"], category="Storage"),
    "backup_for_vpc": _svc("Backup for VPC", "Snapshot and backup protection service for VPC", [r"service:backup-for-vpc\b", r"service:backup\b"], category="Storage"),
    "databases_for_postgresql": _svc("Databases for PostgreSQL", "Managed PostgreSQL service instances", [r"service:databases-for-postgresql\b", r"service:postgresql\b"], category="Data"),
    "databases_for_mysql": _svc("Databases for MySQL", "Managed MySQL service instances", [r"service:databases-for-mysql\b", r"service:mysql\b"], category="Data"),
    "databases_for_mongodb": _svc("Databases for MongoDB", "Managed MongoDB service instances", [r"service:databases-for-mongodb\b", r"service:mongodb\b"], category="Data"),
    "databases_for_redis": _svc("Databases for Redis", "Managed Redis service instances", [r"service:databases-for-redis\b", r"service:redis\b"], category="Data"),
    "databases_for_etcd": _svc("Databases for etcd", "Managed etcd service instances", [r"service:databases-for-etcd\b", r"service:etcd\b"], category="Data"),
    "cloudant": _svc("Cloudant", "Managed CouchDB-compatible data service", [r"service:cloudantnosqldb\b", r"service:cloudant\b"], category="Data"),
    "db2": _svc("Db2", "Managed Db2 database instances", [r"service:dashdb-for-transactions\b", r"service:db2\b"], category="Data"),
    "datastax": _svc("Datastax", "Managed Cassandra-compatible database instances", [r"service:datastax-enterprise\b", r"service:datastax\b"], category="Data"),
    "enterprise_db": _svc("EDB Postgres", "EnterpriseDB managed PostgreSQL services", [r"service:enterprise-db\b", r"service:edb\b"], category="Data"),
    "analytics_engine": _svc("Analytics Engine", "Spark and analytics cluster services", [r"service:analytics-engine\b"], category="Data"),
    "data_stage": _svc("DataStage", "Data integration and ETL service instances", [r"service:datastage\b", r"service:data-stage\b"], category="Data"),
    "data_virtualization": _svc("Data Virtualization", "Federated data virtualization service instances", [r"service:data-virtualization\b"], category="Data"),
    "watson_query": _svc("watsonx.data Query", "Query surfaces for watsonx.data", [r"service:watson-query\b", r"service:watsonx-data\b"], category="Data"),
    "watsonx_ai": _svc("watsonx.ai", "Foundation model and AI runtime service instances", [r"service:watsonx-ai\b", r"service:wml\b", r"service:machine-learning\b"], category="AI"),
    "watsonx_data": _svc("watsonx.data", "Lakehouse and data warehouse service instances", [r"service:watsonx-data\b"], category="AI"),
    "watson_studio": _svc("Watson Studio", "Collaborative notebook and project workspaces", [r"service:watson-studio\b"], category="AI"),
    "knowledge_catalog": _svc("Knowledge Catalog", "Data catalog and governance service instances", [r"service:wkc\b", r"service:knowledge-catalog\b"], category="AI"),
    "assistant": _svc("Watson Assistant", "Conversational AI assistant service instances", [r"service:conversation\b", r"service:assistant\b"], category="AI"),
    "discovery": _svc("Watson Discovery", "Discovery and search service instances", [r"service:discovery\b"], category="AI"),
    "speech_to_text": _svc("Speech to Text", "Speech recognition service instances", [r"service:speech-to-text\b"], category="AI"),
    "text_to_speech": _svc("Text to Speech", "Speech synthesis service instances", [r"service:text-to-speech\b"], category="AI"),
    "natural_language_understanding": _svc("Natural Language Understanding", "Text enrichment and classification service instances", [r"service:natural-language-understanding\b"], category="AI"),
    "language_translator": _svc("Language Translator", "Machine translation service instances", [r"service:language-translator\b"], category="AI"),
    "visual_recognition": _svc("Visual Recognition", "Computer vision service instances", [r"service:visual-recognition\b"], category="AI"),
    "app_id": _svc("App ID", "Identity and user authentication service instances", [r"service:appid\b", r"service:app-id\b"], category="Security", global_service=True),
    "key_protect": _svc("Key Protect", "Managed key management service instances", [r"service:kms\b", r"service:key-protect\b"], category="Security", global_service=True),
    "hyper_protect_crypto_services": _svc("Hyper Protect Crypto Services", "Hardware-backed key management services", [r"service:hs-crypto\b", r"service:hyper-protect-crypto-services\b"], category="Security", global_service=True),
    "secrets_manager": _svc("Secrets Manager", "Managed secret storage service instances", [r"service:secrets-manager\b"], category="Security", global_service=True),
    "security_and_compliance_center": _svc("Security and Compliance Center", "Continuous security posture service instances", [r"service:compliance\b", r"service:security-and-compliance-center\b"], category="Security", global_service=True),
    "certificate_manager": _svc("Certificate Manager", "Managed certificate service instances", [r"service:certificate-manager\b"], category="Security", global_service=True),
    "log_analysis": _svc("Log Analysis", "Indexed log analysis service instances", [r"service:logdnaat\b", r"service:log-analysis\b"], category="Observability"),
    "activity_tracker": _svc("Activity Tracker", "Audit event collection service instances", [r"service:atracker\b", r"service:activity-tracker\b"], category="Observability", global_service=True),
    "cloud_monitoring": _svc("Cloud Monitoring", "Metrics and alerting service instances", [r"service:sysdig-monitor\b", r"service:cloud-monitoring\b"], category="Observability"),
    "cloud_logs": _svc("Cloud Logs", "Next-generation cloud log service instances", [r"service:logs\b", r"service:cloud-logs\b"], category="Observability"),
    "observability_dashboards": _svc("Observability Dashboards", "Dashboard and insights service instances", [r"service:monitoring-dashboard\b", r"service:instana\b"], category="Observability"),
    "instana": _svc("Instana", "Application performance monitoring service instances", [r"service:instana\b"], category="Observability"),
    "turbonomic": _svc("Turbonomic", "Application resource management services", [r"service:turbonomic\b"], category="Observability"),
    "license_service": _svc("License Service", "License and entitlement service instances", [r"service:license-service\b"], category="Platform", global_service=True),
    "global_search_and_tagging": _svc("Global Search and Tagging", "Cross-account search and tag governance services", [r"service:global-search-tagging\b"], category="Platform", global_service=True),
    "support_center": _svc("Support Center", "Support and case-management service instances", [r"service:support-center\b"], category="Platform", global_service=True),
    "billing": _svc("Billing", "Billing and cost management service instances", [r"service:billing\b", r"service:billing-service\b"], category="Platform", global_service=True),
}


def list_ibm_realtime_services() -> List[Dict[str, str]]:
    return [
        {"id": service_id, "name": meta["name"], "description": meta["description"]}
        for service_id, meta in IBM_REALTIME_SERVICE_CATALOG.items()
    ]


def validate_ibm_credentials(api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {"configured": False, "healthy": False, "message": "Missing IBM Cloud API key in .env"}

    try:
        token = _exchange_api_key(api_key)
        headers = _headers(token)
        resource_groups = _collect_paginated(RESOURCE_GROUPS_URL, headers, page_size=1, max_pages=1)
        resource_instances = _collect_paginated(RESOURCE_INSTANCES_URL, headers, page_size=1, max_pages=1)
        account_id = _extract_account_id(resource_groups, resource_instances)
        return {
            "configured": True,
            "healthy": True,
            "message": "IBM Cloud API key verified",
            "details": {
                "account_id": account_id,
                "resource_groups": len(resource_groups),
                "resources_sampled": len(resource_instances),
                "mode": "api-only",
            },
        }
    except Exception as exc:
        return {"configured": True, "healthy": False, "message": f"IBM Cloud validation failed: {exc}"}


def check_ibm_realtime_posture(api_key: str, *, selected_service: str | None = None) -> Dict[str, Any]:
    context = _build_context(api_key)
    services: Dict[str, Any] = {}
    counts = {"pass": 0, "warn": 0, "fail": 0, "unknown": 0}

    for service_id, meta in IBM_REALTIME_SERVICE_CATALOG.items():
        service_result = check_ibm_realtime_service(api_key, service_id, context=context)
        health = service_result.get("api_findings", {}).get("health", {})
        status = health.get("status", "unknown")
        if status not in counts:
            status = "unknown"
        counts[status] += 1
        services[service_id] = {
            "name": meta["name"],
            "status": status,
            "score": health.get("score", 45),
            "summary": health.get("summary") or meta["description"],
            "metrics": {
                "resources": service_result.get("api_findings", {}).get("inventory", {}).get("resource_count", 0),
                "regions": len(service_result.get("api_findings", {}).get("inventory", {}).get("available_regions", [])),
                "groups": len(service_result.get("api_findings", {}).get("scope", {}).get("resource_groups", [])),
            },
            "metadata": service_result,
        }

    total = max(len(services), 1)
    overall_score = round(sum(item["score"] for item in services.values()) / total)
    selected_key = selected_service if selected_service in services else next(iter(services.keys()), None)
    return {
        "provider": "ibm",
        "check": "IBM Cloud Realtime Posture Overview",
        "service_name": "Realtime Posture Overview",
        "selected_service": selected_key,
        "timestamp": datetime.utcnow().isoformat(),
        "ibm_summary": {
            "score": overall_score,
            "overall_status": "pass" if counts["fail"] == 0 and counts["warn"] == 0 else "warn" if counts["fail"] == 0 else "fail",
            "status_counts": counts,
            "service_count": len(services),
            "resource_group_count": len(context["resource_groups"]),
            "resource_count": len(context["resources"]),
            "region_count": len(context["regions"]),
        },
        "services": services,
        "screenshots": [],
        "api_findings": {},
        "vision_analysis": {},
        "status": "completed",
    }


def check_ibm_realtime_service(api_key: str, service: str, *, context: Dict[str, Any] | None = None) -> Dict[str, Any]:
    meta = IBM_REALTIME_SERVICE_CATALOG.get(service)
    if not meta:
        return {
            "provider": "ibm",
            "service": service,
            "service_name": service,
            "status": "error",
            "error": f"Unknown IBM Cloud service integration: {service}",
            "screenshots": [],
            "api_findings": {},
            "vision_analysis": {},
        }

    context = context or _build_context(api_key)
    items = _select_items_for_service(context, meta)
    available_regions = _collect_available_regions(items)
    regional_counts = _count_items_by_region(items)
    resource_group_counts = _count_by_key(items, "resource_group_name")
    resource_type_counts = _count_by_key(items, "_service_name")
    notes = list(context["notes"])
    access_errors = list(context["errors"])

    count = len(items)
    status = "warn" if access_errors else "pass"
    score = 79 if access_errors else 88
    summary = f"Live IBM Cloud API check completed for {meta['name']} with {count} resource(s) discovered."
    observations = [
        f"Realtime IBM Cloud API integration is active for {meta['name']}.",
        f"Observed {count} resource(s) from IBM Cloud Resource Controller.",
    ]
    if access_errors:
        observations.append("One or more IBM Cloud inventory calls returned warnings, so this service summary may be partial.")
    if context["truncated"]:
        notes.append("The IBM Cloud scan samples the first pages returned by Resource Controller to keep provider-wide monitoring responsive.")

    api_findings = {
        "integration": {
            "service_id": service,
            "service_name": meta["name"],
            "description": meta["description"],
            "category": meta["category"],
            "region_scope": "global" if meta.get("global_service") else "regional",
            "available_regions": available_regions,
            "checked_at": datetime.utcnow().isoformat(),
            "mode": "resource-controller realtime monitor",
            "match_patterns": meta["patterns"],
        },
        "health": {
            "status": status,
            "score": score,
            "summary": summary,
            "observations": observations,
        },
        "inventory": {
            "resource_count": count,
            "available_regions": available_regions,
            "regional_resource_counts": regional_counts,
            "resource_group_counts": resource_group_counts,
            "resource_type_counts": resource_type_counts,
            "items_preview": items[:MAX_SERVICE_PREVIEW],
            "sample": [_sample_item(item) for item in items[: min(6, len(items))]],
        },
        "scope": {
            "account_id": context["account_id"],
            "resource_groups": context["resource_groups"],
            "resource_group_count": len(context["resource_groups"]),
            "resource_count": len(context["resources"]),
            "regions": context["regions"],
            "discovered_service_families": context["discovered_service_families"],
            "mode": "api-only",
        },
        "access": {
            "notes": notes,
            "errors": access_errors,
        },
    }
    if meta.get("special_source") == "resource_groups":
        api_findings["resource_groups"] = context["resource_groups"]

    return {
        "provider": "ibm",
        "service": service,
        "service_name": meta["name"],
        "service_description": meta["description"],
        "check": "Realtime IBM Cloud Integration Monitor",
        "check_description": f"Live IBM Cloud API inventory and posture summary for {meta['name']}",
        "status": "completed",
        "timestamp": datetime.utcnow().isoformat(),
        "screenshots": [],
        "api_findings": api_findings,
        "vision_analysis": {},
        "metadata": {
            "inventory_source": "resource-controller",
        },
    }


def _build_context(api_key: str) -> Dict[str, Any]:
    token = _exchange_api_key(api_key)
    headers = _headers(token)
    notes: List[str] = []
    errors: List[str] = []

    resource_groups = _normalize_resource_groups(
        _collect_paginated(RESOURCE_GROUPS_URL, headers, page_size=PAGE_SIZE, max_pages=MAX_GROUP_PAGES)
    )
    resource_group_map = {group["id"]: group["name"] for group in resource_groups if group.get("id")}

    truncated = False
    try:
        raw_resources = _collect_paginated(RESOURCE_INSTANCES_URL, headers, page_size=PAGE_SIZE, max_pages=MAX_INSTANCE_PAGES)
        if len(raw_resources) >= PAGE_SIZE * MAX_INSTANCE_PAGES:
            truncated = True
    except Exception as exc:
        raw_resources = []
        errors.append(str(exc))

    resources = [_normalize_resource(item, resource_group_map) for item in raw_resources]
    account_id = _extract_account_id(resource_groups, resources)
    regions = sorted({item["_region"] for item in resources if item.get("_region")})
    discovered_service_families = sorted({item["_service_name"] for item in resources if item.get("_service_name")})

    return {
        "headers": headers,
        "token": token,
        "account_id": account_id,
        "resource_groups": resource_groups,
        "resource_group_map": resource_group_map,
        "resources": resources,
        "regions": regions,
        "discovered_service_families": discovered_service_families,
        "notes": notes,
        "errors": errors,
        "truncated": truncated,
    }


def _exchange_api_key(api_key: str) -> str:
    response = requests.post(
        IAM_TOKEN_URL,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={
            "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
            "apikey": api_key,
        },
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    payload = response.json()
    token = payload.get("access_token")
    if not token:
        raise RuntimeError("IBM Cloud IAM token exchange succeeded but no access token was returned.")
    return token


def _headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }


def _collect_paginated(url: str, headers: Dict[str, str], *, page_size: int, max_pages: int) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    next_url = url
    params: Dict[str, Any] | None = {"limit": page_size}

    for _ in range(max_pages):
        response = requests.get(next_url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        payload = response.json()
        items.extend(payload.get("resources", []))
        raw_next = payload.get("next_url") or payload.get("next", {}).get("url") or payload.get("next", {}).get("href")
        if not raw_next:
            break
        next_url = urljoin(url, raw_next)
        params = None

    return items


def _normalize_resource_groups(groups: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    for group in groups:
        normalized.append({
            "id": group.get("id") or group.get("guid"),
            "name": group.get("name") or group.get("display_name") or "Unnamed resource group",
            "default": group.get("default", False),
            "state": group.get("state"),
            "quota_id": group.get("quota_id"),
            "account_id": group.get("account_id"),
            "crn": group.get("crn"),
        })
    return normalized


def _normalize_resource(item: Dict[str, Any], resource_group_map: Dict[str, str]) -> Dict[str, Any]:
    crn = str(item.get("crn") or "")
    service_name = _parse_crn_segment(crn, 4)
    location = _parse_crn_segment(crn, 5)
    resource_group_id = item.get("resource_group_id")
    extensions = item.get("extensions") or {}
    display_name = (
        item.get("name")
        or extensions.get("display_name")
        or extensions.get("service_name")
        or _last_crn_segment(crn)
        or "IBM Cloud resource"
    )
    region = item.get("region_id") or item.get("region") or item.get("location") or ""
    if not region and location and location not in {"global", "n/a"}:
        region = location

    match_text = " ".join(filter(None, [
        f"service:{service_name}",
        f"crn:{crn}",
        f"type:{item.get('type')}",
        f"name:{item.get('name')}",
        f"resource_id:{item.get('resource_id')}",
        f"plan_id:{item.get('resource_plan_id')}",
        f"region:{region}",
        f"extensions:{json.dumps(extensions, sort_keys=True)}",
    ])).lower()

    return {
        "id": item.get("id") or item.get("guid"),
        "guid": item.get("guid"),
        "name": item.get("name"),
        "display_name": display_name,
        "crn": crn,
        "state": item.get("state"),
        "type": item.get("type"),
        "resource_id": item.get("resource_id"),
        "resource_plan_id": item.get("resource_plan_id"),
        "resource_group_id": resource_group_id,
        "resource_group_name": resource_group_map.get(resource_group_id, ""),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "region_id": item.get("region_id"),
        "_region": region,
        "_service_name": service_name,
        "_location": location,
        "_match_text": match_text,
        "extensions": extensions,
    }


def _select_items_for_service(context: Dict[str, Any], meta: Dict[str, Any]) -> List[Dict[str, Any]]:
    special_source = meta.get("special_source")
    if special_source == "resource_groups":
        return list(context["resource_groups"])
    if special_source == "resource_instances":
        return list(context["resources"])

    patterns = [re.compile(pattern, re.IGNORECASE) for pattern in meta["patterns"]]
    matched = []
    for item in context["resources"]:
        match_text = item.get("_match_text", "")
        if any(pattern.search(match_text) for pattern in patterns):
            matched.append(item)
    return matched


def _extract_account_id(resource_groups: Iterable[Dict[str, Any]], resources: Iterable[Dict[str, Any]]) -> str:
    for group in resource_groups:
        account_id = group.get("account_id")
        if account_id:
            return account_id
    for item in resources:
        crn = item.get("crn") or ""
        match = re.search(r":a/([^:/]+)", crn)
        if match:
            return match.group(1)
    return ""


def _parse_crn_segment(crn: str, index: int) -> str:
    parts = crn.split(":")
    if len(parts) > index:
        return parts[index]
    return ""


def _last_crn_segment(crn: str) -> str:
    if not crn:
        return ""
    return crn.split(":")[-1].split("/")[-1]


def _collect_available_regions(items: Iterable[Dict[str, Any]]) -> List[str]:
    return sorted({str(item.get("_region") or "").strip() for item in items if str(item.get("_region") or "").strip()})


def _count_items_by_region(items: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        region = str(item.get("_region") or "").strip()
        if not region:
            continue
        counts[region] = counts.get(region, 0) + 1
    return counts


def _count_by_key(items: Iterable[Dict[str, Any]], key: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        value = str(item.get(key) or "").strip()
        if not value:
            continue
        counts[value] = counts.get(value, 0) + 1
    return counts


def _sample_item(item: Dict[str, Any]) -> Dict[str, Any]:
    keys = [
        "display_name",
        "name",
        "_service_name",
        "_region",
        "resource_group_name",
        "state",
        "type",
        "resource_id",
        "crn",
        "created_at",
    ]
    sample: Dict[str, Any] = {}
    for key in keys:
        value = item.get(key)
        if value not in (None, "", []):
            sample[key] = value
    return sample
