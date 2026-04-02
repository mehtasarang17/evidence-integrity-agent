"""API-only Azure realtime monitoring with cached provider posture."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List

import requests

logger = logging.getLogger(__name__)


def _svc(name: str, description: str, path: str, api_version: str, *, global_service: bool = False) -> Dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "path": path,
        "api_version": api_version,
        "global_service": global_service,
    }


AZURE_REALTIME_SERVICE_CATALOG: Dict[str, Dict[str, Any]] = {
    "subscriptions": _svc("Subscriptions", "Tenant subscriptions and access scope", "/subscriptions", "2022-12-01", global_service=True),
    "resource_groups": _svc("Resource Groups", "Resource grouping and ownership boundaries", "/resourcegroups", "2021-04-01"),
    "virtual_machines": _svc("Virtual Machines", "Compute instances and state", "/providers/Microsoft.Compute/virtualMachines", "2023-09-01"),
    "vm_scale_sets": _svc("VM Scale Sets", "Elastic compute pools", "/providers/Microsoft.Compute/virtualMachineScaleSets", "2023-09-01"),
    "managed_disks": _svc("Managed Disks", "Disk inventory and encryption posture", "/providers/Microsoft.Compute/disks", "2023-10-02"),
    "snapshots": _svc("Snapshots", "Snapshot inventory and recovery points", "/providers/Microsoft.Compute/snapshots", "2023-10-02"),
    "images": _svc("Images", "Managed images and galleries", "/providers/Microsoft.Compute/images", "2023-07-03"),
    "galleries": _svc("Compute Galleries", "Shared image galleries", "/providers/Microsoft.Compute/galleries", "2023-07-03"),
    "network_security_groups": _svc("Network Security Groups", "Ingress and egress firewall rules", "/providers/Microsoft.Network/networkSecurityGroups", "2023-09-01"),
    "virtual_networks": _svc("Virtual Networks", "Network segmentation and address space", "/providers/Microsoft.Network/virtualNetworks", "2023-09-01"),
    "subnets": _svc("Subnets", "Subnet boundaries and delegation", "/providers/Microsoft.Network/virtualNetworks", "2023-09-01"),
    "public_ips": _svc("Public IPs", "Publicly routable addresses", "/providers/Microsoft.Network/publicIPAddresses", "2023-09-01"),
    "load_balancers": _svc("Load Balancers", "Traffic distribution resources", "/providers/Microsoft.Network/loadBalancers", "2023-09-01"),
    "application_gateways": _svc("Application Gateways", "Layer 7 routing and WAF edge", "/providers/Microsoft.Network/applicationGateways", "2023-09-01"),
    "route_tables": _svc("Route Tables", "Custom routing definitions", "/providers/Microsoft.Network/routeTables", "2023-09-01"),
    "firewalls": _svc("Azure Firewall", "Centralized network firewall", "/providers/Microsoft.Network/azureFirewalls", "2023-09-01"),
    "bastions": _svc("Azure Bastion", "Secure remote access endpoints", "/providers/Microsoft.Network/bastionHosts", "2023-09-01"),
    "vpn_gateways": _svc("VPN Gateways", "Site-to-site and point-to-site connectivity", "/providers/Microsoft.Network/virtualNetworkGateways", "2023-09-01"),
    "storage_accounts": _svc("Storage Accounts", "Object and file storage posture", "/providers/Microsoft.Storage/storageAccounts", "2023-01-01"),
    "recovery_vaults": _svc("Recovery Services Vaults", "Backup and DR vaults", "/providers/Microsoft.RecoveryServices/vaults", "2023-04-01"),
    "key_vaults": _svc("Key Vaults", "Secrets, keys, and purge protection", "/providers/Microsoft.KeyVault/vaults", "2023-07-01"),
    "sql_servers": _svc("SQL Servers", "Logical SQL server inventory", "/providers/Microsoft.Sql/servers", "2023-05-01-preview"),
    "sql_managed_instances": _svc("SQL Managed Instances", "Managed SQL instances", "/providers/Microsoft.Sql/managedInstances", "2023-08-01-preview"),
    "postgres_servers": _svc("PostgreSQL Flexible Servers", "Managed PostgreSQL fleet", "/providers/Microsoft.DBforPostgreSQL/flexibleServers", "2023-06-01-preview"),
    "mysql_servers": _svc("MySQL Flexible Servers", "Managed MySQL fleet", "/providers/Microsoft.DBforMySQL/flexibleServers", "2023-06-30-preview"),
    "cosmosdb_accounts": _svc("Cosmos DB", "Global NoSQL database accounts", "/providers/Microsoft.DocumentDB/databaseAccounts", "2023-04-15"),
    "aks_clusters": _svc("AKS Clusters", "Managed Kubernetes clusters", "/providers/Microsoft.ContainerService/managedClusters", "2024-02-01"),
    "container_registries": _svc("Container Registries", "Private OCI registries", "/providers/Microsoft.ContainerRegistry/registries", "2023-07-01"),
    "container_apps": _svc("Container Apps", "Serverless containers", "/providers/Microsoft.App/containerApps", "2024-03-01"),
    "app_services": _svc("App Services", "Web apps and app service plans", "/providers/Microsoft.Web/sites", "2023-12-01"),
    "function_apps": _svc("Function Apps", "Serverless functions on App Service", "/providers/Microsoft.Web/sites", "2023-12-01"),
    "service_bus_namespaces": _svc("Service Bus", "Messaging namespaces", "/providers/Microsoft.ServiceBus/namespaces", "2022-10-01-preview"),
    "event_hubs_namespaces": _svc("Event Hubs", "Streaming namespaces", "/providers/Microsoft.EventHub/namespaces", "2024-01-01"),
    "redis_caches": _svc("Azure Cache for Redis", "Managed Redis instances", "/providers/Microsoft.Cache/Redis", "2024-03-01"),
    "log_analytics_workspaces": _svc("Log Analytics", "Workspace inventory and retention", "/providers/Microsoft.OperationalInsights/workspaces", "2023-09-01"),
    "application_insights": _svc("Application Insights", "Telemetry and monitoring components", "/providers/Microsoft.Insights/components", "2020-02-02"),
    "defender_assessments": _svc("Defender for Cloud Assessments", "Security recommendations and posture", "/providers/Microsoft.Security/assessments", "2021-06-01"),
    "policy_assignments": _svc("Policy Assignments", "Azure Policy governance assignments", "/providers/Microsoft.Authorization/policyAssignments", "2023-04-01"),
    "role_assignments": _svc("Role Assignments", "RBAC assignments across subscriptions", "/providers/Microsoft.Authorization/roleAssignments", "2022-04-01"),
}


def list_azure_realtime_services() -> List[Dict[str, str]]:
    return [{"id": service_id, "name": meta["name"], "description": meta["description"]} for service_id, meta in AZURE_REALTIME_SERVICE_CATALOG.items()]


def validate_azure_credentials(tenant_id: str, client_id: str, client_secret: str, access_token: str = "") -> Dict[str, Any]:
    has_token = bool(access_token)
    has_sp = bool(tenant_id and client_id and client_secret)
    if not has_token and not has_sp:
        return {"configured": False, "healthy": False, "message": "Missing Azure credentials in .env"}
    try:
        token = _get_azure_token(tenant_id, client_id, client_secret, access_token=access_token)
        headers = _azure_headers(token)
        subscriptions = _list_subscriptions(headers)
        return {
            "configured": True,
            "healthy": True,
            "message": "Azure access token verified" if has_token else "Azure credentials verified",
            "details": {"subscriptions": len(subscriptions), "mode": "api-only"},
        }
    except Exception as exc:
        return {"configured": True, "healthy": False, "message": f"Azure validation failed: {exc}"}


def check_azure_realtime_service(tenant_id: str, client_id: str, client_secret: str, service: str, *, access_token: str = "") -> Dict[str, Any]:
    meta = AZURE_REALTIME_SERVICE_CATALOG.get(service)
    if not meta:
        return {
            "provider": "azure",
            "service": service,
            "service_name": service,
            "status": "error",
            "error": f"Unknown Azure service integration: {service}",
            "screenshots": [],
            "api_findings": {},
            "vision_analysis": {},
        }

    token = _get_azure_token(tenant_id, client_id, client_secret, access_token=access_token)
    headers = _azure_headers(token)
    subscriptions = _list_subscriptions(headers)

    errors: List[str] = []
    items: List[Any] = []
    if meta.get("global_service"):
        try:
            items = _fetch_subscription_items(headers, "", service, meta)
        except Exception as exc:
            errors.append(str(exc))
    else:
        for sub in subscriptions:
            sub_id = sub["subscriptionId"]
            try:
                sub_items = _fetch_subscription_items(headers, sub_id, service, meta)
                items.extend([
                    _attach_subscription_context(item, sub_id, sub.get("displayName"))
                    for item in sub_items
                ])
            except Exception as exc:
                errors.append(f"{sub.get('displayName') or sub_id}: {exc}")

    api_findings = {
        "integration": {
            "service_id": service,
            "service_name": meta["name"],
            "description": meta["description"],
            "checked_at": datetime.utcnow().isoformat(),
            "mode": "api-only realtime monitor",
        },
        "subscriptions": [{"id": sub["subscriptionId"], "name": sub.get("displayName")} for sub in subscriptions[:10]],
        "inventory": {
            "resource_count": len(items),
            "sample": _sample_items(items),
            "items_preview": _items_preview(items),
        },
        "health": _build_health(meta, items, errors),
    }
    if errors:
        api_findings["errors"] = {"messages": errors[:10]}

    return {
        "provider": "azure",
        "service": service,
        "service_name": meta["name"],
        "service_description": meta["description"],
        "check": "Realtime Azure Integration Monitor",
        "check_description": f"Live Azure API inventory and posture summary for {meta['name']}",
        "timestamp": datetime.utcnow().isoformat(),
        "status": "completed" if not errors else "warn",
        "screenshots": [],
        "api_findings": api_findings,
        "vision_analysis": {},
    }


def check_azure_realtime_posture(tenant_id: str, client_id: str, client_secret: str, *, access_token: str = "", selected_service: str | None = None) -> Dict[str, Any]:
    services: Dict[str, Any] = {}
    counts = {"pass": 0, "warn": 0, "fail": 0, "unknown": 0}

    for service_id, meta in AZURE_REALTIME_SERVICE_CATALOG.items():
        service_result = check_azure_realtime_service(tenant_id, client_id, client_secret, service_id, access_token=access_token)
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
                "subscriptions": len(service_result.get("api_findings", {}).get("subscriptions", [])),
            },
            "metadata": service_result,
        }

    total = max(len(services), 1)
    overall_score = round(sum(item["score"] for item in services.values()) / total)
    selected_key = selected_service if selected_service in services else next(iter(services.keys()), None)
    return {
        "provider": "azure",
        "check": "Azure Realtime Posture Overview",
        "service_name": "Realtime Posture Overview",
        "selected_service": selected_key,
        "timestamp": datetime.utcnow().isoformat(),
        "azure_summary": {
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


def _get_azure_token(tenant_id: str, client_id: str, client_secret: str, *, access_token: str = "") -> str:
    if access_token:
        return access_token
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://management.azure.com/.default",
        "grant_type": "client_credentials",
    }
    response = requests.post(token_url, data=token_data, timeout=20)
    response.raise_for_status()
    return response.json().get("access_token", "")


def _azure_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _list_subscriptions(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    return _collect_paginated(
        "https://management.azure.com/subscriptions?api-version=2022-12-01",
        headers,
    )


def _fetch_subscription_items(headers: Dict[str, str], subscription_id: str, service_id: str, meta: Dict[str, Any]) -> List[Any]:
    if meta.get("global_service"):
        return _list_subscriptions(headers)

    url = f"https://management.azure.com/subscriptions/{subscription_id}{meta['path']}?api-version={meta['api_version']}"
    items = _collect_paginated(url, headers, timeout=30)

    if service_id == "subnets":
        subnet_items = []
        for vnet in items:
            for subnet in (vnet.get("properties", {}) or {}).get("subnets", [])[:20]:
                subnet_items.append({
                    "name": subnet.get("name"),
                    "vnet": vnet.get("name"),
                    "addressPrefix": (subnet.get("properties", {}) or {}).get("addressPrefix"),
                    "privateEndpointNetworkPolicies": (subnet.get("properties", {}) or {}).get("privateEndpointNetworkPolicies"),
                    "privateLinkServiceNetworkPolicies": (subnet.get("properties", {}) or {}).get("privateLinkServiceNetworkPolicies"),
                })
        return subnet_items

    if service_id == "function_apps":
        items = [item for item in items if (item.get("kind") or "").lower().find("functionapp") >= 0]

    return items


def _collect_paginated(url: str, headers: Dict[str, str], *, timeout: int = 20) -> List[Any]:
    items: List[Any] = []
    next_url = url
    page_limit = 8

    while next_url and page_limit > 0:
        response = requests.get(next_url, headers=headers, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
        items.extend(payload.get("value", []))
        next_url = payload.get("nextLink")
        page_limit -= 1

    return items


def _sample_items(items: List[Any]) -> List[Any]:
    sample = []
    for item in items[:5]:
        if isinstance(item, dict):
            compact = {}
            for index, (key, value) in enumerate(item.items()):
                if index >= 6:
                    break
                if isinstance(value, (str, int, float, bool)) or value is None:
                    compact[key] = value
                elif isinstance(value, dict):
                    compact[key] = str(value)[:120]
                elif isinstance(value, list):
                    compact[key] = f"{len(value)} item(s)"
            sample.append(compact)
        else:
            sample.append(item)
    return sample


def _items_preview(items: List[Any]) -> List[Any]:
    return [_serialize_preview_item(item) for item in items[:10]]


def _serialize_preview_item(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_serialize_preview_item(item) for item in value[:8]]
    if isinstance(value, dict):
        data = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 14:
                break
            data[key] = _serialize_preview_item(item)
        return data
    return str(value)


def _attach_subscription_context(item: Any, subscription_id: str, subscription_name: str | None) -> Any:
    if not isinstance(item, dict):
        return item

    enriched = dict(item)
    enriched.setdefault("subscriptionId", subscription_id)
    if subscription_name:
        enriched.setdefault("subscriptionName", subscription_name)

    resource_id = enriched.get("id")
    if resource_id and isinstance(resource_id, str) and "/resourceGroups/" in resource_id:
        parts = resource_id.split("/")
        try:
            group_index = parts.index("resourceGroups")
            enriched.setdefault("resourceGroup", parts[group_index + 1])
        except (ValueError, IndexError):
            pass

    return enriched


def _build_health(meta: Dict[str, Any], items: List[Any], errors: List[str]) -> Dict[str, Any]:
    status = "pass" if not errors else "warn"
    score = 90 if not errors else 60
    return {
        "status": status,
        "score": score,
        "summary": (
            f"Live Azure API check completed for {meta['name']} with {len(items)} resource(s) discovered."
            if not errors
            else f"Azure API check completed with partial visibility issues for {meta['name']}."
        ),
        "observations": [
            f"Realtime Azure API integration is active for {meta['name']}.",
            f"Observed {len(items)} resource(s) from the Azure Resource Manager API.",
        ] + ([f"Permission or API issue: {errors[0]}"] if errors else []),
    }
