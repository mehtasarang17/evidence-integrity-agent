"""API-only GCP realtime monitoring backed by Cloud Asset Inventory."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple

import requests

MAX_PROJECT_SCOPES = 8
MAX_SCOPE_PAGES = 2
SEARCH_PAGE_SIZE = 100
MAX_SERVICE_PREVIEW = 50


def _svc(
    name: str,
    description: str,
    patterns: List[str],
    *,
    collection_prefixes: List[str],
    global_service: bool = False,
) -> Dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "patterns": patterns,
        "collection_prefixes": collection_prefixes,
        "global_service": global_service,
    }


GCP_REALTIME_SERVICE_CATALOG: Dict[str, Dict[str, Any]] = {
    "projects": _svc("Projects", "Project inventory and tenancy boundaries", [r"^cloudresourcemanager\.googleapis\.com/Project$"], collection_prefixes=["cloudresourcemanager.googleapis.com.*"], global_service=True),
    "folders": _svc("Folders", "Folder hierarchy and delegated scope", [r"^cloudresourcemanager\.googleapis\.com/Folder$"], collection_prefixes=["cloudresourcemanager.googleapis.com.*"], global_service=True),
    "organizations": _svc("Organizations", "Organization-level cloud footprint", [r"^cloudresourcemanager\.googleapis\.com/Organization$"], collection_prefixes=["cloudresourcemanager.googleapis.com.*"], global_service=True),
    "compute_instances": _svc("Compute Instances", "Virtual machine fleet across accessible projects", [r"^compute\.googleapis\.com/Instance$"], collection_prefixes=["compute.googleapis.com.*"]),
    "instance_templates": _svc("Instance Templates", "Reusable VM templates and launch definitions", [r"^compute\.googleapis\.com/InstanceTemplate$"], collection_prefixes=["compute.googleapis.com.*"]),
    "managed_instance_groups": _svc("Managed Instance Groups", "Autoscaled VM group posture", [r"^compute\.googleapis\.com/InstanceGroupManager$"], collection_prefixes=["compute.googleapis.com.*"]),
    "machine_images": _svc("Machine Images", "Golden image snapshots for VM recovery", [r"^compute\.googleapis\.com/MachineImage$"], collection_prefixes=["compute.googleapis.com.*"]),
    "disks": _svc("Persistent Disks", "Block storage inventory and attachment state", [r"^compute\.googleapis\.com/Disk$"], collection_prefixes=["compute.googleapis.com.*"]),
    "snapshots": _svc("Snapshots", "Snapshot recovery inventory", [r"^compute\.googleapis\.com/Snapshot$"], collection_prefixes=["compute.googleapis.com.*"]),
    "images": _svc("Images", "Compute image catalog and source lineage", [r"^compute\.googleapis\.com/Image$"], collection_prefixes=["compute.googleapis.com.*"]),
    "networks": _svc("VPC Networks", "Network boundaries and shared VPC topology", [r"^compute\.googleapis\.com/Network$"], collection_prefixes=["compute.googleapis.com.*"], global_service=True),
    "subnetworks": _svc("Subnetworks", "Regional subnetwork inventory", [r"^compute\.googleapis\.com/Subnetwork$"], collection_prefixes=["compute.googleapis.com.*"]),
    "firewall_rules": _svc("Firewall Rules", "Ingress and egress rule inventory", [r"^compute\.googleapis\.com/Firewall$"], collection_prefixes=["compute.googleapis.com.*"], global_service=True),
    "addresses": _svc("Static IP Addresses", "Reserved regional and global addresses", [r"^compute\.googleapis\.com/Address$"], collection_prefixes=["compute.googleapis.com.*"]),
    "routers": _svc("Cloud Routers", "Dynamic routing and BGP topology", [r"^compute\.googleapis\.com/Router$"], collection_prefixes=["compute.googleapis.com.*"]),
    "vpn_tunnels": _svc("VPN Tunnels", "Site-to-site tunnel inventory", [r"^compute\.googleapis\.com/VpnTunnel$"], collection_prefixes=["compute.googleapis.com.*"]),
    "forwarding_rules": _svc("Forwarding Rules", "Load balancer entry points and VIP bindings", [r"^compute\.googleapis\.com/ForwardingRule$", r"^compute\.googleapis\.com/GlobalForwardingRule$"], collection_prefixes=["compute.googleapis.com.*"]),
    "backend_services": _svc("Backend Services", "Load balancer backend pools", [r"^compute\.googleapis\.com/BackendService$", r"^compute\.googleapis\.com/RegionBackendService$"], collection_prefixes=["compute.googleapis.com.*"]),
    "url_maps": _svc("URL Maps", "HTTP routing maps for load balancers", [r"^compute\.googleapis\.com/UrlMap$"], collection_prefixes=["compute.googleapis.com.*"], global_service=True),
    "health_checks": _svc("Health Checks", "Backend health probe inventory", [r"^compute\.googleapis\.com/HealthCheck$"], collection_prefixes=["compute.googleapis.com.*"], global_service=True),
    "target_https_proxies": _svc("Target HTTPS Proxies", "TLS front-end proxies", [r"^compute\.googleapis\.com/TargetHttpsProxy$"], collection_prefixes=["compute.googleapis.com.*"], global_service=True),
    "ssl_certificates": _svc("SSL Certificates", "Legacy SSL certificate inventory", [r"^compute\.googleapis\.com/SslCertificate$", r"^compute\.googleapis\.com/SslPolicy$"], collection_prefixes=["compute.googleapis.com.*"], global_service=True),
    "security_policies": _svc("Security Policies", "Cloud Armor policy inventory", [r"^compute\.googleapis\.com/SecurityPolicy$"], collection_prefixes=["compute.googleapis.com.*"], global_service=True),
    "gke_clusters": _svc("GKE Clusters", "Managed Kubernetes cluster inventory", [r"^container\.googleapis\.com/Cluster$"], collection_prefixes=["container.googleapis.com.*"]),
    "gke_node_pools": _svc("GKE Node Pools", "Node pool capacity and zoning", [r"^container\.googleapis\.com/NodePool$"], collection_prefixes=["container.googleapis.com.*"]),
    "cloud_run_services": _svc("Cloud Run Services", "Serverless service deployments", [r"^run\.googleapis\.com/Service$"], collection_prefixes=["run.googleapis.com.*"]),
    "cloud_run_jobs": _svc("Cloud Run Jobs", "Serverless batch job inventory", [r"^run\.googleapis\.com/Job$"], collection_prefixes=["run.googleapis.com.*"]),
    "cloud_functions": _svc("Cloud Functions", "Function inventory across generations", [r"^cloudfunctions\.googleapis\.com/.*$"], collection_prefixes=["cloudfunctions.googleapis.com.*"]),
    "app_engine_services": _svc("App Engine Services", "App Engine service surface inventory", [r"^appengine\.googleapis\.com/Service$"], collection_prefixes=["appengine.googleapis.com.*"], global_service=True),
    "app_engine_versions": _svc("App Engine Versions", "Deployed App Engine versions", [r"^appengine\.googleapis\.com/Version$"], collection_prefixes=["appengine.googleapis.com.*"]),
    "cloud_sql_instances": _svc("Cloud SQL Instances", "Managed relational database instances", [r"^sqladmin\.googleapis\.com/Instance$"], collection_prefixes=["sqladmin.googleapis.com.*"]),
    "alloydb_clusters": _svc("AlloyDB Clusters", "AlloyDB cluster footprint", [r"^alloydb\.googleapis\.com/Cluster$"], collection_prefixes=["alloydb.googleapis.com.*"]),
    "spanner_instances": _svc("Spanner Instances", "Spanner instance inventory", [r"^spanner\.googleapis\.com/Instance$"], collection_prefixes=["spanner.googleapis.com.*"]),
    "spanner_databases": _svc("Spanner Databases", "Spanner database inventory", [r"^spanner\.googleapis\.com/Database$"], collection_prefixes=["spanner.googleapis.com.*"]),
    "bigtable_instances": _svc("Bigtable Instances", "Bigtable instance footprint", [r"^bigtableadmin\.googleapis\.com/Instance$"], collection_prefixes=["bigtableadmin.googleapis.com.*"]),
    "bigtable_clusters": _svc("Bigtable Clusters", "Bigtable cluster zoning and capacity", [r"^bigtableadmin\.googleapis\.com/Cluster$"], collection_prefixes=["bigtableadmin.googleapis.com.*"]),
    "bigquery_datasets": _svc("BigQuery Datasets", "Dataset inventory and ownership", [r"^bigquery\.googleapis\.com/Dataset$"], collection_prefixes=["bigquery.googleapis.com.*"], global_service=True),
    "bigquery_tables": _svc("BigQuery Tables", "Table inventory and dataset spread", [r"^bigquery\.googleapis\.com/Table$"], collection_prefixes=["bigquery.googleapis.com.*"]),
    "bigquery_routines": _svc("BigQuery Routines", "Stored procedures and routines", [r"^bigquery\.googleapis\.com/Routine$"], collection_prefixes=["bigquery.googleapis.com.*"]),
    "storage_buckets": _svc("Cloud Storage Buckets", "Bucket inventory and storage perimeter", [r"^storage\.googleapis\.com/Bucket$"], collection_prefixes=["storage.googleapis.com.*"], global_service=True),
    "pubsub_topics": _svc("Pub/Sub Topics", "Messaging topic inventory", [r"^pubsub\.googleapis\.com/Topic$"], collection_prefixes=["pubsub.googleapis.com.*"], global_service=True),
    "pubsub_subscriptions": _svc("Pub/Sub Subscriptions", "Subscription inventory and delivery posture", [r"^pubsub\.googleapis\.com/Subscription$"], collection_prefixes=["pubsub.googleapis.com.*"]),
    "cloud_tasks_queues": _svc("Cloud Tasks Queues", "Task queue inventory", [r"^cloudtasks\.googleapis\.com/Queue$"], collection_prefixes=["cloudtasks.googleapis.com.*"]),
    "cloud_scheduler_jobs": _svc("Cloud Scheduler Jobs", "Scheduled job footprint", [r"^cloudscheduler\.googleapis\.com/Job$"], collection_prefixes=["cloudscheduler.googleapis.com.*"]),
    "workflows": _svc("Workflows", "Workflow inventory and automation graph", [r"^workflows\.googleapis\.com/Workflow$"], collection_prefixes=["workflows.googleapis.com.*"]),
    "eventarc_triggers": _svc("Eventarc Triggers", "Event routing triggers", [r"^eventarc\.googleapis\.com/Trigger$"], collection_prefixes=["eventarc.googleapis.com.*"]),
    "secret_manager": _svc("Secret Manager", "Secret inventory and secret store coverage", [r"^secretmanager\.googleapis\.com/Secret$"], collection_prefixes=["secretmanager.googleapis.com.*"], global_service=True),
    "kms_key_rings": _svc("KMS Key Rings", "Key ring inventory and locality", [r"^cloudkms\.googleapis\.com/KeyRing$"], collection_prefixes=["cloudkms.googleapis.com.*"]),
    "kms_crypto_keys": _svc("KMS Crypto Keys", "Crypto key inventory and protection state", [r"^cloudkms\.googleapis\.com/CryptoKey$"], collection_prefixes=["cloudkms.googleapis.com.*"]),
    "artifact_registry": _svc("Artifact Registry", "Repository inventory for packages and containers", [r"^artifactregistry\.googleapis\.com/Repository$"], collection_prefixes=["artifactregistry.googleapis.com.*"]),
    "cloud_build_triggers": _svc("Cloud Build Triggers", "CI trigger inventory", [r"^cloudbuild\.googleapis\.com/BuildTrigger$"], collection_prefixes=["cloudbuild.googleapis.com.*"], global_service=True),
    "cloud_deploy_pipelines": _svc("Cloud Deploy Pipelines", "Delivery pipeline inventory", [r"^clouddeploy\.googleapis\.com/DeliveryPipeline$"], collection_prefixes=["clouddeploy.googleapis.com.*"]),
    "cloud_deploy_targets": _svc("Cloud Deploy Targets", "Deployment target inventory", [r"^clouddeploy\.googleapis\.com/Target$"], collection_prefixes=["clouddeploy.googleapis.com.*"]),
    "dataflow_jobs": _svc("Dataflow Jobs", "Streaming and batch job inventory", [r"^dataflow\.googleapis\.com/Job$"], collection_prefixes=["dataflow.googleapis.com.*"]),
    "dataproc_clusters": _svc("Dataproc Clusters", "Dataproc cluster inventory", [r"^dataproc\.googleapis\.com/Cluster$"], collection_prefixes=["dataproc.googleapis.com.*"]),
    "dataplex_lakes": _svc("Dataplex Lakes", "Dataplex lake and governance domains", [r"^dataplex\.googleapis\.com/Lake$"], collection_prefixes=["dataplex.googleapis.com.*"]),
    "dataform_repositories": _svc("Dataform Repositories", "Dataform repository inventory", [r"^dataform\.googleapis\.com/Repository$"], collection_prefixes=["dataform.googleapis.com.*"]),
    "composer_environments": _svc("Composer Environments", "Managed Airflow environment inventory", [r"^composer\.googleapis\.com/Environment$"], collection_prefixes=["composer.googleapis.com.*"]),
    "redis_instances": _svc("Memorystore Redis", "Redis instance and cluster inventory", [r"^redis\.googleapis\.com/(Instance|Cluster)$"], collection_prefixes=["redis.googleapis.com.*"]),
    "memcache_instances": _svc("Memorystore Memcached", "Memcached instance inventory", [r"^memcache\.googleapis\.com/Instance$"], collection_prefixes=["memcache.googleapis.com.*"]),
    "filestore_instances": _svc("Filestore Instances", "Managed file share inventory", [r"^file\.googleapis\.com/Instance$"], collection_prefixes=["file.googleapis.com.*"]),
    "dns_managed_zones": _svc("Cloud DNS Managed Zones", "DNS zone inventory and naming perimeter", [r"^dns\.googleapis\.com/ManagedZone$"], collection_prefixes=["dns.googleapis.com.*"], global_service=True),
    "certificate_manager_certificates": _svc("Certificate Manager Certificates", "Managed certificate inventory", [r"^certificatemanager\.googleapis\.com/Certificate$"], collection_prefixes=["certificatemanager.googleapis.com.*"], global_service=True),
    "certificate_manager_maps": _svc("Certificate Maps", "Certificate map inventory", [r"^certificatemanager\.googleapis\.com/CertificateMap$"], collection_prefixes=["certificatemanager.googleapis.com.*"], global_service=True),
    "api_gateway_gateways": _svc("API Gateway Gateways", "Gateway inventory for managed APIs", [r"^apigateway\.googleapis\.com/Gateway$"], collection_prefixes=["apigateway.googleapis.com.*"]),
    "service_directory_namespaces": _svc("Service Directory Namespaces", "Namespace inventory for service discovery", [r"^servicedirectory\.googleapis\.com/Namespace$"], collection_prefixes=["servicedirectory.googleapis.com.*"]),
    "service_directory_services": _svc("Service Directory Services", "Service discovery endpoint groupings", [r"^servicedirectory\.googleapis\.com/Service$"], collection_prefixes=["servicedirectory.googleapis.com.*"]),
    "vertex_ai_models": _svc("Vertex AI Models", "Model inventory across ML projects", [r"^aiplatform\.googleapis\.com/Model$"], collection_prefixes=["aiplatform.googleapis.com.*"]),
    "vertex_ai_endpoints": _svc("Vertex AI Endpoints", "Endpoint inventory for online prediction", [r"^aiplatform\.googleapis\.com/Endpoint$"], collection_prefixes=["aiplatform.googleapis.com.*"]),
    "notebooks_instances": _svc("Workbench Instances", "Notebook and workbench instance inventory", [r"^notebooks\.googleapis\.com/.*$"], collection_prefixes=["notebooks.googleapis.com.*"]),
    "monitoring_alert_policies": _svc("Alert Policies", "Monitoring alert policy inventory", [r"^monitoring\.googleapis\.com/AlertPolicy$"], collection_prefixes=["monitoring.googleapis.com.*"], global_service=True),
    "monitoring_notification_channels": _svc("Notification Channels", "Monitoring notification channel inventory", [r"^monitoring\.googleapis\.com/NotificationChannel$"], collection_prefixes=["monitoring.googleapis.com.*"], global_service=True),
    "logging_buckets": _svc("Logging Buckets", "Log bucket and retention inventory", [r"^logging\.googleapis\.com/LogBucket$"], collection_prefixes=["logging.googleapis.com.*"], global_service=True),
    "iam_service_accounts": _svc("Service Accounts", "IAM service account inventory", [r"^iam\.googleapis\.com/ServiceAccount$"], collection_prefixes=["iam.googleapis.com.*"], global_service=True),
    "iam_workload_identity_pools": _svc("Workload Identity Pools", "Federated identity pool inventory", [r"^iam\.googleapis\.com/WorkloadIdentityPool$"], collection_prefixes=["iam.googleapis.com.*"], global_service=True),
    "vpc_access_connectors": _svc("Serverless VPC Access", "VPC connector inventory for serverless egress", [r"^vpcaccess\.googleapis\.com/Connector$"], collection_prefixes=["vpcaccess.googleapis.com.*"]),
    "network_connectivity_hubs": _svc("Network Connectivity Hubs", "Hub inventory for hybrid connectivity", [r"^networkconnectivity\.googleapis\.com/Hub$"], collection_prefixes=["networkconnectivity.googleapis.com.*"], global_service=True),
    "certificate_authority_pools": _svc("Certificate Authority Pools", "CA pool inventory for private PKI", [r"^certificateauthority\.googleapis\.com/CaPool$"], collection_prefixes=["certificateauthority.googleapis.com.*"], global_service=True),
    "certificate_authorities": _svc("Certificate Authorities", "Private CA inventory", [r"^certificateauthority\.googleapis\.com/CertificateAuthority$"], collection_prefixes=["certificateauthority.googleapis.com.*"], global_service=True),
    "firestore_databases": _svc("Firestore Databases", "Firestore database inventory", [r"^firestore\.googleapis\.com/Database$"], collection_prefixes=["firestore.googleapis.com.*"], global_service=True),
}


def list_gcp_realtime_services() -> List[Dict[str, str]]:
    return [
        {"id": service_id, "name": meta["name"], "description": meta["description"]}
        for service_id, meta in GCP_REALTIME_SERVICE_CATALOG.items()
    ]


def validate_gcp_credentials(access_token: str, scope: str = "", project_ids: str = "") -> Dict[str, Any]:
    if not access_token:
        return {"configured": False, "healthy": False, "message": "Missing GCP access token in .env"}

    try:
        headers = _headers(access_token)
        configured_projects = _parse_project_ids(project_ids)
        projects = configured_projects or [project["projectId"] for project in _search_projects(headers)]
        validation_scope = scope or (f"projects/{projects[0]}" if projects else "")
        if not validation_scope:
            raise RuntimeError("No accessible GCP scope was discovered for the provided token.")
        response = requests.get(
            f"https://cloudasset.googleapis.com/v1/{validation_scope}:searchAllResources",
            headers=headers,
            params={"pageSize": 1, "orderBy": "assetType,name"},
            timeout=20,
        )
        response.raise_for_status()
        return {
            "configured": True,
            "healthy": True,
            "message": "GCP access token verified",
            "details": {
                "scope": validation_scope,
                "projects": len(projects),
                "assets_sampled": len(response.json().get("results", [])),
                "mode": "api-only",
            },
        }
    except Exception as exc:
        return {"configured": True, "healthy": False, "message": f"GCP validation failed: {exc}"}


def check_gcp_realtime_posture(
    access_token: str,
    *,
    scope: str = "",
    project_ids: str = "",
    selected_service: str | None = None,
) -> Dict[str, Any]:
    context = _build_context(access_token, scope=scope, project_ids=project_ids)
    services: Dict[str, Any] = {}
    counts = {"pass": 0, "warn": 0, "fail": 0, "unknown": 0}

    for service_id, meta in GCP_REALTIME_SERVICE_CATALOG.items():
        service_result = check_gcp_realtime_service(
            access_token,
            service_id,
            scope=scope,
            project_ids=project_ids,
            context=context,
        )
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
                "projects": len(service_result.get("api_findings", {}).get("scope", {}).get("projects", [])),
            },
            "metadata": service_result,
        }

    total = max(len(services), 1)
    overall_score = round(sum(item["score"] for item in services.values()) / total)
    selected_key = selected_service if selected_service in services else next(iter(services.keys()), None)
    return {
        "provider": "gcp",
        "check": "GCP Realtime Posture Overview",
        "service_name": "Realtime Posture Overview",
        "selected_service": selected_key,
        "timestamp": datetime.utcnow().isoformat(),
        "gcp_summary": {
            "score": overall_score,
            "overall_status": "pass" if counts["fail"] == 0 and counts["warn"] == 0 else "warn" if counts["fail"] == 0 else "fail",
            "status_counts": counts,
            "service_count": len(services),
            "project_count": len(context["projects"]),
            "assets_sampled": len(context["assets"]),
        },
        "services": services,
        "screenshots": [],
        "api_findings": {},
        "vision_analysis": {},
        "status": "completed",
    }


def check_gcp_realtime_service(
    access_token: str,
    service: str,
    *,
    scope: str = "",
    project_ids: str = "",
    context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    meta = GCP_REALTIME_SERVICE_CATALOG.get(service)
    if not meta:
        return {
            "provider": "gcp",
            "service": service,
            "service_name": service,
            "status": "error",
            "error": f"Unknown GCP service integration: {service}",
            "screenshots": [],
            "api_findings": {},
            "vision_analysis": {},
        }

    context = context or _build_context(access_token, scope=scope, project_ids=project_ids)
    items = _filter_assets(context["assets"], meta["patterns"])
    available_regions = _collect_available_regions(items)
    regional_counts = _count_items_by_region(items)
    asset_type_counts = _count_items_by_asset_type(items)
    notes = list(context["notes"])
    errors = []
    collection_errors = context.get("collection_errors", {})
    for prefix in meta["collection_prefixes"]:
        errors.extend(collection_errors.get(prefix, []))
    if context["truncated"]:
        notes.append("The GCP scan samples the first pages returned by Cloud Asset Inventory for each service family to keep provider-wide monitoring responsive.")

    api_findings = {
        "integration": {
            "service_id": service,
            "service_name": meta["name"],
            "description": meta["description"],
            "region_scope": "global" if meta.get("global_service") else "regional",
            "available_regions": available_regions,
            "checked_at": datetime.utcnow().isoformat(),
            "mode": "cloud asset inventory realtime monitor",
            "asset_patterns": meta["patterns"],
        },
        "scope": {
            "scope_label": context["scope_label"],
            "scope_mode": context["scope_mode"],
            "project_count": len(context["projects"]),
            "projects": context["projects"][:12],
            "assets_sampled": len(context["assets"]),
            "collection_prefixes": sorted(meta["collection_prefixes"]),
        },
        "inventory": {
            "resource_count": len(items),
            "sample": _sample_items(items),
            "items_preview": _items_preview(items),
            "available_regions": available_regions,
            "regional_resource_counts": regional_counts,
            "asset_type_counts": asset_type_counts,
        },
        "health": _build_health(meta, items, notes, errors, context),
    }
    if notes or errors:
        api_findings["access"] = {"notes": notes[:12], "errors": errors[:12]}

    return {
        "provider": "gcp",
        "service": service,
        "service_name": meta["name"],
        "service_description": meta["description"],
        "check": "Realtime GCP Integration Monitor",
        "check_description": f"Live GCP asset inventory and posture summary for {meta['name']}",
        "timestamp": datetime.utcnow().isoformat(),
        "status": "completed" if not errors else "warn",
        "screenshots": [],
        "api_findings": api_findings,
        "vision_analysis": {},
    }


def _build_context(access_token: str, *, scope: str = "", project_ids: str = "") -> Dict[str, Any]:
    headers = _headers(access_token)
    configured_projects = _parse_project_ids(project_ids)

    projects = []
    scope_mode = "project-discovery"
    if configured_projects:
        projects = [{"projectId": project_id, "displayName": project_id, "name": f"projects/{project_id}"} for project_id in configured_projects]
        scope_mode = "explicit-projects"
    elif scope and scope.startswith("projects/"):
        project_id = scope.split("/", 1)[1]
        projects = [{"projectId": project_id, "displayName": project_id, "name": scope}]
        scope_mode = "explicit-project-scope"
    elif not scope:
        projects = _search_projects(headers)

    scopes = [scope] if scope else [project["name"] for project in projects[:MAX_PROJECT_SCOPES]]
    if not scopes:
        raise RuntimeError("No GCP projects are visible to the provided token. Set COMPLIANCE_GCP_PROJECT_IDS or COMPLIANCE_GCP_SCOPE if project discovery is restricted.")

    notes: List[str] = []
    errors: List[str] = []
    if len(projects) > MAX_PROJECT_SCOPES and not scope:
        notes.append(f"Sampling the first {MAX_PROJECT_SCOPES} accessible projects to keep provider-wide monitoring responsive.")

    assets, truncated, collection_errors = _collect_assets(headers, scopes)
    errors = [message for messages in collection_errors.values() for message in messages]
    if not assets and errors:
        raise RuntimeError(errors[0])
    return {
        "headers": headers,
        "projects": projects,
        "assets": assets,
        "scope_label": scope or f"{min(len(scopes), len(projects) or len(scopes))} project scope(s)",
        "scope_mode": scope_mode if not scope else "explicit-scope",
        "notes": notes,
        "errors": errors,
        "collection_errors": collection_errors,
        "truncated": truncated,
    }


def _headers(access_token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}


def _parse_project_ids(value: str) -> List[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _search_projects(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    projects: List[Dict[str, Any]] = []
    next_token = ""
    while len(projects) < MAX_PROJECT_SCOPES:
        params = {"pageSize": 50}
        if next_token:
            params["pageToken"] = next_token
        response = requests.get("https://cloudresourcemanager.googleapis.com/v3/projects:search", headers=headers, params=params, timeout=30)
        response.raise_for_status()
        payload = response.json()
        for project in payload.get("projects", []):
            if project.get("state") and str(project.get("state")).upper() != "ACTIVE":
                continue
            project_id = project.get("projectId")
            if not project_id:
                continue
            projects.append({
                "projectId": project_id,
                "displayName": project.get("displayName") or project_id,
                "name": f"projects/{project_id}",
                "projectNumber": project.get("name", "").split("/")[-1] if project.get("name") else "",
            })
            if len(projects) >= MAX_PROJECT_SCOPES:
                break
        next_token = payload.get("nextPageToken") or ""
        if not next_token:
            break
    return projects


def _collect_assets(headers: Dict[str, str], scopes: Iterable[str]) -> Tuple[List[Dict[str, Any]], bool, Dict[str, List[str]]]:
    prefixes = sorted({prefix for meta in GCP_REALTIME_SERVICE_CATALOG.values() for prefix in meta["collection_prefixes"]})
    dedup: Dict[Tuple[str, str], Dict[str, Any]] = {}
    truncated = False
    errors: Dict[str, List[str]] = {}

    for scope in scopes:
        for prefix in prefixes:
            page_token = ""
            pages = 0
            while pages < MAX_SCOPE_PAGES:
                params = {
                    "assetTypes": prefix,
                    "pageSize": SEARCH_PAGE_SIZE,
                    "orderBy": "assetType,name",
                    "readMask": "name,assetType,project,folders,organization,displayName,description,location,labels,tags,effectiveTags,networkTags,kmsKeys,createTime,updateTime,state,additionalAttributes,parentFullResourceName,parentAssetType,versionedResources,relationships",
                }
                if page_token:
                    params["pageToken"] = page_token

                try:
                    response = requests.get(
                        f"https://cloudasset.googleapis.com/v1/{scope}:searchAllResources",
                        headers=headers,
                        params=params,
                        timeout=45,
                    )
                    response.raise_for_status()
                    payload = response.json()
                except Exception as exc:
                    errors.setdefault(prefix, []).append(f"{scope} / {prefix}: {exc}")
                    break
                for raw in payload.get("results", []):
                    asset = _normalize_asset(raw, scope)
                    dedup[(asset.get("assetType", ""), asset.get("name", ""))] = asset
                page_token = payload.get("nextPageToken") or ""
                pages += 1
                if not page_token:
                    break
                truncated = True
    return list(dedup.values()), truncated, errors


def _normalize_asset(item: Dict[str, Any], scope: str) -> Dict[str, Any]:
    asset = dict(item)
    name = asset.get("name", "")
    project = asset.get("project", "")
    asset["scope"] = scope
    asset["projectId"] = _extract_project_id(name) or (project.split("/", 1)[1] if project.startswith("projects/") else "")
    asset["resourceName"] = name
    asset["display_name"] = asset.get("displayName") or _last_name_segment(name) or asset.get("projectId") or asset.get("assetType")
    location = asset.get("location")
    if isinstance(location, str) and location.strip():
        asset["_region"] = location.strip().lower()
    additional = asset.get("additionalAttributes")
    if isinstance(additional, dict):
        for key, value in list(additional.items())[:8]:
            if isinstance(value, (str, int, float, bool)) and key not in asset:
                asset[key] = value
    return asset


def _extract_project_id(name: str) -> str:
    match = re.search(r"/projects/([^/]+)", name or "")
    return match.group(1) if match else ""


def _last_name_segment(name: str) -> str:
    if not name:
        return ""
    parts = [part for part in str(name).split("/") if part]
    return parts[-1] if parts else ""


def _filter_assets(assets: List[Dict[str, Any]], patterns: List[str]) -> List[Dict[str, Any]]:
    compiled = [re.compile(pattern) for pattern in patterns]
    matches = []
    for asset in assets:
        asset_type = str(asset.get("assetType") or "")
        if any(regex.match(asset_type) for regex in compiled):
            matches.append(asset)
    return matches[:MAX_SERVICE_PREVIEW]


def _sample_items(items: List[Dict[str, Any]]) -> List[Any]:
    sample = []
    for item in items[:5]:
        compact = {}
        for key in ["display_name", "assetType", "projectId", "location", "state", "description"]:
            if item.get(key):
                compact[key] = item.get(key)
        if item.get("labels"):
            compact["labels"] = f"{len(item.get('labels', {}))} label(s)"
        if item.get("kmsKeys"):
            compact["kmsKeys"] = f"{len(item.get('kmsKeys', []))} key(s)"
        if item.get("parentFullResourceName"):
            compact["parent"] = item.get("parentFullResourceName")
        sample.append(compact or item)
    return sample


def _items_preview(items: List[Dict[str, Any]]) -> List[Any]:
    return [_serialize_preview_item(item) for item in items[:MAX_SERVICE_PREVIEW]]


def _serialize_preview_item(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [_serialize_preview_item(item) for item in value[:8]]
    if isinstance(value, dict):
        data: Dict[str, Any] = {}
        preferred = [
            "display_name",
            "displayName",
            "assetType",
            "projectId",
            "location",
            "_region",
            "state",
            "description",
            "name",
            "resourceName",
            "parentFullResourceName",
        ]
        for key in preferred:
            if key in value and len(data) < 14:
                data[key] = _serialize_preview_item(value[key])
        for key, item in value.items():
            if len(data) >= 14:
                break
            if key in data:
                continue
            if isinstance(item, (str, int, float, bool)) or item is None:
                data[key] = item
        return data
    return str(value)


def _collect_available_regions(items: List[Dict[str, Any]]) -> List[str]:
    return sorted({item.get("_region") for item in items if item.get("_region")})


def _count_items_by_region(items: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        region = item.get("_region")
        if not region:
            continue
        counts[region] = counts.get(region, 0) + 1
    return counts


def _count_items_by_asset_type(items: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        asset_type = item.get("assetType")
        if not asset_type:
            continue
        counts[asset_type] = counts.get(asset_type, 0) + 1
    return counts


def _build_health(
    meta: Dict[str, Any],
    items: List[Dict[str, Any]],
    notes: List[str],
    errors: List[str],
    context: Dict[str, Any],
) -> Dict[str, Any]:
    status = "pass"
    if errors:
        status = "warn"
    score = 88 if not errors else 60
    project_count = len(context["projects"])
    summary = (
        f"Live GCP asset monitoring completed for {meta['name']} with {len(items)} matching resource(s) across {project_count or 1} project scope."
        if not errors
        else f"GCP monitoring completed with partial visibility issues for {meta['name']}."
    )
    observations = [
        f"Cloud Asset Inventory is providing the current metadata stream for {meta['name']}.",
        f"Observed {len(items)} resource(s) across {project_count or 1} project scope.",
    ]
    if context["truncated"]:
        observations.append("The provider-wide GCP scan is sampled from the first pages of each asset family to keep refreshes responsive.")
    if notes:
        observations.append(notes[0])
    if errors:
        observations.append(f"Permission or API issue: {errors[0]}")
    return {"status": status, "score": score, "summary": summary, "observations": observations}
