"""API-only OCI realtime monitoring backed by OCI Resource Search."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple

import oci
from oci.signer import Signer

MAX_SEARCH_REGIONS = 12
MAX_REGION_PAGES = 3
SEARCH_PAGE_SIZE = 200
MAX_SERVICE_PREVIEW = 50


def _svc(
    name: str,
    description: str,
    patterns: List[str],
    *,
    category: str,
    global_service: bool = False,
) -> Dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "patterns": patterns,
        "category": category,
        "global_service": global_service,
    }


OCI_REALTIME_SERVICE_CATALOG: Dict[str, Dict[str, Any]] = {
    "compartments": _svc("Compartments", "Tenancy compartment hierarchy and delegated boundaries", [r"^Compartment$"], category="Identity", global_service=True),
    "users": _svc("Users", "IAM user inventory and operator identities", [r"^User$"], category="Identity", global_service=True),
    "groups": _svc("Groups", "IAM group definitions and access grouping", [r"^Group$"], category="Identity", global_service=True),
    "policies": _svc("Policies", "IAM policy coverage across the tenancy", [r"^Policy$"], category="Identity", global_service=True),
    "dynamic_groups": _svc("Dynamic Groups", "Dynamic group identities for workload access", [r"^DynamicGroup$"], category="Identity", global_service=True),
    "tag_namespaces": _svc("Tag Namespaces", "Tagging namespace definitions and governance coverage", [r"^TagNamespace$"], category="Identity", global_service=True),
    "tag_defaults": _svc("Tag Defaults", "Default tag propagation rules", [r"^TagDefault$"], category="Identity", global_service=True),
    "identity_domains": _svc("Identity Domains", "Identity domain footprint and separation of auth boundaries", [r"^(IdentityDomain|Domain)$"], category="Identity", global_service=True),
    "vcns": _svc("VCNs", "Virtual cloud network topology", [r"^Vcn$"], category="Networking"),
    "subnets": _svc("Subnets", "Subnet inventory and segmentation", [r"^Subnet$"], category="Networking"),
    "route_tables": _svc("Route Tables", "Routing policy inventory for VCN traffic paths", [r"^RouteTable$"], category="Networking"),
    "security_lists": _svc("Security Lists", "Security list controls and traffic policy sets", [r"^SecurityList$"], category="Networking"),
    "network_security_groups": _svc("Network Security Groups", "Security groups for fine-grained network control", [r"^NetworkSecurityGroup$"], category="Networking"),
    "dhcp_options": _svc("DHCP Options", "DHCP options and name-resolution settings", [r"^DhcpOptions$"], category="Networking"),
    "internet_gateways": _svc("Internet Gateways", "Public internet egress and ingress gateways", [r"^InternetGateway$"], category="Networking"),
    "nat_gateways": _svc("NAT Gateways", "Private subnet egress gateways", [r"^NatGateway$"], category="Networking"),
    "service_gateways": _svc("Service Gateways", "Private access paths to Oracle services", [r"^ServiceGateway$"], category="Networking"),
    "dynamic_routing_gateways": _svc("Dynamic Routing Gateways", "Hybrid connectivity hubs and transit routing", [r"^Drg$"], category="Networking"),
    "local_peering_gateways": _svc("Local Peering Gateways", "In-region VCN peering topology", [r"^LocalPeeringGateway$"], category="Networking"),
    "remote_peering_connections": _svc("Remote Peering Connections", "Cross-region VCN peering links", [r"^RemotePeeringConnection$"], category="Networking"),
    "cpes": _svc("Customer Premises Equipment", "On-premises connectivity endpoints", [r"^Cpe$"], category="Networking"),
    "ipsec_connections": _svc("IPSec Connections", "Site-to-site VPN connectivity", [r"^(IPSecConnection|IpsecConnection)$"], category="Networking"),
    "fastconnect_virtual_circuits": _svc("FastConnect Virtual Circuits", "Private dedicated network connectivity", [r"^VirtualCircuit$"], category="Networking"),
    "load_balancers": _svc("Load Balancers", "Regional layer-7 load balancer fleet", [r"^LoadBalancer$"], category="Networking"),
    "network_load_balancers": _svc("Network Load Balancers", "Layer-4 network load balancers", [r"^NetworkLoadBalancer$"], category="Networking"),
    "public_ips": _svc("Public IPs", "Public IP allocations and bindings", [r"^PublicIp$"], category="Networking"),
    "private_ips": _svc("Private IPs", "Private IP inventory and interface bindings", [r"^PrivateIp$"], category="Networking"),
    "api_gateways": _svc("API Gateways", "Managed API front doors and edge entry points", [r"^ApiGateway$"], category="Networking"),
    "bastions": _svc("Bastions", "Managed bastion hosts and private access sessions", [r"^Bastion$"], category="Networking"),
    "dns_zones": _svc("DNS Zones", "DNS hosted zones and delegated naming boundaries", [r"^Zone$"], category="Networking", global_service=True),
    "instances": _svc("Compute Instances", "Virtual machine fleet and lifecycle state", [r"^Instance$"], category="Compute"),
    "instance_configurations": _svc("Instance Configurations", "Reusable instance launch templates", [r"^InstanceConfiguration$"], category="Compute"),
    "instance_pools": _svc("Instance Pools", "Fleet scaling groups for compute instances", [r"^InstancePool$"], category="Compute"),
    "cluster_networks": _svc("Cluster Networks", "Clustered compute network definitions", [r"^ClusterNetwork$"], category="Compute"),
    "autoscaling_configurations": _svc("Autoscaling Configurations", "Autoscaling policies and thresholds", [r"^AutoScalingConfiguration$"], category="Compute"),
    "images": _svc("Custom Images", "Image inventory for instance launches", [r"^Image$"], category="Compute"),
    "boot_volumes": _svc("Boot Volumes", "Boot volume inventory for instances", [r"^BootVolume$"], category="Storage"),
    "boot_volume_backups": _svc("Boot Volume Backups", "Boot volume backup protection coverage", [r"^BootVolumeBackup$"], category="Storage"),
    "block_volumes": _svc("Block Volumes", "Primary block storage inventory", [r"^Volume$"], category="Storage"),
    "volume_backups": _svc("Volume Backups", "Block volume backup footprint", [r"^VolumeBackup$"], category="Storage"),
    "volume_groups": _svc("Volume Groups", "Grouped block volume collections", [r"^VolumeGroup$"], category="Storage"),
    "volume_group_backups": _svc("Volume Group Backups", "Volume group backup protection coverage", [r"^VolumeGroupBackup$"], category="Storage"),
    "file_systems": _svc("File Systems", "File Storage service file systems", [r"^FileSystem$"], category="Storage"),
    "mount_targets": _svc("Mount Targets", "File Storage mount targets", [r"^MountTarget$"], category="Storage"),
    "export_sets": _svc("Export Sets", "File Storage export sets and mounts", [r"^ExportSet$"], category="Storage"),
    "buckets": _svc("Object Storage Buckets", "Bucket inventory and namespace footprint", [r"^Bucket$"], category="Storage"),
    "oke_clusters": _svc("OKE Clusters", "Kubernetes control planes and cluster posture", [r"^(Cluster|OkeCluster|KubernetesCluster)$"], category="Containers"),
    "oke_node_pools": _svc("OKE Node Pools", "Node pool capacity and worker spread", [r"^NodePool$"], category="Containers"),
    "functions_applications": _svc("Functions Applications", "Serverless application containers", [r"^(FnApplication|Application)$"], category="Serverless"),
    "functions": _svc("Functions", "Serverless function inventory", [r"^Function$"], category="Serverless"),
    "devops_projects": _svc("DevOps Projects", "OCI DevOps project inventory", [r"^(DevopsProject|Project)$"], category="DevOps"),
    "build_pipelines": _svc("Build Pipelines", "OCI DevOps build pipeline definitions", [r"^BuildPipeline$"], category="DevOps"),
    "deploy_pipelines": _svc("Deploy Pipelines", "OCI DevOps deployment pipelines", [r"^DeployPipeline$"], category="DevOps"),
    "build_runs": _svc("Build Runs", "Recent build run inventory", [r"^BuildRun$"], category="DevOps"),
    "deployments": _svc("Deployments", "DevOps deployment execution history", [r"^Deployment$"], category="DevOps"),
    "code_repositories": _svc("Code Repositories", "Hosted source repositories in OCI DevOps", [r"^(Repository|CodeRepository)$"], category="DevOps"),
    "autonomous_databases": _svc("Autonomous Databases", "Autonomous Database inventory", [r"^AutonomousDatabase$"], category="Data"),
    "autonomous_container_databases": _svc("Autonomous Container Databases", "Autonomous container database fleet", [r"^AutonomousContainerDatabase$"], category="Data"),
    "db_systems": _svc("DB Systems", "VM and bare metal database systems", [r"^DbSystem$"], category="Data"),
    "databases": _svc("Databases", "Database inventory across attached systems", [r"^Database$"], category="Data"),
    "mysql_db_systems": _svc("MySQL DB Systems", "MySQL HeatWave and DB system inventory", [r"^(MysqlDbSystem|MySqlDbSystem)$"], category="Data"),
    "mysql_backups": _svc("MySQL Backups", "MySQL backup protection coverage", [r"^(MysqlBackup|MySqlBackup)$"], category="Data"),
    "postgresql_db_systems": _svc("PostgreSQL DB Systems", "OCI PostgreSQL managed database systems", [r"^(PostgresqlDbSystem|PostgreSqlDbSystem|PostgreSqlSystem)$"], category="Data"),
    "analytics_instances": _svc("Analytics Instances", "Oracle Analytics Cloud instances in OCI", [r"^AnalyticsInstance$"], category="Data"),
    "integration_instances": _svc("Integration Instances", "Oracle Integration Cloud instances in OCI", [r"^IntegrationInstance$"], category="Data"),
    "data_flow_applications": _svc("Data Flow Applications", "Spark application definitions in Data Flow", [r"^DataFlowApplication$"], category="Data"),
    "data_flow_runs": _svc("Data Flow Runs", "Data Flow run history and execution state", [r"^DataFlowRun$"], category="Data"),
    "data_science_projects": _svc("Data Science Projects", "Project workspaces for ML initiatives", [r"^DataScienceProject$"], category="AI"),
    "data_science_models": _svc("Data Science Models", "Registered ML models and artifacts", [r"^(DataScienceModel|Model)$"], category="AI"),
    "data_science_notebook_sessions": _svc("Notebook Sessions", "Interactive notebook sessions in Data Science", [r"^NotebookSession$"], category="AI"),
    "stream_pools": _svc("Stream Pools", "Streaming pool infrastructure", [r"^StreamPool$"], category="Data"),
    "streams": _svc("Streams", "Stream topic inventory and throughput channels", [r"^Stream$"], category="Data"),
    "no_sql_tables": _svc("NoSQL Tables", "OCI NoSQL table inventory", [r"^(NoSqlTable|NoSQLTable)$"], category="Data"),
    "vaults": _svc("Vaults", "Vault infrastructure for key management", [r"^Vault$"], category="Security"),
    "keys": _svc("Keys", "KMS key inventory and protection posture", [r"^Key$"], category="Security"),
    "secrets": _svc("Secrets", "Secret storage inventory", [r"^Secret$"], category="Security"),
    "certificates": _svc("Certificates", "Certificate inventory for TLS and PKI", [r"^Certificate$"], category="Security"),
    "certificate_authorities": _svc("Certificate Authorities", "Private certificate authority inventory", [r"^CertificateAuthority$"], category="Security"),
    "log_groups": _svc("Log Groups", "Log group containers and retention boundaries", [r"^LogGroup$"], category="Observability"),
    "logs": _svc("Logs", "Indexed log definitions and sources", [r"^Log$"], category="Observability"),
    "alarms": _svc("Alarms", "Alarm inventory and active telemetry checks", [r"^Alarm$"], category="Observability"),
    "notification_topics": _svc("Notification Topics", "Notification topic definitions", [r"^Topic$"], category="Observability"),
    "notification_subscriptions": _svc("Notification Subscriptions", "Notification endpoint subscriptions", [r"^Subscription$"], category="Observability"),
    "service_connectors": _svc("Service Connectors", "Streaming and telemetry connector pipelines", [r"^ServiceConnector$"], category="Observability"),
    "apm_domains": _svc("APM Domains", "Application Performance Monitoring domains", [r"^ApmDomain$"], category="Observability"),
}


def list_oci_realtime_services() -> List[Dict[str, str]]:
    return [
        {"id": service_id, "name": meta["name"], "description": meta["description"]}
        for service_id, meta in OCI_REALTIME_SERVICE_CATALOG.items()
    ]


def validate_oci_credentials(
    tenancy_ocid: str,
    user_ocid: str,
    fingerprint: str,
    private_key: str,
    region: str,
    *,
    passphrase: str = "",
    private_key_path: str = "",
) -> Dict[str, Any]:
    if not _has_oci_credentials(tenancy_ocid, user_ocid, fingerprint, private_key, private_key_path, region):
        return {"configured": False, "healthy": False, "message": "Missing OCI tenancy, user, fingerprint, private key, or region in .env"}

    try:
        context = _build_context(
            tenancy_ocid,
            user_ocid,
            fingerprint,
            private_key,
            region,
            passphrase=passphrase,
            private_key_path=private_key_path,
            include_resources=False,
        )
        return {
            "configured": True,
            "healthy": True,
            "message": "OCI API key verified",
            "details": {
                "tenancy_ocid": tenancy_ocid,
                "user_ocid": user_ocid,
                "configured_region": region,
                "home_region": context["home_region"],
                "subscribed_regions": len(context["regions"]),
                "searchable_types": len(context["searchable_types"]),
                "mode": "api-only",
            },
        }
    except Exception as exc:
        return {"configured": True, "healthy": False, "message": f"OCI validation failed: {exc}"}


def _has_oci_credentials(
    tenancy_ocid: str,
    user_ocid: str,
    fingerprint: str,
    private_key: str,
    private_key_path: str,
    region: str,
) -> bool:
    return bool(tenancy_ocid and user_ocid and fingerprint and region and (private_key or private_key_path))


def check_oci_realtime_posture(
    tenancy_ocid: str,
    user_ocid: str,
    fingerprint: str,
    private_key: str,
    region: str,
    *,
    passphrase: str = "",
    private_key_path: str = "",
    selected_service: str | None = None,
) -> Dict[str, Any]:
    context = _build_context(
        tenancy_ocid,
        user_ocid,
        fingerprint,
        private_key,
        region,
        passphrase=passphrase,
        private_key_path=private_key_path,
        include_resources=True,
    )
    services: Dict[str, Any] = {}
    counts = {"pass": 0, "warn": 0, "fail": 0, "unknown": 0}

    for service_id, meta in OCI_REALTIME_SERVICE_CATALOG.items():
        service_result = check_oci_realtime_service(
            tenancy_ocid,
            user_ocid,
            fingerprint,
            private_key,
            region,
            service_id,
            passphrase=passphrase,
            private_key_path=private_key_path,
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
                "regions": len(service_result.get("api_findings", {}).get("inventory", {}).get("available_regions", [])),
                "types": len(service_result.get("api_findings", {}).get("inventory", {}).get("resource_type_counts", {})),
            },
            "metadata": service_result,
        }

    total = max(len(services), 1)
    overall_score = round(sum(item["score"] for item in services.values()) / total)
    selected_key = selected_service if selected_service in services else next(iter(services.keys()), None)
    return {
        "provider": "oci",
        "check": "OCI Realtime Posture Overview",
        "service_name": "Realtime Posture Overview",
        "selected_service": selected_key,
        "timestamp": datetime.utcnow().isoformat(),
        "oci_summary": {
            "score": overall_score,
            "overall_status": "pass" if counts["fail"] == 0 and counts["warn"] == 0 else "warn" if counts["fail"] == 0 else "fail",
            "status_counts": counts,
            "service_count": len(services),
            "region_count": len(context["scanned_regions"]),
            "assets_sampled": len(context["resources"]),
            "searchable_type_count": len(context["searchable_types"]),
        },
        "services": services,
        "screenshots": [],
        "api_findings": {},
        "vision_analysis": {},
        "status": "completed",
    }


def check_oci_realtime_service(
    tenancy_ocid: str,
    user_ocid: str,
    fingerprint: str,
    private_key: str,
    region: str,
    service: str,
    *,
    passphrase: str = "",
    private_key_path: str = "",
    context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    meta = OCI_REALTIME_SERVICE_CATALOG.get(service)
    if not meta:
        return {
            "provider": "oci",
            "service": service,
            "service_name": service,
            "status": "error",
            "error": f"Unknown OCI service integration: {service}",
            "screenshots": [],
            "api_findings": {},
            "vision_analysis": {},
        }

    context = context or _build_context(
        tenancy_ocid,
        user_ocid,
        fingerprint,
        private_key,
        region,
        passphrase=passphrase,
        private_key_path=private_key_path,
        include_resources=True,
    )
    items = _filter_resources(context["resources"], meta["patterns"])
    available_regions = _collect_available_regions(items)
    regional_counts = _count_items_by_region(items)
    type_counts = _count_items_by_type(items)
    compartment_counts = _count_items_by_compartment(items)
    notes = list(context["notes"])
    errors = list(context["errors"])
    if context["truncated"]:
        notes.append("The OCI scan samples recent pages from each subscribed region to keep provider-wide monitoring responsive.")

    api_findings = {
        "integration": {
            "service_id": service,
            "service_name": meta["name"],
            "description": meta["description"],
            "category": meta["category"],
            "region_scope": "global" if meta.get("global_service") else "regional",
            "available_regions": available_regions,
            "checked_at": datetime.utcnow().isoformat(),
            "mode": "oci resource search realtime monitor",
            "resource_type_patterns": meta["patterns"],
        },
        "scope": {
            "configured_region": region,
            "home_region": context["home_region"],
            "tenancy_ocid": tenancy_ocid,
            "user_ocid": user_ocid,
            "region_count": len(context["regions"]),
            "subscribed_regions": context["regions"][:12],
            "scanned_regions": context["scanned_regions"],
            "resources_sampled": len(context["resources"]),
            "searchable_type_count": len(context["searchable_types"]),
            "searchable_type_preview": context["searchable_types"][:24],
            "compartments_visible": len(context["compartments"]),
        },
        "inventory": {
            "resource_count": len(items),
            "sample": _sample_items(items),
            "items_preview": _items_preview(items),
            "available_regions": available_regions,
            "regional_resource_counts": regional_counts,
            "resource_type_counts": type_counts,
            "compartment_counts": compartment_counts,
        },
        "health": _build_health(meta, items, notes, errors, context),
    }
    if notes or errors:
        api_findings["access"] = {"notes": notes[:12], "errors": errors[:12]}

    return {
        "provider": "oci",
        "service": service,
        "service_name": meta["name"],
        "service_description": meta["description"],
        "check": "Realtime OCI Integration Monitor",
        "check_description": f"Live OCI Resource Search inventory and posture summary for {meta['name']}",
        "timestamp": datetime.utcnow().isoformat(),
        "status": "completed" if not errors else "warn",
        "screenshots": [],
        "api_findings": api_findings,
        "vision_analysis": {},
    }


def _build_context(
    tenancy_ocid: str,
    user_ocid: str,
    fingerprint: str,
    private_key: str,
    region: str,
    *,
    passphrase: str = "",
    private_key_path: str = "",
    include_resources: bool = True,
) -> Dict[str, Any]:
    signer = _build_signer(tenancy_ocid, user_ocid, fingerprint, private_key, passphrase=passphrase, private_key_path=private_key_path)
    identity_client = oci.identity.IdentityClient({"region": region}, signer=signer)
    region_subscriptions = identity_client.list_region_subscriptions(tenancy_ocid).data
    ready_regions = [item for item in region_subscriptions if getattr(item, "status", "") == oci.identity.models.RegionSubscription.STATUS_READY]
    if not ready_regions:
        raise RuntimeError("No subscribed OCI regions are ready for Resource Search.")

    regions = [{"name": item.region_name, "home": bool(item.is_home_region), "status": item.status} for item in ready_regions]
    home_region = next((item["name"] for item in regions if item["home"]), region)
    scanned_regions = [item["name"] for item in regions[:MAX_SEARCH_REGIONS]]
    notes: List[str] = []
    errors: List[str] = []
    if len(regions) > MAX_SEARCH_REGIONS:
        notes.append(f"Sampling the first {MAX_SEARCH_REGIONS} subscribed OCI regions to keep provider-wide monitoring responsive.")

    searchable_types = _list_resource_types(signer, home_region or region)
    resources: List[Dict[str, Any]] = []
    compartments: Dict[str, str] = {}
    truncated = False

    if include_resources:
        resources, truncated, errors = _collect_resources(signer, scanned_regions)
        compartments = _build_compartment_lookup(resources)
        for item in resources:
            compartment_id = item.get("compartmentId")
            if compartment_id and compartment_id in compartments:
                item["compartmentName"] = compartments[compartment_id]

    return {
        "signer": signer,
        "regions": regions,
        "home_region": home_region,
        "scanned_regions": scanned_regions,
        "notes": notes,
        "errors": errors,
        "resources": resources,
        "compartments": compartments,
        "searchable_types": searchable_types,
        "truncated": truncated,
    }


def _build_signer(
    tenancy_ocid: str,
    user_ocid: str,
    fingerprint: str,
    private_key: str,
    *,
    passphrase: str = "",
    private_key_path: str = "",
) -> Signer:
    normalized_passphrase = passphrase or None
    if private_key_path:
        return Signer(
            tenancy=tenancy_ocid,
            user=user_ocid,
            fingerprint=fingerprint,
            private_key_file_location=private_key_path,
            pass_phrase=normalized_passphrase,
        )

    private_key_content = (private_key or "").replace("\\n", "\n").strip()
    if not private_key_content:
        raise RuntimeError("OCI private key content is empty.")
    return Signer(
        tenancy=tenancy_ocid,
        user=user_ocid,
        fingerprint=fingerprint,
        private_key_file_location=None,
        pass_phrase=normalized_passphrase,
        private_key_content=private_key_content,
    )


def _list_resource_types(signer: Signer, region: str) -> List[str]:
    client = oci.resource_search.ResourceSearchClient({"region": region}, signer=signer)
    names: List[str] = []
    page = None

    while True:
        response = client.list_resource_types(limit=1000, page=page)
        for item in response.data:
            if getattr(item, "name", None):
                names.append(item.name)
        page = response.headers.get("opc-next-page")
        if not page:
            break
    return sorted(set(names))


def _collect_resources(signer: Signer, regions: Iterable[str]) -> Tuple[List[Dict[str, Any]], bool, List[str]]:
    search_details = oci.resource_search.models.StructuredSearchDetails(
        type="Structured",
        query="query all resources sorted by timeCreated desc",
        matching_context_type=oci.resource_search.models.SearchDetails.MATCHING_CONTEXT_TYPE_NONE,
    )
    dedup: Dict[str, Dict[str, Any]] = {}
    truncated = False
    errors: List[str] = []

    for region in regions:
        client = oci.resource_search.ResourceSearchClient({"region": region}, signer=signer)
        page = None
        pages = 0
        while pages < MAX_REGION_PAGES:
            try:
                response = client.search_resources(search_details, limit=SEARCH_PAGE_SIZE, page=page)
            except Exception as exc:
                errors.append(f"{region}: {exc}")
                break

            for item in getattr(response.data, "items", []) or []:
                normalized = _normalize_resource(item, region)
                identifier = normalized.get("identifier") or f"{normalized.get('resourceType')}::{normalized.get('display_name')}"
                dedup[identifier] = normalized

            page = response.headers.get("opc-next-page")
            pages += 1
            if not page:
                break
            truncated = True

    return list(dedup.values()), truncated, errors


def _normalize_resource(item: Any, region: str) -> Dict[str, Any]:
    identifier = getattr(item, "identifier", "") or ""
    resource_type = getattr(item, "resource_type", "") or ""
    display_name = getattr(item, "display_name", "") or ""
    additional_details = getattr(item, "additional_details", {}) or {}
    normalized: Dict[str, Any] = {
        "identifier": identifier,
        "resourceType": resource_type,
        "display_name": display_name or _identifier_tail(identifier) or resource_type,
        "compartmentId": getattr(item, "compartment_id", "") or "",
        "availabilityDomain": getattr(item, "availability_domain", "") or "",
        "lifecycleState": getattr(item, "lifecycle_state", "") or "",
        "timeCreated": _stringify(getattr(item, "time_created", "")),
        "searchRegion": region,
    }
    resource_region = _extract_region_from_ocid(identifier)
    if resource_region:
        normalized["_region"] = resource_region
    elif normalized["availabilityDomain"]:
        normalized["_region"] = region
    else:
        normalized["_region"] = "global"

    if isinstance(additional_details, dict):
        for key, value in additional_details.items():
            flattened = _flatten_additional_value(value)
            if flattened is not None and key not in normalized:
                normalized[key] = flattened

    normalized["display_name"] = (
        normalized.get("display_name")
        or normalized.get("displayName")
        or normalized.get("name")
        or normalized.get("namespace")
        or normalized.get("endpoint")
        or _identifier_tail(identifier)
        or resource_type
    )
    return normalized


def _flatten_additional_value(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return len(value)
    return None


def _extract_region_from_ocid(identifier: str) -> str:
    match = re.search(r"^ocid1\.[^.]+\.[^.]+\.([a-z0-9-]+)\.", identifier or "")
    return match.group(1).lower() if match else ""


def _identifier_tail(identifier: str) -> str:
    if not identifier:
        return ""
    if "." in identifier:
        return identifier.split(".")[-1][:24]
    return identifier[-24:]


def _build_compartment_lookup(resources: Iterable[Dict[str, Any]]) -> Dict[str, str]:
    lookup: Dict[str, str] = {}
    for item in resources:
        if item.get("resourceType") == "Compartment" and item.get("identifier"):
            lookup[item["identifier"]] = item.get("display_name") or item["identifier"]
    return lookup


def _filter_resources(resources: List[Dict[str, Any]], patterns: List[str]) -> List[Dict[str, Any]]:
    compiled = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    matches = []
    for resource in resources:
        resource_type = str(resource.get("resourceType") or "")
        if any(regex.search(resource_type) for regex in compiled):
            matches.append(resource)
    return matches[:MAX_SERVICE_PREVIEW]


def _sample_items(items: List[Dict[str, Any]]) -> List[Any]:
    sample = []
    preferred_keys = [
        "display_name", "resourceType", "identifier", "_region",
        "lifecycleState", "compartmentName", "availabilityDomain",
        "cidrBlock", "shape", "namespace", "publicIp", "privateIp",
    ]
    for item in items[:5]:
        compact = {}
        for key in preferred_keys:
            if item.get(key):
                compact[key] = item.get(key)
        sample.append(compact or item)
    return sample


def _items_preview(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    preview = []
    preferred_keys = [
        "display_name", "resourceType", "identifier", "_region",
        "lifecycleState", "compartmentName", "availabilityDomain",
        "cidrBlock", "shape", "namespace", "vcnId", "subnetId",
        "publicIp", "privateIp", "endpoint", "sizeInGBs", "sizeInGbs",
        "databaseEdition", "cpuCoreCount", "memorySizeInGBs", "timeCreated",
    ]
    for item in items[:MAX_SERVICE_PREVIEW]:
        compact: Dict[str, Any] = {}
        for key in preferred_keys:
            if item.get(key) not in (None, ""):
                compact[key] = item.get(key)
        if not compact:
            compact = dict(item)
        preview.append(compact)
    return preview


def _collect_available_regions(items: Iterable[Dict[str, Any]]) -> List[str]:
    return sorted({str(item.get("_region") or "").lower() for item in items if item.get("_region") and item.get("_region") != "global"})


def _count_items_by_region(items: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        region = str(item.get("_region") or "").lower()
        if not region or region == "global":
            continue
        counts[region] = counts.get(region, 0) + 1
    return counts


def _count_items_by_type(items: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        resource_type = str(item.get("resourceType") or "")
        if not resource_type:
            continue
        counts[resource_type] = counts.get(resource_type, 0) + 1
    return counts


def _count_items_by_compartment(items: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        compartment = str(item.get("compartmentName") or item.get("compartmentId") or "")
        if not compartment:
            continue
        counts[compartment] = counts.get(compartment, 0) + 1
    return counts


def _build_health(meta: Dict[str, Any], items: List[Dict[str, Any]], notes: List[str], errors: List[str], context: Dict[str, Any]) -> Dict[str, Any]:
    count = len(items)
    regional_count = len(_collect_available_regions(items))
    type_count = len(_count_items_by_type(items))
    if count == 0 and errors:
        status = "fail"
        score = 28
    elif count == 0:
        status = "warn"
        score = 56
    elif errors:
        status = "warn"
        score = 68
    else:
        status = "pass"
        score = 88

    summary = (
        f"Matched {count} {meta['name']} resource(s) across {regional_count or 0} active OCI region(s)."
        if count
        else f"No indexed {meta['name']} resources were returned by OCI Resource Search for the current signed principal."
    )
    observations = [
        f"Coverage is sourced from OCI Resource Search across {len(context['scanned_regions'])} subscribed region(s).",
        f"The signed principal can currently query {len(context['searchable_types'])} indexed OCI resource type(s).",
    ]
    if count:
        observations.append(f"The selected service matched {type_count or 1} indexed OCI resource type pattern(s).")
    if notes:
        observations.append(notes[0])
    if errors:
        observations.append("Some regional search calls returned errors, so this snapshot may be incomplete.")

    return {
        "status": status,
        "score": score,
        "summary": summary,
        "observations": observations[:6],
    }


def _stringify(value: Any) -> str:
    if not value:
        return ""
    return str(value)
