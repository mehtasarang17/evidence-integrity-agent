"""Teams DLP realtime monitoring backed by Microsoft Graph UTCM snapshots."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict, Iterable, List, Tuple

import requests


GRAPH_BASE = "https://graph.microsoft.com/beta"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
REQUEST_TIMEOUT = 45
MAX_POLL_ATTEMPTS = 18
POLL_DELAY_SECONDS = 4
SNAPSHOT_RESOURCES = [
    "microsoft.securityAndCompliance.dlpCompliancePolicy",
    "microsoft.securityAndCompliance.dlpComplianceRule",
]


def _svc(name: str, description: str, collector: str) -> Dict[str, str]:
    return {"name": name, "description": description, "collector": collector}


TEAMS_REALTIME_SERVICE_CATALOG: Dict[str, Dict[str, str]] = {
    "dlp_policies": _svc("DLP Policies", "All discovered DLP policies from Microsoft Purview", "policies"),
    "dlp_rules": _svc("DLP Rules", "All discovered DLP rules associated with monitored policies", "rules"),
    "teams_scoped_policies": _svc("Teams-scoped Policies", "Policies that explicitly cover Teams chat and channel messages", "teams_policies"),
    "policy_modes": _svc("Policy Modes", "Enabled, test, and disabled policy execution modes", "policy_modes"),
    "policy_priority": _svc("Policy Priority", "Priority ordering and policy precedence", "policy_priority"),
    "location_coverage": _svc("Location Coverage", "Cross-workload coverage including Teams locations", "location_coverage"),
    "policy_exceptions": _svc("Policy Exceptions", "Policies that carry exception or exclusion logic", "policy_exceptions"),
    "third_party_app_locations": _svc("Third-party App Locations", "Policies extended to third-party DLP application locations", "third_party_apps"),
}


def list_teams_realtime_services() -> List[Dict[str, str]]:
    return [
        {"id": service_id, "name": meta["name"], "description": meta["description"]}
        for service_id, meta in TEAMS_REALTIME_SERVICE_CATALOG.items()
    ]


def validate_teams_credentials(
    access_token: str = "",
    tenant_id: str = "",
    client_id: str = "",
    client_secret: str = "",
) -> Dict[str, Any]:
    has_token = bool(access_token)
    has_sp = bool(tenant_id and client_id and client_secret)
    if not has_token and not has_sp:
        return {"configured": False, "healthy": False, "message": "Missing Teams DLP credentials in .env"}

    try:
        token = _get_teams_access_token(
            access_token=access_token,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        payload = _graph_get(
            token,
            "/admin/configurationManagement/configurationSnapshotJobs",
            {"$top": "1"},
        )
        jobs = payload.get("value", []) or []
        return {
            "configured": True,
            "healthy": True,
            "message": "Teams DLP credentials verified",
            "details": {
                "mode": "graph-utcm app-only" if has_sp and not has_token else "graph-utcm bearer",
                "recent_snapshot_jobs": len(jobs),
                "resources": SNAPSHOT_RESOURCES,
            },
        }
    except Exception as exc:
        return {"configured": True, "healthy": False, "message": f"Teams DLP validation failed: {exc}"}


def check_teams_realtime_posture(
    access_token: str = "",
    *,
    tenant_id: str = "",
    client_id: str = "",
    client_secret: str = "",
    selected_service: str | None = None,
) -> Dict[str, Any]:
    token = _get_teams_access_token(
        access_token=access_token,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )
    context = _build_dlp_context(token)
    services: Dict[str, Any] = {}
    counts = {"pass": 0, "warn": 0, "fail": 0, "unknown": 0}

    for service_id, meta in TEAMS_REALTIME_SERVICE_CATALOG.items():
        service_result = check_teams_realtime_service(access_token, service_id, context=context)
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
                "teams_policies": context.get("scope", {}).get("teams_scoped_policy_count", 0),
                "rules": context.get("scope", {}).get("rule_count", 0),
            },
            "metadata": service_result,
        }

    total = max(len(services), 1)
    overall_score = round(sum(item["score"] for item in services.values()) / total)
    selected_key = selected_service if selected_service in services else next(iter(services.keys()), None)
    scope = context.get("scope", {})

    return {
        "provider": "teams",
        "check": "Teams DLP Posture Overview",
        "service_name": "Teams DLP Overview",
        "selected_service": selected_key,
        "timestamp": datetime.utcnow().isoformat(),
        "teams_summary": {
            "score": overall_score,
            "overall_status": "pass" if counts["fail"] == 0 and counts["warn"] == 0 else "warn" if counts["fail"] == 0 else "fail",
            "status_counts": counts,
            "service_count": len(services),
            "policy_count": scope.get("policy_count", 0),
            "rule_count": scope.get("rule_count", 0),
            "teams_scoped_policy_count": scope.get("teams_scoped_policy_count", 0),
        },
        "services": services,
        "screenshots": [],
        "api_findings": {},
        "vision_analysis": {},
        "status": "completed",
    }


def check_teams_realtime_service(
    service: str,
    *,
    access_token: str = "",
    tenant_id: str = "",
    client_id: str = "",
    client_secret: str = "",
    context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    meta = TEAMS_REALTIME_SERVICE_CATALOG.get(service)
    if not meta:
        return {
            "provider": "teams",
            "service": service,
            "service_name": service,
            "status": "error",
            "error": f"Unknown Teams DLP integration: {service}",
            "screenshots": [],
            "api_findings": {},
            "vision_analysis": {},
        }

    try:
        token = _get_teams_access_token(
            access_token=access_token,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        context = context or _build_dlp_context(token)
        collector = getattr(_TeamsDlpCollector(context), f"collect_{meta['collector']}")
        items, notes = collector()
        inventory = {
            "resource_count": len(items),
            "sample": _sample_items(items),
            "items_preview": items[:50],
            "type_counts": _count_by_key(items, "_kind"),
            "mode_counts": _count_by_key(items, "Mode"),
            "teams_location_counts": _count_nested_lengths(items, "TeamsLocation"),
            "workload_counts": context.get("scope", {}).get("workload_counts", {}),
        }
        health = _build_service_health(service, meta["name"], items, context)
        api_findings = {
            "integration": {
                "service_id": service,
                "service_name": meta["name"],
                "description": meta["description"],
                "checked_at": datetime.utcnow().isoformat(),
                "mode": "graph-utcm snapshot monitor",
                "snapshot_job_id": context.get("snapshot_job", {}).get("id"),
                "snapshot_status": context.get("snapshot_job", {}).get("status"),
                "snapshot_created_at": context.get("snapshot_job", {}).get("createdDateTime"),
                "snapshot_completed_at": context.get("snapshot_job", {}).get("completedDateTime"),
                "resource_location": context.get("snapshot_job", {}).get("resourceLocation"),
                "resources": SNAPSHOT_RESOURCES,
            },
            "scope": context.get("scope", {}),
            "inventory": inventory,
            "health": health,
        }
        access_section = {
            "notes": (context.get("notes", []) + notes)[:12],
            "errors": context.get("errors", [])[:12],
        }
        if access_section["notes"] or access_section["errors"]:
            api_findings["access"] = access_section

        return {
            "provider": "teams",
            "service": service,
            "service_name": meta["name"],
            "service_description": meta["description"],
            "check": "Realtime Teams DLP Monitor",
            "check_description": f"Microsoft Purview DLP snapshot summary for {meta['name']}",
            "timestamp": datetime.utcnow().isoformat(),
            "status": "completed" if not access_section["errors"] else "warn",
            "screenshots": [],
            "api_findings": api_findings,
            "vision_analysis": {},
        }
    except Exception as exc:
        return {
            "provider": "teams",
            "service": service,
            "service_name": meta["name"],
            "service_description": meta["description"],
            "check": "Realtime Teams DLP Monitor",
            "check_description": f"Microsoft Purview DLP snapshot summary for {meta['name']}",
            "timestamp": datetime.utcnow().isoformat(),
            "status": "error",
            "error": str(exc),
            "screenshots": [],
            "api_findings": {},
            "vision_analysis": {},
        }


class _TeamsDlpCollector:
    def __init__(self, context: Dict[str, Any]):
        self.context = context

    def collect_policies(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        return list(self.context.get("policies", [])), [
            "Policies are sourced from Graph UTCM snapshots of Microsoft Purview DLP configuration."
        ]

    def collect_rules(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        return list(self.context.get("rules", [])), [
            "Rules are sourced from Graph UTCM snapshots and normalized for monitoring review."
        ]

    def collect_teams_policies(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        return list(self.context.get("teams_scoped_policies", [])), [
            "Teams-scoped policies are policies that explicitly include Teams chat and channel message coverage."
        ]

    def collect_policy_modes(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        return list(self.context.get("policy_modes", [])), [
            "Policy modes separate enabled, test, and disabled policies for faster triage."
        ]

    def collect_policy_priority(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        return list(self.context.get("policy_priority", [])), [
            "Priority ordering is derived from each policy's configured precedence field when present."
        ]

    def collect_location_coverage(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        return list(self.context.get("location_coverage", [])), [
            "Coverage rows summarize which workloads each DLP policy currently governs."
        ]

    def collect_policy_exceptions(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        return list(self.context.get("policy_exceptions", [])), [
            "Exception rows highlight explicit exclusions that can weaken otherwise broad DLP coverage."
        ]

    def collect_third_party_apps(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        return list(self.context.get("third_party_app_locations", [])), [
            "Third-party app locations show where Purview DLP policy scope extends beyond first-party Microsoft workloads."
        ]


def _build_dlp_context(access_token: str) -> Dict[str, Any]:
    snapshot_job = _create_snapshot_job(access_token)
    resolved_job = _poll_snapshot_job(access_token, snapshot_job.get("id"))
    resource_location = resolved_job.get("resourceLocation") or snapshot_job.get("resourceLocation")
    if not resource_location:
        raise RuntimeError("Teams DLP snapshot completed without a resource location.")

    raw_snapshot = _graph_get(access_token, resource_location)
    policies, rules = _normalize_snapshot_payload(raw_snapshot)
    policy_modes = _build_policy_mode_rows(policies)
    policy_priority = sorted(policy_modes, key=lambda item: item.get("PriorityOrder"))
    location_coverage = _build_location_coverage_rows(policies)
    policy_exceptions = [item for item in policies if item.get("ExceptionSummary")]
    third_party_app_locations = [item for item in policies if item.get("ThirdPartyAppDlpLocation")]
    teams_scoped_policies = [item for item in policies if item.get("HasTeamsCoverage")]
    workload_counts = _build_workload_counts(policies)

    notes = [
        "This Teams provider is monitoring Microsoft Purview DLP configuration, not chats or channel inventory.",
        "Configuration data is collected through Graph UTCM snapshot jobs for DLP policy and rule resources.",
    ]
    if not teams_scoped_policies:
        notes.append("No Teams-scoped DLP policies were discovered in the current snapshot.")

    scope = {
        "policy_count": len(policies),
        "rule_count": len(rules),
        "teams_scoped_policy_count": len(teams_scoped_policies),
        "enabled_policy_count": len([item for item in policies if _normalize_mode(item.get("Mode")) == "enabled"]),
        "test_policy_count": len([item for item in policies if _normalize_mode(item.get("Mode")) == "test"]),
        "disabled_policy_count": len([item for item in policies if _normalize_mode(item.get("Mode")) == "disabled"]),
        "third_party_app_policy_count": len(third_party_app_locations),
        "sampled_policy_names": [item.get("Name") for item in policies[:8] if item.get("Name")],
        "snapshot_job_id": resolved_job.get("id"),
        "snapshot_status": resolved_job.get("status"),
        "snapshot_created_at": resolved_job.get("createdDateTime"),
        "snapshot_completed_at": resolved_job.get("completedDateTime"),
        "workload_counts": workload_counts,
    }

    return {
        "snapshot_job": resolved_job,
        "raw_snapshot": raw_snapshot,
        "policies": policies,
        "rules": rules,
        "teams_scoped_policies": teams_scoped_policies,
        "policy_modes": policy_modes,
        "policy_priority": policy_priority,
        "location_coverage": location_coverage,
        "policy_exceptions": policy_exceptions,
        "third_party_app_locations": third_party_app_locations,
        "scope": scope,
        "notes": notes,
        "errors": [],
    }


def _create_snapshot_job(access_token: str) -> Dict[str, Any]:
    payload = {"resources": SNAPSHOT_RESOURCES}
    return _graph_post(
        access_token,
        "/admin/configurationManagement/configurationSnapshots/createSnapshot",
        payload,
    )


def _get_teams_access_token(
    *,
    access_token: str = "",
    tenant_id: str = "",
    client_id: str = "",
    client_secret: str = "",
) -> str:
    if access_token:
        return access_token
    if not (tenant_id and client_id and client_secret):
        raise RuntimeError("Teams DLP requires either access_token or tenant_id/client_id/client_secret.")

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    response = requests.post(
        token_url,
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": GRAPH_SCOPE,
            "grant_type": "client_credentials",
        },
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    token = response.json().get("access_token", "")
    if not token:
        raise RuntimeError("Teams DLP token response did not include an access_token.")
    return token


def _poll_snapshot_job(access_token: str, job_id: str | None) -> Dict[str, Any]:
    if not job_id:
        raise RuntimeError("Teams DLP snapshot job id was not returned by Microsoft Graph.")

    last_payload = {}
    for _ in range(MAX_POLL_ATTEMPTS):
        payload = _graph_get(access_token, f"/admin/configurationManagement/configurationSnapshotJobs/{job_id}")
        last_payload = payload
        status = str(payload.get("status") or "").lower()
        if status in {"completed", "succeeded"}:
            return payload
        if status in {"failed", "error", "cancelled"}:
            raise RuntimeError(f"Teams DLP snapshot job failed with status {payload.get('status')}.")
        time.sleep(POLL_DELAY_SECONDS)

    raise RuntimeError(
        f"Teams DLP snapshot job did not complete in time. Last known status: {last_payload.get('status') or 'unknown'}"
    )


def _normalize_snapshot_payload(payload: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    policies: List[Dict[str, Any]] = []
    rules: List[Dict[str, Any]] = []
    for candidate in _walk_objects(payload):
        classification = _classify_dlp_candidate(candidate)
        if classification == "policy":
            normalized = _normalize_policy(candidate)
            if normalized:
                policies.append(normalized)
        elif classification == "rule":
            normalized = _normalize_rule(candidate)
            if normalized:
                rules.append(normalized)

    return _dedupe_named_items(policies), _dedupe_named_items(rules)


def _walk_objects(value: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_objects(child)


def _classify_dlp_candidate(item: Dict[str, Any]) -> str | None:
    type_markers = " ".join(
        str(item.get(key, ""))
        for key in ("resourceType", "@odata.type", "type", "configurationType", "schema")
    ).lower()
    if "dlpcompliancerule" in type_markers:
        return "rule"
    if "dlpcompliancepolicy" in type_markers:
        return "policy"

    keys = {str(key).lower() for key in item.keys()}
    policy_keys = {
        "teamslocation", "sharepointlocation", "onedrivelocation", "exchangelocation",
        "powerbidlplocation", "endpointdlplocation", "thirdpartyappdlplocation",
        "mode", "priority",
    }
    rule_keys = {
        "blockaccess", "notifyuser", "generatealert", "incidentreportcontent",
        "ruleserroraction", "accessscope", "policy", "policyid",
    }
    if keys & policy_keys:
        return "policy"
    if keys & rule_keys:
        return "rule"
    return None


def _normalize_policy(item: Dict[str, Any]) -> Dict[str, Any] | None:
    name = _pick_string(item, ["Name", "name", "DisplayName", "displayName", "PolicyName", "policyName"])
    if not name:
        return None

    teams_locations = _coerce_list(_pick_value(item, ["TeamsLocation", "teamsLocation"]))
    third_party_locations = _coerce_list(_pick_value(item, ["ThirdPartyAppDlpLocation", "thirdPartyAppDlpLocation"]))
    policy = {
        "Name": name,
        "Mode": _pick_string(item, ["Mode", "mode", "State", "state"]) or "Unknown",
        "Priority": _pick_value(item, ["Priority", "priority", "Rank", "rank"]),
        "Comment": _pick_string(item, ["Comment", "comment", "Description", "description"]),
        "TeamsLocation": teams_locations,
        "ExchangeLocation": _coerce_list(_pick_value(item, ["ExchangeLocation", "exchangeLocation"])),
        "SharePointLocation": _coerce_list(_pick_value(item, ["SharePointLocation", "sharePointLocation"])),
        "OneDriveLocation": _coerce_list(_pick_value(item, ["OneDriveLocation", "oneDriveLocation"])),
        "EndpointDlpLocation": _coerce_list(_pick_value(item, ["EndpointDlpLocation", "endpointDlpLocation"])),
        "PowerBIDlpLocation": _coerce_list(_pick_value(item, ["PowerBIDlpLocation", "powerBiDlpLocation"])),
        "ThirdPartyAppDlpLocation": third_party_locations,
        "ExceptionSummary": _extract_exception_summary(item),
        "ActionSummary": _extract_action_summary(item),
        "HasTeamsCoverage": bool([entry for entry in teams_locations if str(entry).strip() and str(entry).lower() not in {"none", "notconfigured"}]),
        "display_name": name,
        "_kind": "dlp_policy",
    }
    return policy


def _normalize_rule(item: Dict[str, Any]) -> Dict[str, Any] | None:
    name = _pick_string(item, ["Name", "name", "DisplayName", "displayName", "RuleName", "ruleName"])
    if not name:
        return None

    rule = {
        "Name": name,
        "Policy": _pick_string(item, ["Policy", "policy", "PolicyName", "policyName"]),
        "Severity": _pick_string(item, ["Severity", "severity", "AlertSeverity", "alertSeverity"]),
        "AccessScope": _pick_string(item, ["AccessScope", "accessScope"]),
        "RuleErrorAction": _pick_string(item, ["RuleErrorAction", "ruleErrorAction", "RulesErrorAction", "rulesErrorAction"]),
        "GenerateAlert": _pick_value(item, ["GenerateAlert", "generateAlert"]),
        "NotifyUser": _pick_value(item, ["NotifyUser", "notifyUser"]),
        "BlockAccess": _pick_value(item, ["BlockAccess", "blockAccess"]),
        "IncidentReportContent": _pick_value(item, ["IncidentReportContent", "incidentReportContent"]),
        "ExceptionSummary": _extract_exception_summary(item),
        "ActionSummary": _extract_action_summary(item),
        "display_name": name,
        "_kind": "dlp_rule",
    }
    return rule


def _build_policy_mode_rows(policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for policy in policies:
        rows.append({
            "Name": policy.get("Name"),
            "Mode": _normalize_mode(policy.get("Mode")),
            "PriorityOrder": _as_int(policy.get("Priority")),
            "HasTeamsCoverage": policy.get("HasTeamsCoverage"),
            "display_name": policy.get("Name"),
            "_kind": "policy_mode",
        })
    return rows


def _build_location_coverage_rows(policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for policy in policies:
        workloads = []
        for label, key in (
            ("Teams", "TeamsLocation"),
            ("Exchange", "ExchangeLocation"),
            ("SharePoint", "SharePointLocation"),
            ("OneDrive", "OneDriveLocation"),
            ("Endpoint", "EndpointDlpLocation"),
            ("Power BI", "PowerBIDlpLocation"),
            ("Third-party apps", "ThirdPartyAppDlpLocation"),
        ):
            if policy.get(key):
                workloads.append(label)
        rows.append({
            "Name": policy.get("Name"),
            "Mode": _normalize_mode(policy.get("Mode")),
            "Workloads": workloads,
            "WorkloadCount": len(workloads),
            "TeamsLocation": policy.get("TeamsLocation", []),
            "ThirdPartyAppDlpLocation": policy.get("ThirdPartyAppDlpLocation", []),
            "display_name": policy.get("Name"),
            "_kind": "location_coverage",
        })
    return rows


def _build_workload_counts(policies: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {
        "Teams": 0,
        "Exchange": 0,
        "SharePoint": 0,
        "OneDrive": 0,
        "Endpoint": 0,
        "Power BI": 0,
        "Third-party apps": 0,
    }
    for policy in policies:
        if policy.get("TeamsLocation"):
            counts["Teams"] += 1
        if policy.get("ExchangeLocation"):
            counts["Exchange"] += 1
        if policy.get("SharePointLocation"):
            counts["SharePoint"] += 1
        if policy.get("OneDriveLocation"):
            counts["OneDrive"] += 1
        if policy.get("EndpointDlpLocation"):
            counts["Endpoint"] += 1
        if policy.get("PowerBIDlpLocation"):
            counts["Power BI"] += 1
        if policy.get("ThirdPartyAppDlpLocation"):
            counts["Third-party apps"] += 1
    return counts


def _build_service_health(service_key: str, service_name: str, items: List[Dict[str, Any]], context: Dict[str, Any]) -> Dict[str, Any]:
    scope = context.get("scope", {})
    teams_policies = scope.get("teams_scoped_policy_count", 0)
    disabled = scope.get("disabled_policy_count", 0)
    tests = scope.get("test_policy_count", 0)

    status = "pass"
    score = 88
    observations = [
        f"Teams DLP monitoring is active for {service_name}.",
        f"Observed {len(items)} normalized configuration item(s) in the latest Purview snapshot.",
    ]

    if service_key == "dlp_policies" and not items:
        status, score = "warn", 48
        observations.append("No DLP policies were discovered in the current Teams DLP snapshot.")
    elif service_key == "dlp_rules" and not items:
        status, score = "warn", 48
        observations.append("No DLP rules were discovered in the current Teams DLP snapshot.")
    elif service_key == "teams_scoped_policies" and teams_policies == 0:
        status, score = "warn", 42
        observations.append("No policies explicitly scoped to Teams chat and channel messages were found.")
    elif service_key == "policy_modes" and (disabled > 0 or tests > 0):
        status, score = "warn", 70
        observations.append(f"Detected {disabled} disabled and {tests} test-mode policies that may limit active enforcement.")
    elif service_key == "location_coverage" and teams_policies == 0:
        status, score = "warn", 50
        observations.append("Teams is not represented in the current workload coverage set.")

    summary = (
        f"Teams DLP snapshot review completed for {service_name} with {len(items)} item(s) discovered."
        if status == "pass"
        else f"Teams DLP snapshot review found configuration gaps or partial coverage for {service_name}."
    )
    return {"status": status, "score": score, "summary": summary, "observations": observations}


def _graph_get(access_token: str, path_or_url: str, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
    url = path_or_url if path_or_url.startswith("http") else f"{GRAPH_BASE}{path_or_url}"
    response = requests.get(
        url,
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        params=params or {},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def _graph_post(access_token: str, path_or_url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    url = path_or_url if path_or_url.startswith("http") else f"{GRAPH_BASE}{path_or_url}"
    response = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def _pick_value(item: Dict[str, Any], keys: List[str]) -> Any:
    for key in keys:
        if key in item and item[key] not in (None, "", []):
            return item[key]
    return None


def _pick_string(item: Dict[str, Any], keys: List[str]) -> str:
    value = _pick_value(item, keys)
    if isinstance(value, str):
        return value.strip()
    if value is None:
        return ""
    return str(value).strip()


def _coerce_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        flattened: List[str] = []
        for item in value:
            flattened.extend(_coerce_list(item))
        return [entry for entry in flattened if entry]
    if isinstance(value, dict):
        return [f"{key}:{item}" for key, item in value.items() if item not in (None, "", [], {})]
    return [str(value).strip()] if str(value).strip() else []


def _extract_exception_summary(item: Dict[str, Any]) -> List[str]:
    summary = []
    for key, value in item.items():
        key_lower = str(key).lower()
        if "except" not in key_lower and "exclude" not in key_lower:
            continue
        values = _coerce_list(value)
        if values:
            summary.append(f"{key}: {', '.join(values[:4])}")
    return summary[:8]


def _extract_action_summary(item: Dict[str, Any]) -> List[str]:
    action_keys = [
        "BlockAccess", "NotifyUser", "GenerateAlert", "IncidentReportContent",
        "AccessScope", "RuleErrorAction", "NotifyAllowOverride",
    ]
    summary = []
    for key in action_keys:
        if key in item and item[key] not in (None, "", [], {}):
            summary.append(f"{key}: {item[key]}")
        lower_key = key[:1].lower() + key[1:]
        if lower_key in item and item[lower_key] not in (None, "", [], {}):
            summary.append(f"{key}: {item[lower_key]}")
    return summary[:8]


def _dedupe_named_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    deduped = []
    for item in items:
        name = str(item.get("Name") or item.get("display_name") or "").strip()
        kind = item.get("_kind")
        key = (kind, name)
        if not name or key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _normalize_mode(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"enable", "enabled", "enforce"}:
        return "enabled"
    if text in {"disable", "disabled"}:
        return "disabled"
    if text.startswith("test"):
        return "test"
    return text or "unknown"


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 999999


def _sample_items(items: List[Any]) -> List[Any]:
    sample = []
    for item in items[:6]:
        if isinstance(item, dict):
            compact = {}
            for key in (
                "display_name", "Name", "Mode", "Priority", "Policy", "Severity",
                "TeamsLocation", "Workloads", "ThirdPartyAppDlpLocation", "ActionSummary"
            ):
                if key in item and item[key] not in (None, "", [], {}):
                    compact[key] = item[key]
            sample.append(compact)
        else:
            sample.append(item)
    return sample


def _count_by_key(items: List[Any], key: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get(key)
        if value in (None, "", [], {}):
            continue
        counts[str(value)] = counts.get(str(value), 0) + 1
    return counts


def _count_nested_lengths(items: List[Any], key: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        values = item.get(key)
        if not isinstance(values, list):
            continue
        for entry in values:
            label = str(entry).strip()
            if not label:
                continue
            counts[label] = counts.get(label, 0) + 1
    return counts
