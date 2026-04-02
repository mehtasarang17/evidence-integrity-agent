"""API-only GitLab realtime monitoring with cached provider posture."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Tuple
from urllib.parse import urlsplit

import requests


def _svc(name: str, description: str, collector: str) -> Dict[str, str]:
    return {"name": name, "description": description, "collector": collector}


GITLAB_REALTIME_SERVICE_CATALOG: Dict[str, Dict[str, str]] = {
    "projects": _svc("Projects", "Accessible project inventory and visibility", "projects"),
    "groups": _svc("Groups", "Accessible groups and ownership boundaries", "groups"),
    "members": _svc("Members", "Project and group membership posture", "members"),
    "merge_requests": _svc("Merge Requests", "Open merge request backlog and ownership", "merge_requests"),
    "issues": _svc("Issues", "Open issue backlog and severity indicators", "issues"),
    "pipelines": _svc("Pipelines", "Recent pipeline execution posture", "pipelines"),
    "jobs": _svc("Jobs", "Recent CI job activity across sampled projects", "jobs"),
    "deployments": _svc("Deployments", "Deployment history across sampled projects", "deployments"),
    "environments": _svc("Environments", "Runtime environments and exposure state", "environments"),
    "branches": _svc("Branches", "Repository branch inventory across sampled projects", "branches"),
    "protected_branches": _svc("Protected Branches", "Protected branch controls and coverage", "protected_branches"),
    "tags": _svc("Tags", "Repository tag inventory across sampled projects", "tags"),
    "releases": _svc("Releases", "Release cadence and shipped versions", "releases"),
    "packages": _svc("Packages", "Package registry inventory", "packages"),
    "container_registry": _svc("Container Registry", "Container registry repositories and tags", "container_registry"),
    "webhooks": _svc("Webhooks", "Project webhook coverage and delivery targets", "webhooks"),
    "variables": _svc("CI/CD Variables", "Project variable inventory and masking posture", "variables"),
    "runners": _svc("Runners", "Available GitLab runners and status", "runners"),
    "snippets": _svc("Snippets", "Personal snippets and sharing posture", "snippets"),
    "milestones": _svc("Milestones", "Project milestone inventory and due dates", "milestones"),
}

MAX_PROJECT_SAMPLE = 6
MAX_GROUP_SAMPLE = 4
MAX_PREVIEW_ITEMS = 12


def list_gitlab_realtime_services() -> List[Dict[str, str]]:
    return [
        {"id": service_id, "name": meta["name"], "description": meta["description"]}
        for service_id, meta in GITLAB_REALTIME_SERVICE_CATALOG.items()
    ]


def validate_gitlab_credentials(api_token: str, base_url: str = "https://gitlab.com") -> Dict[str, Any]:
    if not api_token:
        return {"configured": False, "healthy": False, "message": "Missing GitLab token in .env"}

    try:
        resolved_base_url = _resolve_base_url(api_token, base_url)
        user = _request_json(resolved_base_url, "/api/v4/user", _headers(api_token))
        return {
            "configured": True,
            "healthy": True,
            "message": "GitLab token verified",
            "details": {
                "username": user.get("username"),
                "name": user.get("name"),
                "base_url": resolved_base_url,
                "mode": "api-only",
            },
        }
    except Exception as exc:
        return {"configured": True, "healthy": False, "message": f"GitLab validation failed: {exc}"}


def check_gitlab_realtime_posture(api_token: str, base_url: str = "https://gitlab.com", selected_service: str | None = None) -> Dict[str, Any]:
    resolved_base_url = _resolve_base_url(api_token, base_url)
    context = _build_context(api_token, resolved_base_url)
    services: Dict[str, Any] = {}
    counts = {"pass": 0, "warn": 0, "fail": 0, "unknown": 0}

    for service_id, meta in GITLAB_REALTIME_SERVICE_CATALOG.items():
        service_result = check_gitlab_realtime_service(api_token, resolved_base_url, service_id, context=context)
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
                "projects": len(context.get("projects", [])),
                "groups": len(context.get("groups", [])),
            },
            "metadata": service_result,
        }

    total = max(len(services), 1)
    overall_score = round(sum(item["score"] for item in services.values()) / total)
    selected_key = selected_service if selected_service in services else next(iter(services.keys()), None)

    return {
        "provider": "gitlab",
        "check": "GitLab Realtime Posture Overview",
        "service_name": "Realtime Posture Overview",
        "selected_service": selected_key,
        "timestamp": datetime.utcnow().isoformat(),
        "gitlab_summary": {
            "score": overall_score,
            "overall_status": "pass" if counts["fail"] == 0 and counts["warn"] == 0 else "warn" if counts["fail"] == 0 else "fail",
            "status_counts": counts,
            "service_count": len(services),
            "projects": len(context.get("projects", [])),
            "groups": len(context.get("groups", [])),
        },
        "services": services,
        "screenshots": [],
        "api_findings": {},
        "vision_analysis": {},
        "status": "completed",
    }


def check_gitlab_realtime_service(
    api_token: str,
    base_url: str,
    service: str,
    *,
    context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    meta = GITLAB_REALTIME_SERVICE_CATALOG.get(service)
    if not meta:
        return {
            "provider": "gitlab",
            "service": service,
            "service_name": service,
            "status": "error",
            "error": f"Unknown GitLab service integration: {service}",
            "screenshots": [],
            "api_findings": {},
            "vision_analysis": {},
        }

    context = context or _build_context(api_token, base_url)
    headers = _headers(api_token)
    collector = getattr(_GitLabCollector(base_url, headers, context), f"collect_{meta['collector']}")

    try:
        items, notes, errors = collector()
    except Exception as exc:
        items, notes, errors = [], [], [str(exc)]

    api_findings = {
        "integration": {
            "service_id": service,
            "service_name": meta["name"],
            "description": meta["description"],
            "base_url": base_url,
            "checked_at": datetime.utcnow().isoformat(),
            "mode": "api-only realtime monitor",
            "user": {
                "username": context.get("user", {}).get("username"),
                "name": context.get("user", {}).get("name"),
            },
        },
        "scope": {
            "project_count": len(context.get("projects", [])),
            "group_count": len(context.get("groups", [])),
            "sampled_projects": [project.get("path_with_namespace") or project.get("name") for project in context.get("sample_projects", [])],
            "sampled_groups": [group.get("full_path") or group.get("name") for group in context.get("sample_groups", [])],
        },
        "inventory": {
            "resource_count": len(items),
            "sample": _sample_items(items),
            "items_preview": _items_preview(items),
        },
        "health": _build_health(meta, items, notes, errors),
    }
    if notes or errors:
        api_findings["access"] = {"notes": notes[:12], "errors": errors[:12]}

    return {
        "provider": "gitlab",
        "service": service,
        "service_name": meta["name"],
        "service_description": meta["description"],
        "check": "Realtime GitLab Integration Monitor",
        "check_description": f"Live GitLab API inventory and posture summary for {meta['name']}",
        "timestamp": datetime.utcnow().isoformat(),
        "status": "completed" if not errors else "warn",
        "screenshots": [],
        "api_findings": api_findings,
        "vision_analysis": {},
    }


class _GitLabCollector:
    def __init__(self, base_url: str, headers: Dict[str, str], context: Dict[str, Any]):
        self.base_url = base_url
        self.headers = headers
        self.context = context

    def collect_projects(self) -> Tuple[List[Any], List[str], List[str]]:
        return self.context.get("projects", []), ["Project inventory reflects membership-visible projects returned by the GitLab API."], []

    def collect_groups(self) -> Tuple[List[Any], List[str], List[str]]:
        return self.context.get("groups", []), ["Group inventory reflects groups accessible to the provided token."], []

    def collect_members(self) -> Tuple[List[Any], List[str], List[str]]:
        items: List[Any] = []
        notes = []
        errors = []
        for group in self.context.get("sample_groups", []):
            try:
                members = _paginate(self.base_url, f"/api/v4/groups/{group['id']}/members/all", self.headers)
                for member in members:
                    items.append({
                        "source_type": "group",
                        "source_name": group.get("full_path") or group.get("name"),
                        **member,
                    })
            except Exception as exc:
                errors.append(f"Group members for {group.get('full_path') or group.get('name')}: {exc}")
        for project in self.context.get("sample_projects", []):
            try:
                members = _paginate(self.base_url, f"/api/v4/projects/{project['id']}/members/all", self.headers)
                for member in members:
                    items.append({
                        "source_type": "project",
                        "source_name": project.get("path_with_namespace") or project.get("name"),
                        **member,
                    })
            except Exception as exc:
                errors.append(f"Project members for {project.get('path_with_namespace') or project.get('name')}: {exc}")
        notes.append("Membership checks are sampled from the first accessible groups and projects to keep analysis responsive.")
        return items, notes, errors

    def collect_merge_requests(self) -> Tuple[List[Any], List[str], List[str]]:
        items = _paginate(self.base_url, "/api/v4/merge_requests", self.headers, params={"scope": "all", "state": "opened"})
        return items, ["Open merge requests are fetched tenant-wide through the authenticated user scope."], []

    def collect_issues(self) -> Tuple[List[Any], List[str], List[str]]:
        items = _paginate(self.base_url, "/api/v4/issues", self.headers, params={"scope": "all", "state": "opened"})
        return items, ["Open issues are fetched tenant-wide through the authenticated user scope."], []

    def collect_pipelines(self) -> Tuple[List[Any], List[str], List[str]]:
        return self._collect_from_projects("pipelines", lambda project: _paginate(self.base_url, f"/api/v4/projects/{project['id']}/pipelines", self.headers, params={"per_page": 20}))

    def collect_jobs(self) -> Tuple[List[Any], List[str], List[str]]:
        return self._collect_from_projects("jobs", lambda project: _paginate(self.base_url, f"/api/v4/projects/{project['id']}/jobs", self.headers, params={"per_page": 20}))

    def collect_deployments(self) -> Tuple[List[Any], List[str], List[str]]:
        return self._collect_from_projects("deployments", lambda project: _paginate(self.base_url, f"/api/v4/projects/{project['id']}/deployments", self.headers, params={"per_page": 20}))

    def collect_environments(self) -> Tuple[List[Any], List[str], List[str]]:
        return self._collect_from_projects("environments", lambda project: _paginate(self.base_url, f"/api/v4/projects/{project['id']}/environments", self.headers, params={"per_page": 20}))

    def collect_branches(self) -> Tuple[List[Any], List[str], List[str]]:
        return self._collect_from_projects("branches", lambda project: _paginate(self.base_url, f"/api/v4/projects/{project['id']}/repository/branches", self.headers))

    def collect_protected_branches(self) -> Tuple[List[Any], List[str], List[str]]:
        return self._collect_from_projects("protected branches", lambda project: _paginate(self.base_url, f"/api/v4/projects/{project['id']}/protected_branches", self.headers))

    def collect_tags(self) -> Tuple[List[Any], List[str], List[str]]:
        return self._collect_from_projects("tags", lambda project: _paginate(self.base_url, f"/api/v4/projects/{project['id']}/repository/tags", self.headers))

    def collect_releases(self) -> Tuple[List[Any], List[str], List[str]]:
        return self._collect_from_projects("releases", lambda project: _paginate(self.base_url, f"/api/v4/projects/{project['id']}/releases", self.headers))

    def collect_packages(self) -> Tuple[List[Any], List[str], List[str]]:
        return self._collect_from_projects("packages", lambda project: _paginate(self.base_url, f"/api/v4/projects/{project['id']}/packages", self.headers))

    def collect_container_registry(self) -> Tuple[List[Any], List[str], List[str]]:
        return self._collect_from_projects("container registries", lambda project: _paginate(self.base_url, f"/api/v4/projects/{project['id']}/registry/repositories", self.headers))

    def collect_webhooks(self) -> Tuple[List[Any], List[str], List[str]]:
        return self._collect_from_projects("webhooks", lambda project: _paginate(self.base_url, f"/api/v4/projects/{project['id']}/hooks", self.headers))

    def collect_variables(self) -> Tuple[List[Any], List[str], List[str]]:
        return self._collect_from_projects("variables", lambda project: _paginate(self.base_url, f"/api/v4/projects/{project['id']}/variables", self.headers))

    def collect_runners(self) -> Tuple[List[Any], List[str], List[str]]:
        notes: List[str] = []
        try:
            items = _paginate(self.base_url, "/api/v4/runners/all", self.headers)
            notes.append("Runner inventory includes all runners visible to the token.")
            return items, notes, []
        except Exception as exc:
            notes.append("The provided token could not access the global runners endpoint, which usually requires elevated permissions.")
            return [], notes, [str(exc)]

    def collect_snippets(self) -> Tuple[List[Any], List[str], List[str]]:
        items = _paginate(self.base_url, "/api/v4/snippets", self.headers)
        return items, ["Snippet inventory reflects snippets directly visible to the authenticated user."], []

    def collect_milestones(self) -> Tuple[List[Any], List[str], List[str]]:
        return self._collect_from_projects("milestones", lambda project: _paginate(self.base_url, f"/api/v4/projects/{project['id']}/milestones", self.headers))

    def _collect_from_projects(self, label: str, fetcher) -> Tuple[List[Any], List[str], List[str]]:
        items: List[Any] = []
        errors: List[str] = []
        notes = [f"{label.capitalize()} are sampled from up to {len(self.context.get('sample_projects', []))} accessible projects for realtime monitoring."]

        for project in self.context.get("sample_projects", []):
            try:
                project_items = fetcher(project)
                for item in project_items:
                    if isinstance(item, dict):
                        items.append({
                            "project_id": project.get("id"),
                            "project_name": project.get("path_with_namespace") or project.get("name"),
                            **item,
                        })
                    else:
                        items.append({
                            "project_id": project.get("id"),
                            "project_name": project.get("path_with_namespace") or project.get("name"),
                            "value": item,
                        })
            except Exception as exc:
                errors.append(f"{project.get('path_with_namespace') or project.get('name')}: {exc}")

        return items, notes, errors


def _build_context(api_token: str, base_url: str) -> Dict[str, Any]:
    headers = _headers(api_token)
    user = _request_json(base_url, "/api/v4/user", headers)
    projects = _paginate(base_url, "/api/v4/projects", headers, params={"membership": "true", "simple": "true", "order_by": "last_activity_at", "sort": "desc"})
    groups = _paginate(base_url, "/api/v4/groups", headers, params={"min_access_level": 10, "order_by": "name", "sort": "asc"})
    return {
        "user": user,
        "projects": projects,
        "groups": groups,
        "sample_projects": projects[:MAX_PROJECT_SAMPLE],
        "sample_groups": groups[:MAX_GROUP_SAMPLE],
    }


def _headers(api_token: str) -> Dict[str, str]:
    return {"PRIVATE-TOKEN": api_token, "Content-Type": "application/json"}


def _request_json(base_url: str, path: str, headers: Dict[str, str], *, params: Dict[str, Any] | None = None, timeout: int = 20) -> Any:
    response = requests.get(f"{base_url.rstrip('/')}{path}", headers=headers, params=params, timeout=timeout)
    response.raise_for_status()
    return response.json()


def _resolve_base_url(api_token: str, base_url: str) -> str:
    headers = _headers(api_token)
    errors: List[str] = []

    for candidate in _candidate_base_urls(base_url):
        try:
            response = requests.get(f"{candidate}/api/v4/user", headers=headers, timeout=20)
            response.raise_for_status()
            response.json()
            return candidate
        except Exception as exc:
            errors.append(f"{candidate}: {exc}")

    raise RuntimeError("GitLab base URL validation failed. Use the GitLab instance root URL, for example https://gitlab.com")


def _candidate_base_urls(base_url: str) -> List[str]:
    raw = (base_url or "https://gitlab.com").strip().rstrip("/")
    if not raw:
        raw = "https://gitlab.com"

    candidates: List[str] = [raw]
    parts = urlsplit(raw)
    origin = f"{parts.scheme or 'https'}://{parts.netloc}" if parts.netloc else raw
    if origin and origin not in candidates:
        candidates.append(origin)
    return candidates


def _paginate(
    base_url: str,
    path: str,
    headers: Dict[str, str],
    *,
    params: Dict[str, Any] | None = None,
    per_page: int = 100,
    max_pages: int = 3,
) -> List[Any]:
    items: List[Any] = []
    page = 1
    params = dict(params or {})
    params.setdefault("per_page", per_page)

    while page <= max_pages:
        page_params = dict(params)
        page_params["page"] = page
        response = requests.get(f"{base_url.rstrip('/')}{path}", headers=headers, params=page_params, timeout=25)
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, list):
            items.extend(payload)
        else:
            break
        next_page = response.headers.get("X-Next-Page")
        if not next_page:
            break
        page = int(next_page)

    return items


def _build_health(meta: Dict[str, str], items: List[Any], notes: List[str], errors: List[str]) -> Dict[str, Any]:
    if errors and not items:
        status = "warn"
        score = 52
    elif errors:
        status = "warn"
        score = 68
    else:
        status = "pass"
        score = 86

    observations = [
        f"GitLab API returned {len(items)} item(s) for {meta['name']}.",
        "The monitor uses token-based API access without interactive login.",
    ]
    observations.extend(notes[:4])
    if errors:
        observations.append(f"{len(errors)} access or visibility issue(s) were encountered during collection.")

    if len(items) == 0 and not errors:
        summary = f"No {meta['name'].lower()} resources were returned by the GitLab API for the authenticated scope."
    elif errors and not items:
        summary = f"{meta['name']} could not be fully inspected with the current token scope."
    else:
        summary = f"{meta['name']} returned {len(items)} resource(s) through the GitLab API."

    return {
        "status": status,
        "score": score,
        "summary": summary,
        "observations": observations[:6],
    }


def _sample_items(items: List[Any]) -> List[Any]:
    return items[:5]


def _items_preview(items: List[Any]) -> List[Dict[str, Any]]:
    return [_preview_item(item) for item in items[:MAX_PREVIEW_ITEMS]]


def _preview_item(item: Any) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {"value": item}

    preferred_keys = [
        "name",
        "path",
        "path_with_namespace",
        "full_path",
        "title",
        "username",
        "state",
        "status",
        "visibility",
        "web_url",
        "environment_scope",
        "ref",
        "created_at",
        "last_activity_at",
        "project_name",
        "source_name",
    ]
    preview = {key: item.get(key) for key in preferred_keys if item.get(key) not in (None, "", [], {})}
    if "id" in item:
        preview["id"] = item.get("id")
    if "iid" in item:
        preview["iid"] = item.get("iid")
    if "protected" in item:
        preview["protected"] = item.get("protected")
    if "masked" in item:
        preview["masked"] = item.get("masked")
    if "raw" in item:
        preview["raw"] = item.get("raw")
    if not preview:
        for key, value in item.items():
            if value not in (None, "", [], {}):
                preview[key] = value
            if len(preview) >= 10:
                break
    return preview
