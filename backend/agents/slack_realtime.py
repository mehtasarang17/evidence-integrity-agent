"""API-only Slack realtime monitoring backed by Slack Web API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Tuple

import requests


SLACK_API_BASE = "https://slack.com/api"
REQUEST_TIMEOUT = 30
MAX_CURSOR_PAGES = 5
MAX_CHANNEL_SAMPLE = 5
MAX_PREVIEW_ITEMS = 12


def _svc(name: str, description: str, collector: str) -> Dict[str, str]:
    return {"name": name, "description": description, "collector": collector}


SLACK_REALTIME_SERVICE_CATALOG: Dict[str, Dict[str, str]] = {
    "workspace_profile": _svc("Workspace Profile", "Workspace identity, domain, and connected operator", "workspace_profile"),
    "public_channels": _svc("Public Channels", "Open channel inventory and sharing posture", "public_channels"),
    "private_channels": _svc("Private Channels", "Private channel inventory and visibility boundaries", "private_channels"),
    "direct_messages": _svc("Direct Messages", "One-to-one direct message surfaces", "direct_messages"),
    "group_direct_messages": _svc("Group DMs", "Multi-party direct message surfaces", "group_direct_messages"),
    "shared_channels": _svc("Shared Channels", "External and org-shared channel exposure", "shared_channels"),
    "users": _svc("Users", "Workspace member inventory and account state", "users"),
    "workspace_admins": _svc("Workspace Admins", "Administrative and owner accounts", "workspace_admins"),
    "guest_users": _svc("Guest Users", "Restricted and ultra-restricted guest accounts", "guest_users"),
    "bot_users": _svc("Bot Users", "Bot and app-backed identities", "bot_users"),
    "user_groups": _svc("User Groups", "User group aliases and mentionable teams", "user_groups"),
    "channel_memberships": _svc("Channel Memberships", "Member counts across sampled channels", "channel_memberships"),
    "pinned_items": _svc("Pinned Items", "Pinned messages and files across sampled channels", "pinned_items"),
}


def list_slack_realtime_services() -> List[Dict[str, str]]:
    return [
        {"id": service_id, "name": meta["name"], "description": meta["description"]}
        for service_id, meta in SLACK_REALTIME_SERVICE_CATALOG.items()
    ]


def validate_slack_credentials(api_token: str) -> Dict[str, Any]:
    if not api_token:
        return {"configured": False, "healthy": False, "message": "Missing Slack token in .env"}

    try:
        auth = _api_call(api_token, "auth.test")
        team = {}
        try:
            team = _api_call(api_token, "team.info").get("team", {}) or {}
        except Exception:
            team = {}
        return {
            "configured": True,
            "healthy": True,
            "message": "Slack token verified",
            "details": {
                "workspace": team.get("name") or auth.get("team"),
                "team_id": auth.get("team_id"),
                "user": auth.get("user"),
                "url": auth.get("url"),
                "mode": "api-only",
            },
        }
    except Exception as exc:
        return {"configured": True, "healthy": False, "message": f"Slack validation failed: {exc}"}


def check_slack_realtime_posture(api_token: str, selected_service: str | None = None) -> Dict[str, Any]:
    context = _build_context(api_token)
    services: Dict[str, Any] = {}
    counts = {"pass": 0, "warn": 0, "fail": 0, "unknown": 0}

    for service_id, meta in SLACK_REALTIME_SERVICE_CATALOG.items():
        service_result = check_slack_realtime_service(api_token, service_id, context=context)
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
                "channels": len(context.get("public_channels", [])) + len(context.get("private_channels", [])),
                "users": len(context.get("users", [])),
            },
            "metadata": service_result,
        }

    total = max(len(services), 1)
    overall_score = round(sum(item["score"] for item in services.values()) / total)
    selected_key = selected_service if selected_service in services else next(iter(services.keys()), None)

    return {
        "provider": "slack",
        "check": "Slack Realtime Posture Overview",
        "service_name": "Realtime Posture Overview",
        "selected_service": selected_key,
        "timestamp": datetime.utcnow().isoformat(),
        "slack_summary": {
            "score": overall_score,
            "overall_status": "pass" if counts["fail"] == 0 and counts["warn"] == 0 else "warn" if counts["fail"] == 0 else "fail",
            "status_counts": counts,
            "service_count": len(services),
            "users": len(context.get("users", [])),
            "channels": len(context.get("public_channels", [])) + len(context.get("private_channels", [])),
            "user_groups": len(context.get("user_groups", [])),
        },
        "services": services,
        "screenshots": [],
        "api_findings": {},
        "vision_analysis": {},
        "status": "completed",
    }


def check_slack_realtime_service(
    api_token: str,
    service: str,
    *,
    context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    meta = SLACK_REALTIME_SERVICE_CATALOG.get(service)
    if not meta:
        return {
            "provider": "slack",
            "service": service,
            "service_name": service,
            "status": "error",
            "error": f"Unknown Slack service integration: {service}",
            "screenshots": [],
            "api_findings": {},
            "vision_analysis": {},
        }

    context = context or _build_context(api_token)
    collector = getattr(_SlackCollector(context), f"collect_{meta['collector']}")
    items, notes, errors = collector()

    inventory = {
        "resource_count": len(items),
        "sample": _sample_items(items),
        "items_preview": items[:MAX_PREVIEW_ITEMS],
        "type_counts": _count_by_key(items, "_kind"),
    }
    api_findings = {
        "integration": {
            "service_id": service,
            "service_name": meta["name"],
            "description": meta["description"],
            "checked_at": datetime.utcnow().isoformat(),
            "mode": "api-only realtime monitor",
            "workspace": context.get("workspace", {}).get("WorkspaceName"),
            "team_id": context.get("workspace", {}).get("TeamId"),
        },
        "scope": {
            "workspace_name": context.get("workspace", {}).get("WorkspaceName"),
            "team_id": context.get("workspace", {}).get("TeamId"),
            "workspace_url": context.get("workspace", {}).get("Url"),
            "operator": context.get("workspace", {}).get("Operator"),
            "channel_count": len(context.get("public_channels", [])) + len(context.get("private_channels", [])),
            "user_count": len(context.get("users", [])),
            "user_group_count": len(context.get("user_groups", [])),
            "sampled_channels": [item.get("ChannelName") for item in context.get("channel_memberships", [])[:6] if item.get("ChannelName")],
        },
        "inventory": inventory,
        "health": _build_health(meta["name"], len(items), notes, errors),
    }
    if notes or errors:
        api_findings["access"] = {"notes": notes[:12], "errors": errors[:12]}

    return {
        "provider": "slack",
        "service": service,
        "service_name": meta["name"],
        "service_description": meta["description"],
        "check": "Realtime Slack Integration Monitor",
        "check_description": f"Live Slack API inventory and posture summary for {meta['name']}",
        "timestamp": datetime.utcnow().isoformat(),
        "status": "completed" if not errors else "warn",
        "screenshots": [],
        "api_findings": api_findings,
        "vision_analysis": {},
    }


class _SlackCollector:
    def __init__(self, context: Dict[str, Any]):
        self.context = context

    def collect_workspace_profile(self) -> Tuple[List[Any], List[str], List[str]]:
        workspace = self.context.get("workspace")
        return ([workspace] if workspace else []), ["Workspace identity is built from Slack auth.test and team.info responses."], []

    def collect_public_channels(self) -> Tuple[List[Any], List[str], List[str]]:
        return self.context.get("public_channels", []), ["Public channel inventory is fetched from conversations.list using the public_channel type."], []

    def collect_private_channels(self) -> Tuple[List[Any], List[str], List[str]]:
        return self.context.get("private_channels", []), ["Private channel inventory is fetched from conversations.list using the private_channel type."], []

    def collect_direct_messages(self) -> Tuple[List[Any], List[str], List[str]]:
        return self.context.get("direct_messages", []), ["Direct message surfaces are sampled from conversations.list using the im type."], []

    def collect_group_direct_messages(self) -> Tuple[List[Any], List[str], List[str]]:
        return self.context.get("group_direct_messages", []), ["Multi-party DMs are sampled from conversations.list using the mpim type."], []

    def collect_shared_channels(self) -> Tuple[List[Any], List[str], List[str]]:
        return self.context.get("shared_channels", []), ["Shared channels are derived from conversation sharing flags returned by the Slack API."], []

    def collect_users(self) -> Tuple[List[Any], List[str], List[str]]:
        return self.context.get("users", []), ["Workspace member inventory is fetched from users.list."], []

    def collect_workspace_admins(self) -> Tuple[List[Any], List[str], List[str]]:
        return self.context.get("workspace_admins", []), ["Admin and owner accounts are derived from Slack user role flags."], []

    def collect_guest_users(self) -> Tuple[List[Any], List[str], List[str]]:
        return self.context.get("guest_users", []), ["Guest users are derived from restricted account flags."], []

    def collect_bot_users(self) -> Tuple[List[Any], List[str], List[str]]:
        return self.context.get("bot_users", []), ["Bot identities are derived from users.list bot flags and app profile metadata."], []

    def collect_user_groups(self) -> Tuple[List[Any], List[str], List[str]]:
        return self.context.get("user_groups", []), ["User groups are fetched from usergroups.list when the token has access."], list(self.context.get("user_group_errors", []))

    def collect_channel_memberships(self) -> Tuple[List[Any], List[str], List[str]]:
        return self.context.get("channel_memberships", []), ["Channel membership counts are sampled from the first visible channels to keep provider-wide scans responsive."], list(self.context.get("membership_errors", []))

    def collect_pinned_items(self) -> Tuple[List[Any], List[str], List[str]]:
        return self.context.get("pinned_items", []), ["Pinned items are sampled from visible channels returned by conversations.list."], list(self.context.get("pin_errors", []))


def _build_context(api_token: str) -> Dict[str, Any]:
    auth = _api_call(api_token, "auth.test")
    team = {}
    notes: List[str] = []
    errors: List[str] = []

    try:
        team = _api_call(api_token, "team.info").get("team", {}) or {}
    except Exception as exc:
        errors.append(f"team.info: {exc}")

    public_channels = _safe_paginate(api_token, "conversations.list", "channels", {"types": "public_channel", "exclude_archived": True, "limit": 200}, errors, "public channels")
    private_channels = _safe_paginate(api_token, "conversations.list", "channels", {"types": "private_channel", "exclude_archived": True, "limit": 200}, errors, "private channels")
    direct_messages = _safe_paginate(api_token, "conversations.list", "channels", {"types": "im", "limit": 200}, errors, "direct messages")
    group_direct_messages = _safe_paginate(api_token, "conversations.list", "channels", {"types": "mpim", "limit": 200}, errors, "group direct messages")
    users = _safe_paginate(api_token, "users.list", "members", {"limit": 200}, errors, "users")

    user_groups: List[Dict[str, Any]] = []
    user_group_errors: List[str] = []
    try:
        user_groups = _annotate_items(_api_call(api_token, "usergroups.list", {"include_users": False}).get("usergroups", []) or [], ["name", "handle", "id"], kind="user_group")
    except Exception as exc:
        user_group_errors.append(f"usergroups.list: {exc}")

    all_channels = public_channels[:MAX_CHANNEL_SAMPLE] + private_channels[:MAX_CHANNEL_SAMPLE]
    channel_memberships: List[Dict[str, Any]] = []
    membership_errors: List[str] = []
    for conversation in all_channels[:MAX_CHANNEL_SAMPLE]:
        try:
            members = _paginate(api_token, "conversations.members", "members", {"channel": conversation.get("id"), "limit": 200}, max_pages=2)
            channel_memberships.append({
                "ChannelName": conversation.get("name") or conversation.get("id"),
                "ChannelId": conversation.get("id"),
                "MemberCount": len(members),
                "MembersSample": members[:8],
                "IsPrivate": bool(conversation.get("is_private")),
                "_kind": "membership",
                "display_name": conversation.get("name") or conversation.get("id"),
            })
        except Exception as exc:
            membership_errors.append(f"{conversation.get('name') or conversation.get('id')}: {exc}")

    pinned_items: List[Dict[str, Any]] = []
    pin_errors: List[str] = []
    for conversation in all_channels[:MAX_CHANNEL_SAMPLE]:
        try:
            response = _api_call(api_token, "pins.list", {"channel": conversation.get("id")})
            for item in response.get("items", []) or []:
                pinned_items.append({
                    "ChannelName": conversation.get("name") or conversation.get("id"),
                    "ChannelId": conversation.get("id"),
                    "PinType": item.get("type"),
                    "Created": item.get("created"),
                    "CreatedBy": item.get("created_by"),
                    "display_name": f"{conversation.get('name') or conversation.get('id')} · {item.get('type') or 'pin'}",
                    "_kind": "pin",
                })
        except Exception as exc:
            pin_errors.append(f"{conversation.get('name') or conversation.get('id')}: {exc}")

    workspace = {
        "WorkspaceName": team.get("name") or auth.get("team"),
        "TeamId": auth.get("team_id"),
        "Domain": team.get("domain"),
        "Url": auth.get("url"),
        "Operator": auth.get("user"),
        "EnterpriseId": auth.get("enterprise_id"),
        "BotId": auth.get("bot_id"),
        "_kind": "workspace",
        "display_name": team.get("name") or auth.get("team") or auth.get("team_id"),
    }

    shared_channels = [
        item for item in public_channels + private_channels
        if item.get("is_ext_shared") or item.get("is_org_shared") or item.get("pending_shared")
    ]
    workspace_admins = [
        item for item in users
        if item.get("is_admin") or item.get("is_owner") or item.get("is_primary_owner")
    ]
    guest_users = [
        item for item in users
        if item.get("is_restricted") or item.get("is_ultra_restricted")
    ]
    bot_users = [
        item for item in users
        if item.get("is_bot") or item.get("profile", {}).get("api_app_id")
    ]

    if membership_errors:
        notes.append("Channel membership counts are sampled from a small set of visible channels to keep monitoring responsive.")
    if pin_errors:
        notes.append("Pinned items may require additional Slack scopes; missing scopes result in partial inventories.")

    return {
        "auth": auth,
        "workspace": workspace,
        "public_channels": _annotate_items(public_channels, ["name", "id"], kind="channel"),
        "private_channels": _annotate_items(private_channels, ["name", "id"], kind="private_channel"),
        "direct_messages": _annotate_items(direct_messages, ["user", "id"], kind="direct_message"),
        "group_direct_messages": _annotate_items(group_direct_messages, ["name", "id"], kind="group_direct_message"),
        "shared_channels": _annotate_items(shared_channels, ["name", "id"], kind="shared_channel"),
        "users": _annotate_items(users, ["real_name", "name", "id"], kind="user"),
        "workspace_admins": _annotate_items(workspace_admins, ["real_name", "name", "id"], kind="admin"),
        "guest_users": _annotate_items(guest_users, ["real_name", "name", "id"], kind="guest"),
        "bot_users": _annotate_items(bot_users, ["real_name", "name", "id"], kind="bot"),
        "user_groups": user_groups,
        "channel_memberships": channel_memberships,
        "pinned_items": pinned_items,
        "notes": notes,
        "errors": errors,
        "user_group_errors": user_group_errors,
        "membership_errors": membership_errors,
        "pin_errors": pin_errors,
    }


def _api_call(api_token: str, method: str, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
    response = requests.get(
        f"{SLACK_API_BASE}/{method}",
        headers={"Authorization": f"Bearer {api_token}"},
        params=params or {},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    payload = response.json()
    if not payload.get("ok"):
        raise RuntimeError(payload.get("error") or f"{method} failed")
    return payload


def _paginate(
    api_token: str,
    method: str,
    item_key: str,
    params: Dict[str, Any] | None = None,
    *,
    max_pages: int = MAX_CURSOR_PAGES,
) -> List[Any]:
    items: List[Any] = []
    cursor = ""
    base_params = dict(params or {})
    for _ in range(max_pages):
        page_params = dict(base_params)
        if cursor:
            page_params["cursor"] = cursor
        payload = _api_call(api_token, method, page_params)
        items.extend(payload.get(item_key, []) or [])
        cursor = (payload.get("response_metadata") or {}).get("next_cursor") or ""
        if not cursor:
            break
    return items


def _safe_paginate(
    api_token: str,
    method: str,
    item_key: str,
    params: Dict[str, Any],
    errors: List[str],
    label: str,
) -> List[Any]:
    try:
        return _paginate(api_token, method, item_key, params)
    except Exception as exc:
        errors.append(f"{label}: {exc}")
        return []


def _annotate_items(items: List[Any], preferred_keys: List[str], *, kind: str) -> List[Any]:
    annotated = []
    for item in items or []:
        if isinstance(item, dict):
            display_name = ""
            for key in preferred_keys:
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    display_name = value.strip()
                    break
                profile_value = item.get("profile", {}).get(key)
                if isinstance(profile_value, str) and profile_value.strip():
                    display_name = profile_value.strip()
                    break
            if not display_name:
                display_name = item.get("id") or kind
            enriched = dict(item)
            enriched["display_name"] = display_name
            enriched["_kind"] = kind
            annotated.append(enriched)
        else:
            annotated.append(item)
    return annotated


def _sample_items(items: List[Any]) -> List[Any]:
    sample = []
    for item in items[:6]:
        if isinstance(item, dict):
            sample.append({
                key: value
                for key, value in item.items()
                if key in {"display_name", "name", "id", "real_name", "ChannelName", "MemberCount", "PinType", "handle", "_kind"}
            })
        else:
            sample.append(item)
    return sample


def _count_by_key(items: List[Any], key: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get(key)
        if not value:
            continue
        counts[str(value)] = counts.get(str(value), 0) + 1
    return counts


def _build_health(service_name: str, count: int, notes: List[str], errors: List[str]) -> Dict[str, Any]:
    status = "warn" if errors else "pass"
    score = max(64, 90 - (len(errors) * 8))
    summary = f"Live Slack API check completed for {service_name} with {count} resource(s) discovered."
    observations = [
        f"Realtime Slack API integration is active for {service_name}.",
        f"Observed {count} resource(s) from Slack Web API methods.",
    ]
    observations.extend(notes[:3])
    if errors:
        observations.append("One or more Slack API calls returned permission or scope errors, so this view may be partial.")
    return {
        "status": status,
        "score": score,
        "summary": summary,
        "observations": observations,
    }
