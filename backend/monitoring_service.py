"""Shared monitoring snapshot collection and persistence."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from config import Config
from rag.models import MonitoringSnapshot, get_session
from agents.aws_realtime import check_aws_realtime_posture
from agents.azure_realtime import check_azure_realtime_posture
from agents.cloud_compliance import check_github_posture
from agents.gitlab_realtime import check_gitlab_realtime_posture

logger = logging.getLogger(__name__)

MONITORED_PROVIDERS = ("aws", "azure", "github", "gitlab")


def _utc_iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def collect_provider_snapshot(provider: str) -> Dict[str, Any]:
    if provider == "aws":
        return check_aws_realtime_posture(
            Config.COMPLIANCE_AWS_ACCESS_KEY,
            Config.COMPLIANCE_AWS_SECRET_KEY,
            Config.COMPLIANCE_AWS_REGION,
        )
    if provider == "azure":
        return check_azure_realtime_posture(
            Config.COMPLIANCE_AZURE_TENANT_ID,
            Config.COMPLIANCE_AZURE_CLIENT_ID,
            Config.COMPLIANCE_AZURE_CLIENT_SECRET,
            access_token=Config.COMPLIANCE_AZURE_ACCESS_TOKEN or "",
        )
    if provider == "github":
        return check_github_posture(Config.COMPLIANCE_GITHUB_TOKEN, include_visuals=False)
    if provider == "gitlab":
        return check_gitlab_realtime_posture(
            Config.COMPLIANCE_GITLAB_TOKEN,
            Config.COMPLIANCE_GITLAB_BASE_URL,
        )
    raise ValueError(f"Unsupported provider: {provider}")


def refresh_provider_snapshot(provider: str, *, source: str = "manual") -> Dict[str, Any]:
    try:
        result = collect_provider_snapshot(provider)
        status = result.get("status", "completed")
        error = result.get("error")
    except Exception as exc:
        logger.exception("Monitoring snapshot collection failed for %s", provider)
        result = {
            "provider": provider,
            "status": "error",
            "error": str(exc),
            "timestamp": _utc_iso_now(),
            "services": {},
        }
        status = "error"
        error = str(exc)

    result["snapshot_collected_at"] = _utc_iso_now()
    result["snapshot_source"] = source
    snapshot = _save_snapshot(provider, result, status=status, source=source, error=error)
    result["snapshot_id"] = snapshot.id
    return result


def refresh_all_provider_snapshots(*, source: str = "scheduled") -> Dict[str, Dict[str, Any]]:
    collected: Dict[str, Dict[str, Any]] = {}
    for provider in MONITORED_PROVIDERS:
        if _provider_configured(provider):
            collected[provider] = refresh_provider_snapshot(provider, source=source)
    return collected


def get_latest_provider_snapshot(provider: str) -> Optional[MonitoringSnapshot]:
    session = get_session()
    try:
        return (
            session.query(MonitoringSnapshot)
            .filter(MonitoringSnapshot.provider == provider)
            .order_by(MonitoringSnapshot.collected_at.desc())
            .first()
        )
    finally:
        session.close()


def _save_snapshot(provider: str, result: Dict[str, Any], *, status: str, source: str, error: str | None) -> MonitoringSnapshot:
    summary = _build_summary(result)
    session = get_session()
    try:
        snapshot = MonitoringSnapshot(
            provider=provider,
            status=status,
            result=result,
            summary=summary,
            source=source,
            error=error,
        )
        session.add(snapshot)
        session.commit()
        session.refresh(snapshot)
        return snapshot
    finally:
        session.close()


def _provider_configured(provider: str) -> bool:
    if provider == "aws":
        return bool(Config.COMPLIANCE_AWS_ACCESS_KEY and Config.COMPLIANCE_AWS_SECRET_KEY)
    if provider == "azure":
        return bool(
            Config.COMPLIANCE_AZURE_ACCESS_TOKEN
            or (Config.COMPLIANCE_AZURE_TENANT_ID and Config.COMPLIANCE_AZURE_CLIENT_ID and Config.COMPLIANCE_AZURE_CLIENT_SECRET)
        )
    if provider == "github":
        return bool(Config.COMPLIANCE_GITHUB_TOKEN)
    if provider == "gitlab":
        return bool(Config.COMPLIANCE_GITLAB_TOKEN)
    return False


def _build_summary(result: Dict[str, Any]) -> Dict[str, Any]:
    services = result.get("services") or {}
    provider = result.get("provider")
    summary_key = f"{provider}_summary" if provider else "summary"
    provider_summary = result.get(summary_key) or result.get("github_summary") or {}
    return {
        "provider": provider,
        "service_count": provider_summary.get("service_count", len(services)),
        "overall_status": provider_summary.get("overall_status", result.get("status")),
        "timestamp": result.get("snapshot_collected_at") or result.get("timestamp"),
    }
