"""Helpers for identifying the active monitoring connection without exposing secrets."""

from __future__ import annotations

import hashlib

from config import Config


def provider_connection_signature(provider: str) -> str:
    raw = _provider_signature_source(provider)
    if not raw:
        return ""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _provider_signature_source(provider: str) -> str:
    if provider == "aws":
        return f"{Config.COMPLIANCE_AWS_ACCESS_KEY}|{Config.COMPLIANCE_AWS_REGION}"
    if provider == "azure":
        if Config.COMPLIANCE_AZURE_ACCESS_TOKEN:
            return f"token|{Config.COMPLIANCE_AZURE_ACCESS_TOKEN}"
        return f"sp|{Config.COMPLIANCE_AZURE_TENANT_ID}|{Config.COMPLIANCE_AZURE_CLIENT_ID}"
    if provider == "gcp":
        return f"{Config.COMPLIANCE_GCP_ACCESS_TOKEN}|{Config.COMPLIANCE_GCP_SCOPE}|{Config.COMPLIANCE_GCP_PROJECT_IDS}"
    if provider == "ibm":
        return f"{Config.COMPLIANCE_IBM_CLOUD_API_KEY}"
    if provider == "oci":
        return f"{Config.COMPLIANCE_OCI_TENANCY_OCID}|{Config.COMPLIANCE_OCI_USER_OCID}|{Config.COMPLIANCE_OCI_FINGERPRINT}|{Config.COMPLIANCE_OCI_REGION}"
    if provider == "github":
        return f"{Config.COMPLIANCE_GITHUB_TOKEN}"
    if provider == "gitlab":
        return f"{Config.COMPLIANCE_GITLAB_TOKEN}|{Config.COMPLIANCE_GITLAB_BASE_URL}"
    return ""
