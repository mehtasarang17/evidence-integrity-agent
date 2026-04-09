"""Evidence Integrity Agent — Flask API Application."""

import os
import logging
import requests
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

from config import Config, provider_connection_signature, resolved_teams_client_credentials
from rag.models import init_db, AnalysisRecord, get_session
from rag.knowledge_base import initialize_knowledge_base
from utils.file_utils import save_uploaded_file, get_file_path, get_mime_type, is_image_file
from agents.graph import run_analysis
from agents.aws_realtime import (
    AWS_REALTIME_SERVICE_CATALOG,
    check_aws_realtime_posture,
    list_aws_realtime_services,
    validate_aws_credentials,
)
from agents.azure_realtime import (
    AZURE_REALTIME_SERVICE_CATALOG,
    check_azure_realtime_posture,
    list_azure_realtime_services,
    validate_azure_credentials,
)
from agents.gcp_realtime import (
    GCP_REALTIME_SERVICE_CATALOG,
    check_gcp_realtime_posture,
    list_gcp_realtime_services,
    validate_gcp_credentials,
)
from agents.ibm_realtime import (
    IBM_REALTIME_SERVICE_CATALOG,
    check_ibm_realtime_posture,
    list_ibm_realtime_services,
    validate_ibm_credentials,
)
from agents.oci_realtime import (
    OCI_REALTIME_SERVICE_CATALOG,
    check_oci_realtime_posture,
    list_oci_realtime_services,
    validate_oci_credentials,
)
from agents.gitlab_realtime import (
    GITLAB_REALTIME_SERVICE_CATALOG,
    check_gitlab_realtime_posture,
    list_gitlab_realtime_services,
    validate_gitlab_credentials,
)
from agents.slack_realtime import (
    SLACK_REALTIME_SERVICE_CATALOG,
    check_slack_realtime_posture,
    list_slack_realtime_services,
    validate_slack_credentials,
)
from agents.teams_realtime import (
    TEAMS_REALTIME_SERVICE_CATALOG,
    check_teams_realtime_posture,
    list_teams_realtime_services,
    validate_teams_credentials,
)
from agents.cloud_compliance import (
    check_github_posture,
    check_snowflake_service, SNOWFLAKE_SERVICE_PAGES,
    check_sendgrid_service, SENDGRID_SERVICE_PAGES,
)
from monitoring_service import get_latest_provider_snapshot, refresh_provider_snapshot



# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = Config.MAX_CONTENT_LENGTH
CORS(app)

# Ensure upload directory exists
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)


GITHUB_SERVICE_CATALOG = [
    {"id": "repositories", "name": "Repositories", "description": "Repository inventory, branches, and visibility"},
    {"id": "pull_requests", "name": "Pull Requests", "description": "Open and merged pull request backlog"},
    {"id": "settings", "name": "Settings", "description": "2FA and repository security controls"},
    {"id": "vulnerabilities", "name": "Vulnerabilities", "description": "Dependabot alerts and security coverage"},
    {"id": "issues", "name": "Issues", "description": "Issue backlog and labels across accessible repositories"},
]

SUPPORTED_MONITORING_PROVIDERS = {"aws", "azure", "gcp", "ibm", "oci", "github", "gitlab", "slack", "teams"}


def _provider_service_catalog(provider):
    if provider == "aws":
        return list_aws_realtime_services(
            Config.COMPLIANCE_AWS_ACCESS_KEY,
            Config.COMPLIANCE_AWS_SECRET_KEY,
            Config.COMPLIANCE_AWS_REGION,
        )
    if provider == "azure":
        return list_azure_realtime_services(
            Config.COMPLIANCE_AZURE_TENANT_ID,
            Config.COMPLIANCE_AZURE_CLIENT_ID,
            Config.COMPLIANCE_AZURE_CLIENT_SECRET,
            Config.COMPLIANCE_AZURE_ACCESS_TOKEN or "",
        )
    if provider == "gcp":
        return list_gcp_realtime_services()
    if provider == "ibm":
        return list_ibm_realtime_services()
    if provider == "oci":
        return list_oci_realtime_services()
    if provider == "github":
        return GITHUB_SERVICE_CATALOG
    if provider == "gitlab":
        return list_gitlab_realtime_services()
    if provider == "slack":
        return list_slack_realtime_services()
    if provider == "teams":
        return list_teams_realtime_services()
    return []


def _validate_aws_provider():
    return validate_aws_credentials(
        Config.COMPLIANCE_AWS_ACCESS_KEY,
        Config.COMPLIANCE_AWS_SECRET_KEY,
        Config.COMPLIANCE_AWS_REGION,
    )


def _validate_azure_provider():
    return validate_azure_credentials(
        Config.COMPLIANCE_AZURE_TENANT_ID,
        Config.COMPLIANCE_AZURE_CLIENT_ID,
        Config.COMPLIANCE_AZURE_CLIENT_SECRET,
        Config.COMPLIANCE_AZURE_ACCESS_TOKEN or "",
    )


def _validate_github_provider():
    if not Config.COMPLIANCE_GITHUB_TOKEN:
        return {"configured": False, "healthy": False, "message": "Missing GitHub token in .env"}

    try:
        headers = {
            "Authorization": f"token {Config.COMPLIANCE_GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        response = requests.get("https://api.github.com/user", headers=headers, timeout=15)
        response.raise_for_status()
        user = response.json()
        return {
            "configured": True,
            "healthy": True,
            "message": "GitHub token verified",
            "details": {"login": user.get("login"), "name": user.get("name")},
        }
    except Exception as exc:
        return {"configured": True, "healthy": False, "message": f"GitHub validation failed: {exc}"}


def _validate_gcp_provider():
    return validate_gcp_credentials(
        Config.COMPLIANCE_GCP_ACCESS_TOKEN,
        Config.COMPLIANCE_GCP_SCOPE,
        Config.COMPLIANCE_GCP_PROJECT_IDS,
    )


def _validate_ibm_provider():
    return validate_ibm_credentials(
        Config.COMPLIANCE_IBM_CLOUD_API_KEY,
    )


def _validate_oci_provider():
    return validate_oci_credentials(
        Config.COMPLIANCE_OCI_TENANCY_OCID,
        Config.COMPLIANCE_OCI_USER_OCID,
        Config.COMPLIANCE_OCI_FINGERPRINT,
        Config.COMPLIANCE_OCI_PRIVATE_KEY,
        Config.COMPLIANCE_OCI_REGION,
        passphrase=Config.COMPLIANCE_OCI_PASSPHRASE,
        private_key_path=Config.COMPLIANCE_OCI_PRIVATE_KEY_PATH,
    )


def _validate_gitlab_provider():
    return validate_gitlab_credentials(
        Config.COMPLIANCE_GITLAB_TOKEN,
        Config.COMPLIANCE_GITLAB_BASE_URL,
    )


def _validate_slack_provider():
    return validate_slack_credentials(
        Config.COMPLIANCE_SLACK_TOKEN,
    )


def _validate_teams_provider():
    tenant_id, client_id, client_secret = resolved_teams_client_credentials()
    return validate_teams_credentials(
        Config.COMPLIANCE_TEAMS_ACCESS_TOKEN,
        tenant_id,
        client_id,
        client_secret,
    )


def _provider_statuses():
    statuses = {
        "aws": _validate_aws_provider(),
        "azure": _validate_azure_provider(),
        "gcp": _validate_gcp_provider(),
        "ibm": _validate_ibm_provider(),
        "oci": _validate_oci_provider(),
        "github": _validate_github_provider(),
        "gitlab": _validate_gitlab_provider(),
        "slack": _validate_slack_provider(),
        "teams": _validate_teams_provider(),
    }
    for provider, status in statuses.items():
        status["connection_signature"] = provider_connection_signature(provider)
    return statuses


def initialize():
    """Initialize database and knowledge base."""
    logger.info("Initializing database...")
    init_db()
    logger.info("Database initialized.")

    logger.info("Initializing knowledge base...")
    try:
        initialize_knowledge_base()
    except Exception as e:
        logger.warning(f"Knowledge base initialization skipped: {e}")
    logger.info("Application ready.")


# ──────────────────────────────────────
# API Routes
# ──────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "Evidence Integrity Agent",
        "timestamp": datetime.utcnow().isoformat(),
    })


@app.route("/api/upload", methods=["POST"])
def upload_file():
    """Upload evidence file for analysis."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not Config.is_allowed_file(file.filename):
        return jsonify({
            "error": f"File type not allowed. Supported: {', '.join(Config.ALLOWED_EXTENSIONS)}"
        }), 400

    try:
        file_info = save_uploaded_file(file)
        mime_type = get_mime_type(file_info["saved_path"])

        # Determine file type category
        if is_image_file(file_info["saved_path"]):
            file_type = "image"
        elif file_info["extension"] in ("log", "txt", "csv"):
            file_type = "log"
        else:
            file_type = "document"

        file_info["mime_type"] = mime_type
        file_info["file_type"] = file_type

        logger.info(f"File uploaded: {file_info['original_filename']} ({file_type})")

        return jsonify({
            "success": True,
            "file": file_info,
        })

    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/analyze", methods=["POST"])
def analyze_evidence():
    """Trigger analysis on an uploaded file."""
    data = request.get_json()
    if not data or "file_id" not in data:
        return jsonify({"error": "file_id is required"}), 400

    file_id = data["file_id"]
    file_path = get_file_path(file_id)

    if not file_path:
        return jsonify({"error": "File not found"}), 404

    original_filename = data.get("original_filename", os.path.basename(file_path))
    file_type = data.get("file_type", "document")
    mime_type = data.get("mime_type", get_mime_type(file_path))

    # Create analysis record
    session = get_session()
    try:
        record = AnalysisRecord(
            file_id=file_id,
            original_filename=original_filename,
            file_type=file_type,
            file_size=os.path.getsize(file_path),
            status="processing",
        )
        session.add(record)
        session.commit()
        analysis_id = record.id
    finally:
        session.close()

    try:
        logger.info(f"Starting analysis for {original_filename} (ID: {analysis_id})")

        # Run the LangGraph analysis pipeline
        result = run_analysis(
            file_id=file_id,
            file_path=file_path,
            original_filename=original_filename,
            file_type=file_type,
            mime_type=mime_type,
        )

        # Update the analysis record with results
        session = get_session()
        try:
            record = session.query(AnalysisRecord).filter_by(id=analysis_id).first()
            if record:
                record.authenticity_score = result.get("authenticity_score", 0)
                record.tamper_risk = result.get("tamper_risk", "Unknown")
                record.metadata_findings = result.get("metadata_results", {})
                record.hash_findings = result.get("hash_results", {})
                record.visual_findings = result.get("visual_results", {})
                record.rag_findings = result.get("rag_results", {})
                record.report = result.get("report", {})
                record.sha256 = result.get("hash_results", {}).get("sha256")
                record.md5 = result.get("hash_results", {}).get("md5")
                record.perceptual_hash = result.get("hash_results", {}).get("perceptual_hash")
                record.status = "completed"
                record.completed_at = datetime.utcnow()
                session.commit()

                return jsonify({
                    "success": True,
                    "analysis": record.to_dict(),
                })
        finally:
            session.close()

    except Exception as e:
        logger.error(f"Analysis error: {e}")
        # Update record status to failed
        session = get_session()
        try:
            record = session.query(AnalysisRecord).filter_by(id=analysis_id).first()
            if record:
                record.status = "failed"
                record.report = {"error": str(e)}
                session.commit()
        finally:
            session.close()

        return jsonify({"error": str(e)}), 500


@app.route("/api/results/<analysis_id>", methods=["GET"])
def get_results(analysis_id):
    """Get analysis results by ID."""
    session = get_session()
    try:
        record = session.query(AnalysisRecord).filter_by(id=analysis_id).first()
        if not record:
            return jsonify({"error": "Analysis not found"}), 404
        return jsonify({"success": True, "analysis": record.to_dict()})
    finally:
        session.close()


@app.route("/api/history", methods=["GET"])
def get_history():
    """Get analysis history, most recent first."""
    session = get_session()
    try:
        limit = request.args.get("limit", 20, type=int)
        offset = request.args.get("offset", 0, type=int)

        records = (
            session.query(AnalysisRecord)
            .order_by(AnalysisRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        total = session.query(AnalysisRecord).count()

        return jsonify({
            "success": True,
            "analyses": [r.to_dict() for r in records],
            "total": total,
            "limit": limit,
            "offset": offset,
        })
    finally:
        session.close()


# ──────────────────────────────────────
# Service Monitoring Routes
# ──────────────────────────────────────

@app.route("/api/monitoring/providers/status", methods=["GET"])
def monitoring_provider_status():
    """Return env-backed provider configuration and health."""
    return jsonify({"success": True, "providers": _provider_statuses()})


@app.route("/api/monitoring/services/<provider>", methods=["GET"])
def monitoring_services(provider):
    """Return the service catalog for a configured provider."""
    services = _provider_service_catalog(provider)
    if not services:
        return jsonify({"error": f"Unknown provider: {provider}"}), 404
    return jsonify({"success": True, "services": services})


@app.route("/api/monitoring/analyze", methods=["POST"])
def monitoring_analyze():
    """Collect monitoring data for a provider service using environment-backed credentials."""
    data = request.get_json() or {}
    provider = data.get("provider")
    service = data.get("service")

    if not provider or not service:
        return jsonify({"error": "provider and service are required"}), 400

    provider_status = _provider_statuses().get(provider)
    if not provider_status or not provider_status.get("healthy"):
        return jsonify({"error": provider_status.get("message", "Provider credentials are not healthy")}), 400

    try:
        if provider not in SUPPORTED_MONITORING_PROVIDERS:
            return jsonify({"error": f"Unsupported provider: {provider}"}), 400

        result = refresh_provider_snapshot(provider, source="manual")
        result["selected_service"] = service

        for ss in result.get("screenshots", []):
            if "filename" in ss:
                ss["url_path"] = f"/api/screenshots/{ss['filename']}"
            if "path" in ss:
                del ss["path"]

        return jsonify({"success": True, "result": result})
    except Exception as exc:
        logger.error(f"Unified monitoring analyze error: {exc}")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/monitoring/providers/<provider>/latest", methods=["GET"])
def monitoring_provider_latest(provider):
    """Return the latest cached provider-wide monitoring snapshot."""
    if provider not in SUPPORTED_MONITORING_PROVIDERS:
        return jsonify({"error": f"Unsupported provider: {provider}"}), 400

    snapshot = get_latest_provider_snapshot(provider)
    if not snapshot:
        return jsonify({"success": True, "result": None, "snapshot": None})

    return jsonify({"success": True, "result": snapshot.result, "snapshot": snapshot.to_dict()})


@app.route("/api/monitoring/providers/<provider>/refresh", methods=["POST"])
def monitoring_provider_refresh(provider):
    """Trigger an immediate provider-wide monitoring refresh."""
    if provider not in SUPPORTED_MONITORING_PROVIDERS:
        return jsonify({"error": f"Unsupported provider: {provider}"}), 400

    result = refresh_provider_snapshot(provider, source="manual")
    return jsonify({"success": True, "result": result})

@app.route("/api/monitoring/aws/services", methods=["GET"])
def aws_services_list():
    """Return the list of supported AWS services for the service selector."""
    return jsonify({
        "success": True,
        "services": list_aws_realtime_services(
            Config.COMPLIANCE_AWS_ACCESS_KEY,
            Config.COMPLIANCE_AWS_SECRET_KEY,
            Config.COMPLIANCE_AWS_REGION,
        ),
    })


@app.route("/api/monitoring/aws/checks/<service_id>", methods=["GET"])
def aws_checks_list(service_id):
    """Return a single API-based monitor check for a given AWS integration."""
    runtime_catalog = {
        service["id"]: service
        for service in list_aws_realtime_services(
            Config.COMPLIANCE_AWS_ACCESS_KEY,
            Config.COMPLIANCE_AWS_SECRET_KEY,
            Config.COMPLIANCE_AWS_REGION,
        )
    }
    service_info = runtime_catalog.get(service_id) or AWS_REALTIME_SERVICE_CATALOG.get(service_id)
    if not service_info:
        return jsonify({"error": f"Unknown service: {service_id}"}), 404
    checks = [{
        "id": "realtime_monitor",
        "name": "Realtime Monitor",
        "description": f"Live AWS API inventory and posture summary for {service_info['name']}",
    }]
    return jsonify({"success": True, "checks": checks})


@app.route("/api/monitoring/aws", methods=["POST"])
def aws_monitoring():
    """Run AWS realtime service monitoring using API credentials only."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    access_key = data.get("access_key") or Config.COMPLIANCE_AWS_ACCESS_KEY
    secret_key = data.get("secret_key") or Config.COMPLIANCE_AWS_SECRET_KEY
    region = data.get("region", Config.COMPLIANCE_AWS_REGION or "us-east-1")
    service = data.get("service")

    if not access_key or not secret_key:
        return jsonify({"error": "Provide AWS access key and secret key"}), 400
    if not service:
        return jsonify({"error": "service is required"}), 400

    try:
        logger.info(f"Starting AWS realtime posture scan (selected service: {service}) (region: {region})")
        result = check_aws_realtime_posture(access_key, secret_key, region, service)

        for ss in result.get("screenshots", []):
            ss["url_path"] = f"/api/screenshots/{ss['filename']}"
            if "path" in ss:
                del ss["path"]

        if result.get("status") == "error":
            return jsonify({"success": False, "error": result.get("error", "Monitoring request failed"), "result": result})

        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"AWS monitoring error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/monitoring/azure", methods=["POST"])
def azure_monitoring():
    """Run Azure realtime service monitoring using an access token or service principal."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    tenant_id = data.get("tenant_id") or Config.COMPLIANCE_AZURE_TENANT_ID
    client_id = data.get("client_id") or Config.COMPLIANCE_AZURE_CLIENT_ID
    client_secret = data.get("client_secret") or Config.COMPLIANCE_AZURE_CLIENT_SECRET
    access_token = data.get("access_token") or Config.COMPLIANCE_AZURE_ACCESS_TOKEN
    service = data.get("service")

    if not access_token and (not tenant_id or not client_id or not client_secret):
        return jsonify({"error": "Either access_token or (tenant_id, client_id, client_secret) are required"}), 400
    if not service:
        return jsonify({"error": "service is required"}), 400

    try:
        logger.info(f"Starting Azure realtime posture scan (selected service: {service})")
        result = check_azure_realtime_posture(
            tenant_id,
            client_id,
            client_secret,
            access_token=access_token or "",
            selected_service=service,
        )

        for ss in result.get("screenshots", []):
            ss["url_path"] = f"/api/screenshots/{ss['filename']}"
            if "path" in ss:
                del ss["path"]

        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"Azure monitoring error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/monitoring/gcp/services", methods=["GET"])
def gcp_services_list():
    """Return the list of supported GCP services for the service selector."""
    return jsonify({"success": True, "services": list_gcp_realtime_services()})


@app.route("/api/monitoring/gcp/checks/<service_id>", methods=["GET"])
def gcp_checks_list(service_id):
    """Return a single API-based monitor check for a given GCP integration."""
    service_info = GCP_REALTIME_SERVICE_CATALOG.get(service_id)
    if not service_info:
        return jsonify({"error": f"Unknown service: {service_id}"}), 404
    checks = [{
        "id": "realtime_monitor",
        "name": "Realtime Monitor",
        "description": f"Live GCP asset inventory and posture summary for {service_info['name']}",
    }]
    return jsonify({"success": True, "checks": checks})


@app.route("/api/monitoring/gcp", methods=["POST"])
def gcp_monitoring():
    """Run GCP realtime service monitoring using an access token only."""
    data = request.get_json() or {}

    access_token = data.get("access_token") or Config.COMPLIANCE_GCP_ACCESS_TOKEN
    scope = data.get("scope") or Config.COMPLIANCE_GCP_SCOPE
    project_ids = data.get("project_ids") or Config.COMPLIANCE_GCP_PROJECT_IDS
    service = data.get("service")

    if not access_token:
        return jsonify({"error": "access_token is required"}), 400
    if not service:
        return jsonify({"error": "service is required"}), 400

    try:
        logger.info(f"Starting GCP realtime posture scan (selected service: {service})")
        result = check_gcp_realtime_posture(
            access_token,
            scope=scope,
            project_ids=project_ids,
            selected_service=service,
        )
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"GCP monitoring error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/monitoring/oci/services", methods=["GET"])
def oci_services_list():
    """Return the list of supported OCI services for the service selector."""
    return jsonify({"success": True, "services": list_oci_realtime_services()})


@app.route("/api/monitoring/oci/checks/<service_id>", methods=["GET"])
def oci_checks_list(service_id):
    """Return a single API-based monitor check for a given OCI integration."""
    service_info = OCI_REALTIME_SERVICE_CATALOG.get(service_id)
    if not service_info:
        return jsonify({"error": f"Unknown service: {service_id}"}), 404
    checks = [{
        "id": "realtime_monitor",
        "name": "Realtime Monitor",
        "description": f"Live OCI Resource Search inventory and posture summary for {service_info['name']}",
    }]
    return jsonify({"success": True, "checks": checks})


@app.route("/api/monitoring/oci", methods=["POST"])
def oci_monitoring():
    """Run OCI realtime service monitoring using OCI API signing credentials."""
    data = request.get_json() or {}

    tenancy_ocid = data.get("tenancy_ocid") or Config.COMPLIANCE_OCI_TENANCY_OCID
    user_ocid = data.get("user_ocid") or Config.COMPLIANCE_OCI_USER_OCID
    fingerprint = data.get("fingerprint") or Config.COMPLIANCE_OCI_FINGERPRINT
    private_key = data.get("private_key") or Config.COMPLIANCE_OCI_PRIVATE_KEY
    private_key_path = data.get("private_key_path") or Config.COMPLIANCE_OCI_PRIVATE_KEY_PATH
    passphrase = data.get("passphrase") or Config.COMPLIANCE_OCI_PASSPHRASE
    region = data.get("region") or Config.COMPLIANCE_OCI_REGION
    service = data.get("service")

    if not tenancy_ocid or not user_ocid or not fingerprint or not region or not (private_key or private_key_path):
        return jsonify({"error": "tenancy_ocid, user_ocid, fingerprint, region, and private_key/private_key_path are required"}), 400
    if not service:
        return jsonify({"error": "service is required"}), 400

    try:
        logger.info(f"Starting OCI realtime posture scan (selected service: {service})")
        result = check_oci_realtime_posture(
            tenancy_ocid,
            user_ocid,
            fingerprint,
            private_key,
            region,
            passphrase=passphrase,
            private_key_path=private_key_path,
            selected_service=service,
        )
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"OCI monitoring error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/monitoring/github", methods=["POST"])
def github_monitoring():
    """Run GitHub realtime service monitoring."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    api_token = data.get("api_token")
    if not api_token:
        return jsonify({"error": "api_token is required"}), 400

    try:
        logger.info("Starting GitHub monitoring run")
        result = check_github_posture(api_token)

        for ss in result.get("screenshots", []):
            ss["url_path"] = f"/api/screenshots/{ss['filename']}"
            del ss["path"]

        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"GitHub monitoring error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/monitoring/gitlab", methods=["POST"])
def gitlab_monitoring():
    """Run GitLab realtime service monitoring using an API token only."""
    data = request.get_json() or {}

    api_token = data.get("api_token") or Config.COMPLIANCE_GITLAB_TOKEN
    base_url = data.get("base_url") or Config.COMPLIANCE_GITLAB_BASE_URL
    service = data.get("service")

    if not api_token:
        return jsonify({"error": "api_token is required"}), 400
    if not service:
        return jsonify({"error": "service is required"}), 400

    try:
        logger.info(f"Starting GitLab realtime posture scan (selected service: {service})")
        result = check_gitlab_realtime_posture(api_token, base_url, selected_service=service)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"GitLab monitoring error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/monitoring/slack/services", methods=["GET"])
def slack_services_list():
    """Return the list of supported Slack services for the service selector."""
    return jsonify({"success": True, "services": list_slack_realtime_services()})


@app.route("/api/monitoring/slack/checks/<service_id>", methods=["GET"])
def slack_checks_list(service_id):
    """Return a single API-based monitor check for a given Slack integration."""
    service_info = SLACK_REALTIME_SERVICE_CATALOG.get(service_id)
    if not service_info:
        return jsonify({"error": f"Unknown service: {service_id}"}), 404
    checks = [{
        "id": "realtime_monitor",
        "name": "Realtime Monitor",
        "description": f"Live Slack API inventory and posture summary for {service_info['name']}",
    }]
    return jsonify({"success": True, "checks": checks})


@app.route("/api/monitoring/slack", methods=["POST"])
def slack_monitoring():
    """Run Slack realtime service monitoring using an API token only."""
    data = request.get_json() or {}

    api_token = data.get("api_token") or Config.COMPLIANCE_SLACK_TOKEN
    service = data.get("service")

    if not api_token:
        return jsonify({"error": "api_token is required"}), 400
    if not service:
        return jsonify({"error": "service is required"}), 400

    try:
        logger.info(f"Starting Slack realtime posture scan (selected service: {service})")
        result = check_slack_realtime_posture(api_token, selected_service=service)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"Slack monitoring error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/monitoring/teams/services", methods=["GET"])
def teams_services_list():
    """Return the list of supported Teams DLP services for the service selector."""
    return jsonify({"success": True, "services": list_teams_realtime_services()})


@app.route("/api/monitoring/teams/checks/<service_id>", methods=["GET"])
def teams_checks_list(service_id):
    """Return a single API-based monitor check for a given Teams DLP integration."""
    service_info = TEAMS_REALTIME_SERVICE_CATALOG.get(service_id)
    if not service_info:
        return jsonify({"error": f"Unknown service: {service_id}"}), 404
    checks = [{
        "id": "realtime_monitor",
        "name": "Realtime Monitor",
        "description": f"Live Microsoft Purview DLP snapshot summary for {service_info['name']}",
    }]
    return jsonify({"success": True, "checks": checks})


@app.route("/api/monitoring/teams", methods=["POST"])
def teams_monitoring():
    """Run Teams DLP monitoring using a Microsoft Graph access token or app credentials."""
    data = request.get_json() or {}

    access_token = data.get("access_token") or Config.COMPLIANCE_TEAMS_ACCESS_TOKEN
    default_tenant_id, default_client_id, default_client_secret = resolved_teams_client_credentials()
    tenant_id = data.get("tenant_id") or default_tenant_id
    client_id = data.get("client_id") or default_client_id
    client_secret = data.get("client_secret") or default_client_secret
    service = data.get("service")

    if not access_token and (not tenant_id or not client_id or not client_secret):
        return jsonify({"error": "Either access_token or (tenant_id, client_id, client_secret) are required"}), 400
    if not service:
        return jsonify({"error": "service is required"}), 400

    try:
        logger.info(f"Starting Teams DLP posture scan (selected service: {service})")
        result = check_teams_realtime_posture(
            access_token=access_token or "",
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            selected_service=service,
        )
        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"Teams DLP monitoring error: {e}")
        return jsonify({"error": str(e)}), 500




# ──────────────────────────────────────
# Snowflake Monitoring Routes
# ──────────────────────────────────────

@app.route("/api/monitoring/snowflake/services", methods=["GET"])
def snowflake_services_list():
    """Return supported Snowflake services."""
    services = [
        {"id": svc_id, "name": info["name"], "description": info["description"]}
        for svc_id, info in SNOWFLAKE_SERVICE_PAGES.items()
    ]
    return jsonify({"success": True, "services": services})


@app.route("/api/monitoring/snowflake/checks/<service_id>", methods=["GET"])
def snowflake_checks_list(service_id):
    """Return checks for a given Snowflake service."""
    service_info = SNOWFLAKE_SERVICE_PAGES.get(service_id)
    if not service_info:
        return jsonify({"error": f"Unknown service: {service_id}"}), 404
    checks = [
        {"id": c["id"], "name": c["name"], "description": c["description"]}
        for c in service_info.get("checks", [])
    ]
    return jsonify({"success": True, "checks": checks})


@app.route("/api/monitoring/snowflake", methods=["POST"])
def snowflake_monitoring():
    """Run Snowflake monitoring via Playwright browser login."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    account_url = data.get("account_url")
    username = data.get("username")
    password = data.get("password")
    service = data.get("service")

    if not account_url:
        return jsonify({"error": "account_url is required"}), 400
    if not username:
        return jsonify({"error": "username is required"}), 400
    if not password:
        return jsonify({"error": "password is required"}), 400
    if not service:
        return jsonify({"error": "service is required"}), 400

    check_id = data.get("check_id")

    try:
        logger.info(f"Starting Snowflake monitoring run: service={service}, check={check_id}")
        result = check_snowflake_service(account_url, username, password, service, check_id=check_id)

        for ss in result.get("screenshots", []):
            ss["url_path"] = f"/api/screenshots/{ss['filename']}"
            if "path" in ss:
                del ss["path"]

        if result.get("status") == "error":
            return jsonify({"success": False, "error": result.get("error", "Monitoring request failed"), "result": result})

        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"Snowflake monitoring error: {e}")
        return jsonify({"error": str(e)}), 500


# ──────────────────────────────────────
# SendGrid Monitoring Routes
# ──────────────────────────────────────

@app.route("/api/monitoring/sendgrid/services", methods=["GET"])
def sendgrid_services_list():
    """Return supported SendGrid services."""
    services = [
        {"id": svc_id, "name": info["name"], "description": info["description"]}
        for svc_id, info in SENDGRID_SERVICE_PAGES.items()
    ]
    return jsonify({"success": True, "services": services})


@app.route("/api/monitoring/sendgrid/checks/<service_id>", methods=["GET"])
def sendgrid_checks_list(service_id):
    """Return checks for a given SendGrid service."""
    service_info = SENDGRID_SERVICE_PAGES.get(service_id)
    if not service_info:
        return jsonify({"error": f"Unknown service: {service_id}"}), 404
    checks = [
        {"id": c["id"], "name": c["name"], "description": c["description"]}
        for c in service_info.get("checks", [])
    ]
    return jsonify({"success": True, "checks": checks})


@app.route("/api/monitoring/sendgrid", methods=["POST"])
def sendgrid_monitoring():
    """Run SendGrid monitoring via Playwright browser login."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    username = data.get("username")
    password = data.get("password")
    service = data.get("service")

    if not username:
        return jsonify({"error": "username is required"}), 400
    if not password:
        return jsonify({"error": "password is required"}), 400
    if not service:
        return jsonify({"error": "service is required"}), 400

    check_id = data.get("check_id")

    try:
        logger.info(f"Starting SendGrid monitoring run: service={service}, check={check_id}")
        result = check_sendgrid_service(username, password, service, check_id=check_id)

        for ss in result.get("screenshots", []):
            ss["url_path"] = f"/api/screenshots/{ss['filename']}"
            if "path" in ss:
                del ss["path"]

        if result.get("status") == "error":
            return jsonify({"success": False, "error": result.get("error", "Monitoring request failed"), "result": result})

        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"SendGrid monitoring error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/screenshots/<filename>", methods=["GET"])
def serve_screenshot(filename):
    """Serve a monitoring screenshot."""
    from flask import send_from_directory
    screenshots_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "screenshots")
    return send_from_directory(screenshots_dir, filename)


if __name__ == "__main__":
    initialize()
    app.run(host="0.0.0.0", port=5000, debug=Config.DEBUG)
