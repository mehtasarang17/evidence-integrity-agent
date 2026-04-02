"""Evidence Integrity Agent — Flask API Application."""

import os
import logging
import requests
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

from config import Config
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
from agents.gitlab_realtime import (
    GITLAB_REALTIME_SERVICE_CATALOG,
    check_gitlab_realtime_posture,
    list_gitlab_realtime_services,
    validate_gitlab_credentials,
)
from agents.cloud_compliance import (
    check_github_posture,
    check_snowflake_service, SNOWFLAKE_SERVICE_PAGES,
    check_sendgrid_service, SENDGRID_SERVICE_PAGES,
)



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


def _provider_service_catalog(provider):
    if provider == "aws":
        return list_aws_realtime_services()
    if provider == "azure":
        return list_azure_realtime_services()
    if provider == "github":
        return GITHUB_SERVICE_CATALOG
    if provider == "gitlab":
        return list_gitlab_realtime_services()
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


def _validate_gitlab_provider():
    return validate_gitlab_credentials(
        Config.COMPLIANCE_GITLAB_TOKEN,
        Config.COMPLIANCE_GITLAB_BASE_URL,
    )


def _provider_statuses():
    return {
        "aws": _validate_aws_provider(),
        "azure": _validate_azure_provider(),
        "github": _validate_github_provider(),
        "gitlab": _validate_gitlab_provider(),
    }


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
        if provider == "aws":
            result = check_aws_realtime_posture(
                Config.COMPLIANCE_AWS_ACCESS_KEY,
                Config.COMPLIANCE_AWS_SECRET_KEY,
                Config.COMPLIANCE_AWS_REGION,
                service,
            )
        elif provider == "azure":
            result = check_azure_realtime_posture(
                Config.COMPLIANCE_AZURE_TENANT_ID,
                Config.COMPLIANCE_AZURE_CLIENT_ID,
                Config.COMPLIANCE_AZURE_CLIENT_SECRET,
                access_token=Config.COMPLIANCE_AZURE_ACCESS_TOKEN or "",
                selected_service=service,
            )
        elif provider == "github":
            result = check_github_posture(Config.COMPLIANCE_GITHUB_TOKEN)
            result["selected_service"] = service
        elif provider == "gitlab":
            result = check_gitlab_realtime_posture(
                Config.COMPLIANCE_GITLAB_TOKEN,
                Config.COMPLIANCE_GITLAB_BASE_URL,
                selected_service=service,
            )
        else:
            return jsonify({"error": f"Unsupported provider: {provider}"}), 400

        for ss in result.get("screenshots", []):
            if "filename" in ss:
                ss["url_path"] = f"/api/screenshots/{ss['filename']}"
            if "path" in ss:
                del ss["path"]

        return jsonify({"success": True, "result": result})
    except Exception as exc:
        logger.error(f"Unified monitoring analyze error: {exc}")
        return jsonify({"error": str(exc)}), 500

@app.route("/api/monitoring/aws/services", methods=["GET"])
def aws_services_list():
    """Return the list of supported AWS services for the service selector."""
    return jsonify({"success": True, "services": list_aws_realtime_services()})


@app.route("/api/monitoring/aws/checks/<service_id>", methods=["GET"])
def aws_checks_list(service_id):
    """Return a single API-based monitor check for a given AWS integration."""
    service_info = AWS_REALTIME_SERVICE_CATALOG.get(service_id)
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
