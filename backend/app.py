"""Evidence Integrity Agent — Flask API Application."""

import os
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

from config import Config
from rag.models import init_db, AnalysisRecord, get_session
from rag.knowledge_base import initialize_knowledge_base
from utils.file_utils import save_uploaded_file, get_file_path, get_mime_type, is_image_file
from agents.graph import run_analysis
from agents.cloud_compliance import (
    check_aws_ebs_encryption, check_aws_service, AWS_SERVICE_PAGES,
    check_azure_sql_encryption, check_github_mfa,
    check_datadog_service, DATADOG_SERVICE_PAGES,
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
# Cloud Compliance Routes
# ──────────────────────────────────────

@app.route("/api/compliance/aws/services", methods=["GET"])
def aws_services_list():
    """Return the list of supported AWS services for the service selector."""
    services = [
        {"id": svc_id, "name": info["name"], "description": info["description"]}
        for svc_id, info in AWS_SERVICE_PAGES.items()
    ]
    return jsonify({"success": True, "services": services})


@app.route("/api/compliance/aws/checks/<service_id>", methods=["GET"])
def aws_checks_list(service_id):
    """Return the list of compliance checks for a given AWS service."""
    service_info = AWS_SERVICE_PAGES.get(service_id)
    if not service_info:
        return jsonify({"error": f"Unknown service: {service_id}"}), 404
    checks = [
        {"id": c["id"], "name": c["name"], "description": c["description"]}
        for c in service_info.get("checks", [])
    ]
    return jsonify({"success": True, "checks": checks})


@app.route("/api/compliance/aws", methods=["POST"])
def aws_compliance():
    """Run AWS compliance check. If 'service' is provided, scans that service generically.
    Falls back to legacy EBS-only check when no service is specified."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    access_key = data.get("access_key")
    secret_key = data.get("secret_key")
    region = data.get("region", "us-east-1")
    account_id = data.get("account_id")
    iam_username = data.get("iam_username")
    iam_password = data.get("iam_password")
    service = data.get("service")  # new: generic service selector
    check_id = data.get("check_id")  # specific check within the service

    has_api_keys = access_key and secret_key
    has_console_creds = account_id and iam_username and iam_password
    if not has_api_keys and not has_console_creds:
        return jsonify({"error": "Provide either (access_key + secret_key) or (account_id + iam_username + iam_password)"}), 400

    try:
        if service and has_console_creds:
            logger.info(f"Starting AWS service scan: {service} / check: {check_id} (region: {region})")
            result = check_aws_service(account_id, iam_username, iam_password, region, service, check_id=check_id)
        else:
            logger.info(f"Starting AWS EBS encryption compliance check (region: {region})")
            result = check_aws_ebs_encryption(
                access_key, secret_key, region,
                account_id=account_id,
                iam_username=iam_username,
                iam_password=iam_password,
            )

        for ss in result.get("screenshots", []):
            ss["url_path"] = f"/api/screenshots/{ss['filename']}"
            if "path" in ss:
                del ss["path"]

        if result.get("status") == "error":
            return jsonify({"success": False, "error": result.get("error", "Compliance check failed"), "result": result})

        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"AWS compliance check error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/compliance/azure", methods=["POST"])
def azure_compliance():
    """Run Azure SQL Database & Data Warehouse encryption compliance check."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    tenant_id = data.get("tenant_id")
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")
    access_token = data.get("access_token")

    if not access_token and (not tenant_id or not client_id or not client_secret):
        return jsonify({"error": "Either access_token or (tenant_id, client_id, client_secret) are required"}), 400

    try:
        logger.info("Starting Azure SQL encryption compliance check")
        result = check_azure_sql_encryption(tenant_id, client_id, client_secret, access_token=access_token)

        for ss in result.get("screenshots", []):
            ss["url_path"] = f"/api/screenshots/{ss['filename']}"
            del ss["path"]

        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"Azure compliance check error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/compliance/github", methods=["POST"])
def github_compliance():
    """Run GitHub MFA compliance check."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    api_token = data.get("api_token")
    if not api_token:
        return jsonify({"error": "api_token is required"}), 400

    try:
        logger.info("Starting GitHub MFA compliance check")
        result = check_github_mfa(api_token)

        for ss in result.get("screenshots", []):
            ss["url_path"] = f"/api/screenshots/{ss['filename']}"
            del ss["path"]

        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"GitHub compliance check error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/compliance/datadog/services", methods=["GET"])
def datadog_services_list():
    """Return all Datadog service areas."""
    services = [
        {"id": svc_id, "name": info["name"], "description": info["description"]}
        for svc_id, info in DATADOG_SERVICE_PAGES.items()
    ]
    return jsonify({"success": True, "services": services})


@app.route("/api/compliance/datadog/checks/<service_id>", methods=["GET"])
def datadog_checks_list(service_id):
    """Return checks for a specific Datadog service area."""
    service_info = DATADOG_SERVICE_PAGES.get(service_id)
    if not service_info:
        return jsonify({"error": f"Unknown service: {service_id}"}), 404
    checks = [
        {"id": c["id"], "name": c["name"], "description": c["description"]}
        for c in service_info.get("checks", [])
    ]
    return jsonify({"success": True, "checks": checks})


@app.route("/api/compliance/datadog", methods=["POST"])
def datadog_compliance():
    """Run a Datadog compliance check via Playwright browser login."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    email = data.get("email")
    password = data.get("password")
    service = data.get("service")

    if not email:
        return jsonify({"error": "email is required"}), 400
    if not password:
        return jsonify({"error": "password is required"}), 400
    if not service:
        return jsonify({"error": "service is required"}), 400

    check_id = data.get("check_id")
    site = data.get("site", "datadoghq.com")

    try:
        logger.info(f"Starting Datadog compliance check: service={service}, check={check_id}")
        result = check_datadog_service(email, password, service, check_id=check_id, site=site)

        for ss in result.get("screenshots", []):
            ss["url_path"] = f"/api/screenshots/{ss['filename']}"
            del ss["path"]

        return jsonify({"success": True, "result": result})
    except Exception as e:
        logger.error(f"Datadog compliance check error: {e}")
        return jsonify({"error": str(e)}), 500



@app.route("/api/screenshots/<filename>", methods=["GET"])
def serve_screenshot(filename):
    """Serve a compliance check screenshot."""
    from flask import send_from_directory
    screenshots_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "screenshots")
    return send_from_directory(screenshots_dir, filename)


if __name__ == "__main__":
    initialize()
    app.run(host="0.0.0.0", port=5000, debug=Config.DEBUG)
