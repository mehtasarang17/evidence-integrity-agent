import os
import hashlib
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration."""

    # Flask
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"
    MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50"))
    MAX_CONTENT_LENGTH = MAX_UPLOAD_SIZE_MB * 1024 * 1024
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")

    # Database
    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        "postgresql://evidence_user:evidence_secure_pass_2024@localhost:5432/evidence_integrity",
    )

    # AWS Bedrock
    AWS_BEARER_TOKEN = os.getenv("AWS_BEARER_TOKEN_BEDROCK", "")
    AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "ap-south-1")
    BEDROCK_MODEL = os.getenv("BEDROCK_MODEL", "apac.amazon.nova-lite-v1:0")
    EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "amazon.titan-embed-text-v2:0")
    EMBEDDING_DIMENSIONS = int(os.getenv("EMBEDDING_DIMENSIONS", "1024"))

    # Compliance provider credentials
    COMPLIANCE_AWS_ACCESS_KEY = os.getenv("COMPLIANCE_AWS_ACCESS_KEY", "")
    COMPLIANCE_AWS_SECRET_KEY = os.getenv("COMPLIANCE_AWS_SECRET_KEY", "")
    COMPLIANCE_AWS_REGION = os.getenv("COMPLIANCE_AWS_REGION", AWS_REGION)
    COMPLIANCE_AWS_ACCOUNT_ID = os.getenv("COMPLIANCE_AWS_ACCOUNT_ID", "")
    COMPLIANCE_AWS_IAM_USERNAME = os.getenv("COMPLIANCE_AWS_IAM_USERNAME", "")
    COMPLIANCE_AWS_IAM_PASSWORD = os.getenv("COMPLIANCE_AWS_IAM_PASSWORD", "")

    COMPLIANCE_AZURE_ACCESS_TOKEN = os.getenv("COMPLIANCE_AZURE_ACCESS_TOKEN", "")
    COMPLIANCE_AZURE_TENANT_ID = os.getenv("COMPLIANCE_AZURE_TENANT_ID", "")
    COMPLIANCE_AZURE_CLIENT_ID = os.getenv("COMPLIANCE_AZURE_CLIENT_ID", "")
    COMPLIANCE_AZURE_CLIENT_SECRET = os.getenv("COMPLIANCE_AZURE_CLIENT_SECRET", "")

    COMPLIANCE_GCP_ACCESS_TOKEN = os.getenv("COMPLIANCE_GCP_ACCESS_TOKEN", "")
    COMPLIANCE_GCP_SCOPE = os.getenv("COMPLIANCE_GCP_SCOPE", "")
    COMPLIANCE_GCP_PROJECT_IDS = os.getenv("COMPLIANCE_GCP_PROJECT_IDS", "")

    COMPLIANCE_IBM_CLOUD_API_KEY = os.getenv("COMPLIANCE_IBM_CLOUD_API_KEY", "")

    COMPLIANCE_OCI_TENANCY_OCID = os.getenv("COMPLIANCE_OCI_TENANCY_OCID", "")
    COMPLIANCE_OCI_USER_OCID = os.getenv("COMPLIANCE_OCI_USER_OCID", "")
    COMPLIANCE_OCI_FINGERPRINT = os.getenv("COMPLIANCE_OCI_FINGERPRINT", "")
    COMPLIANCE_OCI_PRIVATE_KEY = os.getenv("COMPLIANCE_OCI_PRIVATE_KEY", "")
    COMPLIANCE_OCI_PRIVATE_KEY_PATH = os.getenv("COMPLIANCE_OCI_PRIVATE_KEY_PATH", "")
    COMPLIANCE_OCI_PASSPHRASE = os.getenv("COMPLIANCE_OCI_PASSPHRASE", "")
    COMPLIANCE_OCI_REGION = os.getenv("COMPLIANCE_OCI_REGION", "us-ashburn-1")

    COMPLIANCE_GITHUB_TOKEN = os.getenv("COMPLIANCE_GITHUB_TOKEN", "")
    COMPLIANCE_GITLAB_TOKEN = os.getenv("COMPLIANCE_GITLAB_TOKEN", "")
    COMPLIANCE_GITLAB_BASE_URL = os.getenv("COMPLIANCE_GITLAB_BASE_URL", "https://gitlab.com")
    COMPLIANCE_SLACK_TOKEN = os.getenv("COMPLIANCE_SLACK_TOKEN", "")
    COMPLIANCE_TEAMS_ACCESS_TOKEN = os.getenv("COMPLIANCE_TEAMS_ACCESS_TOKEN", "")
    COMPLIANCE_TEAMS_TENANT_ID = os.getenv("COMPLIANCE_TEAMS_TENANT_ID", "")
    COMPLIANCE_TEAMS_CLIENT_ID = os.getenv("COMPLIANCE_TEAMS_CLIENT_ID", "")
    COMPLIANCE_TEAMS_CLIENT_SECRET = os.getenv("COMPLIANCE_TEAMS_CLIENT_SECRET", "")
    MONITORING_REFRESH_INTERVAL_SECONDS = int(os.getenv("MONITORING_REFRESH_INTERVAL_SECONDS", "300"))
    MONITORING_FRONTEND_POLL_SECONDS = int(os.getenv("MONITORING_FRONTEND_POLL_SECONDS", "30"))

    # LangSmith
    LANGCHAIN_TRACING_V2 = os.getenv("LANGCHAIN_TRACING_V2", "false").lower() == "true"
    LANGCHAIN_API_KEY = os.getenv("LANGCHAIN_API_KEY", "")
    LANGCHAIN_PROJECT = os.getenv("LANGCHAIN_PROJECT", "evidence-integrity-agent")

    # Allowed file extensions
    ALLOWED_EXTENSIONS = {
        "png", "jpg", "jpeg", "gif", "bmp", "tiff", "webp",  # Images
        "pdf",                                                  # Documents
        "log", "txt", "csv", "json", "xml",                   # Logs/Text
    }

    @classmethod
    def is_allowed_file(cls, filename: str) -> bool:
        return "." in filename and filename.rsplit(".", 1)[1].lower() in cls.ALLOWED_EXTENSIONS


def resolved_teams_client_credentials() -> tuple[str, str, str]:
    tenant_id = Config.COMPLIANCE_TEAMS_TENANT_ID or Config.COMPLIANCE_AZURE_TENANT_ID
    client_id = Config.COMPLIANCE_TEAMS_CLIENT_ID or Config.COMPLIANCE_AZURE_CLIENT_ID
    client_secret = Config.COMPLIANCE_TEAMS_CLIENT_SECRET or Config.COMPLIANCE_AZURE_CLIENT_SECRET
    return tenant_id, client_id, client_secret


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
    if provider == "slack":
        return f"{Config.COMPLIANCE_SLACK_TOKEN}"
    if provider == "teams":
        if Config.COMPLIANCE_TEAMS_ACCESS_TOKEN:
            return f"token|{Config.COMPLIANCE_TEAMS_ACCESS_TOKEN}"
        tenant_id, client_id, _ = resolved_teams_client_credentials()
        return f"sp|{tenant_id}|{client_id}"
    return ""
