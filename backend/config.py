import os
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
