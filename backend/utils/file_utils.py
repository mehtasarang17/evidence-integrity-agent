import os
import uuid
import shutil
from werkzeug.utils import secure_filename
from config import Config


def save_uploaded_file(file) -> dict:
    """Save an uploaded file and return file metadata."""
    file_id = str(uuid.uuid4())
    original_filename = secure_filename(file.filename)
    extension = original_filename.rsplit(".", 1)[1].lower() if "." in original_filename else ""

    # Create unique directory for this upload
    upload_dir = os.path.join(Config.UPLOAD_FOLDER, file_id)
    os.makedirs(upload_dir, exist_ok=True)

    # Save file
    saved_filename = f"{file_id}.{extension}" if extension else file_id
    file_path = os.path.join(upload_dir, saved_filename)
    file.save(file_path)

    file_size = os.path.getsize(file_path)

    return {
        "file_id": file_id,
        "original_filename": original_filename,
        "saved_path": file_path,
        "extension": extension,
        "size_bytes": file_size,
        "size_human": _human_readable_size(file_size),
    }


def get_file_path(file_id: str) -> str | None:
    """Get the path of a previously uploaded file."""
    upload_dir = os.path.join(Config.UPLOAD_FOLDER, file_id)
    if not os.path.exists(upload_dir):
        return None
    files = os.listdir(upload_dir)
    if not files:
        return None
    return os.path.join(upload_dir, files[0])


def cleanup_upload(file_id: str) -> None:
    """Remove uploaded file and its directory."""
    upload_dir = os.path.join(Config.UPLOAD_FOLDER, file_id)
    if os.path.exists(upload_dir):
        shutil.rmtree(upload_dir)


def get_mime_type(file_path: str) -> str:
    """Detect MIME type of a file."""
    try:
        import magic
        return magic.from_file(file_path, mime=True)
    except ImportError:
        # Fallback based on extension
        ext = file_path.rsplit(".", 1)[1].lower() if "." in file_path else ""
        mime_map = {
            "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
            "gif": "image/gif", "bmp": "image/bmp", "tiff": "image/tiff",
            "webp": "image/webp", "pdf": "application/pdf",
            "log": "text/plain", "txt": "text/plain", "csv": "text/csv",
            "json": "application/json", "xml": "application/xml",
        }
        return mime_map.get(ext, "application/octet-stream")


def is_image_file(file_path: str) -> bool:
    """Check if a file is an image."""
    mime = get_mime_type(file_path)
    return mime.startswith("image/")


def _human_readable_size(size_bytes: int) -> str:
    """Convert bytes to human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"
