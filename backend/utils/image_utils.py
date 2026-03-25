import os
import struct
from datetime import datetime
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS


def extract_image_metadata(file_path: str) -> dict:
    """Extract comprehensive metadata from an image file."""
    metadata = {
        "basic": _extract_basic_info(file_path),
        "exif": {},
        "gps": {},
        "timestamps": {},
        "anomalies": [],
    }

    try:
        img = Image.open(file_path)
        metadata["basic"].update({
            "format": img.format,
            "mode": img.mode,
            "width": img.width,
            "height": img.height,
            "resolution": f"{img.width}x{img.height}",
        })

        # Extract EXIF data
        exif_data = img.getexif()
        if exif_data:
            metadata["exif"] = _parse_exif(exif_data)
            metadata["gps"] = _extract_gps(exif_data)
            metadata["timestamps"] = _extract_timestamps(exif_data, file_path)
            metadata["anomalies"] = _detect_metadata_anomalies(metadata)
    except Exception as e:
        metadata["anomalies"].append(f"Failed to fully parse image: {str(e)}")

    return metadata


def compute_ela(file_path: str, quality: int = 90) -> dict:
    """Compute Error Level Analysis to detect manipulated regions."""
    try:
        import tempfile
        import numpy as np

        original = Image.open(file_path).convert("RGB")

        # Save at reduced quality and reload
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
            tmp_path = tmp.name
            original.save(tmp_path, "JPEG", quality=quality)

        resaved = Image.open(tmp_path)

        # Compute difference
        orig_array = list(original.getdata())
        resaved_array = list(resaved.getdata())

        total_diff = 0
        max_diff = 0
        pixel_count = len(orig_array)

        for o, r in zip(orig_array, resaved_array):
            diff = sum(abs(a - b) for a, b in zip(o, r))
            total_diff += diff
            max_diff = max(max_diff, diff)

        avg_diff = total_diff / (pixel_count * 3) if pixel_count > 0 else 0

        os.unlink(tmp_path)

        return {
            "average_error_level": round(avg_diff, 2),
            "max_error_level": max_diff,
            "pixel_count": pixel_count,
            "suspicious": avg_diff > 10,
            "interpretation": (
                "High error levels detected - possible manipulation"
                if avg_diff > 10
                else "Error levels within normal range"
            ),
        }
    except Exception as e:
        return {"error": str(e), "suspicious": False}


def extract_text_file_metadata(file_path: str) -> dict:
    """Extract metadata from text/log files."""
    stat = os.stat(file_path)
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception:
        content = ""

    line_count = content.count("\n") + 1 if content else 0
    return {
        "basic": _extract_basic_info(file_path),
        "content_stats": {
            "line_count": line_count,
            "char_count": len(content),
            "word_count": len(content.split()),
            "encoding": "utf-8",
        },
        "timestamps": {
            "file_created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "file_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        },
        "anomalies": [],
    }


def _extract_basic_info(file_path: str) -> dict:
    """Extract basic file system information."""
    stat = os.stat(file_path)
    return {
        "filename": os.path.basename(file_path),
        "file_size": stat.st_size,
        "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
    }


def _parse_exif(exif_data) -> dict:
    """Parse EXIF tags into readable dictionary."""
    parsed = {}
    for tag_id, value in exif_data.items():
        tag_name = TAGS.get(tag_id, str(tag_id))
        try:
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            elif isinstance(value, (tuple, list)):
                value = str(value)
            parsed[tag_name] = str(value)
        except Exception:
            parsed[tag_name] = "<unparseable>"
    return parsed


def _extract_gps(exif_data) -> dict:
    """Extract GPS information from EXIF data."""
    gps_info = {}
    gps_ifd = exif_data.get_ifd(0x8825)
    if gps_ifd:
        for tag_id, value in gps_ifd.items():
            tag_name = GPSTAGS.get(tag_id, str(tag_id))
            gps_info[tag_name] = str(value)
    return gps_info


def _extract_timestamps(exif_data, file_path: str) -> dict:
    """Extract all timestamps from EXIF and filesystem."""
    stat = os.stat(file_path)
    timestamps = {
        "file_created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "file_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
    }

    # EXIF timestamps
    exif_time_tags = {
        "DateTimeOriginal": 36867,
        "DateTimeDigitized": 36868,
        "DateTime": 306,
    }
    for name, tag_id in exif_time_tags.items():
        value = exif_data.get(tag_id)
        if value:
            timestamps[name] = str(value)

    return timestamps


def _detect_metadata_anomalies(metadata: dict) -> list:
    """Detect potential anomalies in metadata."""
    anomalies = []

    # Check for missing EXIF on images that usually have it
    if not metadata.get("exif"):
        anomalies.append("No EXIF data found - may have been stripped (common in edited images)")

    # Check for software editing indicators
    software = metadata.get("exif", {}).get("Software", "")
    editing_software = ["photoshop", "gimp", "paint", "snapseed", "lightroom", "canva"]
    for sw in editing_software:
        if sw.lower() in software.lower():
            anomalies.append(f"Detected editing software in EXIF: {software}")
            break

    # Timestamp consistency
    timestamps = metadata.get("timestamps", {})
    if timestamps.get("file_created") and timestamps.get("file_modified"):
        created = timestamps["file_created"]
        modified = timestamps["file_modified"]
        if created > modified:
            anomalies.append("File creation date is after modification date - possible copy or manipulation")

    return anomalies
