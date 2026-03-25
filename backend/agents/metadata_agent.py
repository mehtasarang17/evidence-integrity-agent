"""Metadata Extraction Agent — Extracts and analyzes file metadata for anomalies."""

import logging
from agents.state import EvidenceState
from utils.image_utils import extract_image_metadata, extract_text_file_metadata

logger = logging.getLogger(__name__)


def metadata_agent(state: EvidenceState) -> dict:
    """Extract metadata from the evidence file and flag anomalies."""
    logger.info(f"[MetadataAgent] Analyzing: {state['original_filename']}")

    try:
        file_path = state["file_path"]
        file_type = state["file_type"]

        if file_type == "image":
            metadata = extract_image_metadata(file_path)
        else:
            metadata = extract_text_file_metadata(file_path)

        # Count anomalies for scoring
        anomalies = metadata.get("anomalies", [])
        anomaly_count = len(anomalies)

        results = {
            "status": "completed",
            "metadata": metadata,
            "anomaly_count": anomaly_count,
            "anomalies": anomalies,
            "has_exif": bool(metadata.get("exif")),
            "has_gps": bool(metadata.get("gps")),
            "timestamps": metadata.get("timestamps", {}),
            "risk_contribution": _calculate_risk(anomaly_count, file_type, metadata),
        }

        logger.info(f"[MetadataAgent] Found {anomaly_count} anomalies")
        return {
            "metadata_results": results,
            "agents_completed": state.get("agents_completed", []) + ["metadata"],
        }

    except Exception as e:
        logger.error(f"[MetadataAgent] Error: {e}")
        return {
            "metadata_results": {"status": "error", "error": str(e)},
            "errors": state.get("errors", []) + [f"MetadataAgent: {e}"],
            "agents_completed": state.get("agents_completed", []) + ["metadata"],
        }


def _calculate_risk(anomaly_count: int, file_type: str, metadata: dict) -> dict:
    """Calculate risk contribution from metadata analysis."""
    score = 100  # Start at 100 (authentic) and deduct

    # Deductions
    if anomaly_count > 0:
        score -= min(anomaly_count * 10, 40)

    if file_type == "image" and not metadata.get("exif"):
        score -= 15  # Missing EXIF is suspicious for screenshots

    # Check for editing software
    software = metadata.get("exif", {}).get("Software", "")
    if any(sw in software.lower() for sw in ["photoshop", "gimp", "paint"]):
        score -= 20

    return {
        "score": max(0, score),
        "deductions": 100 - max(0, score),
        "reasoning": f"Found {anomaly_count} metadata anomalies. "
                     + ("EXIF data present. " if metadata.get("exif") else "No EXIF data. ")
                     + (f"Editing software detected: {software}. " if software else ""),
    }
