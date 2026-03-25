"""Hash Verification Agent — Computes and verifies file integrity hashes."""

import logging
from agents.state import EvidenceState
from utils.hash_utils import compute_all_hashes, compute_perceptual_hash
from rag.models import AnalysisRecord, get_session

logger = logging.getLogger(__name__)


def hash_agent(state: EvidenceState) -> dict:
    """Compute cryptographic hashes and check for known files."""
    logger.info(f"[HashAgent] Computing hashes for: {state['original_filename']}")

    try:
        file_path = state["file_path"]

        # Compute all hashes
        hashes = compute_all_hashes(file_path)

        # Compute perceptual hash for images
        p_hash = None
        if state["file_type"] == "image":
            p_hash = compute_perceptual_hash(file_path)

        # Check for duplicate/known files in database
        duplicate_check = _check_known_hashes(hashes["sha256"])

        results = {
            "status": "completed",
            "sha256": hashes["sha256"],
            "md5": hashes["md5"],
            "file_size": hashes["file_size"],
            "perceptual_hash": p_hash,
            "duplicate_found": duplicate_check["found"],
            "duplicate_info": duplicate_check.get("info"),
            "risk_contribution": _calculate_risk(duplicate_check),
        }

        logger.info(f"[HashAgent] SHA256: {hashes['sha256'][:16]}... | Duplicate: {duplicate_check['found']}")
        return {
            "hash_results": results,
            "agents_completed": state.get("agents_completed", []) + ["hash"],
        }

    except Exception as e:
        logger.error(f"[HashAgent] Error: {e}")
        return {
            "hash_results": {"status": "error", "error": str(e)},
            "errors": state.get("errors", []) + [f"HashAgent: {e}"],
            "agents_completed": state.get("agents_completed", []) + ["hash"],
        }


def _check_known_hashes(sha256: str) -> dict:
    """Check if this file's hash exists in previous analyses."""
    session = get_session()
    try:
        existing = (
            session.query(AnalysisRecord)
            .filter(AnalysisRecord.sha256 == sha256)
            .first()
        )
        if existing:
            return {
                "found": True,
                "info": {
                    "previous_analysis_id": existing.id,
                    "original_filename": existing.original_filename,
                    "analyzed_at": existing.created_at.isoformat() if existing.created_at else None,
                    "previous_score": existing.authenticity_score,
                },
            }
        return {"found": False}
    finally:
        session.close()


def _calculate_risk(duplicate_check: dict) -> dict:
    """Calculate risk contribution from hash analysis."""
    score = 100

    if duplicate_check["found"]:
        # File was seen before — not necessarily bad, but note it
        score -= 5
        reasoning = (
            f"File previously analyzed as '{duplicate_check['info']['original_filename']}'. "
            f"Previous score: {duplicate_check['info']['previous_score']}"
        )
    else:
        reasoning = "File hash is unique — no previous submissions match."

    return {
        "score": score,
        "deductions": 100 - score,
        "reasoning": reasoning,
    }
