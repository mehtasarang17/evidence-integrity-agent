"""LangGraph state schema for the Evidence Integrity workflow."""

from typing import TypedDict, Optional, Any


class EvidenceState(TypedDict):
    """State that flows through the LangGraph evidence analysis pipeline."""

    # Input
    file_id: str
    file_path: str
    original_filename: str
    file_type: str  # "image", "log", "document"
    mime_type: str

    # Agent outputs
    metadata_results: dict[str, Any]
    hash_results: dict[str, Any]
    visual_results: dict[str, Any]
    rag_results: dict[str, Any]

    # Final report
    report: dict[str, Any]
    authenticity_score: float
    tamper_risk: str  # "Low", "Medium", "High", "Critical"

    # Tracking
    agents_completed: list[str]
    errors: list[str]
