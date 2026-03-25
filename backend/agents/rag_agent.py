"""RAG Evidence Pattern Agent — Queries knowledge base for relevant tampering patterns."""

import logging
from agents.state import EvidenceState
from rag.vector_store import VectorStore

logger = logging.getLogger(__name__)


def rag_agent(state: EvidenceState) -> dict:
    """Query the knowledge base for evidence patterns relevant to this file."""
    logger.info(f"[RAGAgent] Searching patterns for: {state['original_filename']}")

    try:
        store = VectorStore()

        # Build query from accumulated findings
        query = _build_query(state)

        # Search for relevant patterns
        patterns = store.similarity_search(query, top_k=5)

        # Analyze relevance of found patterns
        relevant_patterns = []
        for pattern in patterns:
            if pattern["similarity"] > 0.3:  # Minimum relevance threshold
                relevant_patterns.append(pattern)

        results = {
            "status": "completed",
            "query_used": query[:200],
            "patterns_found": len(relevant_patterns),
            "patterns": relevant_patterns,
            "risk_contribution": _calculate_risk(relevant_patterns, state),
        }

        logger.info(f"[RAGAgent] Found {len(relevant_patterns)} relevant patterns")
        return {
            "rag_results": results,
            "agents_completed": state.get("agents_completed", []) + ["rag"],
        }

    except Exception as e:
        logger.error(f"[RAGAgent] Error: {e}")
        return {
            "rag_results": {"status": "error", "error": str(e)},
            "errors": state.get("errors", []) + [f"RAGAgent: {e}"],
            "agents_completed": state.get("agents_completed", []) + ["rag"],
        }


def _build_query(state: EvidenceState) -> str:
    """Build a search query from the current analysis state."""
    parts = [f"Evidence file: {state['original_filename']} ({state['file_type']})"]

    # Include metadata anomalies
    meta = state.get("metadata_results", {})
    if meta.get("anomalies"):
        parts.append(f"Metadata anomalies: {', '.join(meta['anomalies'][:3])}")

    # Include visual findings
    visual = state.get("visual_results", {})
    vision = visual.get("vision_analysis", {})
    if vision.get("suspicious_indicators"):
        parts.append(f"Visual indicators: {', '.join(vision['suspicious_indicators'][:3])}")
    if vision.get("tampering_likelihood"):
        parts.append(f"Tampering likelihood: {vision['tampering_likelihood']}")

    # Include ELA findings
    ela = visual.get("ela", {})
    if ela.get("suspicious"):
        parts.append("Error Level Analysis shows suspicious patterns")

    # Include hash info
    hash_info = state.get("hash_results", {})
    if hash_info.get("duplicate_found"):
        parts.append("Duplicate file detected in database")

    return ". ".join(parts)


def _calculate_risk(patterns: list, state: EvidenceState) -> dict:
    """Calculate risk contribution from RAG pattern matching."""
    if not patterns:
        return {
            "score": 100,
            "deductions": 0,
            "reasoning": "No relevant tampering patterns found in knowledge base",
        }

    score = 100
    risk_levels = {"Low": 5, "Medium": 10, "High": 20, "Critical": 30}

    reasoning_parts = []
    for pattern in patterns[:3]:
        deduction = risk_levels.get(pattern["risk_level"], 5)
        similarity_multiplier = pattern["similarity"]
        adjusted_deduction = int(deduction * similarity_multiplier)
        score -= adjusted_deduction
        reasoning_parts.append(
            f"{pattern['title']} ({pattern['risk_level']}, "
            f"similarity: {pattern['similarity']:.2f})"
        )

    return {
        "score": max(0, score),
        "deductions": 100 - max(0, score),
        "reasoning": f"Matched patterns: " + "; ".join(reasoning_parts),
    }
