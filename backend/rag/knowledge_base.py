import json
import os
import logging

from rag.vector_store import VectorStore
from rag.models import EvidencePattern, get_session

logger = logging.getLogger(__name__)


def initialize_knowledge_base():
    """Load evidence patterns from JSON seed data into the vector store."""
    store = VectorStore()

    # Check if already initialized
    if store.get_pattern_count() > 0:
        logger.info(f"Knowledge base already initialized with {store.get_pattern_count()} patterns.")
        return

    # Load seed data
    data_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "knowledge_data",
        "evidence_patterns.json",
    )

    if not os.path.exists(data_path):
        logger.warning(f"Seed data not found at {data_path}")
        return

    with open(data_path, "r") as f:
        patterns = json.load(f)

    logger.info(f"Loading {len(patterns)} evidence patterns into knowledge base...")

    for i, pattern in enumerate(patterns):
        try:
            store.add_pattern(
                category=pattern["category"],
                title=pattern["title"],
                description=pattern["description"],
                indicators=pattern["indicators"],
                risk_level=pattern["risk_level"],
            )
            logger.info(f"  [{i+1}/{len(patterns)}] Added: {pattern['title']}")
        except Exception as e:
            logger.error(f"  [{i+1}/{len(patterns)}] Failed: {pattern['title']} - {e}")

    logger.info(f"Knowledge base initialized with {store.get_pattern_count()} patterns.")
