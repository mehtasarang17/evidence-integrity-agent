from utils.bedrock_client import get_embeddings
from sqlalchemy import text
from rag.models import EvidencePattern, get_session
from config import Config


class VectorStore:
    """PostgreSQL + pgvector based vector store for evidence patterns."""

    def __init__(self):
        self.embeddings = get_embeddings()

    def add_pattern(self, category: str, title: str, description: str,
                    indicators: str, risk_level: str) -> str:
        """Add an evidence pattern with its embedding to the store."""
        # Create embedding from combined text
        combined_text = f"{title}\n{description}\n{indicators}"
        embedding = self.embeddings.embed_query(combined_text)

        session = get_session()
        try:
            pattern = EvidencePattern(
                category=category,
                title=title,
                description=description,
                indicators=indicators,
                risk_level=risk_level,
                embedding=embedding,
            )
            session.add(pattern)
            session.commit()
            return pattern.id
        finally:
            session.close()

    def similarity_search(self, query: str, top_k: int = 5) -> list[dict]:
        """Find the most similar evidence patterns using cosine similarity."""
        query_embedding = self.embeddings.embed_query(query)

        session = get_session()
        try:
            # Use pgvector cosine distance operator
            results = session.execute(
                text("""
                    SELECT id, category, title, description, indicators, risk_level,
                           1 - (embedding <=> :query_vec::vector) as similarity
                    FROM evidence_patterns
                    ORDER BY embedding <=> :query_vec::vector
                    LIMIT :limit
                """),
                {"query_vec": str(query_embedding), "limit": top_k},
            )

            patterns = []
            for row in results:
                patterns.append({
                    "id": row.id,
                    "category": row.category,
                    "title": row.title,
                    "description": row.description,
                    "indicators": row.indicators,
                    "risk_level": row.risk_level,
                    "similarity": round(float(row.similarity), 4),
                })
            return patterns
        finally:
            session.close()

    def get_pattern_count(self) -> int:
        """Get total number of patterns in the store."""
        session = get_session()
        try:
            count = session.query(EvidencePattern).count()
            return count
        finally:
            session.close()
