import uuid
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Text, DateTime, Float, Integer, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
from pgvector.sqlalchemy import Vector
from config import Config

Base = declarative_base()

engine = create_engine(Config.DATABASE_URL, pool_pre_ping=True, pool_size=5)
SessionLocal = sessionmaker(bind=engine)


class EvidencePattern(Base):
    """Knowledge base entries for evidence tampering patterns."""
    __tablename__ = "evidence_patterns"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    category = Column(String(100), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    indicators = Column(Text, nullable=False)
    risk_level = Column(String(20), nullable=False)
    embedding = Column(Vector(1024))
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "indicators": self.indicators,
            "risk_level": self.risk_level,
        }


class AnalysisRecord(Base):
    """Records of evidence analysis runs."""
    __tablename__ = "analysis_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    file_id = Column(String(36), nullable=False, index=True)
    original_filename = Column(String(255))
    file_type = Column(String(50))
    file_size = Column(Integer)

    # Results
    authenticity_score = Column(Float, default=0.0)
    tamper_risk = Column(String(20), default="Unknown")
    metadata_findings = Column(JSON, default=dict)
    hash_findings = Column(JSON, default=dict)
    visual_findings = Column(JSON, default=dict)
    rag_findings = Column(JSON, default=dict)
    report = Column(JSON, default=dict)

    # Hashes
    sha256 = Column(String(64))
    md5 = Column(String(32))
    perceptual_hash = Column(String(32))

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    status = Column(String(20), default="pending")

    def to_dict(self):
        return {
            "id": self.id,
            "file_id": self.file_id,
            "original_filename": self.original_filename,
            "file_type": self.file_type,
            "file_size": self.file_size,
            "authenticity_score": self.authenticity_score,
            "tamper_risk": self.tamper_risk,
            "metadata_findings": self.metadata_findings,
            "hash_findings": self.hash_findings,
            "visual_findings": self.visual_findings,
            "rag_findings": self.rag_findings,
            "report": self.report,
            "sha256": self.sha256,
            "md5": self.md5,
            "perceptual_hash": self.perceptual_hash,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status,
        }


def init_db():
    """Create all tables and install pgvector extension."""
    with engine.connect() as conn:
        conn.execute(
            __import__("sqlalchemy").text("CREATE EXTENSION IF NOT EXISTS vector")
        )
        conn.commit()
    Base.metadata.create_all(bind=engine)


def get_session():
    """Get a database session."""
    session = SessionLocal()
    try:
        return session
    except Exception:
        session.close()
        raise
