import uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, String, Text, DateTime, Float, Integer, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
from pgvector.sqlalchemy import Vector
from config import Config

Base = declarative_base()

engine = create_engine(Config.DATABASE_URL, pool_pre_ping=True, pool_size=5)
SessionLocal = sessionmaker(bind=engine)


def _iso_utc(value):
    """Serialize naive UTC datetimes with an explicit Z suffix."""
    if not value:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


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
            "created_at": _iso_utc(self.created_at),
            "completed_at": _iso_utc(self.completed_at),
            "status": self.status,
        }


class MonitoringSnapshot(Base):
    """Cached provider-wide monitoring snapshots for low-cost background refresh."""
    __tablename__ = "monitoring_snapshots"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    provider = Column(String(50), nullable=False, index=True)
    status = Column(String(20), default="pending", nullable=False)
    result = Column(JSON, default=dict, nullable=False)
    summary = Column(JSON, default=dict, nullable=False)
    collected_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    source = Column(String(20), default="scheduled", nullable=False)
    error = Column(Text)

    def to_dict(self):
        return {
            "id": self.id,
            "provider": self.provider,
            "status": self.status,
            "result": self.result,
            "summary": self.summary,
            "collected_at": _iso_utc(self.collected_at),
            "source": self.source,
            "error": self.error,
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
