import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base, TimestampMixin, UUIDPKMixin


class AnalysisRunStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    DEGRADED = "degraded"  # completed with one or more providers unavailable


class AnalysisRun(UUIDPKMixin, TimestampMixin, Base):
    """One execution of the full analysis pipeline against a case.

    Re-analysis (e.g. after new threat intel arrives) creates a new run
    rather than mutating a previous one, preserving history.
    """

    __tablename__ = "analysis_runs"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[AnalysisRunStatus] = mapped_column(
        Enum(AnalysisRunStatus, name="analysis_run_status"), default=AnalysisRunStatus.QUEUED
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    pipeline_version: Mapped[str] = mapped_column(String(32), default="0.1.0")
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)


class AnalysisFinding(UUIDPKMixin, TimestampMixin, Base):
    """A single deterministic or ML-derived finding produced by one engine.

    Each finding carries its own evidence pointer and confidence so the
    risk-fusion layer -- and the human analyst -- can see exactly why it
    fired.
    """

    __tablename__ = "analysis_findings"

    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    engine: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. header_forensics, url_analysis, bec_heuristics
    code: Mapped[str] = mapped_column(String(128), nullable=False)  # e.g. SPF_FAIL, NEWLY_REGISTERED_DOMAIN
    severity: Mapped[str] = mapped_column(String(16), nullable=False)  # info|low|medium|high|critical
    confidence: Mapped[float] = mapped_column(Float, nullable=False)  # 0.0-1.0
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)  # e.g. "ioc_record:<id>"


class ModelPrediction(UUIDPKMixin, TimestampMixin, Base):
    """Raw output of an individual ML model, kept separate from the fused
    findings so model provenance/version is always traceable.
    """

    __tablename__ = "model_predictions"

    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    model_name: Mapped[str] = mapped_column(String(128), nullable=False)
    model_version: Mapped[str] = mapped_column(String(32), nullable=False)
    label: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. phishing, bec, benign
    probability: Mapped[float] = mapped_column(Float, nullable=False)
    is_external_model: Mapped[bool] = mapped_column(default=True)  # True unless a proprietary model


class RiskScore(UUIDPKMixin, TimestampMixin, Base):
    """The fused, explainable risk score for a case at a point in time."""

    __tablename__ = "risk_scores"

    analysis_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False)  # 0-100
    classification: Mapped[str] = mapped_column(String(32), nullable=False)  # benign|suspicious|likely_malicious|malicious
    confidence_band: Mapped[str] = mapped_column(String(16), nullable=False)  # low|medium|high
    rationale_summary: Mapped[str] = mapped_column(Text, nullable=False)
