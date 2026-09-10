import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.analysis import AnalysisFinding, AnalysisRun, RiskScore
from app.models.case import Case
from app.models.user import User
from app.schemas.analysis import RiskScoreOut
from app.schemas.case import CaseOut
from app.security.deps import get_current_user

router = APIRouter(prefix="/cases", tags=["cases"])


@router.get("", response_model=list[CaseOut])
async def list_cases(
    current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    """Tenant-isolated: only cases belonging to the caller's organization
    are ever returned, regardless of role.
    """
    result = await db.execute(
        select(Case).where(Case.organization_id == current_user.organization_id).order_by(Case.created_at.desc())
    )
    return result.scalars().all()


@router.get("/{case_id}", response_model=CaseOut)
async def get_case(
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    case = await db.get(Case, case_id)
    if case is None or case.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    return case


@router.get("/{case_id}/risk-score", response_model=RiskScoreOut)
async def get_latest_risk_score(
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    case = await db.get(Case, case_id)
    if case is None or case.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")

    result = await db.execute(
        select(RiskScore).where(RiskScore.case_id == case_id).order_by(RiskScore.created_at.desc())
    )
    risk_score = result.scalars().first()
    if risk_score is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No risk score computed yet.")
    return risk_score


@router.get("/{case_id}/findings")
async def get_findings(
    case_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    case = await db.get(Case, case_id)
    if case is None or case.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")

    runs = (
        await db.execute(select(AnalysisRun).where(AnalysisRun.case_id == case_id).order_by(AnalysisRun.created_at.desc()))
    ).scalars().all()
    if not runs:
        return []

    latest_run = runs[0]
    findings = (
        await db.execute(select(AnalysisFinding).where(AnalysisFinding.analysis_run_id == latest_run.id))
    ).scalars().all()

    return [
        {
            "engine": f.engine,
            "code": f.code,
            "severity": f.severity,
            "confidence": f.confidence,
            "description": f.description,
            "evidence_ref": f.evidence_ref,
        }
        for f in findings
    ]
