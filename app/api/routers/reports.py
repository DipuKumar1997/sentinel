import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.case import Case
from app.models.user import User
from app.security.deps import get_current_user
from app.services.audit import record_audit_event
from app.services.report_generator import generate_and_store_report

router = APIRouter(prefix="/cases", tags=["reports"])


@router.get("/{case_id}/report")
async def get_case_report(
    case_id: uuid.UUID,
    format: Literal["html", "pdf"] = Query("html", description="Report output format."),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns a self-contained forensic report for the case in either
    HTML (default, viewable directly in a browser) or native PDF. Also
    persists a Report + EvidenceObject record for audit purposes.
    """
    case = await db.get(Case, case_id)
    if case is None or case.organization_id != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")

    report, content, media_type = await generate_and_store_report(
        db, case=case, generated_by_user_id=current_user.id, fmt=format
    )

    await record_audit_event(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        action="report.generate",
        resource_type="case",
        resource_id=str(case.id),
        detail={"report_id": str(report.id), "format": format},
    )

    headers = {}
    if format == "pdf":
        headers["Content-Disposition"] = f'attachment; filename="{case.case_number}_report.pdf"'

    return Response(content=content, media_type=media_type, headers=headers)
