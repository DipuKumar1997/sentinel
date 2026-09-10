"""Email submission/ingestion endpoints.

Enforces the core product rule: the REPORTER is the authenticated caller
(from the JWT), never anything read out of the uploaded email itself. If
the caller's account is not registered/active, we do not attempt to
create a case at all -- registration is a separate, explicit step.

Two upload formats are supported, normalized to the same pipeline:
`.eml` (RFC 5322/MIME) and Outlook `.msg`.
"""
from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db
from app.models.evidence import EvidenceHash, EvidenceKind, EvidenceObject
from app.models.user import User
from app.schemas.case import CaseOut, CaseSubmitResponse
from app.security.deps import get_current_user
from app.services import ingestion
from app.services.audit import record_audit_event

router = APIRouter(prefix="/ingestion", tags=["ingestion"])


async def _handle_submission(
    *,
    file: UploadFile,
    source_format: str,
    allowed_suffixes: tuple[str, ...],
    current_user: User,
    db: AsyncSession,
) -> CaseSubmitResponse:
    if not file.filename or not file.filename.lower().endswith(allowed_suffixes):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=(
                f"This endpoint only accepts {'/'.join(allowed_suffixes)} files. "
                "Use /ingestion/eml for .eml or /ingestion/msg for Outlook .msg files."
            ),
        )

    raw_bytes = await file.read()
    if len(raw_bytes) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty.")
    if len(raw_bytes) > settings.max_upload_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB}MB.",
        )

    try:
        case, email_message, risk_score = await ingestion.ingest_email_and_create_case(
            db,
            organization_id=current_user.organization_id,
            reporter_user_id=current_user.id,
            raw_bytes=raw_bytes,
            original_filename=file.filename,
            source_format=source_format,
        )
    except ingestion.IngestionError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    await record_audit_event(
        db,
        organization_id=current_user.organization_id,
        actor_user_id=current_user.id,
        action=f"case.create_from_{source_format}",
        resource_type="case",
        resource_id=str(case.id),
        detail={"risk_score": risk_score.score, "classification": risk_score.classification},
    )

    evidence_hash = None
    evidence = await db.scalar(
        select(EvidenceObject).where(
            EvidenceObject.case_id == case.id, EvidenceObject.kind == EvidenceKind.RAW_EMAIL
        )
    )
    if evidence:
        hash_row = await db.scalar(select(EvidenceHash).where(EvidenceHash.evidence_object_id == evidence.id))
        evidence_hash = hash_row.hex_digest if hash_row else None

    return CaseSubmitResponse(
        case=CaseOut.model_validate(case),
        evidence_sha256=evidence_hash or "unavailable",
        message=(
            f"Case {case.case_number} created and analyzed. "
            f"Risk score: {risk_score.score}/100 ({risk_score.classification})."
        ),
    )


@router.post("/eml", response_model=CaseSubmitResponse, status_code=status.HTTP_201_CREATED)
async def submit_eml(
    file: UploadFile,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await _handle_submission(
        file=file, source_format="eml", allowed_suffixes=(".eml",),
        current_user=current_user, db=db,
    )


@router.post("/msg", response_model=CaseSubmitResponse, status_code=status.HTTP_201_CREATED)
async def submit_msg(
    file: UploadFile,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    return await _handle_submission(
        file=file, source_format="msg", allowed_suffixes=(".msg",),
        current_user=current_user, db=db,
    )
