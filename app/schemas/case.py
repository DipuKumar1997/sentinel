import uuid
from datetime import datetime

from pydantic import BaseModel


class CaseOut(BaseModel):
    id: uuid.UUID
    case_number: str
    status: str
    priority: str
    summary: str | None
    created_at: datetime
    reporter_user_id: uuid.UUID

    model_config = {"from_attributes": True}


class CaseSubmitResponse(BaseModel):
    case: CaseOut
    evidence_sha256: str
    message: str


class NotRegisteredResponse(BaseModel):
    """Returned when the reporter's email domain/account is not a
    registered organization/user in the platform.
    """
    registered: bool = False
    message: str
    registration_url: str = "/api/v1/auth/register"
