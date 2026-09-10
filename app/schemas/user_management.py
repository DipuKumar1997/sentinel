import uuid

from pydantic import BaseModel

from app.models.rbac import RoleName


class UpdateUserRoleRequest(BaseModel):
    role: RoleName


class UserSummaryOut(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    role: str
    status: str
    is_email_verified: bool

    model_config = {"from_attributes": True}
