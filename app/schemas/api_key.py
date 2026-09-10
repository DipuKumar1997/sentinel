import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class CreateApiKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class ApiKeyCreatedResponse(BaseModel):
    id: uuid.UUID
    name: str
    key_prefix: str
    raw_key: str
    message: str = (
        "Store this key now -- it is shown only once and cannot be retrieved again. "
        "Use it in the 'X-API-Key' header when calling /ingestion/eml or /ingestion/msg."
    )


class ApiKeyOut(BaseModel):
    id: uuid.UUID
    name: str
    key_prefix: str
    is_active: bool
    last_used_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}
