import uuid

from pydantic import BaseModel


class RiskScoreOut(BaseModel):
    score: int
    classification: str
    confidence_band: str
    rationale_summary: str

    model_config = {"from_attributes": True}
