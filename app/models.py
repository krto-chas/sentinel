from datetime import UTC, datetime
from pydantic import BaseModel, Field


class UploadRecord(BaseModel):
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    filename: str
    sha256: str
    content_type: str
    status: str = Field(default="accepted")
    decision: str = Field(default="accepted")
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_reasons: list[str] = Field(default_factory=list)
    scan_status: str = Field(default="clean")
    scan_engine: str = Field(default="mock")
    scan_detail: str = Field(default="No signature matched")
    deduplicated: bool = Field(default=False)
    user_id: str = Field(default="anonymous")