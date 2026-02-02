from pydantic import BaseModel, Field


class UploadRecord(BaseModel):
    filename: str
    content_type: str
    status: str = Field(default="accepted")
