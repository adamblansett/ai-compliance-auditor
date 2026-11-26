from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class PolicyDocumentCreateRequest(BaseModel):
    title: str = Field(min_length=2, max_length=255)
    filename: str = Field(default="policy.md", min_length=1, max_length=255)
    framework: Literal["SOC2", "HIPAA", "GDPR", "ALL"] = "ALL"
    version: str = Field(default="1.0", min_length=1, max_length=64)
    content: str = Field(min_length=10, max_length=250000)


class PolicyDocumentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    filename: str
    framework: str
    version: str
    document_sha256: str
    pii_redaction_count: int
    chunk_count: int
    uploaded_by: str
    created_at: datetime


class PolicyCitationOut(BaseModel):
    chunk_id: str
    document_id: str
    document_title: str
    framework: str
    section_heading: str
    chunk_index: int
    score: float
    mapped_controls: list[str]
    excerpt: str


class RagQueryRequest(BaseModel):
    query: str = Field(min_length=3, max_length=2000)
    framework: str | None = Field(default=None)
    top_k: int = Field(default=4, ge=1, le=12)


class RagQueryResponse(BaseModel):
    query: str
    answer: str
    llm_provider: str
    pii_redacted: bool
    citations: list[PolicyCitationOut]
