from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AlertEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    alert_type: str
    severity: str
    title: str
    detail: str
    entity_type: str
    entity_id: str
    status: str
    dispatched_webhooks_count: int
    acknowledged_by: str | None = None
    acknowledged_at: datetime | None = None
    created_at: datetime


class WebhookCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    target_url: str = Field(min_length=8, max_length=500)
    event_types: list[str] = Field(default_factory=list)
    secret_hmac: str = Field(default="", max_length=255)


class AlertWebhookOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    target_url: str
    event_types_json: list[str]
    is_active: bool
    last_delivery_status: str | None = None
    created_by: str
    created_at: datetime
