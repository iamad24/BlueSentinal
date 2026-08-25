from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    event_id: str | None = None
    timestamp: datetime
    host: str
    os: str
    event_type: str

    user: str | None = None
    process: str | None = None
    parent_process: str | None = None
    command_line: str | None = None

    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None

    file_path: str | None = None
    file_hash: str | None = None
    registry_key: str | None = None

    log_source: str | None = None
    raw_event: dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    matched: bool
    rule_id: str | None = None
    rule_title: str | None = None
    severity: str | None = None
    description: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class SecurityAlert(BaseModel):
    alert_id: str
    timestamp: datetime

    rule_id: str
    title: str
    severity: str

    host: str
    user: str | None = None

    event_type: str
    description: str

    mitre_techniques: list[str] = Field(default_factory=list)

    source_ip: str | None = None
    destination_ip: str | None = None

    evidence: dict[str, Any] = Field(default_factory=dict)