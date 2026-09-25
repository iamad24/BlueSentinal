from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    """
    Common normalized security event used throughout
    the BlueSentinel detection pipeline.

    Different telemetry sources contain different fields.
    Therefore, event-specific fields are optional.
    """

    # =========================================================
    # Event identification
    # =========================================================

    event_id: str | None = None
    timestamp: datetime

    # =========================================================
    # Host information
    # =========================================================

    host: str
    os: str
    event_type: str

    # =========================================================
    # User / process information
    # =========================================================

    user: str | None = None

    process: str | None = None
    process_id: int | str | None = None

    parent_process: str | None = None
    parent_process_id: int | str | None = None

    command_line: str | None = None

    # =========================================================
    # PowerShell
    # =========================================================

    script_block_text: str | None = None

    # =========================================================
    # Network information
    #
    # These fields are optional because not every event
    # contains network information.
    # =========================================================

    source_ip: str | None = None
    destination_ip: str | None = None

    source_port: int | None = None
    destination_port: int | None = None

    protocol: str | None = None

    # =========================================================
    # File information
    # =========================================================

    file_path: str | None = None
    file_hash: str | None = None

    # =========================================================
    # Registry information
    # =========================================================

    registry_key: str | None = None
    registry_value: str | None = None

    # =========================================================
    # Telemetry source
    # =========================================================

    log_source: str | None = None

    # =========================================================
    # Original raw telemetry
    #
    # Keeping the original event is important for:
    # - investigation
    # - evidence
    # - debugging
    # - future parsing improvements
    # =========================================================

    raw_event: dict[str, Any] = Field(
        default_factory=dict
    )


class DetectionResult(BaseModel):
    """
    Result produced when a Sigma rule is evaluated
    against a SecurityEvent.
    """

    matched: bool

    rule_id: str | None = None
    rule_title: str | None = None

    severity: str | None = None
    description: str | None = None

    mitre_techniques: list[str] = Field(
        default_factory=list
    )

    evidence: dict[str, Any] = Field(
        default_factory=dict
    )


class SecurityAlert(BaseModel):
    """
    Structured security alert generated from
    a successful detection.
    """

    alert_id: str
    timestamp: datetime

    rule_id: str
    title: str
    severity: str

    host: str
    user: str | None = None

    event_type: str
    description: str

    mitre_techniques: list[str] = Field(
        default_factory=list
    )

    source_ip: str | None = None
    destination_ip: str | None = None

    evidence: dict[str, Any] = Field(
        default_factory=dict
    )