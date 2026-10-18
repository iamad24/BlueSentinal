
"""BlueSentinel XDR FastAPI backend.

Features:
- Event ingestion and normalization
- Sigma detection and alert generation
- SQLite persistence
- Threat hunting and findings
- Dashboard statistics
- Local frontend CORS
- Detection and API error logging
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ValidationError

from Engine.detection.alert_builder import AlertBuilder
from Engine.detection.engine import DetectionEngine
from Engine.detection.models import DetectionResult, SecurityAlert, SecurityEvent


# --------------------------------------------------
# Configuration
# --------------------------------------------------

logger = logging.getLogger("bluesentinel.api")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_PATH = PROJECT_ROOT / "bluesentinel.db"


# --------------------------------------------------
# Application startup
# --------------------------------------------------

def initialize_database() -> None:
    """Create the required SQLite tables if they do not exist."""
    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(str(DATABASE_PATH), timeout=10) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT,
                created_at TEXT NOT NULL,
                event_json TEXT NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT,
                created_at TEXT NOT NULL,
                alert_json TEXT NOT NULL
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                finding_json TEXT NOT NULL
            )
            """
        )


@asynccontextmanager
async def lifespan(_app: FastAPI):
    initialize_database()
    logger.info("BlueSentinel XDR database initialized")
    yield


app = FastAPI(
    title="BlueSentinel XDR",
    description="AI Detection Engineering and Threat Hunting Platform",
    version="1.1.0",
    lifespan=lifespan,
)


# --------------------------------------------------
# Frontend CORS configuration
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


# --------------------------------------------------
# Request models
# --------------------------------------------------

class EventPayload(BaseModel):
    event: dict[str, Any]


class AlertPayload(BaseModel):
    alert: dict[str, Any]


class HuntPayload(BaseModel):
    hunt_id: str | None = None


# --------------------------------------------------
# General helpers
# --------------------------------------------------

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def json_safe(value: Any) -> Any:
    """Convert Pydantic models and datetimes into JSON-compatible data."""
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, dict):
        return {
            str(key): json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]

    return value


def db_connect() -> sqlite3.Connection:
    """Open a SQLite connection using the configured database path."""
    connection = sqlite3.connect(str(DATABASE_PATH), timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def normalize_event(raw_event: dict[str, Any]) -> SecurityEvent:
    """Normalize common telemetry field names into SecurityEvent."""
    if not isinstance(raw_event, dict):
        raise ValueError("event must be a JSON object")

    event = dict(raw_event)

    # Support common hostname field names.
    if not event.get("host"):
        event["host"] = (
            event.get("hostname")
            or event.get("computer_name")
            or "unknown-host"
        )

    event.setdefault("os", "unknown")
    event.setdefault("event_type", "unknown")
    event.setdefault("timestamp", utc_now().isoformat())

    # Preserve the original event for investigation and evidence.
    if not isinstance(event.get("raw_event"), dict):
        event["raw_event"] = dict(raw_event)

    return SecurityEvent.model_validate(event)


def normalize_detection_result(item: Any) -> DetectionResult:
    """Convert supported detection output into DetectionResult."""
    if isinstance(item, DetectionResult):
        return item

    if hasattr(item, "model_dump"):
        item = item.model_dump()

    return DetectionResult.model_validate(item)


# --------------------------------------------------
# Detection engine
# --------------------------------------------------

def run_detection(event: SecurityEvent) -> list[DetectionResult]:
    """Run the existing detection engine against one normalized event."""
    engine = DetectionEngine()
    results = engine.detect(event)

    return [
        normalize_detection_result(item)
        for item in (results or [])
    ]


def save_alerts(
    alerts: list[SecurityAlert],
) -> list[dict[str, Any]]:
    """Persist generated alerts and return their database records."""
    saved = []
    created_at = utc_now().isoformat()

    with db_connect() as conn:
        for alert in alerts:
            data = json_safe(alert)

            cursor = conn.execute(
                """
                INSERT INTO alerts (alert_id, created_at, alert_json)
                VALUES (?, ?, ?)
                """,
                (
                    data.get("alert_id"),
                    created_at,
                    json.dumps(data),
                ),
            )

            saved.append(
                {
                    "id": cursor.lastrowid,
                    "created_at": created_at,
                    "alert": data,
                }
            )

    return saved


# --------------------------------------------------
# Event and finding storage helpers
# --------------------------------------------------

def load_events() -> list[dict[str, Any]]:
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT event_json FROM events ORDER BY id ASC"
        ).fetchall()

    return [
        json.loads(row["event_json"])
        for row in rows
    ]


def normalize_finding(item: Any) -> dict[str, Any]:
    if hasattr(item, "model_dump"):
        item = item.model_dump(mode="json")

    if not isinstance(item, dict):
        raise ValueError(
            "Threat-hunting engine returned an unsupported finding format"
        )

    return json_safe(item)


def persist_findings(
    findings: list[Any],
) -> list[dict[str, Any]]:
    """Save findings without inserting duplicate finding IDs."""
    saved = []

    with db_connect() as conn:
        for item in findings:
            finding = normalize_finding(item)

            finding_id = (
                finding.get("finding_id")
                or finding.get("id")
            )

            if not finding_id:
                logger.warning(
                    "Skipping finding without finding_id: %r",
                    finding,
                )
                continue

            finding["finding_id"] = str(finding_id)
            created_at = (
                finding.get("created_at")
                or utc_now().isoformat()
            )
            finding["created_at"] = created_at

            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO findings
                    (finding_id, created_at, finding_json)
                VALUES (?, ?, ?)
                """,
                (
                    finding["finding_id"],
                    created_at,
                    json.dumps(finding),
                ),
            )

            saved.append(
                {
                    "id": cursor.lastrowid or None,
                    "created_at": created_at,
                    "finding": finding,
                }
            )

    return saved


# --------------------------------------------------
# Root and health endpoints
# --------------------------------------------------

@app.get("/")
def root() -> dict[str, str]:
    return {
        "project": "BlueSentinel XDR",
        "status": "running",
        "api_docs": "/docs",
    }


@app.get("/health")
def health_check() -> dict[str, str]:
    try:
        initialize_database()

        with db_connect() as conn:
            conn.execute("SELECT 1").fetchone()

        return {
            "status": "healthy",
            "database": "connected",
        }

    except sqlite3.Error as exc:
        logger.exception("Health check failed")
        raise HTTPException(
            status_code=503,
            detail="Database unavailable",
        ) from exc


# --------------------------------------------------
# Event ingestion and retrieval
# --------------------------------------------------

@app.post("/events", status_code=201)
def ingest_event(payload: EventPayload) -> dict[str, Any]:
    """Store an event, run detections, and save any generated alerts."""
    try:
        event = normalize_event(payload.event)

    except (ValidationError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    event_data = json_safe(event)
    created_at = utc_now().isoformat()

    # Store the event before detection so telemetry is not lost
    # if a detection rule or integration fails.
    try:
        with db_connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO events (event_id, created_at, event_json)
                VALUES (?, ?, ?)
                """,
                (
                    event.event_id,
                    created_at,
                    json.dumps(event_data),
                ),
            )
            event_row_id = cursor.lastrowid

    except sqlite3.Error as exc:
        logger.exception("Failed to persist event")
        raise HTTPException(
            status_code=500,
            detail="Failed to store event",
        ) from exc

    try:
        detections = run_detection(event)
        alerts = AlertBuilder().build_batch(event, detections)
        saved_alerts = save_alerts(alerts)

        detection_status = "completed"
        detection_error = None

    except Exception as exc:
        logger.exception(
            "Detection failed for stored event id=%s",
            event.event_id,
        )

        detections = []
        saved_alerts = []
        detection_status = "failed"
        detection_error = str(exc)

    response = {
        "id": event_row_id,
        "created_at": created_at,
        "event": event_data,
        "detections_matched": len(detections),
        "alerts_created": len(saved_alerts),
        "alerts": saved_alerts,
        "detection_status": detection_status,
    }

    if detection_error:
        response["detection_error"] = detection_error

    return response


@app.get("/events")
def get_events(
    limit: int = Query(default=500, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    with db_connect() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

        rows = conn.execute(
            """
            SELECT id, created_at, event_json
            FROM events
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()

    return {
        "total": total,
        "items": [
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "event": json.loads(row["event_json"]),
            }
            for row in rows
        ],
    }


# --------------------------------------------------
# Alert creation and retrieval
# --------------------------------------------------

@app.post("/alerts", status_code=201)
def create_alert(payload: AlertPayload) -> dict[str, Any]:
    try:
        alert = SecurityAlert.model_validate(payload.alert)

    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=exc.errors(),
        ) from exc

    data = json_safe(alert)
    created_at = utc_now().isoformat()

    with db_connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO alerts (alert_id, created_at, alert_json)
            VALUES (?, ?, ?)
            """,
            (
                data.get("alert_id"),
                created_at,
                json.dumps(data),
            ),
        )

    return {
        "id": cursor.lastrowid,
        "created_at": created_at,
        "alert": data,
    }


@app.get("/alerts")
def get_alerts(
    limit: int = Query(default=500, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    with db_connect() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        rows = conn.execute(
            """
            SELECT id, created_at, alert_json
            FROM alerts
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()

    return {
        "total": total,
        "items": [
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "alert": json.loads(row["alert_json"]),
            }
            for row in rows
        ],
    }


# --------------------------------------------------
# Threat hunting
# --------------------------------------------------

@app.post("/hunts/run")
def run_hunt(
    payload: HuntPayload | None = None,
) -> dict[str, Any]:
    payload = payload or HuntPayload()
    events = load_events()

    if not events:
        return {
            "events_examined": 0,
            "findings_created": 0,
            "findings": [],
        }

    try:
        from ThreatHunting.hunt_engine import HuntEngine

        hunt_engine = HuntEngine()

        if payload.hunt_id:
            findings = hunt_engine.run_hunt(
                events,
                payload.hunt_id,
            )
        elif hasattr(hunt_engine, "run_all"):
            findings = hunt_engine.run_all(events)
        else:
            # The existing project has TH-001 as its default hunt.
            findings = hunt_engine.run_hunt(events, "TH-001")

        findings = list(findings or [])
        persist_findings(findings)

        return {
            "events_examined": len(events),
            "findings_created": len(findings),
            "findings": [
                normalize_finding(item)
                for item in findings
            ],
        }

    except Exception as exc:
        logger.exception("Threat-hunting request failed")
        raise HTTPException(
            status_code=500,
            detail="Threat hunt failed; check backend logs",
        ) from exc


@app.get("/findings")
def get_findings(
    limit: int = Query(default=500, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    with db_connect() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM findings"
        ).fetchone()[0]

        rows = conn.execute(
            """
            SELECT id, created_at, finding_json
            FROM findings
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()

    return {
        "total": total,
        "items": [
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "finding": json.loads(row["finding_json"]),
            }
            for row in rows
        ],
    }


# --------------------------------------------------
# Dashboard statistics
# --------------------------------------------------

@app.get("/stats")
def get_stats() -> dict[str, int]:
    with db_connect() as conn:
        events = conn.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

        alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        findings = conn.execute(
            "SELECT COUNT(*) FROM findings"
        ).fetchone()[0]

        high_critical = 0

        rows = conn.execute(
            "SELECT alert_json FROM alerts"
        ).fetchall()

        for row in rows:
            severity = str(
                json.loads(row["alert_json"]).get("severity", "")
            ).lower()

            if severity in {"high", "critical"}:
                high_critical += 1

    return {
        "events": events,
        "alerts": alerts,
        "findings": findings,
        "high_critical_alerts": high_critical,
    }


# --------------------------------------------------
# Local development entry point
# --------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "Engine.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
