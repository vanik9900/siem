from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional

from database import Base, engine, SessionLocal
from models import SecurityEvent, Alert
from detection import detect_event


# Create database tables
Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="SentinelAI",
    description="Explainable and Adaptive SIEM",
    version="1.0.0"
)


class EventInput(BaseModel):

    username: str
    hostname: str
    source_ip: str

    event_type: str

    failed_attempts: Optional[int] = 0


@app.get("/")
def root():

    return {
        "project": "SentinelAI",
        "status": "running"
    }


@app.get("/api/health")
def health():

    return {
        "status": "ok"
    }


@app.post("/api/events")
def create_event(event: EventInput):

    db = SessionLocal()

    # Save security event
    security_event = SecurityEvent(
        username=event.username,
        hostname=event.hostname,
        source_ip=event.source_ip,
        event_type=event.event_type,
        failed_attempts=event.failed_attempts
    )

    db.add(security_event)
    db.commit()
    db.refresh(security_event)

    # Run detection
    detected_alerts = detect_event(security_event)

    saved_alerts = []

    for detected in detected_alerts:

        alert = Alert(
            event_id=security_event.id,
            title=detected["title"],
            severity=detected["severity"],
            risk_score=detected["risk_score"]
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        saved_alerts.append({
            "id": alert.id,
            "title": alert.title,
            "severity": alert.severity,
            "risk_score": alert.risk_score,
            "status": alert.status
        })

    db.close()

    return {
        "event_id": security_event.id,
        "alerts": saved_alerts
    }


@app.get("/api/alerts")
def get_alerts():

    db = SessionLocal()

    alerts = db.query(Alert).all()

    result = []

    for alert in alerts:

        result.append({
            "id": alert.id,
            "event_id": alert.event_id,
            "title": alert.title,
            "severity": alert.severity,
            "risk_score": alert.risk_score,
            "status": alert.status
        })

    db.close()

    return result