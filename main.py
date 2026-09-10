from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional

from database import Base, engine, SessionLocal
from models import SecurityEvent, Alert
from detection import detect_event
from ml_detector import detect_anomaly
from mitre import map_event_to_mitre


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

    try:
        # 1. Create security event
        security_event = SecurityEvent(
            username=event.username,
            hostname=event.hostname,
            source_ip=event.source_ip,
            event_type=event.event_type,
            failed_attempts=event.failed_attempts
        )

        # 2. Save event
        db.add(security_event)
        db.commit()

        # IMPORTANT:
        # Store the ID before closing the database session
        db.refresh(security_event)
        event_id = security_event.id

        # 3. Run detection
        detected_alerts = detect_event(security_event)

        #  Run ML anomaly detection
        ml_result = detect_anomaly(event.failed_attempts)

        saved_alerts = []

        # 4. Create alerts
        for detected in detected_alerts:

            alert = Alert(
                event_id=event_id,
                title=detected["title"],
                severity=detected["severity"],
                risk_score=detected["risk_score"],
                status="OPEN"
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

        # 5. Return result
        return {
            "event_id": event_id,
            "alerts": saved_alerts,
            "ml_detection": ml_result
        }

    except Exception as e:

        db.rollback()

        return {
            "error": str(e)
        }

    finally:
        db.close()


@app.get("/api/alerts")
def get_alerts():

    db = SessionLocal()

    try:

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

        return result

    finally:
        db.close()