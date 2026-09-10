from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional

from database import Base, engine, SessionLocal
from models import SecurityEvent, Alert
from detection import detect_event
from ml_detector import detect_anomaly
from mitre import map_event_to_mitre
from risk_engine import calculate_risk
from soc_report import generate_soc_report
from threat_intel import check_ip_reputation
from correlation import correlate_events


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

        db.refresh(security_event)
        event_id = security_event.id

        # 3. Correlate with previous events
        correlation = correlate_events(
            db,
            security_event
        )

        # 4. Rule-based detection
        detected_alerts = detect_event(security_event)

        # 5. ML anomaly detection
        ml_result = detect_anomaly(
            event.failed_attempts
        )

        # 6. MITRE ATT&CK mapping
        mitre = map_event_to_mitre(
            event.event_type,
            event.failed_attempts
        )

        # 7. Threat Intelligence
        threat_intel = check_ip_reputation(
            event.source_ip
        )

        saved_alerts = []

        # Default values
        risk_result = None
        soc_report = None

        # 8. Create alerts
        for detected in detected_alerts:

            risk_result = calculate_risk(
                base_risk=detected["risk_score"],
                ml_result=ml_result,
                mitre_result=mitre,
                failed_attempts=event.failed_attempts,
                hostname=event.hostname
            )

            alert = Alert(
                event_id=event_id,
                title=detected["title"],
                severity=risk_result["risk_level"],
                risk_score=risk_result["risk_score"],
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

        # 9. Generate SOC Report
        soc_report = generate_soc_report(
            security_event,
            saved_alerts,
            ml_result,
            mitre,
            risk_result
        )

        # 10. Return complete analysis
        return {
            "event_id": event_id,
            "alerts": saved_alerts,
            "ml_detection": ml_result,
            "mitre": mitre,
            "threat_intelligence": threat_intel,
            "correlation": correlation,
            "risk_analysis": risk_result,
            "soc_report": soc_report
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