import os
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional

from database import Base, engine, SessionLocal
from models import SecurityEvent, Alert, Incident, ResponseAction   
from detection import detect_event
from ml_detector import detect_anomaly
from mitre import map_event_to_mitre
from risk_engine import calculate_risk
from soc_report import generate_soc_report
from threat_intel import check_ip_reputation
from correlation import correlate_events
from vulnerability_intel import check_vulnerabilities
from fastapi.responses import FileResponse
from pdf_report import generate_pdf_report


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

        # 8. Vulnerability Intelligence
        vulnerability_intel = check_vulnerabilities(
                event.hostname
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
                hostname=event.hostname,
                vulnerability_result=vulnerability_intel
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

            incident = None

            if saved_alerts:

                highest_alert = max(
                    saved_alerts,
                    key=lambda x: x.get("risk_score", 0)
                )

                incident = Incident(
                    title=highest_alert["title"],
                    severity=highest_alert["severity"],
                    risk_score=highest_alert["risk_score"],
                    status="OPEN",
                    username=event.username,
                    hostname=event.hostname,
                    source_ip=event.source_ip,
                    mitre_technique=mitre.get(
                        "technique_id",
                        "N/A"
                    )
                )

                db.add(incident)
                db.commit()
                db.refresh(incident)

            response_action = None

            if incident:

                if incident.severity == "CRITICAL":
                    action = "ISOLATE_HOST_RECOMMENDED"
                    reason = (
                        "Critical incident detected. "
                        "Host isolation is recommended "
                        "for analyst review."
                    )

                elif incident.severity == "HIGH":
                    action = "INCREASE_MONITORING"
                    reason = (
                        "High-risk incident detected. "
                        "Increase monitoring of the affected asset."
                    )

                else:
                    action = "CONTINUE_MONITORING"
                    reason = (
                        "Lower-risk event detected. "
                        "Continue monitoring."
                    )

                response_action = ResponseAction(
                    incident_id=incident.id,
                    action=action,
                    reason=reason,
                    status="SIMULATED",
                    performed_by="SentinelAI"
                )

                db.add(response_action)
                db.commit()
                db.refresh(response_action)

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
            "vulnerability_intelligence": vulnerability_intel,
            "incident": {
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "risk_score": incident.risk_score,
                "status": incident.status,
                "username": incident.username,
                "hostname": incident.hostname,
                "source_ip": incident.source_ip,
                "mitre_technique": incident.mitre_technique
            } if incident else None,
             "response_action": {
                "id": response_action.id,
                "action": response_action.action,
                "reason": response_action.reason,
                "status": response_action.status,
                "performed_by": response_action.performed_by
            } if response_action else None,
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

@app.get("/api/incidents")
def get_incidents():

    db = SessionLocal()

    try:

        incidents = (
            db.query(Incident)
            .order_by(Incident.created_at.desc())
            .all()
        )

        result = []

        for incident in incidents:

            result.append({
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "risk_score": incident.risk_score,
                "status": incident.status,
                "username": incident.username,
                "hostname": incident.hostname,
                "source_ip": incident.source_ip,
                "mitre_technique": incident.mitre_technique,
                "created_at": incident.created_at
            })

        return result

    finally:
        db.close()


@app.get("/api/incidents/{incident_id}/report")
def download_incident_report(incident_id: int):

    db = SessionLocal()

    try:

        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            return {
                "error": "Incident not found"
            }

        file_path = (
            f"incident_report_{incident.id}.pdf"
        )

        generate_pdf_report(
            incident,
            file_path
        )

        return FileResponse(
            file_path,
            media_type="application/pdf",
            filename=f"SentinelAI_Incident_{incident.id}.pdf"
        )

    finally:
        db.close()

@app.get("/api/response-actions")
def get_response_actions():

    db = SessionLocal()

    try:

        actions = (
            db.query(ResponseAction)
            .order_by(ResponseAction.created_at.desc())
            .all()
        )

        result = []

        for action in actions:

            result.append({
                "id": action.id,
                "incident_id": action.incident_id,
                "action": action.action,
                "reason": action.reason,
                "status": action.status,
                "performed_by": action.performed_by,
                "created_at": action.created_at
            })

        return result

    finally:
        db.close()