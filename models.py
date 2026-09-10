from sqlalchemy import Column, Integer, String, Float, DateTime
from datetime import datetime

from database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    username = Column(String)
    hostname = Column(String)
    source_ip = Column(String)

    event_type = Column(String)
    failed_attempts = Column(Integer, default=0)

    severity = Column(String, default="LOW")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)

    event_id = Column(Integer)

    title = Column(String)
    severity = Column(String)

    risk_score = Column(Float, default=0)

    status = Column(String, default="OPEN")

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)

    title = Column(String)
    severity = Column(String)
    risk_score = Column(Float, default=0)

    status = Column(String, default="OPEN")

    username = Column(String)
    hostname = Column(String)
    source_ip = Column(String)

    mitre_technique = Column(String)

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )

class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True)

    incident_id = Column(Integer)

    action = Column(String)
    reason = Column(String)

    status = Column(String, default="SIMULATED")

    performed_by = Column(String, default="SentinelAI")

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )