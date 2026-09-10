from datetime import datetime, timedelta


def correlate_events(db, current_event):
    """
    Find recent events from the same user/host
    that may belong to the same security incident.
    """

    time_limit = datetime.utcnow() - timedelta(minutes=10)

    recent_events = (
        db.query(type(current_event))
        .filter(
            type(current_event).username == current_event.username,
            type(current_event).hostname == current_event.hostname,
            type(current_event).timestamp >= time_limit
        )
        .all()
    )

    suspicious_events = []

    for event in recent_events:

        if event.event_type in [
            "failed_login",
            "suspicious_login",
            "unusual_login",
            "privilege_change"
        ]:
            suspicious_events.append({
                "event_id": event.id,
                "event_type": event.event_type,
                "username": event.username,
                "hostname": event.hostname,
                "source_ip": event.source_ip,
                "failed_attempts": event.failed_attempts
            })

    if len(suspicious_events) >= 2:

        return {
            "correlated": True,
            "event_count": len(suspicious_events),
            "incident_type": "Possible Account Compromise",
            "events": suspicious_events
        }

    return {
        "correlated": False,
        "event_count": len(suspicious_events),
        "incident_type": None,
        "events": suspicious_events
    }