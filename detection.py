def detect_event(event):
    """
    Simple rule-based detection engine.
    """

    alerts = []

    # Rule 1: Multiple failed logins
    if event.failed_attempts >= 5:

        alerts.append({
            "title": "Multiple Failed Login Attempts",
            "severity": "HIGH",
            "risk_score": 70
        })

    # Rule 2: Unusual login
    if event.event_type == "unusual_login":

        alerts.append({
            "title": "Unusual Login Activity",
            "severity": "MEDIUM",
            "risk_score": 50
        })

    return alerts