from datetime import datetime


def generate_soc_report(
    event,
    alerts,
    ml_result,
    mitre,
    risk_analysis
):
    """
    Generate a structured SOC incident report.
    """

    if alerts:
        highest_alert = max(
            alerts,
            key=lambda x: x.get("risk_score", 0)
        )

        alert_title = highest_alert.get(
            "title",
            "Security Alert"
        )

        severity = highest_alert.get(
            "severity",
            "UNKNOWN"
        )
    else:
        alert_title = "Security Event"
        severity = risk_analysis.get(
            "risk_level",
            "UNKNOWN"
        )

    report = {
        "report_id": f"SOC-{event.id}-{datetime.now().strftime('%Y%m%d%H%M%S')}",

        "generated_at": datetime.now().isoformat(),

        "incident": {
            "title": alert_title,
            "severity": severity,
            "risk_score": risk_analysis.get(
                "risk_score",
                0
            ),
            "risk_level": risk_analysis.get(
                "risk_level",
                "UNKNOWN"
            )
        },

        "affected_asset": {
            "username": event.username,
            "hostname": event.hostname,
            "source_ip": event.source_ip
        },

        "event": {
            "event_type": event.event_type,
            "failed_attempts": event.failed_attempts
        },

        "ml_analysis": ml_result,

        "mitre_attack": mitre,

        "risk_analysis": risk_analysis,

        "summary": (
            f"SentinelAI detected {alert_title.lower()} "
            f"associated with user {event.username} "
            f"on host {event.hostname}. "
            f"The calculated risk level is "
            f"{risk_analysis.get('risk_level', 'UNKNOWN')}."
        ),

        "recommendations": [
            "Review the affected account.",
            "Verify whether the authentication activity was legitimate.",
            "Review related security events from the same source IP.",
            "Monitor the affected host for additional suspicious activity."
        ]
    }

    return report