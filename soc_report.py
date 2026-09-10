from datetime import datetime


def generate_soc_report(
    event,
    alerts,
    ml_result,
    mitre,
    risk_analysis
):

    # Handle events where no rule-based alert was generated
    if risk_analysis is None:
        risk_analysis = {
            "risk_score": 0,
            "risk_level": "LOW",
            "asset_criticality": "NORMAL",
            "factors": {}
        }

    # Determine incident information
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
            "LOW"
        )

    report = {

        "report_id": (
            f"SOC-{event.id}-"
            f"{datetime.now().strftime('%Y%m%d%H%M%S')}"
        ),

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
                "LOW"
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
            f"SentinelAI analyzed a {event.event_type} event "
            f"associated with user {event.username} "
            f"on host {event.hostname}. "
            f"The calculated risk level is "
            f"{risk_analysis.get('risk_level', 'LOW')}."
        ),

        "recommendations": [
            "Review the affected account.",
            "Verify whether the activity was legitimate.",
            "Review related events from the same source IP.",
            "Monitor the affected host for additional suspicious activity."
        ]
    }

    return report