from datetime import datetime


def generate_soc_report(
    event,
    alerts,
    ml_result,
    mitre,
    risk_analysis
):

    # Safe default when no alert/risk exists
    if risk_analysis is None:
        risk_analysis = {
            "risk_score": 0,
            "risk_level": "LOW",
            "asset_criticality": "NORMAL",
            "factors": {}
        }

    # Determine alert information
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

    risk_score = risk_analysis.get(
        "risk_score",
        0
    )

    risk_level = risk_analysis.get(
        "risk_level",
        "LOW"
    )

    # Explain ML result
    if ml_result.get("is_anomaly", False):
        ml_explanation = (
            f"Machine-learning analysis identified the event "
            f"as anomalous with an anomaly score of "
            f"{ml_result.get('anomaly_score', 0)}."
        )
    else:
        ml_explanation = (
            "Machine-learning analysis did not identify "
            "the event as anomalous."
        )

    # Explain MITRE mapping
    mitre_explanation = (
        f"The activity maps to MITRE ATT&CK technique "
        f"{mitre.get('technique_id', 'N/A')} "
        f"({mitre.get('technique', 'Unknown')})."
    )

    if mitre.get("subtechnique_id"):
        mitre_explanation += (
            f" Sub-technique: "
            f"{mitre.get('subtechnique_id')} "
            f"({mitre.get('subtechnique', 'Unknown')})."
        )

    # Explain risk
    risk_explanation = (
        f"SentinelAI calculated a risk score of "
        f"{risk_score}/100, classified as {risk_level}. "
        f"The score combines rule detection, ML anomaly "
        f"analysis, MITRE confidence, authentication activity, "
        f"asset criticality, and vulnerability intelligence."
    )

    # Final SOC report
    report = {

        "report_id": (
            f"SOC-{event.id}-"
            f"{datetime.now().strftime('%Y%m%d%H%M%S')}"
        ),

        "generated_at": datetime.now().isoformat(),

        "incident": {
            "title": alert_title,
            "severity": severity,
            "risk_score": risk_score,
            "risk_level": risk_level
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

        "ai_explanation": {
            "ml_analysis": ml_explanation,
            "mitre_analysis": mitre_explanation,
            "risk_analysis": risk_explanation
        },

        "ml_analysis": ml_result,

        "mitre_attack": mitre,

        "risk_analysis": risk_analysis,

        "summary": (
            f"SentinelAI detected {alert_title.lower()} "
            f"associated with user {event.username} "
            f"on host {event.hostname}. "
            f"The event received a {risk_level} risk "
            f"classification with a score of "
            f"{risk_score}/100."
        ),

        "recommendations": [
            "Review the affected account.",
            "Verify whether the authentication activity was legitimate.",
            "Review related security events from the same source IP.",
            "Check the affected asset for known vulnerabilities.",
            "Monitor the host for additional suspicious activity."
        ]
    }

    return report