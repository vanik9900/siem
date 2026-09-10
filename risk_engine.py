def calculate_risk(
    base_risk: int,
    ml_result: dict,
    mitre_result: dict,
    failed_attempts: int,
    hostname: str,
    vulnerability_result: dict = None
):

    risk = float(base_risk)

    # ML anomaly
    anomaly_score = ml_result.get("anomaly_score", 0)
    is_anomaly = ml_result.get("is_anomaly", False)

    if is_anomaly:
        risk += anomaly_score * 0.20
    else:
        risk += anomaly_score * 0.05

    # MITRE confidence
    mitre_confidence = mitre_result.get("confidence", 0)
    risk += mitre_confidence * 0.15

    # Failed attempts
    if failed_attempts >= 10:
        risk += 15
    elif failed_attempts >= 5:
        risk += 10
    elif failed_attempts >= 3:
        risk += 5

    # Asset criticality
    hostname_lower = hostname.lower()

    if any(keyword in hostname_lower for keyword in [
        "dc",
        "domain-controller",
        "database",
        "db",
        "server"
    ]):
        risk += 10
        asset_criticality = "CRITICAL"

    elif any(keyword in hostname_lower for keyword in [
        "admin",
        "management"
    ]):
        risk += 7
        asset_criticality = "HIGH"

    else:
        risk += 2
        asset_criticality = "NORMAL"

    # Vulnerability intelligence
    vulnerability_bonus = 0
    highest_vulnerability_severity = "NONE"

    if vulnerability_result:

        highest_vulnerability_severity = vulnerability_result.get(
            "highest_severity",
            "NONE"
        )

        if vulnerability_result.get("vulnerable", False):

            if highest_vulnerability_severity == "CRITICAL":
                vulnerability_bonus = 15

            elif highest_vulnerability_severity == "HIGH":
                vulnerability_bonus = 10

            elif highest_vulnerability_severity == "MEDIUM":
                vulnerability_bonus = 5

            risk += vulnerability_bonus

    # Final score
    final_score = min(
        100,
        max(0, round(risk))
    )

    # Risk level
    if final_score >= 76:
        risk_level = "CRITICAL"

    elif final_score >= 51:
        risk_level = "HIGH"

    elif final_score >= 26:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "asset_criticality": asset_criticality,

        "factors": {
            "base_rule_risk": base_risk,
            "ml_anomaly_score": anomaly_score,
            "ml_anomaly": is_anomaly,
            "mitre_confidence": mitre_confidence,
            "failed_attempts": failed_attempts,
            "vulnerability_bonus": vulnerability_bonus,
            "vulnerability_severity": highest_vulnerability_severity
        }
    }