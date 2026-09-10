# SentinelAI Intelligent Risk Engine


def calculate_risk(
    base_risk: int,
    ml_result: dict,
    mitre_result: dict,
    failed_attempts: int,
    hostname: str
):
    """
    Calculate a final risk score from multiple security signals.

    Score range: 0 - 100
    """

    # Start with the rule-based risk
    risk = float(base_risk)

    # -------------------------------------------------
    # 1. ML ANOMALY CONTRIBUTION
    # -------------------------------------------------

    anomaly_score = ml_result.get("anomaly_score", 0)
    is_anomaly = ml_result.get("is_anomaly", False)

    if is_anomaly:
        # ML contributes up to 20 points
        risk += anomaly_score * 0.20
    else:
        # Small contribution when behavior is not anomalous
        risk += anomaly_score * 0.05

    # -------------------------------------------------
    # 2. MITRE ATT&CK CONTRIBUTION
    # -------------------------------------------------

    mitre_confidence = mitre_result.get("confidence", 0)

    # MITRE confidence contributes up to 15 points
    risk += mitre_confidence * 0.15

    # -------------------------------------------------
    # 3. FAILED LOGIN CONTRIBUTION
    # -------------------------------------------------

    if failed_attempts >= 10:
        risk += 15
    elif failed_attempts >= 5:
        risk += 10
    elif failed_attempts >= 3:
        risk += 5

    # -------------------------------------------------
    # 4. ASSET CRITICALITY
    # -------------------------------------------------

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

    # -------------------------------------------------
    # 5. LIMIT SCORE TO 0-100
    # -------------------------------------------------

    final_score = min(100, max(0, round(risk)))

    # -------------------------------------------------
    # 6. DETERMINE RISK LEVEL
    # -------------------------------------------------

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
            "failed_attempts": failed_attempts
        }
    }