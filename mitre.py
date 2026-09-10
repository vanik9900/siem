# MITRE ATT&CK mapping for SentinelAI

MITRE_MAPPINGS = {
    "failed_login": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique": "Brute Force",
        "subtechnique_id": "T1110.001",
        "subtechnique": "Password Guessing",
        "description": "Repeated authentication failures may indicate an attempt to guess account credentials.",
        "confidence": 90
    },

    "multiple_failed_login": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique": "Brute Force",
        "subtechnique_id": "T1110.001",
        "subtechnique": "Password Guessing",
        "description": "Multiple failed authentication attempts detected.",
        "confidence": 90
    },

    "suspicious_login": {
        "tactic": "Initial Access",
        "technique_id": "T1078",
        "technique": "Valid Accounts",
        "subtechnique_id": None,
        "subtechnique": None,
        "description": "A suspicious authentication event may indicate misuse of a valid account.",
        "confidence": 70
    },

    "normal_login": {
        "tactic": None,
        "technique_id": None,
        "technique": None,
        "subtechnique_id": None,
        "subtechnique": None,
        "description": "No suspicious MITRE ATT&CK behavior identified.",
        "confidence": 0
    }
}


def map_event_to_mitre(event_type: str, failed_attempts: int = 0):

    # Stronger mapping for multiple failed attempts
    if event_type == "failed_login" and failed_attempts >= 5:
        return MITRE_MAPPINGS["multiple_failed_login"]

    return MITRE_MAPPINGS.get(
        event_type,
        {
            "tactic": None,
            "technique_id": None,
            "technique": None,
            "subtechnique_id": None,
            "subtechnique": None,
            "description": "No MITRE ATT&CK mapping available.",
            "confidence": 0
        }
    )