def check_ip_reputation(source_ip: str):
    """
    Local/demo threat-intelligence lookup.
    Later this can be connected to a live TI API.
    """

    known_malicious_ips = {
        "192.168.1.99",
        "10.10.10.99"
    }

    if source_ip in known_malicious_ips:
        return {
            "is_malicious": True,
            "reputation": "MALICIOUS",
            "confidence": 95,
            "source": "Local Threat Intelligence"
        }

    return {
        "is_malicious": False,
        "reputation": "UNKNOWN",
        "confidence": 50,
        "source": "Local Threat Intelligence"
    }