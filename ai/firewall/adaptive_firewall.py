from collections import defaultdict


# Store behavior history for each source IP
source_history = defaultdict(
    lambda: {
        "suspicious_count": 0,
        "attack_count": 0,
        "last_probability": 0.0
    }
)


def get_firewall_action(
    prediction,
    attack_probability,
    source_ip=None
):
    probability = float(attack_probability)

    # If no source IP is provided, use the original behavior
    if source_ip is None:
        if prediction == "ATTACK" and probability >= 0.70:
            return "BLOCK"

        elif probability >= 0.30:
            return "MONITOR"

        else:
            return "ALLOW"

    history = source_history[source_ip]

    history["last_probability"] = probability

    # Confirmed high-risk attack
    if prediction == "ATTACK" and probability >= 0.70:
        history["attack_count"] += 1
        history["suspicious_count"] += 1
        return "BLOCK"

    # Suspicious behavior
    if probability >= 0.30:
        history["suspicious_count"] += 1

        # Repeated suspicious behavior
        if history["suspicious_count"] >= 3:
            return "BLOCK"

        return "MONITOR"

    # Normal behavior
    return "ALLOW"