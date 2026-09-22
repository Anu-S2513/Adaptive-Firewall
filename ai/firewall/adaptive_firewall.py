def get_firewall_action(prediction, attack_probability):
    probability = float(attack_probability)

    if prediction == "ATTACK" and probability >= 0.70:
        return "BLOCK"

    elif probability >= 0.30:
        return "MONITOR"

    else:
        return "ALLOW"