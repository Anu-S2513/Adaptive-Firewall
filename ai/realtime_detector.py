from ai.features.flow_aggregator import process_packet
from ai.predict.predict import predict_flow
from ai.logs.prediction_logger import log_prediction
from ai.firewall.adaptive_firewall import get_firewall_action
from ai.firewall.firewall_enforcer import enforce_firewall_action


def analyze_packet(parsed_packet):
    """
    SentinelAI real-time detection pipeline:

    Packet
        ↓
    Flow Aggregation
        ↓
    Feature Extraction
        ↓
    Random Forest ML Prediction
        ↓
    Attack Probability
        ↓
    Adaptive Firewall Decision
        ↓
    Firewall Enforcement Layer
        ↓
    Prediction Logging
    """

    # 1. Add packet to its network flow
    flow_features = process_packet(parsed_packet)

    # 2. Wait until enough packets are available
    if flow_features is None:
        return None

    # 3. ML prediction
    result = predict_flow(flow_features)

    # 4. Get prediction and attack probability
    prediction = result["prediction"]
    attack_probability = result["attack_probability"]

    # 5. Adaptive firewall decision
    firewall_action = get_firewall_action(
        prediction,
        attack_probability
    )

    # 6. Execute firewall enforcement layer
    enforcement_result = enforce_firewall_action(
        firewall_action,
        parsed_packet["source_ip"]
    )

    # 7. Prepare complete result
    prediction_result = {
        "flow_features": flow_features,
        "prediction": prediction,
        "attack_probability": attack_probability,
        "firewall_action": firewall_action,
        "enforcement_status": enforcement_result["status"],
        "enforcement_message": enforcement_result["message"]
    }

    # 8. Save prediction and firewall decision
    log_prediction(
        parsed_packet,
        prediction_result
    )

    return prediction_result