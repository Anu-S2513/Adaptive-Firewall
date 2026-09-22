import pandas as pd
import joblib


# ==========================================
# LOAD TRAINED MODEL
# ==========================================

MODEL_FILE = "ai/models/sentinelai_model.joblib"

model = joblib.load(MODEL_FILE)


# ==========================================
# FEATURE ORDER
# Must be EXACTLY the same as training
# ==========================================

FEATURES = [
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packets Length Total",
    "Bwd Packets Length Total",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "FIN Flag Count"
]


def predict_flow(flow_features):
    """
    Receive flow features dynamically and
    return the ML prediction.
    """

    # Convert incoming dictionary into DataFrame
    input_data = pd.DataFrame(
        [flow_features],
        columns=FEATURES
    )

    # Prediction
    prediction = model.predict(input_data)[0]

    # Probability
    probability = model.predict_proba(input_data)[0]

    attack_probability = probability[1]

    # Convert prediction to readable result
    if prediction == 0:
        result = "NORMAL"
    else:
        result = "ATTACK"

    return {
        "prediction": result,
        "attack_probability": float(attack_probability)
    }