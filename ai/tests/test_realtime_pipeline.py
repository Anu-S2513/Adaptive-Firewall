import sys
import os

import pandas as pd


# ==========================================
# ADD PROJECT ROOT
# ==========================================

project_root = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

sys.path.append(project_root)


# ==========================================
# IMPORT SENTINELAI MODULES
# ==========================================

from ai.predict.predict import predict_flow
from ai.firewall.adaptive_firewall import get_firewall_action
from ai.firewall.firewall_enforcer import enforce_firewall_action
from ai.logs.prediction_logger import log_prediction


# ==========================================
# DATASET
# ==========================================

DATASET_FILE = os.path.join(
    project_root,
    "ai",
    "dataset",
    "processed",
    "sentinelai_training_data.csv"
)


# ==========================================
# FEATURES
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


# ==========================================
# LOAD DATASET
# ==========================================

print("Loading dataset...")

df = pd.read_csv(DATASET_FILE)

print("Dataset loaded.")


# ==========================================
# SELECT HIGH-CONFIDENCE ATTACK SAMPLE
# ==========================================

attack_data = df[
    df["Label"] != "Benign"
].copy()

if attack_data.empty:
    raise ValueError(
        "No attack samples found."
    )


# ==========================================
# FIND HIGHEST ATTACK PROBABILITY
# ==========================================

X_attack = attack_data[FEATURES]

from ai.predict.predict import model

probabilities = model.predict_proba(
    X_attack
)

attack_probabilities = probabilities[:, 1]

best_index = attack_probabilities.argmax()

sample = attack_data.iloc[
    best_index
]


# ==========================================
# CREATE FLOW FEATURES
# ==========================================

flow_features = {
    feature: sample[feature]
    for feature in FEATURES
}


# ==========================================
# ML PREDICTION
# ==========================================

result = predict_flow(
    flow_features
)

prediction = result["prediction"]

probability = result[
    "attack_probability"
]


# ==========================================
# ADAPTIVE FIREWALL
# ==========================================

firewall_action = get_firewall_action(
    prediction,
    probability
)


# ==========================================
# FIREWALL ENFORCEMENT
# ==========================================

enforcement_result = (
    enforce_firewall_action(
        firewall_action,
        "CONTROLLED_TEST"
    )
)


# ==========================================
# LOG RESULT
# ==========================================

test_packet = {
    "source_ip": "CONTROLLED_TEST",
    "destination_ip": "DATASET_SAMPLE",
    "source_port": 0,
    "destination_port": 0,
    "protocol": "TEST"
}


test_result = {
    "prediction": prediction,
    "attack_probability": float(
        probability
    ),
    "firewall_action": firewall_action
}


log_prediction(
    test_packet,
    test_result
)


# ==========================================
# DISPLAY RESULT
# ==========================================

print()
print("=" * 60)
print("SENTINELAI - END-TO-END CONTROLLED TEST")
print("=" * 60)

print(
    f"\nDataset Label       : "
    f"{sample['Label']}"
)

print("\nML RESULT")

print(
    f"Prediction          : "
    f"{prediction}"
)

print(
    f"Attack Probability  : "
    f"{probability:.4f}"
)

print("\nADAPTIVE FIREWALL")

print(
    f"Firewall Action     : "
    f"{firewall_action}"
)

print("\nFIREWALL ENFORCEMENT")

print(
    f"Status              : "
    f"{enforcement_result['status']}"
)

print(
    f"Message             : "
    f"{enforcement_result['message']}"
)

print("\nLOGGING")

print(
    "Result saved to predictions.csv"
)

print("=" * 60)