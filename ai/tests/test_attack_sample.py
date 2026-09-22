import sys
import os

import pandas as pd


# ==========================================
# ADD PROJECT ROOT TO PYTHON PATH
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

from ai.predict.predict import model
from ai.firewall.adaptive_firewall import get_firewall_action
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
# SELECT ATTACK SAMPLES
# ==========================================

attack_data = df[
    df["Label"] != "Benign"
].copy()

if attack_data.empty:
    raise ValueError(
        "No attack samples found."
    )

print(
    f"Attack samples found: "
    f"{len(attack_data)}"
)


# ==========================================
# PREPARE ATTACK FEATURES
# ==========================================

X_attack = attack_data[FEATURES]


# ==========================================
# ML PREDICTION
# ==========================================

print("Running ML prediction...")

predictions = model.predict(
    X_attack
)

probabilities = model.predict_proba(
    X_attack
)

attack_probabilities = probabilities[:, 1]


# ==========================================
# FIND HIGHEST-CONFIDENCE ATTACK
# ==========================================

best_index = (
    attack_probabilities.argmax()
)

sample = attack_data.iloc[
    best_index
]

prediction_value = predictions[
    best_index
]

probability = attack_probabilities[
    best_index
]


# ==========================================
# CONVERT ML RESULT
# ==========================================

if prediction_value == 0:

    prediction = "NORMAL"

else:

    prediction = "ATTACK"


# ==========================================
# ADAPTIVE FIREWALL DECISION
# ==========================================

firewall_action = get_firewall_action(
    prediction,
    probability
)


# ==========================================
# LOG CONTROLLED TEST RESULT
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
print("       SENTINELAI - CONTROLLED ML TEST")
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

print("\nLOGGING")

print(
    "Result saved to predictions.csv"
)

print("=" * 60)