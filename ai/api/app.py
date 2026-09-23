import csv
import os
import json

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ai.predict.predict import predict_flow


# =========================================================
# CREATE APP
# =========================================================

app = FastAPI(
    title="SentinelAI ML API",
    version="1.0"
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# PROJECT ROOT
# =========================================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        ".."
    )
)


# =========================================================
# PREDICTIONS FILE
# =========================================================

PREDICTIONS_FILE = os.path.join(
    PROJECT_ROOT,
    "ai",
    "logs",
    "predictions.csv"
)


# =========================================================
# ACTIVE FLOWS FILE
# =========================================================

ACTIVE_FLOWS_FILE = os.path.join(
    PROJECT_ROOT,
    "ai",
    "logs",
    "active_flows.json"
)


# =========================================================
# INPUT MODEL
# =========================================================

class FlowData(BaseModel):

    Protocol: int

    Flow_Duration: float

    Total_Fwd_Packets: int

    Total_Backward_Packets: int

    Fwd_Packets_Length_Total: float

    Bwd_Packets_Length_Total: float

    Flow_Bytes_per_s: float

    Flow_Packets_per_s: float

    Packet_Length_Mean: float

    Packet_Length_Std: float

    SYN_Flag_Count: int

    ACK_Flag_Count: int

    RST_Flag_Count: int

    FIN_Flag_Count: int


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():

    return {
        "message": "SentinelAI API running",
        "status": "active"
    }


# =========================================================
# PREDICT
# =========================================================

@app.post("/predict")
def predict(data: FlowData):

    features = {

        "Protocol":
            data.Protocol,

        "Flow Duration":
            data.Flow_Duration,

        "Total Fwd Packets":
            data.Total_Fwd_Packets,

        "Total Backward Packets":
            data.Total_Backward_Packets,

        "Fwd Packets Length Total":
            data.Fwd_Packets_Length_Total,

        "Bwd Packets Length Total":
            data.Bwd_Packets_Length_Total,

        "Flow Bytes/s":
            data.Flow_Bytes_per_s,

        "Flow Packets/s":
            data.Flow_Packets_per_s,

        "Packet Length Mean":
            data.Packet_Length_Mean,

        "Packet Length Std":
            data.Packet_Length_Std,

        "SYN Flag Count":
            data.SYN_Flag_Count,

        "ACK Flag Count":
            data.ACK_Flag_Count,

        "RST Flag Count":
            data.RST_Flag_Count,

        "FIN Flag Count":
            data.FIN_Flag_Count
    }

    return predict_flow(
        features
    )


# =========================================================
# GET PREDICTIONS
# =========================================================

@app.get("/api/predictions")
def get_predictions():

    if not os.path.exists(
        PREDICTIONS_FILE
    ):

        return {
            "error":
                "predictions.csv not found",

            "path":
                PREDICTIONS_FILE
        }


    predictions = []


    with open(
        PREDICTIONS_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(
            file
        )

        for row in reader:

            predictions.append(
                row
            )


    predictions.reverse()


    return {
        "total":
            len(predictions),

        "predictions":
            predictions
    }


# =========================================================
# GET STATISTICS
# =========================================================

@app.get("/api/stats")
def get_stats():

    if not os.path.exists(
        PREDICTIONS_FILE
    ):

        return {

            "total_predictions":
                0,

            "normal_predictions":
                0,

            "attack_predictions":
                0,

            "average_attack_probability":
                0,

            "allowed":
                0,

            "monitored":
                0,

            "blocked":
                0,

            "system_status":
                "file_not_found",

            "file_path":
                PREDICTIONS_FILE
        }


    predictions = []


    with open(
        PREDICTIONS_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(
            file
        )

        for row in reader:

            predictions.append(
                row
            )


    # =====================================================
    # BASIC COUNTS
    # =====================================================

    total = len(
        predictions
    )


    normal = sum(
        1
        for row in predictions
        if row.get(
            "prediction"
        ) == "NORMAL"
    )


    attack = sum(
        1
        for row in predictions
        if row.get(
            "prediction"
        ) == "ATTACK"
    )


    # =====================================================
    # ATTACK PROBABILITY
    # =====================================================

    probabilities = []


    for row in predictions:

        try:

            probabilities.append(
                float(
                    row.get(
                        "attack_probability",
                        0
                    )
                )
            )

        except (
            ValueError,
            TypeError
        ):

            pass


    average_probability = (

        sum(probabilities)
        /
        len(probabilities)

        if probabilities

        else 0
    )


    # =====================================================
    # FIREWALL ACTION COUNTS
    # =====================================================

    allowed = sum(
        1
        for row in predictions
        if row.get(
            "firewall_action"
        ) == "ALLOW"
    )


    monitored = sum(
        1
        for row in predictions
        if row.get(
            "firewall_action"
        ) == "MONITOR"
    )


    blocked = sum(
        1
        for row in predictions
        if row.get(
            "firewall_action"
        ) == "BLOCK"
    )


    # =====================================================
    # RETURN STATISTICS
    # =====================================================

    return {

        "total_predictions":
            total,

        "normal_predictions":
            normal,

        "attack_predictions":
            attack,

        "average_attack_probability":
            round(
                average_probability,
                4
            ),

        "allowed":
            allowed,

        "monitored":
            monitored,

        "blocked":
            blocked,

        "system_status":
            "active"
    }


# =========================================================
# GET BEHAVIORAL NETWORK FLOWS
# =========================================================

@app.get("/api/flows")
def get_flows():

    # -----------------------------------------------------
    # If flow file does not exist yet
    # -----------------------------------------------------

    if not os.path.exists(
        ACTIVE_FLOWS_FILE
    ):

        return {
            "total_flows": 0,
            "flows": []
        }


    # -----------------------------------------------------
    # Read flow file
    # -----------------------------------------------------

    try:

        with open(
            ACTIVE_FLOWS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(
                file
            )


        return data


    # -----------------------------------------------------
    # Handle empty/corrupted file
    # -----------------------------------------------------

    except (
        json.JSONDecodeError,
        OSError
    ):

        return {
            "total_flows": 0,
            "flows": []
        }