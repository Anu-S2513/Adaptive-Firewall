import csv
import os
from datetime import datetime


# Get SentinelAI project root
project_root = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)


# Save predictions here:
# SentinelAI/ai/logs/predictions.csv
log_file = os.path.join(
    project_root,
    "ai",
    "logs",
    "predictions.csv"
)


# CSV columns
fieldnames = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "prediction",
    "attack_probability",
    "firewall_action"
]


def initialize_log():
    """
    Create predictions.csv and add header if needed.
    """

    os.makedirs(
        os.path.dirname(log_file),
        exist_ok=True
    )

    # Create file with header if it doesn't exist or is empty
    if (
        not os.path.exists(log_file)
        or os.path.getsize(log_file) == 0
    ):

        with open(
            log_file,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames
            )

            writer.writeheader()


def log_prediction(packet, result):
    """
    Save ML prediction and adaptive firewall decision.
    """

    initialize_log()

    log_data = {
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "source_ip": packet["source_ip"],

        "destination_ip": packet["destination_ip"],

        "source_port": packet["source_port"],

        "destination_port": packet["destination_port"],

        "protocol": packet["protocol"],

        "prediction": result["prediction"],

        "attack_probability": result["attack_probability"],

        "firewall_action": result["firewall_action"]
    }


    with open(
        log_file,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writerow(log_data)

        file.flush()


# Create the CSV immediately when this file is imported
initialize_log()