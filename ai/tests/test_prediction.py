import sys
import os

# Add ai folder to Python path
sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from predict.predict import predict_flow


# Sample flow features
flow_features = {
    "Protocol": 6,
    "Flow Duration": 1000000,
    "Total Fwd Packets": 10,
    "Total Backward Packets": 8,
    "Fwd Packets Length Total": 5000,
    "Bwd Packets Length Total": 4000,
    "Flow Bytes/s": 9000,
    "Flow Packets/s": 18,
    "Packet Length Mean": 500,
    "Packet Length Std": 100,
    "SYN Flag Count": 1,
    "ACK Flag Count": 15,
    "RST Flag Count": 0,
    "FIN Flag Count": 0
}


result = predict_flow(flow_features)

print("\n" + "=" * 50)
print("SENTINELAI - PREDICTION TEST")
print("=" * 50)

print("\nFlow Features:")
print(flow_features)

print("\nPrediction Result:")
print(result)