import pandas as pd


def extract_features():
    print("===================================")
    print(" SentinelAI - Feature Engineering ")
    print("===================================")

    # Example features (temporary)
    features = {
        "packets_per_sec": 250,
        "avg_packet_size": 512,
        "tcp_packets": 180,
        "udp_packets": 70,
        "syn_count": 45,
        "ack_count": 120,
        "unique_destination_ports": 18,
        "unique_source_ips": 6,
        "avg_ttl": 104
    }

    # Convert to DataFrame
    df = pd.DataFrame([features])

    # Save to CSV
    df.to_csv("ai/dataset/raw/traffic.csv", mode="a", header=False, index=False)

    print("Features saved successfully!")
    print(df)


if __name__ == "__main__":
    extract_features()