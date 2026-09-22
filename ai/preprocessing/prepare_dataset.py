import pandas as pd


# ==============================
# 1. LOAD THE RAW DATASET
# ==============================

INPUT_FILE = (
    "ai/dataset/raw/"
    "Bruteforce-Tuesday-no-metadata.parquet"
)

OUTPUT_FILE = (
    "ai/dataset/processed/"
    "sentinelai_training_data.csv"
)

df = pd.read_parquet(INPUT_FILE)

print("Dataset loaded successfully!")
print("Original shape:", df.shape)


# ==============================
# 2. SELECT COMPATIBLE FEATURES
# ==============================

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

TARGET = "Label"

# Keep only our ML features + Label
df = df[FEATURES + [TARGET]]

print("\nSelected features:")
for feature in FEATURES:
    print("-", feature)


# ==============================
# 3. CHECK PROTOCOL VALUES
# ==============================

print("\nProtocol values:")
print(df["Protocol"].value_counts())


# ==============================
# 4. SAVE PROCESSED DATASET
# ==============================

df.to_csv(OUTPUT_FILE, index=False)

print("\nDataset prepared successfully!")
print("Final shape:", df.shape)

print("\nSaved to:")
print(OUTPUT_FILE)

print("\nLabel distribution:")
print(df[TARGET].value_counts())