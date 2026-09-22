import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score
)


# ==========================================
# 1. LOAD PROCESSED DATASET
# ==========================================

DATASET_FILE = "ai/dataset/processed/sentinelai_training_data.csv"

df = pd.read_csv(DATASET_FILE)

print("=" * 60)
print("SENTINELAI - MODEL TRAINING")
print("=" * 60)

print("\nDataset loaded successfully!")
print("Dataset shape:", df.shape)


# ==========================================
# 2. CREATE BINARY LABELS
# ==========================================

# Benign = 0
# Any attack = 1

df["Target"] = df["Label"].apply(
    lambda label: 0 if label == "Benign" else 1
)

print("\nOriginal labels:")
print(df["Label"].value_counts())

print("\nBinary labels:")
print(df["Target"].value_counts())


# ==========================================
# 3. PREPARE FEATURES AND TARGET
# ==========================================

X = df.drop(columns=["Label", "Target"])
y = df["Target"]

print("\nFeatures used:")
print(list(X.columns))


# ==========================================
# 4. TRAIN / TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ==========================================
# 5. CREATE MODEL
# ==========================================

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

print("\nTraining model...")
model.fit(X_train, y_train)


# ==========================================
# 6. MAKE PREDICTIONS
# ==========================================

y_pred = model.predict(X_test)


# ==========================================
# 7. EVALUATE MODEL
# ==========================================

print("\n" + "=" * 60)
print("MODEL EVALUATION")
print("=" * 60)

print("\nAccuracy:")
print(accuracy_score(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))


# ==========================================
# 8. SAVE MODEL
# ==========================================

MODEL_FILE = "ai/models/sentinelai_model.joblib"

joblib.dump(model, MODEL_FILE)

print("\nModel saved successfully!")
print("Saved to:", MODEL_FILE)