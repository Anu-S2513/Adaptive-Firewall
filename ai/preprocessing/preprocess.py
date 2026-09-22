import pandas as pd

# Load dataset
df = pd.read_parquet(
    "ai/dataset/raw/Bruteforce-Tuesday-no-metadata.parquet"
)

print("=" * 60)
print("DATASET SHAPE")
print("=" * 60)
print(df.shape)

print("\n" + "=" * 60)
print("COLUMN NAMES")
print("=" * 60)
for column in df.columns:
    print(column)

print("\n" + "=" * 60)
print("DATA TYPES")
print("=" * 60)
print(df.dtypes)

print("\n" + "=" * 60)
print("LABEL DISTRIBUTION")
print("=" * 60)
print(df["Label"].value_counts(dropna=False))

print("\n" + "=" * 60)
print("MISSING VALUES")
print("=" * 60)
missing = df.isnull().sum()
print(missing[missing > 0])

print("\n" + "=" * 60)
print("INFINITE VALUES")
print("=" * 60)

numeric_df = df.select_dtypes(include="number")

positive_inf = (numeric_df == float("inf")).sum().sum()
negative_inf = (numeric_df == float("-inf")).sum().sum()

print("Positive infinity:", positive_inf)
print("Negative infinity:", negative_inf)

print("\n" + "=" * 60)
print("DUPLICATE ROWS")
print("=" * 60)
print(df.duplicated().sum())