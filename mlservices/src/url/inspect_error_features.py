
import pandas as pd

DATASET_FILE = "datasets/processed/url_features.csv"
ERROR_FILE = "models/misclassified_urls.csv"

df = pd.read_csv(DATASET_FILE)
errors = pd.read_csv(ERROR_FILE)

# Add the original feature values to each error.
feature_columns = [
    c for c in df.columns
    if c not in ["url", "label"]
]

merged = errors.merge(
    df[["url"] + feature_columns],
    on="url",
    how="left",
    suffixes=("", "_original")
)

false_negatives = merged[
    merged["error_type"] == "False Negative"
]

false_positives = merged[
    merged["error_type"] == "False Positive"
]

print("=== ERROR ANALYSIS ===")
print("False negatives:", len(false_negatives))
print("False positives:", len(false_positives))

print("\n=== FALSE NEGATIVE FEATURE AVERAGES ===")
print(false_negatives[feature_columns].mean().round(3).to_string())

print("\n=== FALSE POSITIVE FEATURE AVERAGES ===")
print(false_positives[feature_columns].mean().round(3).to_string())

# Find repeated feature patterns among missed phishing URLs.
if not false_negatives.empty:
    repeated = (
        false_negatives.groupby(feature_columns, dropna=False)
        .size()
        .sort_values(ascending=False)
    )

    print("\n=== MOST REPEATED FALSE NEGATIVE PATTERNS ===")
    print(repeated.head(10).to_string())

merged.to_csv("models/error_feature_analysis.csv", index=False)
print("\nSaved detailed analysis to models/error_feature_analysis.csv")
