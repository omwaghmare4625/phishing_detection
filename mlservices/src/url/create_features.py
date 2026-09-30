import pandas as pd
from feature_extractor import extract_features


# -----------------------------------
# File paths
# -----------------------------------

INPUT_FILE = "datasets/processed/urls.csv"
OUTPUT_FILE = "datasets/processed/url_features.csv"


# -----------------------------------
# Load dataset
# -----------------------------------

print("Loading URL dataset...")

df = pd.read_csv(INPUT_FILE)

print(f"Total URLs: {len(df)}")


# -----------------------------------
# Extract features
# -----------------------------------

print("\nExtracting features...")
print("This may take a little while...")


feature_rows = []

for index, url in enumerate(df["url"]):

    features = extract_features(url)

    feature_rows.append(features)

    # Show progress every 10,000 URLs
    if (index + 1) % 10000 == 0:
        print(f"Processed {index + 1} URLs")


# -----------------------------------
# Convert features to DataFrame
# -----------------------------------

features_df = pd.DataFrame(feature_rows)


# -----------------------------------
# Add labels
# -----------------------------------

features_df["label"] = df["label"].values


# -----------------------------------
# Add original URL
# -----------------------------------

features_df.insert(
    0,
    "url",
    df["url"].values
)


# -----------------------------------
# Save feature dataset
# -----------------------------------

features_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# -----------------------------------
# Display information
# -----------------------------------

print("\nFeature extraction complete!")

print(f"Total records: {len(features_df)}")

print(f"Total columns: {len(features_df.columns)}")

print("\nColumns:")
print(features_df.columns.tolist())

print("\nFirst 5 rows:")
print(features_df.head())

print(f"\nSaved to: {OUTPUT_FILE}")