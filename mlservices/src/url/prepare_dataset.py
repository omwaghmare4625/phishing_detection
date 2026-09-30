import pandas as pd
from pathlib import Path

# -----------------------------------
# File paths
# -----------------------------------

PHISHTANK_FILE = Path("datasets/raw/verified_online.csv")
TRANCO_FILE = Path("datasets/raw/tranco_K9LZW.csv")
OUTPUT_FILE = Path("datasets/processed/urls.csv")

# -----------------------------------
# 1. Load PhishTank dataset
# -----------------------------------

print("Loading PhishTank dataset...")

phishing_df = pd.read_csv(PHISHTANK_FILE)

print(f"PhishTank records: {len(phishing_df)}")


# -----------------------------------
# 2. Extract phishing URLs
# -----------------------------------

phishing_urls = phishing_df[["url"]].copy()

phishing_urls["label"] = 1


# -----------------------------------
# 3. Remove duplicate phishing URLs
# -----------------------------------

phishing_urls = phishing_urls.drop_duplicates(subset="url")

print(f"Unique phishing URLs: {len(phishing_urls)}")


# -----------------------------------
# 4. Load Tranco dataset
# -----------------------------------

print("Loading Tranco dataset...")

tranco_df = pd.read_csv(
    TRANCO_FILE,
    header=None,
    names=["rank", "domain"]
)

print(f"Tranco records: {len(tranco_df)}")


# -----------------------------------
# 5. Convert domains to URLs
# -----------------------------------

legitimate_urls = tranco_df[["domain"]].copy()

legitimate_urls["url"] = "https://" + legitimate_urls["domain"]

legitimate_urls["label"] = 0

legitimate_urls = legitimate_urls[["url", "label"]]


# -----------------------------------
# 6. Remove duplicate legitimate URLs
# -----------------------------------

legitimate_urls = legitimate_urls.drop_duplicates(subset="url")


# -----------------------------------
# 7. Sample legitimate URLs
# -----------------------------------

sample_size = min(
    len(phishing_urls),
    len(legitimate_urls)
)

legitimate_urls = legitimate_urls.sample(
    n=sample_size,
    random_state=42
)

print(f"Legitimate URLs selected: {len(legitimate_urls)}")


# -----------------------------------
# 8. Combine both datasets
# -----------------------------------

combined_df = pd.concat(
    [phishing_urls, legitimate_urls],
    ignore_index=True
)


# -----------------------------------
# 9. Shuffle dataset
# -----------------------------------

combined_df = combined_df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)


# -----------------------------------
# 10. Save dataset
# -----------------------------------

OUTPUT_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)

combined_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# -----------------------------------
# 11. Print final information
# -----------------------------------

print("\nDataset preparation complete!")

print(f"Total records: {len(combined_df)}")

print("\nClass distribution:")
print(combined_df["label"].value_counts())

print("\nFirst 5 records:")
print(combined_df.head())

print(f"\nSaved to: {OUTPUT_FILE}")