
import pandas as pd
from urllib.parse import urlsplit

FILE = "datasets/processed/url_features.csv"

df = pd.read_csv(FILE)

print("=== DATASET AUDIT ===")
print("Shape:", df.shape)
print("\nLabel counts:")
print(df["label"].value_counts(dropna=False))

# Check duplicate URLs
print("\nExact duplicate URLs:", df["url"].duplicated().sum())

# Extract hostnames for domain-level analysis
def get_hostname(url):
    try:
        parsed = urlsplit(str(url).strip())
        return (parsed.hostname or "").lower().rstrip(".")
    except (ValueError, TypeError):
        return ""

df["hostname"] = df["url"].apply(get_hostname)

print("Missing/invalid hostnames:", (df["hostname"] == "").sum())
print("Unique hostnames:", df["hostname"].nunique())

# Check whether a hostname occurs with both labels
valid = df[df["hostname"] != ""]

labels_per_host = valid.groupby("hostname")["label"].nunique()

print(
    "Hostnames associated with both labels:",
    (labels_per_host > 1).sum()
)

# Compare basic URL characteristics by class
df["has_path"] = df["url"].apply(
    lambda u: int(bool(urlsplit(str(u)).path.strip("/")))
)

print("\nMean feature values by label:")
print(
    df.groupby("label")[
        [
            "url_length",
            "hostname_length",
            "path_length",
            "num_dots",
            "num_hyphens",
            "has_https",
            "has_ip",
            "num_subdomains",
            "suspicious_keyword_count",
            "has_path",
        ]
    ].mean().round(3).T
)

print("\nAudit complete. Original CSV was not modified.")
