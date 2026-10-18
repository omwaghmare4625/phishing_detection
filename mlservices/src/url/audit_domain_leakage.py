
import pandas as pd
import tldextract

from urllib.parse import urlsplit
from sklearn.model_selection import GroupShuffleSplit

DATASET_FILE = "datasets/processed/url_features.csv"

# Disable network fetching of the Public Suffix List.
# tldextract uses its bundled suffix snapshot when available.
extractor = tldextract.TLDExtract(
    suffix_list_urls=None
)


def get_hostname(url):
    try:
        return (urlsplit(str(url)).hostname or "").lower().rstrip(".")
    except (ValueError, TypeError):
        return ""


def get_registered_domain(hostname):
    if not hostname:
        return ""

    result = extractor(hostname)

    # Handle IP addresses and single-label/internal hostnames.
    if result.domain and result.suffix:
        return f"{result.domain}.{result.suffix}".lower()

    return hostname.lower()


print("Loading dataset...")
df = pd.read_csv(DATASET_FILE)

required = {"url", "label"}
missing = required - set(df.columns)

if missing:
    raise ValueError(f"Missing required columns: {missing}")

df["hostname"] = df["url"].apply(get_hostname)
df["registered_domain"] = df["hostname"].apply(
    get_registered_domain
)

# Remove rows without usable domain information.
df = df[
    (df["hostname"] != "") &
    (df["registered_domain"] != "")
].copy()

print(f"Usable records: {len(df)}")
print(f"Unique hostnames: {df['hostname'].nunique()}")
print(
    "Unique registered domains:",
    df["registered_domain"].nunique()
)

# Reproduce the outer hostname-separated holdout split
# used by the earlier evaluation scripts.
X = df.drop(
    columns=["url", "label", "hostname", "registered_domain"]
)
y = df["label"]
hostname_groups = df["hostname"]

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42
)

train_idx, test_idx = next(
    splitter.split(X, y, groups=hostname_groups)
)

train = df.iloc[train_idx].copy()
test = df.iloc[test_idx].copy()

train_domains = set(train["registered_domain"])
test_domains = set(test["registered_domain"])

overlapping_domains = train_domains & test_domains

print("\n=== REGISTERED-DOMAIN LEAKAGE AUDIT ===")
print(f"Training records: {len(train)}")
print(f"Test records: {len(test)}")
print(
    "Training registered domains:",
    len(train_domains)
)
print(
    "Test registered domains:",
    len(test_domains)
)
print(
    "Registered domains in both sets:",
    len(overlapping_domains)
)

if overlapping_domains:
    print("\nExample overlapping domains:")
    for domain in sorted(overlapping_domains)[:30]:
        print(domain)

    print(
        "\nWARNING: The hostname-separated split "
        "contains registered-domain overlap."
    )
else:
    print(
        "\nNo registered-domain overlap detected "
        "in this split."
    )

# Check whether the same registered domain has both labels.
label_counts = (
    df.groupby("registered_domain")["label"]
    .nunique()
)

mixed_label_domains = label_counts[label_counts > 1].index

print(
    "\nRegistered domains associated with both labels:",
    len(mixed_label_domains)
)

# Save an audit report.
report = pd.DataFrame([
    {
        "metric": "usable_records",
        "value": len(df)
    },
    {
        "metric": "unique_hostnames",
        "value": df["hostname"].nunique()
    },
    {
        "metric": "unique_registered_domains",
        "value": df["registered_domain"].nunique()
    },
    {
        "metric": "training_records",
        "value": len(train)
    },
    {
        "metric": "test_records",
        "value": len(test)
    },
    {
        "metric": "registered_domain_overlap",
        "value": len(overlapping_domains)
    },
    {
        "metric": "mixed_label_registered_domains",
        "value": len(mixed_label_domains)
    }
])

report.to_csv(
    "models/domain_leakage_audit.csv",
    index=False
)

if overlapping_domains:
    pd.DataFrame({
        "registered_domain": sorted(overlapping_domains)
    }).to_csv(
        "models/overlapping_registered_domains.csv",
        index=False
    )

print("\nSaved report to models/domain_leakage_audit.csv")
