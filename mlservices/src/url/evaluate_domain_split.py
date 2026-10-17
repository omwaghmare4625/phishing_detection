
import pandas as pd

from urllib.parse import urlsplit
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)
from xgboost import XGBClassifier


DATASET_FILE = "datasets/processed/url_features.csv"
MODEL_FILE = "models/url_xgboost_model.json"


def get_hostname(url):
    try:
        return (urlsplit(str(url)).hostname or "").lower().rstrip(".")
    except (ValueError, TypeError):
        return ""


print("Loading dataset...")
df = pd.read_csv(DATASET_FILE)

# Remove rows whose hostnames cannot be parsed.
df["hostname"] = df["url"].apply(get_hostname)
df = df[df["hostname"] != ""].copy()

# Do not use the raw URL or hostname as model features.
X = df.drop(columns=["url", "label", "hostname"])
y = df["label"]
groups = df["hostname"]

# Split by hostname, not by individual URL.
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)

train_idx, test_idx = next(
    splitter.split(X, y, groups=groups)
)

X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

train_hosts = set(groups.iloc[train_idx])
test_hosts = set(groups.iloc[test_idx])

print("\nDomain-separated split:")
print("Training URLs:", len(X_train))
print("Testing URLs:", len(X_test))
print("Training hostnames:", len(train_hosts))
print("Testing hostnames:", len(test_hosts))
print("Hostnames in both sets:", len(train_hosts & test_hosts))

print("\nTraining label distribution:")
print(y_train.value_counts())

print("\nTesting label distribution:")
print(y_test.value_counts())

if y_train.nunique() < 2 or y_test.nunique() < 2:
    raise ValueError(
        "A split contains only one class. "
        "A different grouping strategy is needed."
    )

# Load the already-trained model; do not retrain it here.
model = XGBClassifier()
model.load_model(MODEL_FILE)

if list(model.feature_names_in_) != list(X.columns):
    raise ValueError(
        "Feature columns/order do not match the saved model."
    )

predictions = model.predict(X_test)

print("\n=== DOMAIN-SEPARATED EVALUATION ===")
print(f"Accuracy:  {accuracy_score(y_test, predictions):.4f}")
print(f"Precision: {precision_score(y_test, predictions, zero_division=0):.4f}")
print(f"Recall:    {recall_score(y_test, predictions, zero_division=0):.4f}")
print(f"F1 score:  {f1_score(y_test, predictions, zero_division=0):.4f}")

print("\nClassification report:")
print(
    classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["Legitimate", "Phishing"],
        zero_division=0,
    )
)

print("\nConfusion matrix:")
print(confusion_matrix(y_test, predictions, labels=[0, 1]))
