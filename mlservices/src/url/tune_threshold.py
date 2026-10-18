
import json
import pandas as pd

from urllib.parse import urlsplit
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
from xgboost import XGBClassifier

DATASET_FILE = "datasets/processed/url_features.csv"
FEATURE_FILE = "models/url_xgboost_tuned_features.json"

def hostname(url):
    try:
        return (urlsplit(str(url)).hostname or "").lower().rstrip(".")
    except (ValueError, TypeError):
        return ""

df = pd.read_csv(DATASET_FILE)
df["hostname"] = df["url"].apply(hostname)
df = df[df["hostname"] != ""].copy()

features = json.load(open(FEATURE_FILE))

X = df[features]
y = df["label"]
groups = df["hostname"]

# Reproduce the original hostname-separated split.
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)
train_idx, test_idx = next(
    splitter.split(X, y, groups=groups)
)

# Split the original training portion into train and validation.
X_train_full = X.iloc[train_idx]
y_train_full = y.iloc[train_idx]
groups_train = groups.iloc[train_idx]

inner_splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=43,
)
inner_train_idx, val_idx = next(
    inner_splitter.split(
        X_train_full, y_train_full, groups=groups_train
    )
)

X_train = X_train_full.iloc[inner_train_idx]
y_train = y_train_full.iloc[inner_train_idx]
X_val = X_train_full.iloc[val_idx]
y_val = y_train_full.iloc[val_idx]

model = XGBClassifier(
    max_depth=6,
    learning_rate=0.1,
    min_child_weight=1,
    reg_lambda=1,
    n_estimators=200,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    eval_metric="logloss",
)

print("Training on training partition...")
model.fit(X_train, y_train)

probabilities = model.predict_proba(X_val)[:, 1]

results = []

for threshold in [0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]:
    predictions = (probabilities >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_val, predictions, labels=[0, 1]
    ).ravel()

    results.append({
        "threshold": threshold,
        "accuracy": accuracy_score(y_val, predictions),
        "precision": precision_score(
            y_val, predictions, zero_division=0
        ),
        "recall": recall_score(
            y_val, predictions, zero_division=0
        ),
        "f1": f1_score(y_val, predictions, zero_division=0),
        "false_positives": int(fp),
        "false_negatives": int(fn),
    })

results_df = pd.DataFrame(results)
print("\n=== VALIDATION THRESHOLD COMPARISON ===")
print(results_df.round(4).to_string(index=False))

results_df.to_csv(
    "models/threshold_comparison.csv", index=False
)
print("\nSaved to models/threshold_comparison.csv")
