
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

DATASET = "datasets/processed/url_features.csv"
MODEL = "models/url_xgboost_tuned.json"
FEATURES = "models/url_xgboost_tuned_features.json"

THRESHOLD = 0.35


def get_hostname(url):
    try:
        return (urlsplit(str(url)).hostname or "").lower().rstrip(".")
    except (ValueError, TypeError):
        return ""


df = pd.read_csv(DATASET)
df["hostname"] = df["url"].apply(get_hostname)
df = df[df["hostname"] != ""].copy()

features = json.load(open(FEATURES))
X = df[features]
y = df["label"]
groups = df["hostname"]

# Reproduce the original holdout split.
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)

train_idx, test_idx = next(
    splitter.split(X, y, groups=groups)
)

# Reproduce the original training/validation partition.
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
        X_train_full,
        y_train_full,
        groups=groups_train,
    )
)

X_train = X_train_full.iloc[inner_train_idx]
y_train = y_train_full.iloc[inner_train_idx]
X_val = X_train_full.iloc[val_idx]
y_val = y_train_full.iloc[val_idx]

# Reproduce the threshold experiment's training protocol.
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

model.fit(X_train, y_train)

# Evaluate the holdout only after fixing the threshold.
X_test = X.iloc[test_idx]
y_test = y.iloc[test_idx]

probabilities = model.predict_proba(X_test)[:, 1]

for threshold in [0.50, THRESHOLD]:
    predictions = (probabilities >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_test, predictions, labels=[0, 1]
    ).ravel()

    print(f"\n=== HOLDOUT THRESHOLD {threshold:.2f} ===")
    print(f"Accuracy:  {accuracy_score(y_test, predictions):.4f}")
    print(f"Precision: {precision_score(y_test, predictions):.4f}")
    print(f"Recall:    {recall_score(y_test, predictions):.4f}")
    print(f"F1 score:  {f1_score(y_test, predictions):.4f}")
    print(f"TN: {tn} | FP: {fp} | FN: {fn} | TP: {tp}")

print("\nHoldout evaluation complete.")
