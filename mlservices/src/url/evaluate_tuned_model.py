
import json
import pandas as pd

from pathlib import Path
from urllib.parse import urlsplit

from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    average_precision_score,
    roc_auc_score,
)

from xgboost import XGBClassifier


DATASET_FILE = "datasets/processed/url_features.csv"
MODEL_DIR = Path("models")
MODEL_FILE = MODEL_DIR / "url_xgboost_tuned.json"

MODEL_DIR.mkdir(parents=True, exist_ok=True)


def get_hostname(url):
    try:
        return (urlsplit(str(url)).hostname or "").lower().rstrip(".")
    except (ValueError, TypeError):
        return ""


print("Loading dataset...")
df = pd.read_csv(DATASET_FILE)

df["hostname"] = df["url"].apply(get_hostname)
df = df[df["hostname"] != ""].copy()

X = df.drop(columns=["url", "label", "hostname"])
y = df["label"]
groups = df["hostname"]

# Reproduce the same outer split used during tuning.
outer_split = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)

trainval_idx, test_idx = next(
    outer_split.split(X, y, groups=groups)
)

X_trainval = X.iloc[trainval_idx]
y_trainval = y.iloc[trainval_idx]
g_trainval = groups.iloc[trainval_idx]

X_test = X.iloc[test_idx]
y_test = y.iloc[test_idx]
g_test = groups.iloc[test_idx]

assert set(g_trainval).isdisjoint(set(g_test))

# Use the same 21 features evaluated during tuning.
features = [
    col for col in X.columns
    if col not in {"path_length", "num_slashes"}
]

# Best validation configuration from your tuning output.
model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.10,
    min_child_weight=1,
    subsample=0.8,
    colsample_bytree=0.8,
    reg_lambda=1,
    objective="binary:logistic",
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1,
)

print("\nTraining selected model on training + validation data...")
model.fit(X_trainval[features], y_trainval)

print("Training complete.")

# Evaluate only once on the untouched test set.
predictions = model.predict(X_test[features])
probabilities = model.predict_proba(X_test[features])[:, 1]

print("\n=== FINAL HOLDOUT RESULTS ===")
print(f"Test samples: {len(y_test)}")
print(f"Features: {len(features)}")
print(f"Accuracy:  {accuracy_score(y_test, predictions):.4f}")
print(
    f"Precision: {precision_score(y_test, predictions, zero_division=0):.4f}"
)
print(
    f"Recall:    {recall_score(y_test, predictions, zero_division=0):.4f}"
)
print(
    f"F1 score:  {f1_score(y_test, predictions, zero_division=0):.4f}"
)
print(
    f"PR-AUC:    {average_precision_score(y_test, probabilities):.4f}"
)
print(
    f"ROC-AUC:   {roc_auc_score(y_test, probabilities):.4f}"
)

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

# Save the newly trained candidate separately.
model.save_model(str(MODEL_FILE))

with open(MODEL_DIR / "url_xgboost_tuned_features.json", "w") as file:
    json.dump(features, file, indent=2)

print(f"\nTuned model saved to: {MODEL_FILE}")
print("Feature list saved separately.")
