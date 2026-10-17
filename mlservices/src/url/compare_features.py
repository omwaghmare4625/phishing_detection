
import pandas as pd

from urllib.parse import urlsplit
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)
from xgboost import XGBClassifier


DATASET_FILE = "datasets/processed/url_features.csv"

df = pd.read_csv(DATASET_FILE)


def get_hostname(url):
    try:
        return (urlsplit(str(url)).hostname or "").lower().rstrip(".")
    except (ValueError, TypeError):
        return ""


df["hostname"] = df["url"].apply(get_hostname)
df = df[df["hostname"] != ""].copy()

X = df.drop(columns=["url", "label", "hostname"])
y = df["label"]
groups = df["hostname"]

# Keep the same domain split for both experiments.
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)

train_idx, test_idx = next(
    splitter.split(X, y, groups=groups)
)

X_train = X.iloc[train_idx]
X_test = X.iloc[test_idx]
y_train = y.iloc[train_idx]
y_test = y.iloc[test_idx]

feature_sets = {
    "All features": list(X.columns),
    "Without path_length and num_slashes": [
        col for col in X.columns
        if col not in ["path_length", "num_slashes"]
    ],
}

print("Training and evaluating fresh models...")
print("Training URLs:", len(X_train))
print("Testing URLs:", len(X_test))
print(
    "Shared hostnames:",
    len(set(groups.iloc[train_idx]) &
        set(groups.iloc[test_idx]))
)

results = []

for name, columns in feature_sets.items():
    print(f"\nTraining: {name}")

    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric="logloss",
        n_jobs=-1,
    )

    model.fit(X_train[columns], y_train)
    predictions = model.predict(X_test[columns])

    metrics = {
        "Experiment": name,
        "Features": len(columns),
        "Accuracy": accuracy_score(y_test, predictions),
        "Precision": precision_score(
            y_test, predictions, zero_division=0
        ),
        "Recall": recall_score(
            y_test, predictions, zero_division=0
        ),
        "F1": f1_score(
            y_test, predictions, zero_division=0
        ),
    }

    results.append(metrics)

    print(f"Accuracy:  {metrics['Accuracy']:.4f}")
    print(f"Precision: {metrics['Precision']:.4f}")
    print(f"Recall:    {metrics['Recall']:.4f}")
    print(f"F1 score:  {metrics['F1']:.4f}")

results_df = pd.DataFrame(results)

print("\n=== FEATURE ABLATION RESULTS ===")
print(results_df.to_string(index=False))

results_df.to_csv(
    "models/feature_ablation_results.csv",
    index=False,
)

print("\nResults saved to models/feature_ablation_results.csv")
