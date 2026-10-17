
import pandas as pd

from urllib.parse import urlsplit
from sklearn.model_selection import GroupShuffleSplit, ParameterGrid
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

# First, separate the final test set by hostname.
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

# Then create a validation set from the training portion.
inner_split = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=43,
)

train_idx, val_idx = next(
    inner_split.split(
        X_trainval,
        y_trainval,
        groups=g_trainval,
    )
)

X_train = X_trainval.iloc[train_idx]
y_train = y_trainval.iloc[train_idx]
g_train = g_trainval.iloc[train_idx]

X_val = X_trainval.iloc[val_idx]
y_val = y_trainval.iloc[val_idx]
g_val = g_trainval.iloc[val_idx]

print("Training URLs:", len(X_train))
print("Validation URLs:", len(X_val))
print("Final test URLs:", len(X_test))

assert set(g_train).isdisjoint(set(g_val))
assert set(g_train).isdisjoint(set(groups.iloc[test_idx]))
assert set(g_val).isdisjoint(set(groups.iloc[test_idx]))

# Exclude the two dominant features for this experiment.
excluded = {"path_length", "num_slashes"}
features = [
    col for col in X.columns if col not in excluded
]

X_train = X_train[features]
X_val = X_val[features]

# Small search grid to keep the experiment manageable.
param_grid = {
    "max_depth": [3, 6],
    "learning_rate": [0.05, 0.1],
    "n_estimators": [200],
    "min_child_weight": [1, 5],
    "subsample": [0.8],
    "colsample_bytree": [0.8],
    "reg_lambda": [1, 5],
}

results = []

for i, params in enumerate(ParameterGrid(param_grid), start=1):
    print(f"\nExperiment {i}/{len(ParameterGrid(param_grid))}")
    print(params)

    model = XGBClassifier(
        **params,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_val)

    result = {
        **params,
        "accuracy": accuracy_score(y_val, predictions),
        "precision": precision_score(
            y_val, predictions, zero_division=0
        ),
        "recall": recall_score(
            y_val, predictions, zero_division=0
        ),
        "f1": f1_score(
            y_val, predictions, zero_division=0
        ),
    }

    results.append(result)

results_df = pd.DataFrame(results).sort_values(
    ["recall", "f1"],
    ascending=False,
)

print("\n=== VALIDATION RESULTS ===")
print(results_df.to_string(index=False))

results_df.to_csv(
    "models/xgboost_tuning_results.csv",
    index=False,
)

print("\nSaved results to models/xgboost_tuning_results.csv")
print("Final test set has not been evaluated or used for tuning.")
