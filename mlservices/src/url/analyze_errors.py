
import pandas as pd

from urllib.parse import urlsplit
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import confusion_matrix
from xgboost import XGBClassifier

DATASET_FILE = "datasets/processed/url_features.csv"
MODEL_FILE = "models/url_xgboost_tuned.json"
FEATURE_FILE = "models/url_xgboost_tuned_features.json"


def get_hostname(url):
    try:
        return (urlsplit(str(url)).hostname or "").lower().rstrip(".")
    except (ValueError, TypeError):
        return ""


df = pd.read_csv(DATASET_FILE)
df["hostname"] = df["url"].apply(get_hostname)
df = df[df["hostname"] != ""].copy()

X = df.drop(columns=["url", "label", "hostname"])
y = df["label"]
groups = df["hostname"]

# Reproduce the original final holdout split.
splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)
train_idx, test_idx = next(
    splitter.split(X, y, groups=groups)
)

test = df.iloc[test_idx].copy()
X_test = X.iloc[test_idx]

# Load the exact feature list used by the tuned model.
features = pd.read_json(FEATURE_FILE, typ="series").tolist()

model = XGBClassifier()
model.load_model(MODEL_FILE)

predictions = model.predict(X_test[features])
probabilities = model.predict_proba(X_test[features])[:, 1]

test["prediction"] = predictions
test["phishing_score"] = probabilities

# 0 = legitimate, 1 = phishing
test["error_type"] = "Correct"
test.loc[
    (test["label"] == 1) & (test["prediction"] == 0),
    "error_type"
] = "False Negative"

test.loc[
    (test["label"] == 0) & (test["prediction"] == 1),
    "error_type"
] = "False Positive"

errors = test[test["label"] != test["prediction"]].copy()

print("Confusion matrix:")
print(confusion_matrix(test["label"], predictions))

print("\nError counts:")
print(errors["error_type"].value_counts())

print("\nExample misclassified URLs:")
print(
    errors[
        ["url", "label", "prediction", "phishing_score", "error_type"]
    ].head(30).to_string(index=False)
)

errors.to_csv("models/misclassified_urls.csv", index=False)
print("\nSaved errors to models/misclassified_urls.csv")
