from pathlib import Path
import joblib
import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)
from xgboost import XGBClassifier  # type: ignore


# -----------------------------------
# 1. Load feature dataset
# -----------------------------------

BASE_DIR = Path(__file__).resolve().parents[2]  # mlservices directory
DATASET_FILE = BASE_DIR / "datasets" / "processed" / "url_features.csv"
REPO_ROOT = BASE_DIR.parent
MODEL_OUTPUT_DIR = REPO_ROOT / "backend" / "models"
MODEL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
MODEL_FILE = MODEL_OUTPUT_DIR / "url_model.joblib"

print(f"Loading dataset from: {DATASET_FILE}")

df = pd.read_csv(DATASET_FILE)

print(f"Total records: {len(df)}")


# -----------------------------------
# 2. Separate features and label
# -----------------------------------

# Remove the raw URL because XGBoost
# will use the numerical features.

X = df.drop(columns=["url", "label"])

y = df["label"]


print(f"\nNumber of features: {X.shape[1]}")


# -----------------------------------
# 3. Train/Test Split
# -----------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print("\nDataset split:")
print(f"Training samples: {len(X_train)}")
print(f"Testing samples: {len(X_test)}")


# -----------------------------------
# 4. Create XGBoost model
# -----------------------------------

print("\nCreating XGBoost model...")

model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    eval_metric="logloss"
)


# -----------------------------------
# 5. Train model
# -----------------------------------

print("\nTraining model...")

model.fit(
    X_train,
    y_train
)

print("Training complete!")
MODEL_DIR="models"
MODEL_FILE="models/url_XGboost_model.json"
os.makedirs(MODEL_DIR,exist_ok=True)
model.save_model(MODEL_FILE)
print(f"Model Saved to: {MODEL_FILE}")

# -----------------------------------
# 6. Make predictions
# -----------------------------------

print("\nMaking predictions...")

y_pred = model.predict(X_test)


# -----------------------------------
# 7. Calculate metrics
# -----------------------------------

accuracy = accuracy_score(
    y_test,
    y_pred
)

precision = precision_score(
    y_test,
    y_pred
)

recall = recall_score(
    y_test,
    y_pred
)

f1 = f1_score(
    y_test,
    y_pred
)


# -----------------------------------
# 8. Display results
# -----------------------------------

print("\n==============================")
print("       MODEL RESULTS")
print("==============================")

print(f"Accuracy:  {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")
print(f"F1 Score:  {f1:.4f}")


# -----------------------------------
# 9. Detailed classification report
# -----------------------------------

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "Legitimate",
            "Phishing"
        ]
    )
)


# -----------------------------------
# 10. Confusion Matrix
# -----------------------------------

print("\nConfusion Matrix:")

cm = confusion_matrix(
    y_test,
    y_pred
)

print(cm)

# -----------------------------------
# 11. Save trained model & feature names
# -----------------------------------

print(f"\nSaving model artifact to: {MODEL_FILE}")
joblib.dump(
    {
        "model": model,
        "features": list(X.columns)
    },
    MODEL_FILE
)
print("Model saved successfully!")