
import pandas as pd
import matplotlib.pyplot as plt
from xgboost import XGBClassifier

MODEL_FILE = "models/url_xgboost_model.json"

model = XGBClassifier()
model.load_model(MODEL_FILE)

importance = pd.DataFrame({
    "feature": model.get_booster().feature_names,
    "importance": model.feature_importances_,
})

importance = importance.sort_values(
    "importance", ascending=False
)

print("\n=== XGBoost Feature Importance ===")
print(importance.to_string(index=False))

# Plot the top 15 features
top = importance.head(15).sort_values("importance")

plt.figure(figsize=(10, 7))
plt.barh(top["feature"], top["importance"])
plt.xlabel("Feature importance")
plt.ylabel("Feature")
plt.title("Top 15 URL Features — XGBoost")
plt.tight_layout()

output_file = "models/feature_importance.png"
plt.savefig(output_file, dpi=150)
print(f"\nChart saved to: {output_file}")

plt.show()
