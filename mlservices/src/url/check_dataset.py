import pandas as pd

# -----------------------------------
# Load feature dataset
# -----------------------------------

FILE = "datasets/processed/url_features.csv"

df = pd.read_csv(FILE)

print("Dataset loaded successfully!\n")


# -----------------------------------
# Basic information
# -----------------------------------

print("Dataset shape:")
print(df.shape)

print("\n")


# -----------------------------------
# Data types
# -----------------------------------

print("Data types:")
print(df.dtypes)

print("\n")


# -----------------------------------
# Missing values
# -----------------------------------

print("Missing values:")
print(df.isnull().sum())

print("\n")


# -----------------------------------
# Duplicate rows
# -----------------------------------

print("Duplicate rows:")
print(df.duplicated().sum())

print("\n")


# -----------------------------------
# Label distribution
# -----------------------------------

print("Label distribution:")
print(df["label"].value_counts())

print("\n")


# -----------------------------------
# Label percentages
# -----------------------------------

print("Label percentages:")
print(df["label"].value_counts(normalize=True) * 100)

print("\n")


# -----------------------------------
# Summary statistics
# -----------------------------------

print("Numerical feature statistics:")
print(df.describe())