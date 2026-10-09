"""
train_classifier.py
Role 4 (ML/RAG Engineer, Dagi) — XGBoost False-Positive Classifier

Trains an XGBoost model to predict if an alert is benign or malicious.
The model is trained on historical incidents (historical_alerts.csv).

The trained model is saved as a pickle file (fp_classifier.pkl)
and later used by classifier_inference.py for real-time predictions.
"""

import pickle
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
import xgboost as xgb


# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
CSV_PATH = "historical_alerts.csv"
MODEL_OUTPUT = "fp_classifier.pkl"
ENCODER_OUTPUT = "alert_type_encoder.pkl"


# ---------------------------------------------------------------------------
# STEP 1: LOAD DATA
# ---------------------------------------------------------------------------
def load_data(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    print(f"[INFO] Loaded {len(df)} rows from {csv_path}")
    return df


# ---------------------------------------------------------------------------
# STEP 2: FEATURE ENGINEERING
# ---------------------------------------------------------------------------
def extract_features(df: pd.DataFrame):
    """
    Convert raw CSV columns into numerical features the model can learn from.

    Returns:
        (features_df, labels_series, alert_type_encoder)
    """
    features = pd.DataFrame()

    # Feature 1: Severity (ordinal encoding)
    severity_map = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    features["severity_encoded"] = df["severity"].map(severity_map)

    # Feature 2: Alert type (label encoding — each type gets a unique number)
    le_alert = LabelEncoder()
    features["alert_type_encoded"] = le_alert.fit_transform(df["alert_type"])

    # Feature 3: Description length (proxy for complexity)
    features["desc_length"] = df["description"].apply(len)

    # Feature 4: Binary flag for high severity
    features["is_high_severity"] = (
        df["severity"].isin(["High", "Critical"])
    ).astype(int)

    # Label: 1 = Malicious, 0 = Benign
    label = (df["resolution"] == "Malicious").astype(int)

    print(f"[INFO] Extracted {features.shape[1]} features")
    print(f"[INFO] Alert types: {list(le_alert.classes_)}")

    return features, label, le_alert


# ---------------------------------------------------------------------------
# STEP 3: TRAIN XGBOOST MODEL
# ---------------------------------------------------------------------------
def train_model(X_train, y_train, X_test, y_test):
    print("\n[TRAIN] Starting XGBoost training...")

    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        objective="binary:logistic",
        eval_metric="logloss",
        random_state=42,
    )

    model.fit(X_train, y_train)

    # Evaluate on test set
    y_pred = model.predict(X_test)

    print("\n" + "=" * 60)
    print("MODEL PERFORMANCE")
    print("=" * 60)
    print(f"Accuracy:  {accuracy_score(y_test, y_pred):.3f}")
    print(f"Precision: {precision_score(y_test, y_pred, zero_division=0):.3f}")
    print(f"Recall:    {recall_score(y_test, y_pred, zero_division=0):.3f}")
    print(f"F1 Score:  {f1_score(y_test, y_pred, zero_division=0):.3f}")

    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"                 Predicted Benign   Predicted Malicious")
    print(f"Actual Benign           {cm[0][0]:>3}                 {cm[0][1]:>3}")
    print(f"Actual Malicious        {cm[1][0]:>3}                 {cm[1][1]:>3}")

    # Feature importance
    print("\nFeature Importance:")
    for name, importance in zip(
        ["severity_encoded", "alert_type_encoded", "desc_length", "is_high_severity"],
        model.feature_importances_,
    ):
        print(f"  {name:25s} {importance:.4f}")

    return model


# ---------------------------------------------------------------------------
# STEP 4: SAVE MODEL & ENCODER
# ---------------------------------------------------------------------------
def save_artifacts(model, encoder):
    with open(MODEL_OUTPUT, "wb") as f:
        pickle.dump(model, f)
    with open(ENCODER_OUTPUT, "wb") as f:
        pickle.dump(encoder, f)

    print(f"\n[SAVE] Model saved to   {MODEL_OUTPUT}")
    print(f"[SAVE] Encoder saved to {ENCODER_OUTPUT}")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("XGBOOST FALSE-POSITIVE CLASSIFIER — TRAINING")
    print("=" * 60)

    # Load and prepare data
    df = load_data(CSV_PATH)
    X, y, encoder = extract_features(df)

    # Split into training and test sets (stratified to preserve class balance)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n[SPLIT] Training samples: {len(X_train)}")
    print(f"[SPLIT] Test samples:     {len(X_test)}")

    # Train the model
    model = train_model(X_train, y_train, X_test, y_test)

    # Save artifacts
    save_artifacts(model, encoder)

    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)