"""
classifier_inference.py
Role 4 (ML/RAG Engineer, Dagi) — Inference API for FP Classifier

Loads the trained XGBoost model + label encoder and exposes a clean
predict() method that Teferi's LangGraph agent can call.

Usage:
    from classifier_inference import FPClassifier

    clf = FPClassifier()
    result = clf.predict(
        alert_type="Suspicious PowerShell",
        severity="High",
        description="User ran encoded PowerShell connecting to external IP"
    )
    # Returns:
    # {
    #   "prediction": "MALICIOUS",
    #   "confidence": 0.87,
    #   "auto_close": False
    # }
"""

import pickle
import numpy as np


# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
MODEL_PATH = "fp_classifier.pkl"
ENCODER_PATH = "alert_type_encoder.pkl"

# Severity mapping must match the training script exactly.
SEVERITY_MAP = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

# Auto-close threshold: if the model predicts BENIGN with confidence
# above this value, the alert is safe to close without human review.
AUTO_CLOSE_THRESHOLD = 0.95


# ---------------------------------------------------------------------------
# CLASSIFIER CLASS
# ---------------------------------------------------------------------------
class FPClassifier:
    """
    Wrapper around the trained XGBoost model + LabelEncoder.
    Provides a clean predict() API for the orchestrator.
    """

    def __init__(self, model_path: str = MODEL_PATH, encoder_path: str = ENCODER_PATH):
        # Load the trained XGBoost model
        with open(model_path, "rb") as f:
            self.model = pickle.load(f)

        # Load the fitted LabelEncoder (needed to encode new alert types)
        with open(encoder_path, "rb") as f:
            self.encoder = pickle.load(f)

        print(f"[INFO] Loaded classifier from {model_path}")
        print(f"[INFO] Loaded encoder from {encoder_path}")
        print(f"[INFO] Known alert types: {len(self.encoder.classes_)}")

    # -----------------------------------------------------------------------
    # FEATURE EXTRACTION (must match train_classifier.py exactly)
    # -----------------------------------------------------------------------
    def _extract_features(self, alert_type: str, severity: str, description: str) -> np.ndarray:
        """
        Convert raw alert data into the same 4-feature vector used in training.

        IMPORTANT: The order of features MUST match the training pipeline.
        """
        # Feature 1: Severity (ordinal)
        severity_encoded = SEVERITY_MAP.get(severity, 0)

        # Feature 2: Alert type (label encoding)
        # Handle unseen alert types gracefully — if we don't recognize it,
        # we use a special "unknown" bucket by reusing an existing label.
        if alert_type in self.encoder.classes_:
            alert_type_encoded = self.encoder.transform([alert_type])[0]
        else:
            # Unknown type: use the last class as a fallback.
            # This is a defensive measure; in production, retrain with the new type.
            alert_type_encoded = len(self.encoder.classes_) - 1

        # Feature 3: Description length
        desc_length = len(description)

        # Feature 4: High severity flag
        is_high_severity = 1 if severity in ["High", "Critical"] else 0

        # Return as a 2D array (XGBoost expects shape (n_samples, n_features))
        return np.array([[severity_encoded, alert_type_encoded, desc_length, is_high_severity]])

    # -----------------------------------------------------------------------
    # PREDICT
    # -----------------------------------------------------------------------
    def predict(self, alert_type: str, severity: str, description: str) -> dict:
        """
        Predict whether an alert is likely benign or malicious.

        Args:
            alert_type: e.g. "Suspicious PowerShell"
            severity:   "Low" | "Medium" | "High" | "Critical"
            description: free-text description of the alert

        Returns:
            {
                "prediction": "BENIGN" | "MALICIOUS",
                "confidence": float between 0.0 and 1.0,
                "auto_close": bool (True if benign + confidence >= 0.95),
                "features": dict (for debugging/transparency)
            }
        """
        # Extract features
        features = self._extract_features(alert_type, severity, description)

        # Get probabilities: [P(benign), P(malicious)]
        proba = self.model.predict_proba(features)[0]

        # Pick the class with the higher probability
        prediction_idx = int(np.argmax(proba))
        confidence = float(proba[prediction_idx])

        prediction = "MALICIOUS" if prediction_idx == 1 else "BENIGN"

        # Auto-close logic: only benign AND high confidence
        auto_close = (prediction == "BENIGN") and (confidence >= AUTO_CLOSE_THRESHOLD)

        return {
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "auto_close": auto_close,
            "features": {
                "severity_encoded": int(features[0][0]),
                "alert_type_encoded": int(features[0][1]),
                "desc_length": int(features[0][2]),
                "is_high_severity": int(features[0][3]),
            },
        }


# ---------------------------------------------------------------------------
# MAIN (manual smoke test)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("FP CLASSIFIER — Inference Smoke Test")
    print("=" * 60)

    clf = FPClassifier()

    # Test 1: Known malicious pattern
    print("\n[TEST 1] Known malicious alert:")
    result = clf.predict(
        alert_type="C2 Beaconing",
        severity="High",
        description="PowerShell established HTTPS connection to unknown IP every 30 seconds",
    )
    print(f"  Prediction:  {result['prediction']}")
    print(f"  Confidence:  {result['confidence']}")
    print(f"  Auto-close:  {result['auto_close']}")

    # Test 2: Known benign pattern
    print("\n[TEST 2] Known benign alert:")
    result = clf.predict(
        alert_type="Failed Login Attempts",
        severity="Medium",
        description="User forgot password and tried 5 times within 2 minutes",
    )
    print(f"  Prediction:  {result['prediction']}")
    print(f"  Confidence:  {result['confidence']}")
    print(f"  Auto-close:  {result['auto_close']}")

    # Test 3: Ambiguous high-severity
    print("\n[TEST 3] Ambiguous high-severity alert:")
    result = clf.predict(
        alert_type="Suspicious PowerShell",
        severity="High",
        description="PowerShell script executed during scheduled maintenance",
    )
    print(f"  Prediction:  {result['prediction']}")
    print(f"  Confidence:  {result['confidence']}")
    print(f"  Auto-close:  {result['auto_close']}")

    # Test 4: Unknown alert type (defensive)
    print("\n[TEST 4] Unknown alert type (graceful fallback):")
    result = clf.predict(
        alert_type="Quantum Encryption Attack",
        severity="Critical",
        description="A never-before-seen attack type",
    )
    print(f"  Prediction:  {result['prediction']}")
    print(f"  Confidence:  {result['confidence']}")
    print(f"  Auto-close:  {result['auto_close']}")

    print("\n" + "=" * 60)
    print("SMOKE TEST COMPLETE")
    print("=" * 60)