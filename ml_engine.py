"""ML inference engine for NetSentinelAI.

Loads XGBoost model and applies custom thresholds for real-time threat detection.
Handles unit conversion (seconds → microseconds) to align with training data.
"""

import json
import logging
import math
import numpy as np
import pandas as pd
import joblib
import xgboost as xgb

logger = logging.getLogger(__name__)

# Load artifacts at module import time (once per process)
try:
    scaler = joblib.load('netsentinel_scaler.pkl')
    le = joblib.load('label_encoder.pkl')
    model = xgb.XGBClassifier()
    model.load_model('netsentinel_model.pkl')

    with open('feature_names.json') as f:
        FEATURE_NAMES = json.load(f)

    with open('optimal_thresholds.json') as f:
        THRESHOLDS = json.load(f)

    logger.info(f"ML artifacts loaded. Classes: {list(le.classes_)}, Features: {len(FEATURE_NAMES)}")
except Exception as e:
    logger.error(f"Failed to load ML artifacts: {e}")
    raise


def convert_units(feature_dict: dict) -> dict:
    """Convert feature units from seconds to microseconds.

    The scaler was trained on CIC-IDS2017 where temporal features are in microseconds.
    The live system (FlowRecord) computes temporal features in seconds.
    This conversion ensures the features are on the same scale as training data.
    """
    converted = feature_dict.copy()

    # Temporal features: multiply by 1e6 to convert seconds → microseconds
    converted['flow_duration'] = feature_dict.get('flow_duration', 0) * 1_000_000
    converted['iat_mean'] = feature_dict.get('iat_mean', 0) * 1_000_000

    # iat_variance: training used Flow IAT Std (std, not variance)
    # Live system returns population variance (in seconds²)
    # Convert variance → std, then seconds² → microseconds
    iat_var_s2 = feature_dict.get('iat_variance', 0)
    if iat_var_s2 > 0:
        iat_std_s = math.sqrt(iat_var_s2)
        converted['iat_variance'] = iat_std_s * 1_000_000
    else:
        converted['iat_variance'] = 0

    return converted


def predict_flow(feature_dict: dict) -> dict:
    """Predict attack class for a flow.

    Args:
        feature_dict: Dict with 14 features (from FlowRecord.get_feature_vector())

    Returns:
        {
            'class': str,                # predicted class name
            'confidence': float,         # confidence of the prediction
            'probabilities': dict,       # {class_name: probability} for all 5 classes
            'raw_proba': list,          # raw probability vector from model
        }
    """
    try:
        # 1. Convert units (seconds → microseconds)
        converted = convert_units(feature_dict)

        # 2. Build feature vector in the exact order expected by the scaler
        # Use DataFrame with feature names to avoid sklearn warning
        X = pd.DataFrame([[converted[f] for f in FEATURE_NAMES]], columns=FEATURE_NAMES)

        # 3. Scale features
        X_scaled = scaler.transform(X)

        # 4. Get probability predictions (shape: (1, 5) → take [0])
        proba = model.predict_proba(X_scaled)[0]

        # 5. Apply custom thresholds
        pred_idx = apply_thresholds(proba)
        pred_class = le.classes_[pred_idx]
        confidence = float(proba[pred_idx])

        return {
            'class': pred_class,
            'confidence': confidence,
            'probabilities': {le.classes_[i]: float(proba[i]) for i in range(5)},
            'raw_proba': proba.tolist(),
        }

    except Exception as e:
        logger.error(f"ML prediction failed: {e}", exc_info=True)
        return {
            'class': 'Normal',
            'confidence': 0.0,
            'probabilities': {},
            'error': str(e),
        }


def apply_thresholds(proba: np.ndarray) -> int:
    """Apply custom decision thresholds to probability vector.

    Custom thresholds are higher for minority classes (Botnet, Brute Force)
    to maximize precision at the cost of small recall loss.

    Args:
        proba: numpy array of shape (5,) with probabilities for each class

    Returns:
        Predicted class index (0-4)
    """
    botnet_threshold = THRESHOLDS.get('Botnet', 0.9)
    brute_force_threshold = THRESHOLDS.get('Brute Force', 0.9)

    # Check high-threshold classes first (minority classes)
    if proba[0] >= botnet_threshold:  # Botnet
        return 0
    if proba[1] >= brute_force_threshold:  # Brute Force
        return 1

    # All other classes use default argmax
    return int(np.argmax(proba))


def batch_predict(feature_dicts: list) -> list:
    """Predict attack classes for multiple flows (batch prediction).

    Slightly more efficient than calling predict_flow() in a loop.

    Args:
        feature_dicts: List of dicts, each with 14 features

    Returns:
        List of prediction dicts (same format as predict_flow)
    """
    results = []
    for fd in feature_dicts:
        results.append(predict_flow(fd))
    return results
