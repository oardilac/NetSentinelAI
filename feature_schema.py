"""
Feature schema for CIC-IDS2017 dataset.
Defines expected columns, port encoding, and feature alignment.
"""

import logging
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Top-15 features selected by SHAP from the 94 CIC-IDS2017 features
# These are the features that survived SHAP feature importance ranking in the training pipeline
# Used by live_feature_extractor.get_feature_vector() to select which features to emit to models
FEATURE_COLUMNS = [
    "Bwd Packet Length Min",
    "Bwd Packet Length Max",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow Duration",
    "URG Flag Count",
    "PSH Flag Count",
    "Fwd PSH Flags",
    "Down/Up Ratio",
]



def align_features(feature_dict: dict, feature_columns: list) -> pd.DataFrame:
    """
    Align feature dictionary to exact column order and names expected by model.

    Steps:
    1. Create DataFrame from dict
    2. Fill missing columns with 0
    3. Select only feature_columns in exact order
    4. Replace inf/-inf with NaN, then fill NaN with 0

    Args:
        feature_dict: dict with feature names and values
        feature_columns: list of expected column names in order

    Returns:
        pd.DataFrame with shape (1, len(feature_columns))
    """
    df = pd.DataFrame([feature_dict])

    # Log missing columns (truncated if too many)
    missing = [c for c in feature_columns if c not in df.columns]
    if missing:
        display = missing[:5] + (["..."] if len(missing) > 5 else [])
        logger.warning(
            f"align_features: {len(missing)} missing columns, filling with 0: {display}"
        )

    # Fill missing columns with 0
    for col in feature_columns:
        if col not in df.columns:
            df[col] = 0

    # Select columns in exact order
    df = df[feature_columns]

    # Clean infinities and NaN
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

    return df


