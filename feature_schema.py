"""
Feature schema for CIC-IDS2017 dataset.
Defines expected columns, port encoding, and feature alignment.
"""

import logging
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Top-16 features extracted by live_feature_extractor for all flows
# Always extracted and emitted; models select their subset below
ALL_FEATURES_16 = [
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
    "ACK Flag Count",  # 16th feature, always computed
    "PSH Flag Count",
    "Fwd PSH Flags",
    "Down/Up Ratio",
    "URG Flag Count",
]

# Binary model: 15 features WITHOUT ACK Flag Count (keeps URG Flag Count)
# Trained on 15 features; does not expect ACK Flag Count in input
FEATURE_COLUMNS_BINARY = [
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
    "URG Flag Count",  # Kept for binary
    "PSH Flag Count",
    "Fwd PSH Flags",
    "Down/Up Ratio",
]

# Multi model: 15 features WITH ACK Flag Count (replaces URG Flag Count)
# Trained on 15 features; expects ACK Flag Count, NOT URG Flag Count
FEATURE_COLUMNS_MULTI = [
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
    "ACK Flag Count",  # Included for multi (replaces URG)
    "PSH Flag Count",
    "Fwd PSH Flags",
    "Down/Up Ratio",
]

# Backward compatibility: FEATURE_COLUMNS defaults to all 16 for live extractor
# (live extractor computes all 16, inference pipeline selects per-model subset)
FEATURE_COLUMNS = ALL_FEATURES_16



def align_features(feature_dict: dict, feature_columns: list) -> pd.DataFrame:
    """
    Align feature dictionary to exact column order and names expected by model.

    Used by inference_pipeline to convert the 16-feature vector from live_feature_extractor
    into the model-specific subset (15 features for binary or multi).

    Steps:
    1. Create DataFrame from dict
    2. Fill missing columns with 0
    3. Select only feature_columns in exact order
    4. Replace inf/-inf with NaN, then fill NaN with 0

    Args:
        feature_dict: dict with all 16 core features from live_feature_extractor
        feature_columns: list of expected column names in order (15 for binary, 15 for multi)

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


