"""
Feature schema for CIC-IDS2017 dataset.
Defines expected columns, port encoding, and feature alignment.
"""

import logging
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Top 10 features selected by the trained RandomForest model
# These match Models/binary/feature_columns.json (source of truth)
FEATURE_COLUMNS = [
    "Bwd Packet Length Min",
    "Bwd Packet Length Max",
    "Port_80",
    "Total Length of Fwd Packets",
    "Port_53",
    "Total Length of Bwd Packets",
    "Port_443",
    "Total Backward Packets",
    "Fwd Packet Length Max",
    "Total Fwd Packets",
]

# Single source of truth for port one-hot encoding — used by data_preparation.py and live_feature_extractor.py
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]


def encode_port(dst_port: int) -> dict:
    """
    Encode destination port as one-hot + range flags.
    Returns dict with Port_XX, Port_WellKnown, Port_Registered, Port_Dynamic keys.

    Logic from main.py:
    - WellKnown: 0-1023
    - Registered: 1024-49151
    - Dynamic: > 49151
    """
    result = {}

    # One-hot encoding for common ports
    for port in COMMON_PORTS:
        result[f"Port_{port}"] = 1 if dst_port == port else 0

    # Range-based flags
    result["Port_WellKnown"] = 1 if dst_port <= 1023 else 0
    result["Port_Registered"] = 1 if 1024 <= dst_port <= 49151 else 0
    result["Port_Dynamic"] = 1 if dst_port > 49151 else 0

    return result


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
            f"align_features: {len(missing)} columnas faltantes, rellenando con 0: {display}"
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


