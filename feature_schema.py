"""
Feature schema for CIC-IDS2017 dataset.
Defines expected columns, port encoding, and feature alignment.
"""

import json
import logging
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# 14 core features: byte-count-independent, trained on live extraction semantics
# These are identical between CicFlowMeter and BidirectionalFlowRecord
FEATURE_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Packets/s",
    "SYN Flag Count",
    "ACK Flag Count",
    "PSH Flag Count",
    "RST Flag Count",
    "Port_22",
    "Port_80",
    "FIN Flag Count",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Down/Up Ratio",
]

# Minimal core feature set: 14 byte-count-independent features
# These work identically in CicFlowMeter and live extractor
# Strategy: verify 14-feature model works, then expand to 59
CORE_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Packets/s",
    "SYN Flag Count",
    "ACK Flag Count",
    "PSH Flag Count",
    "RST Flag Count",
    "Port_22",
    "Port_80",
    "FIN Flag Count",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Down/Up Ratio",
]

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


def save_feature_columns(feature_columns: list, file_path: str) -> None:
    """
    Save feature columns list to JSON file.

    Args:
        feature_columns: list of feature names
        file_path: path to save JSON file
    """
    with open(file_path, 'w') as f:
        json.dump(feature_columns, f, indent=2)
