"""
Feature schema for CIC-IDS2017 dataset.
Defines expected columns, port encoding, and feature alignment.
"""

import logging
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# The exact 94 columns expected by models trained on CIC-IDS2017
# Order matches DataClean/binary/binary_X_train.csv
FEATURE_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
    "Port_21",
    "Port_22",
    "Port_23",
    "Port_25",
    "Port_53",
    "Port_80",
    "Port_110",
    "Port_143",
    "Port_443",
    "Port_445",
    "Port_3306",
    "Port_3389",
    "Port_8080",
    "Port_8443",
    "Port_WellKnown",
    "Port_Registered",
    "Port_Dynamic",
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

    # Log missing columns
    missing = [c for c in feature_columns if c not in df.columns]
    if missing:
        logger.warning(
            f"align_features: {len(missing)} columnas faltantes, rellenando con 0: {missing}"
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
