#!/usr/bin/env python3
"""
Offline validator for 14-feature binary classification pipeline.
Reads raw CIC-IDS2017 CSVs from DataRaw/, applies same transformations
as the live pipeline, and validates detection accuracy.
"""

import logging
import numpy as np
import pandas as pd
from pathlib import Path
from collections import defaultdict

from inference_pipeline import InferencePipeline
from feature_schema import FEATURE_COLUMNS

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

DATARAW_DIR = "./DataRaw"
RESULTS_FILE = "./offline_validation.csv"

# Columns to drop (same as main.py)
COLS_TO_DROP = [
    "Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

def load_dataraw_sample(max_per_class=500):
    """
    Load sample rows from all DataRaw CSVs.
    Takes up to max_per_class rows per attack type + max_per_class BENIGN rows.

    Returns: DataFrame with columns stripped, inf/NaN handled, labels cleaned.
    """
    logger.info(f"Loading DataRaw CSVs from {DATARAW_DIR}...")

    dataframes = []
    csv_files = sorted(Path(DATARAW_DIR).glob("*.csv"))

    for csv_file in csv_files:
        logger.info(f"  Reading {csv_file.name}...")
        df = pd.read_csv(csv_file)

        # Strip column names (they have leading spaces)
        df.columns = df.columns.str.strip()

        # Replace inf/-inf with NaN, then drop NaN rows
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)

        # Clean labels: strip spaces
        if "Label" in df.columns:
            df["Label"] = df["Label"].str.strip()

        dataframes.append(df)

    # Concat all
    full_df = pd.concat(dataframes, ignore_index=True)
    logger.info(f"Total rows loaded: {len(full_df)}")

    # Sample by label to keep manageable size
    sampled_rows = []
    label_counts = defaultdict(int)

    for _, row in full_df.iterrows():
        label = row.get("Label", "BENIGN")

        # Skip unwanted labels
        if label in ["Infiltration", "Heartbleed"]:
            continue

        # Merge Web Attack variants
        if label.startswith("Web Attack"):
            label = "Web_Attack"

        # Enforce sampling cap
        if label_counts[label] < max_per_class:
            label_counts[label] += 1
            sampled_rows.append(row)

    sampled_df = pd.DataFrame(sampled_rows)
    logger.info(f"Sampled rows by class: {dict(label_counts)}")

    return sampled_df


def apply_transforms(df):
    """
    Apply the EXACT transforms as main.py + feature selection:
    - Drop identity and excluded columns (same as main.py)
    - Full port encoding: all common ports + range flags (same as main.py)
    - Select only FEATURE_COLUMNS (14 core features)
    """
    logger.info("Applying transforms...")

    # Drop identity columns (same as main.py)
    cols_to_drop_exist = [c for c in COLS_TO_DROP if c in df.columns]
    df = df.drop(columns=cols_to_drop_exist, errors='ignore')

    # Full port encoding (matching main.py exactly)
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]

    if "Destination Port" in df.columns:
        port = df["Destination Port"].astype(int)

        # One-hot for common ports
        for p in COMMON_PORTS:
            df[f"Port_{p}"] = (port == p).astype(float)

        # Range-based flags (IANA)
        df["Port_WellKnown"]  = (port <= 1023).astype(float)
        df["Port_Registered"] = ((port > 1023) & (port <= 49151)).astype(float)
        df["Port_Dynamic"]    = (port > 49151).astype(float)

        df = df.drop(columns=["Destination Port"], errors='ignore')

    # Ensure all FEATURE_COLUMNS exist, fill missing with 0
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0

    # Select only FEATURE_COLUMNS in exact order
    df = df[FEATURE_COLUMNS]

    # Replace inf/NaN with 0 (safety net, though raw data should already be clean)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    logger.info(f"Transformed data shape: {df.shape}")
    return df


def validate(df):
    """
    Run binary model on each row. Returns DataFrame with predictions and ground truth.
    """
    logger.info("Initializing InferencePipeline...")
    pipeline = InferencePipeline(models_dir="./Models", results_dir="./Results")

    results = []
    labels_true = df.pop("Label") if "Label" in df.columns else [None] * len(df)

    logger.info(f"Running predictions on {len(df)} samples...")
    for i, (_, row) in enumerate(df.iterrows()):
        if (i + 1) % 100 == 0:
            logger.info(f"  {i+1}/{len(df)} processed")

        feature_dict = row.to_dict()
        label_true = labels_true.iloc[i] if hasattr(labels_true, 'iloc') else labels_true[i]

        try:
            pred = pipeline.predict(feature_dict)

            results.append({
                "label_true": label_true,
                "binary_true": 0 if label_true == "BENIGN" else 1,
                "decision": pred["decision"],
                "binary_prediction": 1 if pred["decision"] == "ATTACK" else 0,
                "binary_probability": pred.get("binary_probability", 0.0),
                "attack_type": pred.get("attack_type", "N/A"),
                "correct": (pred["decision"] == "BENIGN" and label_true == "BENIGN") or
                           (pred["decision"] == "ATTACK" and label_true != "BENIGN"),
            })
        except Exception as e:
            logger.error(f"Prediction failed for row {i}: {e}")
            results.append({
                "label_true": label_true,
                "binary_true": 0 if label_true == "BENIGN" else 1,
                "decision": "ERROR",
                "binary_prediction": -1,
                "binary_probability": -1,
                "attack_type": "ERROR",
                "correct": False,
            })

    return pd.DataFrame(results)


def summarize(results_df):
    """Print summary statistics."""

    # Split by ground truth
    attacks = results_df[results_df["binary_true"] == 1]
    benigns = results_df[results_df["binary_true"] == 0]

    # Metrics
    tp = len(results_df[(results_df["binary_true"] == 1) & (results_df["binary_prediction"] == 1)])
    fn = len(results_df[(results_df["binary_true"] == 1) & (results_df["binary_prediction"] == 0)])
    tn = len(results_df[(results_df["binary_true"] == 0) & (results_df["binary_prediction"] == 0)])
    fp = len(results_df[(results_df["binary_true"] == 0) & (results_df["binary_prediction"] == 1)])

    recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
    specificity = tn / (tn + fp) * 100 if (tn + fp) > 0 else 0

    print("\n" + "=" * 60)
    print("  📊 OFFLINE VALIDATION RESULTS")
    print("=" * 60)
    print(f"\nConfusion Matrix:")
    print(f"  True Positive:  {tp:4d}  |  False Negative: {fn:4d}")
    print(f"  False Positive: {fp:4d}  |  True Negative:  {tn:4d}")
    print(f"\nPerformance:")
    print(f"  Attack Recall (TP/(TP+FN)):    {recall:6.2f}%")
    print(f"  Benign Specificity (TN/(TN+FP)): {specificity:6.2f}%")

    if len(attacks) > 0:
        print(f"\nP(ATTACK) Distribution — ATTACKS (ground truth):")
        print(f"  Count:  {len(attacks)}")
        print(f"  Median: {attacks['binary_probability'].median():.4f}")
        print(f"  Min:    {attacks['binary_probability'].min():.4f}")
        print(f"  Max:    {attacks['binary_probability'].max():.4f}")

    if len(benigns) > 0:
        print(f"\nP(ATTACK) Distribution — BENIGN (ground truth):")
        print(f"  Count:  {len(benigns)}")
        print(f"  Median: {benigns['binary_probability'].median():.4f}")
        print(f"  Min:    {benigns['binary_probability'].min():.4f}")
        print(f"  Max:    {benigns['binary_probability'].max():.4f}")

    print("\n" + "=" * 60)
    print(f"Results saved to: {RESULTS_FILE}")
    print("=" * 60 + "\n")


def main():
    """Main validation pipeline."""
    # Load and transform
    df = load_dataraw_sample(max_per_class=500)

    # Store labels before transform
    labels = df["Label"].copy() if "Label" in df.columns else pd.Series([None] * len(df))

    # Transform
    df = apply_transforms(df)
    df["Label"] = labels

    # Validate
    results = validate(df)

    # Save
    results.to_csv(RESULTS_FILE, index=False)
    logger.info(f"Saved {len(results)} results to {RESULTS_FILE}")

    # Summary
    summarize(results)


if __name__ == "__main__":
    main()
