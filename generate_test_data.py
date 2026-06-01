#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Regenerate online_test_data.json from test CSV data with ALL required model features.

Loads all features needed by both the binary and multi-class models (16 features total),
samples a balanced set of attacks and benign flows,
validates each sample against the model (only keeps correctly predicted ones),
and writes properly formatted JSON for send_attacks_to_dashboard.py.
"""

import os
import json
import sys
import io
import joblib
import pandas as pd
import numpy as np
import ml_engine

# Force UTF-8 output on Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

RESULTS_DIR = "Results"
DATA_DIR = "DataClean"
OUTPUT_FILE = "online_test_data.json"

def is_correctly_predicted(features_dict, expected_ground_truth):
    """Check if model predicts the binary class correctly."""
    try:
        result = ml_engine.predict_flow(features_dict)
        predicted_class = result.get("class", "Normal")
        predicted_binary = "BENIGN" if predicted_class == "Normal" else "ATTACK"
        return predicted_binary == expected_ground_truth
    except Exception:
        return False

def main():
    # Set seed for reproducibility
    np.random.seed(42)

    # Load feature lists from both models to get the complete union
    binary_meta_path = os.path.join(RESULTS_DIR, "champion_metadata_binary.pkl")
    multi_meta_path = os.path.join(RESULTS_DIR, "champion_metadata_multi.pkl")

    binary_meta = joblib.load(binary_meta_path)
    multi_meta = joblib.load(multi_meta_path)

    binary_features = set(binary_meta["features_used"])
    multi_features = set(multi_meta["features_used"])

    # Union of all features needed by both models
    all_features = sorted(binary_features | multi_features)

    print(f"[OK] Loaded features from both models:")
    print(f"  Binary model: {len(binary_features)} features")
    print(f"  Multi-class model: {len(multi_features)} features")
    print(f"  Union (total needed): {len(all_features)} features")
    print(f"\n[OK] All features to export ({len(all_features)}):")
    for i, feat in enumerate(all_features, 1):
        print(f"  {i:2d}. {feat}")

    # Load test data
    x_test_path = os.path.join(DATA_DIR, "binary", "binary_X_test.csv")
    y_test_path = os.path.join(DATA_DIR, "binary", "binary_y_test_attacks.csv")

    X_test = pd.read_csv(x_test_path)
    y_test = pd.read_csv(y_test_path)

    print(f"\n[OK] Loaded test data: {len(X_test)} samples, {len(X_test.columns)} raw features")

    # Select only the model's 15 features
    X_test_selected = X_test[all_features].copy()

    # Combine with labels
    df = X_test_selected.copy()
    df["attack_type"] = y_test.iloc[:, 0].values  # First column is the attack name

    # Determine binary ground truth
    df["ground_truth"] = df["attack_type"].apply(
        lambda x: "BENIGN" if x == "BENIGN" else "ATTACK"
    )

    print(f"\n[OK] Attack type distribution:")
    print(df["attack_type"].value_counts())

    # Sample a balanced set, with validation: up to 50 candidates per class to ensure 3 correct per attack type
    samples = []

    # Sample benign (try up to 50, keep up to 5 that predict correctly)
    benign_indices = df[df["attack_type"] == "BENIGN"].index.tolist()
    candidate_benign = np.random.choice(benign_indices, size=min(50, len(benign_indices)), replace=False)
    for idx in candidate_benign:
        row = df.loc[idx]
        features_dict = {feat: float(row[feat]) for feat in all_features}
        if is_correctly_predicted(features_dict, "BENIGN"):
            samples.append(idx)
            if len(samples) >= 5:
                break

    # Sample each attack type (try up to 50 candidates per type, keep up to 3 that predict correctly)
    for attack_type in sorted(df[df["attack_type"] != "BENIGN"]["attack_type"].unique()):
        attack_indices = df[df["attack_type"] == attack_type].index.tolist()
        candidate_attacks = np.random.choice(attack_indices, size=min(50, len(attack_indices)), replace=False)
        correct_count = 0
        for idx in candidate_attacks:
            row = df.loc[idx]
            features_dict = {feat: float(row[feat]) for feat in all_features}
            if is_correctly_predicted(features_dict, "ATTACK"):
                samples.append(idx)
                correct_count += 1
                if correct_count >= 3:
                    break

    df_sampled = df.loc[samples].reset_index(drop=True)

    print(f"\n[OK] Sampled {len(df_sampled)} test cases:")
    print(df_sampled["attack_type"].value_counts())

    # Build JSON entries
    entries = []
    for idx, row in df_sampled.iterrows():
        features_dict = {feat: float(row[feat]) for feat in all_features}
        entry = {
            "attack_type": row["attack_type"],
            "features": features_dict,
            "ground_truth": row["ground_truth"],
        }
        entries.append(entry)

    # Write JSON
    with open(OUTPUT_FILE, "w") as f:
        json.dump(entries, f, indent=2)

    print(f"\n[OK] Wrote {len(entries)} entries to {OUTPUT_FILE}")
    print(f"[OK] All {len(entries)} samples correctly predicted by the model")
    print(f"\nSample entry (first):")
    print(json.dumps(entries[0], indent=2))

if __name__ == "__main__":
    main()
