"""
Inference pipeline for CIC-IDS2017 models.

Two-stage inference:
1. Binary classifier: BENIGN vs ATTACK
2. Multi-class classifier (only if binary predicts ATTACK): which attack type

Loads models from Models/ directory with flat filenames.
"""

import os
import json
import logging
from typing import Dict, Any

import joblib
import numpy as np
import pandas as pd

from feature_schema import align_features

logger = logging.getLogger(__name__)

# Threshold for binary classification to maximize recall (prefer false positives over missed attacks)
ATTACK_PROBABILITY_THRESHOLD = 0.05


class InferencePipeline:
    """
    Two-stage inference pipeline for CIC-IDS2017 binary + multi-class classification.
    """

    def __init__(self, models_dir: str = "Models", results_dir: str = "Results"):
        """
        Initialize the pipeline by loading models and metadata.

        Args:
            models_dir: path to Models/ directory
            results_dir: path to Results/ directory
        """
        self.models_dir = models_dir
        self.results_dir = results_dir

        logger.info("Initializing InferencePipeline...")
        self.binary = self._load_task("binary")
        self.multi = self._load_task("multi")
        logger.info(
            f"✓ Binary model loaded: {self.binary['model_name']} "
            f"({len(self.binary['feature_columns'])} features)"
        )
        logger.info(
            f"✓ Multi model loaded: {self.multi['model_name']} "
            f"({len(self.multi['feature_columns'])} features)"
        )

    def _clip_to_scaler_range(self, X_array: np.ndarray, scaler, n_iqr: float = 10.0) -> np.ndarray:
        """
        Clip features to ±n_iqr × IQR from scaler.center_ to prevent out-of-distribution values.

        This guards against single-packet flows and other extreme cases that have never
        been seen in training. Uses the scaler's own training statistics (center_ and scale_).

        Args:
            X_array: numpy array of shape (1, n_features)
            scaler: fitted RobustScaler instance
            n_iqr: how many IQRs away from median to allow (default 10 = ±10 IQRs)

        Returns:
            clipped numpy array, same shape
        """
        if not hasattr(scaler, "center_") or not hasattr(scaler, "scale_"):
            logger.warning("Scaler does not have center_ or scale_ attributes; returning input unchanged")
            return X_array
        lower = scaler.center_ - n_iqr * scaler.scale_
        upper = scaler.center_ + n_iqr * scaler.scale_
        return np.clip(X_array, lower, upper)

    def _load_task(self, task: str) -> Dict[str, Any]:
        """
        Load model, scaler, label encoder (if multi), and feature columns from flat Models/ directory.

        Returns:
            dict with keys: model_name, model, scaler, label_encoder (or None),
                           feature_columns, classes (or None)
        """
        # Models are stored flat in Models/ with task-specific names
        model_file = os.path.join(self.models_dir, f"champion_model_{task}.pkl")
        if not os.path.exists(model_file):
            raise FileNotFoundError(f"Model file not found: {model_file}")

        scaler_file = os.path.join(self.models_dir, f"production_scaler_{task}.pkl")
        if not os.path.exists(scaler_file):
            raise FileNotFoundError(f"Scaler file not found: {scaler_file}")

        # Load model
        model = joblib.load(model_file)
        model_name = f"champion_model_{task}"
        logger.debug(f"  {task}: loaded model from {model_file}")

        # Load scaler
        scaler = joblib.load(scaler_file)
        logger.debug(f"  {task}: loaded scaler from {scaler_file}")

        # Load feature columns from Results/
        feature_cols_file = os.path.join(self.results_dir, f"ranked_features_list_{task}.pkl")
        if not os.path.exists(feature_cols_file):
            raise FileNotFoundError(f"Feature columns file not found: {feature_cols_file}")
        feature_columns = joblib.load(feature_cols_file)
        logger.debug(f"  {task}: loaded {len(feature_columns)} feature columns")

        # Load label encoder (only for multi)
        label_encoder = None
        classes = None
        if task == "multi":
            le_file = os.path.join(self.results_dir, "champion_metadata_multi.pkl")
            if not os.path.exists(le_file):
                raise FileNotFoundError(f"Label encoder file not found: {le_file}")
            metadata = joblib.load(le_file)
            label_encoder = metadata.get("label_encoder")
            if label_encoder is None:
                raise ValueError("Label encoder not found in metadata")
            classes = label_encoder.classes_.tolist()
            logger.debug(f"  {task}: loaded label encoder with classes: {classes}")

        return {
            "model_name": model_name,
            "model": model,
            "scaler": scaler,
            "label_encoder": label_encoder,
            "feature_columns": feature_columns,
            "classes": classes,
        }

    def _select_best_from_report(self, task: str) -> str:
        """
        Legacy: read best model name from final_performance_report.csv.
        Not used in the current flat Models/ layout, but kept for backward compatibility.
        """
        report_file = os.path.join(self.results_dir, "final_performance_report.csv")
        if not os.path.exists(report_file):
            raise FileNotFoundError(f"Cannot find {report_file}")

        df = pd.read_csv(report_file)

        # Filter by task — MUST have Task column
        if "Task" not in df.columns:
            raise RuntimeError(
                f"final_performance_report.csv missing 'Task' column. "
                f"Cannot determine which model to load for task='{task}'"
            )
        task_df = df[df["Task"] == task]
        if task_df.empty:
            raise ValueError(f"No models found for task {task} in report")

        # Sort by F1 (or F1 Weighted), then MCC
        metric_col = "F1" if "F1" in task_df.columns else "F1 Weighted"
        if metric_col not in task_df.columns:
            raise ValueError(
                f"Cannot find F1 or F1 Weighted metric in {report_file}"
            )

        best = task_df.sort_values(
            [metric_col, "MCC"] if "MCC" in task_df.columns else [metric_col],
            ascending=False,
        ).iloc[0]
        return best["Model"]

    def predict(self, flow_features: Dict[str, float]) -> Dict[str, Any]:
        """
        Two-stage inference:
        1. Binary: BENIGN vs ATTACK
        2. Multi (if attack): which attack type

        Args:
            flow_features: dict with feature names and float values (94 features)

        Returns:
            dict with keys:
              - decision: "BENIGN" or "ATTACK"
              - binary_prediction: 0 or 1
              - binary_probability: float in [0, 1]
              - (if ATTACK) attack_type: string
              - (if ATTACK) multi_prediction: int class index
              - (if ATTACK) multi_probability: float
              - (if ATTACK) multi_probabilities: dict of {class: prob}

        Raises:
            ValueError: If input dict lacks CIC-IDS2017 column names
        """
        # Guard: reject dicts with no recognizable CIC-IDS2017 column names
        known = set(self.binary["feature_columns"]) | set(self.multi["feature_columns"])
        if flow_features and not any(k in known for k in flow_features):
            raise ValueError(
                "Input dict has no CIC-IDS2017 column names. "
                "Pass features using CIC-IDS2017 names (e.g., 'Flow Duration', 'Port_80')."
            )

        # ── Stage 1: Binary classification
        binary_x = align_features(flow_features, self.binary["feature_columns"])

        logger.debug(f"Binary input shape: {binary_x.shape}, columns: {len(binary_x.columns)}")
        logger.debug(f"Binary input sample (first 5 cols): {dict(list(binary_x.iloc[0].items())[:5])}")

        binary_x_clipped = self._clip_to_scaler_range(binary_x.values, self.binary["scaler"])
        binary_x_scaled = self.binary["scaler"].transform(binary_x_clipped)
        logger.debug(f"Binary scaled sample (first 5): {binary_x_scaled[0][:5]}")
        logger.debug(f"Binary scaled min/max/mean: min={binary_x_scaled.min():.4f}, max={binary_x_scaled.max():.4f}, mean={binary_x_scaled.mean():.4f}")

        binary_proba = self.binary["model"].predict_proba(binary_x_scaled)[0]
        # binary_proba[0] = P(BENIGN), binary_proba[1] = P(ATTACK)
        if hasattr(self.binary["model"], "classes_"):
            if self.binary["model"].classes_[1] != 1:
                raise RuntimeError(
                    "Binary model class ordering unexpected: classes_[1] must be 1 (ATTACK)"
                )

        logger.debug(f"Binary proba: BENIGN={binary_proba[0]:.4f}, ATTACK={binary_proba[1]:.4f}")

        if binary_proba[1] < ATTACK_PROBABILITY_THRESHOLD:
            # BENIGN
            logger.debug(f"  → Decision: BENIGN (P(ATTACK)={binary_proba[1]:.4f} < {ATTACK_PROBABILITY_THRESHOLD})")
            return {
                "decision": "BENIGN",
                "binary_prediction": 0,
                "binary_probability": float(binary_proba[1]),  # Always return P(ATTACK)
            }

        # ── Stage 2: Multi-class classification (only if binary predicts ATTACK)
        logger.debug(f"  → Decision: ATTACK (P(ATTACK)={binary_proba[1]:.4f} >= {ATTACK_PROBABILITY_THRESHOLD})")
        multi_x = align_features(flow_features, self.multi["feature_columns"])
        multi_x_clipped = self._clip_to_scaler_range(multi_x.values, self.multi["scaler"])
        multi_x_scaled = self.multi["scaler"].transform(multi_x_clipped)
        multi_pred = self.multi["model"].predict(multi_x_scaled)[0]
        multi_proba = self.multi["model"].predict_proba(multi_x_scaled)[0]

        # Decode attack label
        attack_label = self.multi["label_encoder"].inverse_transform([multi_pred])[0]

        # Build probabilities dict
        multi_probs_dict = {
            cls: float(p)
            for cls, p in zip(self.multi["classes"], multi_proba)
        }

        return {
            "decision": "ATTACK",
            "attack_type": attack_label,
            "binary_prediction": 1,
            "binary_probability": float(binary_proba[1]),
            "multi_prediction": int(multi_pred),
            "multi_probability": float(max(multi_proba)),
            "multi_probabilities": multi_probs_dict,
        }

__all__ = ["InferencePipeline"]
