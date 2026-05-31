"""
Inference pipeline for CIC-IDS2017 models.

Two-stage inference:
1. Binary classifier: BENIGN vs ATTACK
2. Multi-class classifier (only if binary predicts ATTACK): which attack type

Loads models from Models/ directory with flat filenames.
"""

import os
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

        # Validate feature consistency between live extractor and trained models
        from feature_schema import FEATURE_COLUMNS
        if set(FEATURE_COLUMNS) != set(self.binary["feature_columns"]):
            raise RuntimeError(
                f"Feature mismatch between live extractor (FEATURE_COLUMNS) and binary model. "
                f"Live extractor: {set(FEATURE_COLUMNS)}, Binary model: {set(self.binary['feature_columns'])}"
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

        # Load feature columns from champion_metadata (the exact features used for model/scaler training)
        metadata_file = os.path.join(self.results_dir, f"champion_metadata_{task}.pkl")
        if not os.path.exists(metadata_file):
            raise FileNotFoundError(f"Champion metadata file not found: {metadata_file}")
        metadata = joblib.load(metadata_file)
        feature_columns = metadata["features_used"]
        logger.debug(f"  {task}: loaded {len(feature_columns)} feature columns")

        # Validate model class ordering (binary: class 1 must be ATTACK)
        if task == "binary" and hasattr(model, "classes_"):
            if model.classes_[1] != 1:
                raise RuntimeError(
                    "Binary model class ordering unexpected: classes_[1] must be 1 (ATTACK)"
                )

        # Load label encoder (only for multi)
        label_encoder = None
        classes = None
        if task == "multi":
            le_file = os.path.join(self.results_dir, "label_encoder_multi.pkl")
            if not os.path.exists(le_file):
                raise FileNotFoundError(f"Label encoder file not found: {le_file}")
            label_encoder = joblib.load(le_file)
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

    def _predict_binary(self, binary_x_scaled: np.ndarray) -> tuple:
        """Run binary classification. Returns (binary_proba, early_return_dict or None)."""
        binary_proba = self.binary["model"].predict_proba(binary_x_scaled)[0]
        logger.debug(f"Binary proba: BENIGN={binary_proba[0]:.4f}, ATTACK={binary_proba[1]:.4f}")

        if binary_proba[1] < ATTACK_PROBABILITY_THRESHOLD:
            logger.debug(f"  → Decision: BENIGN (P(ATTACK)={binary_proba[1]:.4f} < {ATTACK_PROBABILITY_THRESHOLD})")
            return binary_proba, {
                "decision": "BENIGN",
                "binary_prediction": 0,
                "binary_probability": float(binary_proba[1]),
            }
        return binary_proba, None

    def _predict_multiclass(self, flow_features: Dict[str, float], binary_proba: np.ndarray) -> Dict[str, Any]:
        """Run multi-class classification (only if binary predicted ATTACK)."""
        logger.debug(f"  → Decision: ATTACK (P(ATTACK)={binary_proba[1]:.4f} >= {ATTACK_PROBABILITY_THRESHOLD})")
        multi_x = align_features(flow_features, self.multi["feature_columns"])
        multi_x_clipped = self._clip_to_scaler_range(multi_x.values, self.multi["scaler"])
        multi_x_scaled = self.multi["scaler"].transform(multi_x_clipped)

        multi_pred = self.multi["model"].predict(multi_x_scaled)[0]
        multi_proba = self.multi["model"].predict_proba(multi_x_scaled)[0]
        attack_label = self.multi["label_encoder"].inverse_transform([multi_pred])[0]

        multi_probs_dict = {cls: float(p) for cls, p in zip(self.multi["classes"], multi_proba)}

        return {
            "decision": "ATTACK",
            "attack_type": attack_label,
            "binary_prediction": 1,
            "binary_probability": float(binary_proba[1]),
            "multi_prediction": int(multi_pred),
            "multi_probability": float(max(multi_proba)),
            "multi_probabilities": multi_probs_dict,
        }

    def predict(self, flow_features: Dict[str, float]) -> Dict[str, Any]:
        """
        Two-stage inference: Binary (BENIGN vs ATTACK), then Multi-class if ATTACK.

        Args:
            flow_features: dict with feature names and float values

        Returns:
            dict with decision, predictions, and probabilities

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

        # Stage 1: Binary classification
        binary_x = align_features(flow_features, self.binary["feature_columns"])
        logger.debug(f"Binary input shape: {binary_x.shape}, columns: {len(binary_x.columns)}")

        binary_x_clipped = self._clip_to_scaler_range(binary_x.values, self.binary["scaler"])
        binary_x_scaled = self.binary["scaler"].transform(binary_x_clipped)

        binary_proba, early_return = self._predict_binary(binary_x_scaled)
        if early_return:
            return early_return

        # Stage 2: Multi-class classification (only if binary predicts ATTACK)
        return self._predict_multiclass(flow_features, binary_proba)

__all__ = ["InferencePipeline"]
