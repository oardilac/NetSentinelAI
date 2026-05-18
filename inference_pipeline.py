"""
Inference pipeline for CIC-IDS2017 models.

Two-stage inference:
1. Binary classifier: BENIGN vs ATTACK
2. Multi-class classifier (only if binary predicts ATTACK): which attack type

Loads models from Models/binary and Models/multi directories.
"""

import os
import json
import logging
from typing import Dict, Any

import joblib
import pandas as pd

from feature_schema import align_features

logger = logging.getLogger(__name__)


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

    def _load_task(self, task: str) -> Dict[str, Any]:
        """
        Load model, scaler, label encoder (if multi), and feature columns.

        Returns:
            dict with keys: model_name, model, scaler, label_encoder (or None),
                           feature_columns, classes (or None)
        """
        task_dir = os.path.join(self.models_dir, task)

        # 1. Determine best model
        best_model_name_file = os.path.join(task_dir, "best_model_name.txt")
        if os.path.exists(best_model_name_file):
            with open(best_model_name_file, "r") as f:
                model_name = f.read().strip()
            logger.debug(f"  {task}: best model from file = {model_name}")
        else:
            # Fallback: read from final_performance_report.csv
            logger.warning(
                f"  {task}: best_model_name.txt not found, reading from "
                f"final_performance_report.csv"
            )
            model_name = self._select_best_from_report(task)
            logger.debug(f"  {task}: best model selected = {model_name}")

        # 2. Load feature columns
        feature_cols_file = os.path.join(task_dir, "feature_columns.json")
        with open(feature_cols_file, "r") as f:
            feature_columns = json.load(f)
        logger.debug(f"  {task}: loaded {len(feature_columns)} feature columns")

        # 3. Load model
        model_file = os.path.join(task_dir, f"{model_name}_final.pkl")
        model = joblib.load(model_file)
        logger.debug(f"  {task}: loaded model from {model_file}")

        # 4. Load scaler
        scaler_file = os.path.join(task_dir, f"scaler_{model_name}.pkl")
        scaler = joblib.load(scaler_file)
        logger.debug(f"  {task}: loaded scaler from {scaler_file}")

        # 5. Load label encoder (only for multi)
        label_encoder = None
        classes = None
        if task == "multi":
            le_file = os.path.join(task_dir, "label_encoder.pkl")
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

    def _select_best_from_report(self, task: str) -> str:
        """
        Fallback: read best model name from final_performance_report.csv.

        Selects by highest F1 (or F1 Weighted for multi), MCC as tiebreaker.
        """
        report_file = os.path.join(self.results_dir, "final_performance_report.csv")
        if not os.path.exists(report_file):
            raise FileNotFoundError(f"Cannot find {report_file}")

        df = pd.read_csv(report_file)

        # Filter by task
        task_df = df[df["Task"] == task] if "Task" in df.columns else df
        if task_df.empty:
            raise ValueError(f"No models found for task {task}")

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
            flow_features: dict with feature names and float values (87 features)

        Returns:
            dict with keys:
              - decision: "BENIGN" or "ATTACK"
              - binary_prediction: 0 or 1
              - binary_probability: float in [0, 1]
              - (if ATTACK) attack_type: string
              - (if ATTACK) multi_prediction: int class index
              - (if ATTACK) multi_probability: float
              - (if ATTACK) multi_probabilities: dict of {class: prob}
        """

        # ── Stage 1: Binary classification
        binary_x = align_features(flow_features, self.binary["feature_columns"])
        binary_x_scaled = self.binary["scaler"].transform(binary_x)
        binary_pred = self.binary["model"].predict(binary_x_scaled)[0]
        binary_proba = self.binary["model"].predict_proba(binary_x_scaled)[0]

        if binary_pred == 0:
            # BENIGN
            return {
                "decision": "BENIGN",
                "binary_prediction": 0,
                "binary_probability": float(binary_proba[0]),
            }

        # ── Stage 2: Multi-class classification (only if binary predicts ATTACK)
        multi_x = align_features(flow_features, self.multi["feature_columns"])
        multi_x_scaled = self.multi["scaler"].transform(multi_x)
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
            "multi_probability": float(multi_proba[multi_pred]),
            "multi_probabilities": multi_probs_dict,
        }

    def batch_predict(self, flow_features_list: list) -> list:
        """
        Predict on multiple flows.

        Args:
            flow_features_list: list of dicts, each with 87 features

        Returns:
            list of prediction dicts
        """
        results = []
        for features in flow_features_list:
            try:
                result = self.predict(features)
                results.append(result)
            except Exception as e:
                logger.error(f"Prediction failed: {e}")
                results.append({"error": str(e)})
        return results


__all__ = ["InferencePipeline"]
