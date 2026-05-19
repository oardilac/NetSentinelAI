"""ML inference engine for NetSentinelAI — compatibility shim over InferencePipeline.

Provides lazy-loaded InferencePipeline singleton and compatibility functions
for existing code that expects old ml_engine interface.
"""

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

_pipeline = None

def _get_pipeline():
    """Lazy-load InferencePipeline singleton."""
    global _pipeline
    if _pipeline is None:
        from inference_pipeline import InferencePipeline
        _pipeline = InferencePipeline()
    return _pipeline


def get_attack_classes() -> list:
    """Return full class list: ['Normal'] + attack labels from label encoder."""
    pipe = _get_pipeline()
    return ["Normal"] + list(pipe.multi["classes"])


def predict_flow(feature_dict: dict) -> dict:
    """Compatibility wrapper around InferencePipeline.predict().

    Maps new pipeline result shape to old shape expected by network_monitor.py.

    Old shape: {'class': str, 'confidence': float, 'probabilities': dict}
    New shape: {'decision': str, 'binary_probability': float, ...}

    Args:
        feature_dict: 94-feature dict with CIC-IDS2017 feature names

    Returns:
        {'class': 'BENIGN'/'ATTACK'/'...' , 'confidence': float, 'probabilities': {}}
    """
    try:
        pipe = _get_pipeline()
        result = pipe.predict(feature_dict)

        if result["decision"] == "BENIGN":
            cls = "Normal"
            confidence = float(result["binary_probability"])
            probabilities = {"Normal": confidence}
        else:
            cls = result.get("attack_type", "ATTACK")
            confidence = float(result.get("multi_probability", result.get("binary_probability", 0.0)))
            probabilities = result.get("multi_probabilities", {cls: confidence})

        return {
            "class": cls,
            "confidence": confidence,
            "probabilities": probabilities,
        }
    except Exception as e:
        logger.error(f"ML prediction failed: {e}", exc_info=True)
        return {
            "class": "Normal",
            "confidence": 0.0,
            "probabilities": {},
            "error": str(e),
        }


def normalize_feature_payload(payload: dict) -> dict:
    """Normalize API payload to flat CIC-IDS2017 feature dict.

    Accepts:
    - Nested:  {"src_ip": "...", "features": {"Flow Duration": 1, ...}}
    - Direct:  {"Flow Duration": 1, "Port_80": 1, ...}

    Rejects legacy 14-feature dicts (old pipeline).

    Args:
        payload: API request payload or feature dict

    Returns:
        Flat dict with CIC-IDS2017 feature names and values

    Raises:
        ValueError: If payload uses legacy 14-feature format
    """
    if "features" in payload and isinstance(payload["features"], dict):
        data = payload["features"]
    else:
        data = payload

    legacy_keys = {"flow_duration", "packet_count", "iat_mean", "iat_variance"}
    has_cic = any(" " in k or k.startswith("Port_") or k.startswith("Flow") for k in data)

    if not has_cic and legacy_keys.intersection(data.keys()):
        raise ValueError(
            "Legacy 14-feature payload rejected. Use CIC-IDS2017 feature names "
            "(e.g., 'Flow Duration', 'Port_80')."
        )

    return data


def batch_predict(feature_dicts: list) -> list:
    """Predict attack classes for multiple flows.

    Args:
        feature_dicts: List of 94-feature dicts

    Returns:
        List of prediction results (same format as predict_flow)
    """
    return [predict_flow(fd) for fd in feature_dicts]
