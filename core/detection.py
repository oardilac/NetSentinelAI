# Pysentry Detection System Using IsolationForest
# Written by: @dukebismaya

from sklearn.ensemble import IsolationForest
import numpy as np

class DetectionEngine:
    def __init__(self) -> None:
        self.anomaly_detector = IsolationForest(contamination=0.05, random_state=42)
        self._train_dummy_model() # Baseline training to prevent crashes
        
        # Hardcoded Signature Rules
        self.signature_rules = {
            'syn_flood': lambda f: f.get('tcp_flag', 0) == 2 and f.get('packet_rate', 0) > 500,
            'port_scan': lambda f: f.get('packet_size', 0) < 100 and f.get('packet_rate', 0) > 300
        }
        
    def _train_dummy_model(self):
        """Provides a baseline 'normal' traffic profile so the AI can function immediately."""
        normal_data = np.array([[500, 10, 5000], [512, 12, 6000], [480, 11, 5200]])
        self.anomaly_detector.fit(normal_data)
        
    def detect_threats(self, features):
        threats = []
        
        # 1. Signature Check
        for rule_name, condition in self.signature_rules.items():
            if condition(features):
                threats.append({'type': 'Signature', 'rule': rule_name, 'confidence': 1.0})

        # 2. Anomaly Check (AI)
        feature_vector = np.array([[features['packet_size'], features['packet_rate'], features['byte_rate']]])
        anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
        
        if anomaly_score < -0.6: # Stricter threshold for fewer false positives
            threats.append({'type': 'Anomaly', 'score': float(anomaly_score), 'confidence': min(1.0, abs(anomaly_score))})

        return threats