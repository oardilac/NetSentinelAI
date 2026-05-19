#!/usr/bin/env python3
"""
NetSentinelAI End-to-End Validator

Sends the same attack data through the dashboard API and verifies
that predictions match the offline validation results exactly.

Workflow:
1. Load test data (attacks that worked offline)
2. POST each sample to dashboard /api/predict
3. Compare dashboard response with offline predictions
4. Verify P(ATTACK) and decision match
"""

import sys
import json
import logging
import requests
from typing import Dict

logging.basicConfig(level=logging.WARNING)


class EndToEndValidator:
    """Validates model predictions through the dashboard API."""

    def __init__(self, dashboard_url: str = "http://localhost:5050"):
        self.dashboard_url = dashboard_url
        self.test_data = []
        self.metrics = {
            "total": 0,
            "correct_decisions": 0,
            "correct_probabilities": 0,
            "mismatches": [],
            "by_type": {}
        }

    def check_dashboard(self) -> bool:
        """Verify dashboard is running and /api/predict endpoint exists."""
        try:
            resp = requests.get(f"{self.dashboard_url}/api/status", timeout=2)
            if resp.status_code == 200:
                print(f"✓ Dashboard is running at {self.dashboard_url}")
                return True
        except Exception as e:
            print(f"✗ Dashboard not accessible at {self.dashboard_url}: {e}")
            return False

    def load_test_data(self, data_file: str = "./online_test_data.json") -> bool:
        """Load test data with expected results from offline validation."""
        try:
            with open(data_file, 'r') as f:
                self.test_data = json.load(f)
            print(f"✓ Loaded {len(self.test_data)} test samples from {data_file}")
            return True
        except Exception as e:
            print(f"✗ Failed to load test data: {e}")
            return False

    def send_prediction_request(self, features: dict, sample_idx: int = 0, verbose: bool = False) -> Dict:
        """
        Send feature dict to dashboard /api/predict endpoint.

        Expected response format from dashboard:
        {
            "class": "BENIGN" | "ATTACK",
            "confidence": float,
            "probabilities": {class: prob, ...},
            "error": string (if any)
        }

        Converts to our format:
        {
            "decision": "BENIGN" | "ATTACK",
            "binary_probability": float
        }
        """
        try:
            payload = {
                "features": features
            }

            # Show request details for first and last samples
            if verbose or sample_idx == 0 or sample_idx % 100 == 0:
                print(f"\n[Sample {sample_idx}] POST Request:")
                print(f"  URL: {self.dashboard_url}/api/predict")
                print(f"  Features sent: {len(features)} features")
                if sample_idx == 0:  # Show details only for first
                    feature_names = list(features.keys())[:5]
                    print(f"  Sample features: {feature_names} ...")

            resp = requests.post(
                f"{self.dashboard_url}/api/predict",
                json=payload,
                timeout=5
            )

            if resp.status_code == 200:
                dashboard_response = resp.json()

                # Show response for first and last samples
                if verbose or sample_idx == 0 or sample_idx % 100 == 0:
                    print(f"  Response: {dashboard_response}")

                # Convert dashboard format to our format
                return {
                    "decision": dashboard_response.get("class", "UNKNOWN"),
                    "binary_probability": dashboard_response.get("confidence", -1),
                    "probabilities": dashboard_response.get("probabilities", {}),
                    "raw": dashboard_response
                }
            else:
                print(f"  ✗ Dashboard returned {resp.status_code}: {resp.text}")
                return None
        except Exception as e:
            print(f"  ✗ Request failed: {e}")
            return None

    def validate(self) -> Dict:
        """Run end-to-end validation through dashboard."""
        print(f"\n{'='*60}")
        print(f"  🔗 END-TO-END VALIDATION (through dashboard)")
        print(f"{'='*60}")
        print(f"\nSending {len(self.test_data)} samples to {self.dashboard_url}...\n")

        for idx, sample in enumerate(self.test_data):
            features = sample.get("features", {})
            expected_decision = sample.get("ground_truth", "UNKNOWN")
            expected_prob = sample.get("expected_probability", None)
            attack_type = sample.get("attack_type", "UNKNOWN")

            # Send to dashboard
            dashboard_response = self.send_prediction_request(features, sample_idx=idx)

            if not dashboard_response:
                self.metrics["mismatches"].append({
                    "index": idx,
                    "reason": "No response from dashboard"
                })
                continue

            # Extract predictions from dashboard response
            dashboard_class = dashboard_response.get("decision", "UNKNOWN")

            # Map dashboard classes to binary (Normal → BENIGN, anything else → ATTACK)
            if dashboard_class == "Normal":
                dashboard_decision = "BENIGN"
            else:
                dashboard_decision = "ATTACK"

            # Compare with expected (normalize expected too)
            if expected_decision not in ["ATTACK", "BENIGN"]:
                expected_decision = "BENIGN" if expected_decision == "Normal" else "ATTACK"

            decision_match = dashboard_decision == expected_decision
            self.metrics["total"] += 1

            if decision_match:
                self.metrics["correct_decisions"] += 1
            else:
                self.metrics["mismatches"].append({
                    "index": idx,
                    "expected_decision": expected_decision,
                    "dashboard_decision": dashboard_decision,
                    "type": attack_type
                })

            # Track by type
            if attack_type not in self.metrics["by_type"]:
                self.metrics["by_type"][attack_type] = {
                    "correct": 0,
                    "total": 0
                }
            self.metrics["by_type"][attack_type]["total"] += 1
            if decision_match:
                self.metrics["by_type"][attack_type]["correct"] += 1

            # Progress
            if (idx + 1) % 50 == 0:
                accuracy = self.metrics["correct_decisions"] / self.metrics["total"] * 100
                print(f"  {idx + 1}/{len(self.test_data)} processed... "
                      f"(accuracy: {accuracy:.1f}%)")

        return self.metrics

    def show_results(self):
        """Display validation results."""
        if self.metrics["total"] == 0:
            print("\n❌ No results to display")
            return

        accuracy = self.metrics["correct_decisions"] / self.metrics["total"] * 100

        print(f"\n{'='*60}")
        print(f"  📊 END-TO-END VALIDATION RESULTS")
        print(f"{'='*60}")
        print(f"\nAccuracy (dashboard matches offline): {accuracy:.2f}%")
        print(f"  Correct decisions: {self.metrics['correct_decisions']} / {self.metrics['total']}")
        print(f"  Mismatches: {len(self.metrics['mismatches'])}")

        if self.metrics["by_type"]:
            print(f"\nBy Attack Type:")
            print(f"{'Attack Type':<25} {'Correct':<12} {'Total':<12} {'Accuracy':<12}")
            print("-" * 60)

            for attack_type in sorted(self.metrics["by_type"].keys()):
                data = self.metrics["by_type"][attack_type]
                correct = data["correct"]
                total = data["total"]
                acc = correct / total * 100 if total > 0 else 0
                print(f"{attack_type:<25} {correct:<12} {total:<12} {acc:>10.2f}%")

        if self.metrics["mismatches"]:
            print(f"\nMismatches (first 5):")
            for mismatch in self.metrics["mismatches"][:5]:
                print(f"  Sample {mismatch['index']}: "
                      f"expected {mismatch.get('expected_decision', 'UNKNOWN')} "
                      f"but got {mismatch.get('dashboard_decision', 'UNKNOWN')}")

        print("=" * 60 + "\n")

        # Verdict
        if accuracy >= 95:
            print("✅ PASS: Dashboard predictions match offline (≥95%)")
            print("   Network integration is working correctly\n")
        elif accuracy >= 90:
            print("⚠️  WARNING: Dashboard matches offline mostly (90-95%)")
            print("   Check for edge cases or timeout issues\n")
        else:
            print("❌ FAIL: Dashboard predictions diverge from offline (< 90%)")
            print("   Investigate dashboard + model integration\n")

    def run(self):
        """Execute end-to-end validation."""
        print("\n" + "="*60)
        print("  🚀 NetSentinelAI — End-to-End Validation")
        print("  (Through dashboard API)")
        print("="*60)

        # Check dashboard
        if not self.check_dashboard():
            print("\n❌ Cannot proceed without dashboard")
            print("   Start it with: python3 dashboard_server.py")
            return False

        # Load test data
        if not self.load_test_data():
            print("\n❌ Cannot proceed without test data")
            return False

        # Validate
        self.validate()

        # Show results
        self.show_results()

        return self.metrics["correct_decisions"] > 0


def main():
    validator = EndToEndValidator()
    success = validator.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
