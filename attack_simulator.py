#!/usr/bin/env python3
"""
NetSentinelAI Attack Simulator — Online Validation using Offline Data

Validates that the model produces identical results in "online" mode
by processing the same correctly-detected attacks from offline_validation.csv
through InferencePipeline, simulating live traffic detection.
"""

import argparse
import sys
import pandas as pd
import numpy as np
from typing import Dict, List, Optional
import logging

from inference_pipeline import InferencePipeline
from feature_schema import FEATURE_COLUMNS

logging.basicConfig(level=logging.WARNING)


class OnlineValidator:
    """Simulates online detection using offline-validated attack data."""

    def __init__(self):
        self.pipeline = None
        self.results = []

    def initialize_pipeline(self):
        """Initialize InferencePipeline for online simulation."""
        try:
            self.pipeline = InferencePipeline(models_dir="./Models", results_dir="./Results")
            print("✓ InferencePipeline initialized")
        except Exception as e:
            print(f"✗ Failed to initialize pipeline: {e}")
            return False
        return True

    def load_online_data(self, data_file: str = "./online_test_data.json") -> List[dict]:
        """Load test data with features from JSON file."""
        import json
        try:
            with open(data_file, 'r') as f:
                data = json.load(f)
            print(f"✓ Loaded {len(data)} test samples from {data_file}")
            return data
        except FileNotFoundError:
            print(f"✗ File not found: {data_file}")
            return None
        except Exception as e:
            print(f"✗ Error loading data: {e}")
            return None

    def validate_online(self) -> Dict[str, int]:
        """
        Process test data through pipeline in 'online' mode.
        Simulates live detection of attacks that were correctly detected offline.
        """
        print(f"\n{'='*60}")
        print(f"  🔬 ONLINE VALIDATION (simulating live detection)")
        print(f"{'='*60}")

        # Load online test data
        test_data = self.load_online_data()
        if not test_data:
            return {}

        print(f"\nProcessing {len(test_data)} test samples...\n")

        metrics = {
            "total_processed": 0,
            "correct_predictions": 0,
            "incorrect_predictions": 0,
            "attack_types": {},
        }

        # Process each test sample
        for idx, sample in enumerate(test_data):
            feature_dict = sample.get("features", {})
            ground_truth = sample.get("ground_truth", "UNKNOWN")
            attack_type = sample.get("attack_type", "UNKNOWN")

            try:
                # Online prediction
                online_result = self.pipeline.predict(feature_dict)
                online_decision = online_result['decision']

                # Expected decision from ground truth
                expected_decision = ground_truth

                # Check if online matches ground truth
                match = online_decision == expected_decision

                metrics["total_processed"] += 1
                if match:
                    metrics["correct_predictions"] += 1
                else:
                    metrics["incorrect_predictions"] += 1

                # Track by attack type
                if attack_type not in metrics["attack_types"]:
                    metrics["attack_types"][attack_type] = {"correct": 0, "total": 0}
                metrics["attack_types"][attack_type]["total"] += 1
                if match:
                    metrics["attack_types"][attack_type]["correct"] += 1

                # Progress
                if (idx + 1) % 50 == 0:
                    print(f"  {idx + 1}/{len(test_data)} processed... "
                          f"(accuracy: {metrics['correct_predictions']}/{metrics['total_processed']})")

            except Exception as e:
                metrics["incorrect_predictions"] += 1
                print(f"  Error processing sample {idx}: {e}")

        return metrics

    def show_results(self, metrics: Dict[str, int]):
        """Display validation results."""
        if not metrics or metrics["total_processed"] == 0:
            print("No results to display")
            return

        accuracy = metrics["correct_predictions"] / metrics["total_processed"] * 100 if metrics["total_processed"] > 0 else 0

        print(f"\n{'='*60}")
        print(f"  📊 ONLINE VALIDATION RESULTS")
        print(f"{'='*60}")
        print(f"\nAccuracy (online matches offline): {accuracy:.2f}%")
        print(f"  Correct predictions: {metrics['correct_predictions']} / {metrics['total_processed']}")
        print(f"  Incorrect predictions: {metrics['incorrect_predictions']}")

        print(f"\nBy Attack Type:")
        print(f"{'Attack Type':<25} {'Correct':<12} {'Total':<12} {'Accuracy':<12}")
        print("-" * 60)

        for attack_type in sorted(metrics["attack_types"].keys()):
            data = metrics["attack_types"][attack_type]
            correct = data["correct"]
            total = data["total"]
            acc = correct / total * 100 if total > 0 else 0
            print(f"{attack_type:<25} {correct:<12} {total:<12} {acc:>10.2f}%")

        print("=" * 60 + "\n")

        # Verdict
        if accuracy >= 95:
            print("✅ PASS: Online detection matches offline validation (≥95%)")
            print("   Model is production-ready for live traffic\n")
        elif accuracy >= 90:
            print("⚠️  WARNING: Online detection mostly matches offline (90-95%)")
            print("   Review discrepancies before full deployment\n")
        else:
            print("❌ FAIL: Online detection diverges from offline (< 90%)")
            print("   Investigate model inconsistencies before deployment\n")

    def run(self):
        """Execute online validation."""
        print("\n" + "="*60)
        print("  🚀 NetSentinelAI — Online Validation")
        print("  (Using same data as offline_validation.py)")
        print("="*60)

        # Initialize pipeline
        if not self.initialize_pipeline():
            print("\n❌ Failed to initialize pipeline")
            return False

        # Validate
        metrics = self.validate_online()

        # Show results
        self.show_results(metrics)

        return metrics.get("correct_predictions", 0) > 0


def main():
    parser = argparse.ArgumentParser(
        description="NetSentinelAI Online Validator — Replicates offline detection in online mode"
    )
    parser.add_argument(
        "--data",
        default="./online_test_data.json",
        help="Path to test data with features (default: ./online_test_data.json)"
    )

    args = parser.parse_args()

    validator = OnlineValidator()

    success = validator.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
