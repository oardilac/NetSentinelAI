#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Send attack samples to dashboard and validate predictions.

Workflow:
1. Load all samples from online_test_data.json
2. POST each to /api/predict showing full request/response detail
3. Compare against ground_truth and report accuracy
"""

import json
import sys
import os
import io
import requests
from typing import Optional

# Force UTF-8 output on Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

DASHBOARD_URL = "http://localhost:5050"

# HTTP timeouts
HTTP_TIMEOUT_SHORT = 2
HTTP_TIMEOUT_LONG = 5

# Accuracy evaluation thresholds
PASS_THRESHOLD = 95
WARN_THRESHOLD = 90

# UI display parameters
FEATURES_PREVIEW_COUNT = 5
PROGRESS_BAR_WIDTH = 40


def check_dashboard() -> bool:
    try:
        resp = requests.get(f"{DASHBOARD_URL}/api/status", timeout=HTTP_TIMEOUT_SHORT)
        if resp.status_code == 200:
            print(f"✓ Dashboard running at {DASHBOARD_URL}")
            return True
        return False
    except Exception as e:
        print(f"✗ Cannot reach dashboard: {e}")
        print(f"  Start it with: python dashboard_server.py")
        return False


def load_attacks(data_file: str = None) -> list:
    if data_file is None:
        data_file = os.path.join(os.path.dirname(__file__), "online_test_data.json")
    try:
        with open(data_file, "r") as f:
            data = json.load(f)
        print(f"✓ Loaded {len(data)} samples from {data_file}\n")
        return data
    except Exception as e:
        print(f"✗ Failed to load data: {e}")
        return []


def send_and_display(features: dict, index: int, attack_type: str) -> Optional[dict]:
    print(f"\n{'='*70}")
    print(f"[ATTACK {index + 1}] {attack_type}")
    print(f"{'='*70}")

    print(f"\n📤 REQUEST:")
    print(f"   POST {DASHBOARD_URL}/api/predict")
    print(f"   Features: {len(features)} indicators")
    for k, v in list(features.items())[:FEATURES_PREVIEW_COUNT]:
        print(f"      {k}: {v}")
    if len(features) > FEATURES_PREVIEW_COUNT:
        print(f"      ... and {len(features) - FEATURES_PREVIEW_COUNT} more")

    try:
        resp = requests.post(
            f"{DASHBOARD_URL}/api/predict",
            json={"features": features},
            timeout=HTTP_TIMEOUT_LONG,
        )

        if resp.status_code != 200:
            print(f"\n❌ Server returned {resp.status_code}")
            return None

        result = resp.json()

        print(f"\n📥 RESPONSE:")
        print(f"   Detected: {result.get('class', 'UNKNOWN')}")
        print(f"   Confidence: {result.get('confidence', 0) * 100:.1f}%")

        probs = result.get("probabilities", {})
        if probs and not (len(probs) == 1 and "Normal" in probs):
            print(f"   Attack probabilities:")
            for cls, prob in sorted(probs.items(), key=lambda x: x[1], reverse=True)[:3]:
                bar = "█" * int(prob * PROGRESS_BAR_WIDTH) + "░" * (PROGRESS_BAR_WIDTH - int(prob * PROGRESS_BAR_WIDTH))
                print(f"      {cls:<22} {bar} {prob * 100:5.1f}%")

        return result

    except Exception as e:
        print(f"\n❌ Request failed: {e}")
        return None


def main():
    print("\n" + "=" * 70)
    print("  NetSentinelAI — Attack Sender & Validator")
    print("=" * 70)

    if not check_dashboard():
        sys.exit(1)

    # Reset ML stats for clean demo slate
    try:
        requests.post(f"{DASHBOARD_URL}/api/reset-ml-stats", timeout=HTTP_TIMEOUT_SHORT)
        print("[OK] ML stats reset")
    except Exception as e:
        print(f"[WARN] Could not reset ML stats: {e}")

    samples = load_attacks()
    if not samples:
        sys.exit(1)

    total = correct = skipped = 0
    by_type: dict = {}

    for idx, sample in enumerate(samples):
        features = sample.get("features", {})
        attack_type = sample.get("attack_type", "UNKNOWN")
        ground_truth = sample.get("ground_truth", "UNKNOWN")

        if not features:
            skipped += 1
            continue

        result = send_and_display(features, idx, attack_type)

        if result is None:
            skipped += 1
            continue

        # Normalize to binary decision
        detected = result.get("class", "Normal")
        detected_binary = "BENIGN" if detected == "Normal" else "ATTACK"
        expected_binary = "BENIGN" if ground_truth in ("Normal", "BENIGN") else "ATTACK"

        match = detected_binary == expected_binary
        total += 1
        if match:
            correct += 1

        print(f"\n   Ground truth : {ground_truth}")
        print(f"   Match        : {'✅' if match else '❌'} ({detected_binary} vs {expected_binary})")

        if attack_type not in by_type:
            by_type[attack_type] = {"correct": 0, "total": 0}
        by_type[attack_type]["total"] += 1
        if match:
            by_type[attack_type]["correct"] += 1

    # Summary
    print(f"\n\n{'='*70}")
    print(f"  📊 SUMMARY")
    print(f"{'='*70}")

    if total == 0:
        print("No results.")
        sys.exit(1)

    accuracy = correct / total * 100
    print(f"\nOverall accuracy : {accuracy:.1f}%  ({correct}/{total})")
    if skipped > 0:
        print(f"Samples skipped  : {skipped} (missing features or request failure)")
    print(f"\n{'Attack Type':<25} {'Correct':<10} {'Total':<10} {'Accuracy'}")
    print("-" * 60)
    for atype in sorted(by_type):
        d = by_type[atype]
        acc = d["correct"] / d["total"] * 100 if d["total"] > 0 else 0
        print(f"{atype:<25} {d['correct']:<10} {d['total']:<10} {acc:.1f}%")

    print()
    if accuracy >= PASS_THRESHOLD:
        print(f"✅ PASS — dashboard predictions match ground truth (≥{PASS_THRESHOLD}%)")
    elif accuracy >= WARN_THRESHOLD:
        print(f"⚠️  WARNING — mostly correct ({WARN_THRESHOLD}–{PASS_THRESHOLD}%), check edge cases")
    else:
        print(f"❌ FAIL — predictions diverge from ground truth (<{WARN_THRESHOLD}%)")
    print()


if __name__ == "__main__":
    main()
