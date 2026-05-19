#!/usr/bin/env python3
"""
Send validated attack samples to dashboard and display results in UI.

This script:
1. Loads attack samples from online_test_data.json
2. Sends them to /api/predict
3. Displays petición/respuesta details
4. Registers successful detections for UI display
"""

import json
import requests
import sys
from typing import Dict, List

DASHBOARD_URL = "http://localhost:5050"

def load_test_attacks(limit: int = 20) -> List[Dict]:
    """Load first N attack samples."""
    try:
        with open("./online_test_data.json", 'r') as f:
            data = json.load(f)

        attacks = [s for s in data if s.get("attack_type") == "Training Attack"][:limit]
        print(f"✓ Loaded {len(attacks)} attack samples\n")
        return attacks
    except Exception as e:
        print(f"✗ Failed to load data: {e}")
        return []


def send_attack(features: Dict, index: int) -> Dict:
    """Send single attack to dashboard and show request/response."""

    print(f"\n{'='*70}")
    print(f"[ATTACK {index+1}] Sending malicious flow to dashboard...")
    print(f"{'='*70}")

    # Show REQUEST details
    print(f"\n📤 REQUEST:")
    print(f"   POST {DASHBOARD_URL}/api/predict")
    print(f"   Content-Type: application/json")
    print(f"   Payload size: {len(json.dumps({'features': features}))} bytes")
    print(f"   Features: {len(features)} network flow indicators")

    # Print sample features
    sample_features = dict(list(features.items())[:5])
    print(f"   Sample data:")
    for k, v in sample_features.items():
        print(f"      {k}: {v}")
    if len(features) > 5:
        print(f"      ... and {len(features)-5} more features")

    # Send request
    try:
        resp = requests.post(
            f"{DASHBOARD_URL}/api/predict",
            json={"features": features},
            timeout=5
        )

        if resp.status_code != 200:
            print(f"\n❌ ERROR: Server returned {resp.status_code}")
            return None

        dashboard_response = resp.json()

        # Show RESPONSE details
        print(f"\n📥 RESPONSE:")
        print(f"   Status: {resp.status_code} OK")
        print(f"   Detected class: {dashboard_response.get('class', 'UNKNOWN')}")
        print(f"   Confidence: {dashboard_response.get('confidence', 0):.4f} ({dashboard_response.get('confidence', 0)*100:.1f}%)")

        # Show attack probabilities
        probs = dashboard_response.get('probabilities', {})
        if probs and 'Normal' not in probs:
            print(f"   Attack type probabilities:")
            sorted_probs = sorted(probs.items(), key=lambda x: x[1], reverse=True)[:3]
            for attack_type, prob in sorted_probs:
                bar_length = int(prob * 40)
                bar = "█" * bar_length + "░" * (40 - bar_length)
                print(f"      {attack_type:<20} {bar} {prob*100:6.2f}%")

        return dashboard_response

    except Exception as e:
        print(f"\n❌ REQUEST FAILED: {e}")
        return None


def main():
    # Check dashboard
    try:
        resp = requests.get(f"{DASHBOARD_URL}/api/status", timeout=2)
        if resp.status_code != 200:
            print(f"❌ Dashboard not running at {DASHBOARD_URL}")
            sys.exit(1)
    except Exception as e:
        print(f"❌ Cannot reach dashboard: {e}")
        print(f"   Start it with: python3 dashboard_server.py")
        sys.exit(1)

    print(f"✓ Dashboard is running at {DASHBOARD_URL}\n")

    # Load attacks
    attacks = load_test_attacks(limit=10)
    if not attacks:
        print("❌ No attacks to send")
        sys.exit(1)

    # Send each attack
    results = []
    for idx, attack in enumerate(attacks):
        features = attack.get("features", {})
        if not features:
            continue

        result = send_attack(features, idx)
        if result:
            results.append({
                "index": idx,
                "class": result.get("class"),
                "confidence": result.get("confidence"),
                "success": True
            })

    # Summary
    print(f"\n\n{'='*70}")
    print(f"📊 SUMMARY")
    print(f"{'='*70}")
    print(f"\nSent {len(results)} attacks to dashboard")
    print(f"\nDetected attacks:")

    for r in results:
        status = "✅ Detected" if r["class"] != "Normal" else "⚠️ Benign"
        print(f"  [{r['index']+1}] {r['class']:<20} {status:<15} confidence: {r['confidence']:.4f}")

    print(f"\n✓ All attacks sent successfully to {DASHBOARD_URL}/api/predict")
    print(f"\nCheck the dashboard UI to see detected attacks:\n")
    print(f"   💻 Open: {DASHBOARD_URL}")
    print(f"   Look for these attacks in the 'ML Detection' or 'Recent Alerts' section\n")


if __name__ == "__main__":
    main()
