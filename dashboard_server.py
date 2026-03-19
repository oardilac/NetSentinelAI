#!/usr/bin/env python3
"""
Dashboard Web Server
====================
Flask server that serves the SentinelAI dashboard and exposes
REST endpoints for real-time metrics, flow data, and feature vectors.
"""

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from threading import Thread
import network_monitor
import os
import sys

app = Flask(__name__)
CORS(app)

sniffer_thread = None


@app.route("/")
def index():
    """Serve the main dashboard page."""
    return send_from_directory("./", "dashboard.html")


@app.route("/api/metrics")
def get_metrics():
    """Full metrics snapshot (overview + flows + alerts)."""
    sniffer = network_monitor.get_sniffer()
    return jsonify(sniffer.metrics.get_metrics())


@app.route("/api/flows")
def get_flows():
    """Active flows with their computed feature vectors."""
    sniffer = network_monitor.get_sniffer()
    flows = sniffer.metrics.flow_table.get_active_flows()
    return jsonify({
        "active_count": sniffer.metrics.flow_table.get_active_count(),
        "flows": sorted(flows, key=lambda f: f.get("total_bytes", 0), reverse=True)[:100],
    })


@app.route("/api/features")
def get_features():
    """Raw feature vectors for all active flows (ML pipeline ready)."""
    sniffer = network_monitor.get_sniffer()
    return jsonify(sniffer.metrics.get_flow_features())


@app.route("/api/start")
def start_monitoring():
    """Start the network sniffer."""
    global sniffer_thread

    if sniffer_thread is not None and sniffer_thread.is_alive():
        return jsonify({"status": "already_running", "message": "Monitoring is already active"})

    sniffer = network_monitor.get_sniffer()
    sniffer_thread = Thread(target=sniffer.start_sniffing, daemon=True)
    sniffer_thread.start()

    return jsonify({"status": "started", "message": "Monitoring started"})


@app.route("/api/stop")
def stop_monitoring():
    """Stop the network sniffer."""
    sniffer = network_monitor.get_sniffer()
    sniffer.stop_sniffing()
    return jsonify({"status": "stopped", "message": "Monitoring stopped"})


@app.route("/api/status")
def get_status():
    """Current sniffer status."""
    sniffer = network_monitor.get_sniffer()
    return jsonify({
        "running": sniffer.running,
        "interface": sniffer.interface or "all",
    })


def main():
    print("=" * 70)
    print("  SENTINEL AI — Network Security Monitor (Flow-Based)")
    print("=" * 70)
    print()
    print("  IMPORTANT: Run as Administrator on Windows")
    print("             (Right-click -> Run as administrator)")
    print()
    print("  Dashboard available at: http://localhost:5050")
    print("  API endpoints:")
    print("    GET /api/metrics   — full metrics snapshot")
    print("    GET /api/flows     — active flows with features")
    print("    GET /api/features  — raw ML feature vectors")
    print()
    print("  Press Ctrl+C to stop the server")
    print("=" * 70)
    print()

    os.makedirs("static", exist_ok=True)

    try:
        app.run(host="0.0.0.0", port=5050, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n[!] Server stopped")
        sys.exit(0)


if __name__ == "__main__":
    main()
