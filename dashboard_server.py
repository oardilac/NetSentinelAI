#!/usr/bin/env python3
"""
Dashboard Web Server
====================
Flask server that serves the SentinelAI dashboard and exposes REST
endpoints for real-time metrics, flow data, feature vectors, and
**historical data** from the local SQLite database.

Graceful shutdown
-----------------
On Ctrl+C (SIGINT) or SIGTERM the server flushes all active flows and
alerts to the database before exiting, so nothing is lost.
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from threading import Thread
import atexit
import signal
import network_monitor
import os
import sys

app = Flask(__name__)
CORS(app)

sniffer_thread = None
_shutdown_done = False


# ──────────────────────────────────────────────
# Graceful shutdown
# ──────────────────────────────────────────────

def _graceful_shutdown(*_args) -> None:
    """Flush data to DB before the process terminates."""
    global _shutdown_done
    if _shutdown_done:
        return
    _shutdown_done = True
    print("\n[*] Graceful shutdown — saving data to database...")
    try:
        sniffer = network_monitor.get_sniffer()
        sniffer.shutdown()
    except Exception as e:
        print(f"[ERROR] Shutdown flush failed: {e}")
    print("[*] Shutdown complete.")


atexit.register(_graceful_shutdown)
signal.signal(signal.SIGINT, lambda *a: (_graceful_shutdown(), sys.exit(0)))
signal.signal(signal.SIGTERM, lambda *a: (_graceful_shutdown(), sys.exit(0)))


# ──────────────────────────────────────────────
# Serve dashboard
# ──────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("./", "dashboard.html")


# ──────────────────────────────────────────────
# Live metrics API
# ──────────────────────────────────────────────

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


# ──────────────────────────────────────────────
# Sniffer controls
# ──────────────────────────────────────────────

@app.route("/api/start")
def start_monitoring():
    global sniffer_thread

    if sniffer_thread is not None and sniffer_thread.is_alive():
        return jsonify({"status": "already_running", "message": "Monitoring is already active"})

    sniffer = network_monitor.get_sniffer()
    sniffer_thread = Thread(target=sniffer.start_sniffing, daemon=True)
    sniffer_thread.start()

    return jsonify({"status": "started", "message": "Monitoring started"})


@app.route("/api/stop")
def stop_monitoring():
    """Stop sniffer and flush current data to database."""
    sniffer = network_monitor.get_sniffer()
    sniffer.shutdown()
    return jsonify({"status": "stopped", "message": "Monitoring stopped — data saved to database"})


@app.route("/api/status")
def get_status():
    sniffer = network_monitor.get_sniffer()
    return jsonify({
        "running": sniffer.running,
        "interface": sniffer.interface or "all",
    })


# ──────────────────────────────────────────────
# History API (reads from SQLite)
# ──────────────────────────────────────────────

@app.route("/api/history/summary")
def history_summary():
    """Aggregate statistics across all past sessions."""
    db = network_monitor.get_db()
    return jsonify(db.get_history_summary())


@app.route("/api/history/sessions")
def history_sessions():
    """List recent capture sessions."""
    limit = request.args.get("limit", 20, type=int)
    db = network_monitor.get_db()
    return jsonify(db.get_sessions(limit=limit))


@app.route("/api/history/flows")
def history_flows():
    """Query stored flows with optional filters.

    Query params:
      session_id  — filter by session
      protocol    — filter by protocol (TCP, UDP, ICMP, OTHER)
      src_ip      — filter by source IP
      limit       — max rows (default 200)
      offset      — pagination offset
    """
    db = network_monitor.get_db()
    flows = db.get_flows(
        session_id=request.args.get("session_id", None, type=int),
        protocol=request.args.get("protocol", None, type=str),
        src_ip=request.args.get("src_ip", None, type=str),
        limit=request.args.get("limit", 200, type=int),
        offset=request.args.get("offset", 0, type=int),
    )
    return jsonify({
        "count": len(flows),
        "total_stored": db.get_flow_count(),
        "flows": flows,
    })


@app.route("/api/history/alerts")
def history_alerts():
    """Query stored alerts."""
    db = network_monitor.get_db()
    session_id = request.args.get("session_id", None, type=int)
    limit = request.args.get("limit", 100, type=int)
    alerts = db.get_alerts(session_id=session_id, limit=limit)
    return jsonify({
        "count": len(alerts),
        "total_stored": db.get_alert_count(),
        "alerts": alerts,
    })


@app.route("/api/history/clear", methods=["POST"])
def history_clear():
    """Delete all stored history (sessions, flows, alerts)."""
    db = network_monitor.get_db()
    db.clear_all()
    return jsonify({"status": "cleared", "message": "All historical data deleted"})


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  SENTINEL AI — Network Security Monitor (Flow-Based + SQLite)")
    print("=" * 70)
    print()
    print("  IMPORTANT: Run as Administrator on Windows")
    print("             (Right-click -> Run as administrator)")
    print()
    print("  Dashboard:  http://localhost:5050")
    print()
    print("  API endpoints:")
    print("    GET  /api/metrics          — live metrics snapshot")
    print("    GET  /api/flows            — active flows with features")
    print("    GET  /api/features         — raw ML feature vectors")
    print("    GET  /api/history/summary  — aggregated DB statistics")
    print("    GET  /api/history/sessions — past capture sessions")
    print("    GET  /api/history/flows    — stored flows (filterable)")
    print("    GET  /api/history/alerts   — stored alerts")
    print("    POST /api/history/clear    — delete all history")
    print()
    print("  Press Ctrl+C to stop (data auto-saved to database)")
    print("=" * 70)
    print()

    os.makedirs("static", exist_ok=True)

    try:
        app.run(host="0.0.0.0", port=5050, debug=False, threaded=True)
    except KeyboardInterrupt:
        _graceful_shutdown()
        sys.exit(0)


if __name__ == "__main__":
    main()
