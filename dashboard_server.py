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
from threading import Thread, Event
from collections import defaultdict
import atexit
import signal
import datetime
import time
import network_monitor
import ml_engine
import os
import sys
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(name)s: %(message)s')

DEFAULT_PORT = int(os.environ.get("PORT", 5050))

# History endpoint limits
_HISTORY_FLOWS_LIMIT = 200
_HISTORY_ALERTS_LIMIT = 100
_HISTORY_SESSIONS_LIMIT = 20

# Flow expiry simulation offset
FAR_FUTURE_OFFSET_SECONDS = 99999

app = Flask(__name__)
CORS(app)

sniffer_thread = None
_shutdown_done = Event()


# ──────────────────────────────────────────────
# Graceful shutdown
# ──────────────────────────────────────────────

def _graceful_shutdown(*_args) -> None:
    """Flush data to DB before the process terminates."""
    if _shutdown_done.is_set():
        return
    _shutdown_done.set()
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
# Helper functions
# ──────────────────────────────────────────────

def _compute_ml_stats(sniffer):
    """Compute ML class distribution from expired (classified) flows + active flows."""
    stats = defaultdict(int)

    # Session-wide counts from expired/classified flows (survives flush)
    for cls, cnt in sniffer.metrics.ml_class_counts.items():
        stats[cls] += cnt

    # Active flows that have already been predicted in real-time
    active = sniffer.metrics.flow_table.get_active_flows()
    for flow in active:
        ml_class = flow.get("ml_class")
        if ml_class:
            stats[ml_class] += 1

    # Initialize all known classes to 0, then overlay observed counts
    try:
        known_classes = ml_engine.get_attack_classes()
    except Exception:
        known_classes = ["Normal"]
    result = {cls: stats.get(cls, 0) for cls in known_classes}
    # Include any observed classes not in the known list (future-proof)
    for cls, count in stats.items():
        result.setdefault(cls, count)
    return result


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
    """Full metrics snapshot (overview + flows + alerts + ML stats)."""
    sniffer = network_monitor.get_sniffer()
    metrics = sniffer.metrics.get_metrics()

    # Compute ML stats from active + recent expired flows
    ml_stats = _compute_ml_stats(sniffer)
    metrics["ml_stats"] = ml_stats

    return jsonify(metrics)


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


@app.route("/api/flush-flows", methods=["POST"])
def flush_flows():
    """Force immediate expiry and ML classification of all active flows.

    Used by attack simulation scripts to get instant classification results
    without waiting for the 120s flow timeout.
    """
    sniffer = network_monitor.get_sniffer()
    sniffer.metrics._expire_and_alert(time.time() + FAR_FUTURE_OFFSET_SECONDS)
    return jsonify({"status": "ok", "message": "All flows flushed and classified"})


@app.route("/api/predict", methods=["POST"])
def predict():
    """On-demand ML prediction for a single flow.

    POST body accepts either:
    1. Nested: {"features": {feature_dict}}
    2. Direct: {feature_name: value, ...}
    Optional: "src_ip", "dst_ip", "src_port", "dst_port", "protocol"

    Returns: {
        "class": str,
        "confidence": float,
        "probabilities": {class: prob, ...},
        "error": str (if any)
    }
    """
    try:
        payload = request.get_json()
        if not payload:
            return jsonify({"error": "Empty request body"}), 400

        features = ml_engine.normalize_feature_payload(payload)
        result = ml_engine.predict_flow(features)

        # Update live flow object if flow_key is provided
        sniffer = network_monitor.get_sniffer()
        predicted_class = result.get("class", "Normal")
        predicted_confidence = result.get("confidence", 0.0)
        flow_key = payload.get("_flow_key")

        if flow_key and hasattr(sniffer, "flow_table"):
            import ast
            parsed_key = flow_key
            if isinstance(flow_key, str):
                try:
                    parsed_key = ast.literal_eval(flow_key)
                except (ValueError, SyntaxError):
                    parsed_key = None

            flow = sniffer.flow_table.flows.get(parsed_key) if parsed_key else None
            if flow:
                flow.ml_class = predicted_class
                flow.ml_confidence = predicted_confidence

                # Trigger alert immediately if attack detected
                if predicted_class != "Normal":
                    flow_summary = flow.to_summary()
                    sniffer.alert_engine.add_ml_alert(flow_summary, result)

        # Defer database writes to background (non-critical path)
        def _async_save():
            try:
                sniffer = network_monitor.get_sniffer()
                with sniffer.metrics.lock:
                    sniffer.metrics.ml_class_counts[predicted_class] += 1

                db = network_monitor.get_db()
                protocol = payload.get("protocol", "TCP")
                synthetic_flow = {
                    "src_ip": payload.get("src_ip", "0.0.0.0"),
                    "dst_ip": payload.get("dst_ip", "0.0.0.0"),
                    "src_port": payload.get("src_port", 0),
                    "dst_port": payload.get("dst_port", 0),
                    "protocol": protocol,
                    "flow_duration": 0,
                    "iat_mean": 0,
                    "iat_variance": 0,
                    "total_bytes": 0,
                    "avg_bytes_per_pkt": 0,
                    "packet_count": 0,
                    "syn_count": 0,
                    "ack_count": 0,
                    "fin_count": 0,
                    "rst_count": 0,
                    "proto_tcp": 1 if protocol == "TCP" else 0,
                    "proto_udp": 1 if protocol == "UDP" else 0,
                    "proto_icmp": 1 if protocol == "ICMP" else 0,
                    "proto_other": 1 if protocol not in ("TCP", "UDP", "ICMP") else 0,
                    "ml_class": result.get("class"),
                    "ml_confidence": result.get("confidence", 0.0),
                }

                db.save_flows([synthetic_flow], session_id=sniffer.metrics.session_id)

                if result.get("class") != "Normal":
                    alert_data = {
                        "timestamp": datetime.datetime.now().isoformat(),
                        "type": f"ml_{result.get('class', 'unknown').lower().replace(' ', '_')}",
                        "source": synthetic_flow["src_ip"],
                        "description": f"ML detected {result.get('class')} (confidence: {result.get('confidence', 0):.1%})",
                    }
                    db.save_alerts([alert_data], session_id=sniffer.metrics.session_id)
            except Exception as e:
                print(f"[WARN] Async save failed: {e}")

        Thread(target=_async_save, daemon=True).start()
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ──────────────────────────────────────────────
# Sniffer controls
# ──────────────────────────────────────────────

@app.route("/api/debug/ml_counts")
def debug_ml_counts():
    """Debug endpoint to see current ml_class_counts state."""
    sniffer = network_monitor.get_sniffer()
    return jsonify({
        "ml_class_counts": dict(sniffer.metrics.ml_class_counts),
        "session_id": sniffer.metrics.session_id,
    })


@app.route("/api/start", methods=["POST"])
def start_monitoring():
    global sniffer_thread

    if sniffer_thread is not None and sniffer_thread.is_alive():
        return jsonify({"status": "already_running", "message": "Monitoring is already active"})

    network_monitor._sniffer = None
    sniffer = network_monitor.get_sniffer()
    sniffer_thread = Thread(target=sniffer.start_sniffing, daemon=True)
    sniffer_thread.start()

    return jsonify({"status": "started", "message": "Monitoring started"})


@app.route("/api/stop", methods=["POST"])
def stop_monitoring():
    """Stop sniffer and flush current data to database."""
    global sniffer_thread
    sniffer = network_monitor.get_sniffer()
    sniffer.shutdown()
    network_monitor._sniffer = None
    sniffer_thread = None
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
    limit = request.args.get("limit", _HISTORY_SESSIONS_LIMIT, type=int)
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
        limit=request.args.get("limit", _HISTORY_FLOWS_LIMIT, type=int),
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
    limit = request.args.get("limit", _HISTORY_ALERTS_LIMIT, type=int)
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


@app.route("/api/reset-ml-stats", methods=["POST"])
def reset_ml_stats():
    """Reset in-memory ML classification counters (for demo / clean-slate runs)."""
    sniffer = network_monitor.get_sniffer()
    sniffer.metrics.ml_class_counts.clear()
    return jsonify({"status": "reset", "message": "ML stats cleared"})


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
    print(f"  Dashboard:  http://localhost:{DEFAULT_PORT}")
    print()
    print("  API endpoints:")
    print("    GET  /api/metrics          — live metrics snapshot (incl. ML stats)")
    print("    GET  /api/flows            — active flows with features")
    print("    GET  /api/features         — raw ML feature vectors")
    print("    POST /api/predict          — on-demand ML prediction for a flow")
    print("    GET  /api/history/summary  — aggregated DB statistics")
    print("    GET  /api/history/sessions — past capture sessions")
    print("    GET  /api/history/flows    — stored flows (filterable, incl. ML)")
    print("    GET  /api/history/alerts   — stored alerts")
    print("    POST /api/history/clear    — delete all history")
    print()
    print("  Press Ctrl+C to stop (data auto-saved to database)")
    print("=" * 70)
    print()

    try:
        app.run(host="0.0.0.0", port=DEFAULT_PORT, debug=False, threaded=True)
    except KeyboardInterrupt:
        _graceful_shutdown()
        sys.exit(0)


if __name__ == "__main__":
    main()
