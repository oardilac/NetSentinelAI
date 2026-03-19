# SentinelAI — Flow-Based Network Security Monitor

Real-time network traffic analyzer that groups packets into **flows** by 5-tuple, extracts incremental security features, and **persists all data to a local SQLite database** so nothing is lost on program interruption or restart.

---

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌─────────────┐     ┌────────────────────┐
│  Scapy       │────▶│  FlowTable       │────▶│  SQLite DB  │────▶│  Dashboard / API   │
│  Sniffer     │     │  (5-tuple keyed) │     │  (local)    │     │  (Flask + Chart.js)│
└──────────────┘     └──────────────────┘     └─────────────┘     └────────────────────┘
      │                      │                       │
      │  packet-by-packet    │  IncrementalStat      │  sentinel_data.db
      │  callback            │  (Welford's alg.)     │  sessions / flows / alerts
      ▼                      ▼                       ▼
  network_monitor.py    flow_extractor.py      database.py
                        + inc_stat.py
```

### File Overview

| File | Purpose |
|---|---|
| `inc_stat.py` | Welford-based incremental mean / variance / std calculator |
| `flow_extractor.py` | `FlowRecord` dataclass + `FlowTable` (LRU, thread-safe, bounded) |
| `database.py` | SQLite persistence — sessions, flows (all 14 features), alerts |
| `network_monitor.py` | Scapy sniffer, packet parser, alert engine, DB integration |
| `dashboard_server.py` | Flask REST API + graceful shutdown + history endpoints |
| `dashboard.html` | Dashboard with live flow table, charts, alerts, **and DB history viewer** |

---

## Database Persistence

SentinelAI uses a **local SQLite database** (`sentinel_data.db`) created automatically next to the script. Data is saved in three situations:

1. **Automatically on flow expiry** — when a flow exceeds the idle timeout (default 120s), it is persisted to the `flows` table along with all 14 computed features.
2. **On stop** — clicking "Stop" in the dashboard or calling `GET /api/stop` flushes all remaining active flows and alerts to the database.
3. **On shutdown** — pressing `Ctrl+C` (SIGINT) or receiving SIGTERM triggers a graceful shutdown that saves everything before the process exits.

### Database Schema

```
sessions
├── id, started_at, stopped_at
├── total_packets, total_bytes, flow_count
│
flows
├── id, session_id, captured_at
├── src_ip, dst_ip, src_port, dst_port, protocol  (5-tuple)
├── flow_duration, iat_mean, iat_variance           (temporal)
├── total_bytes, avg_bytes_per_pkt, packet_count     (volume)
├── syn_count, ack_count, fin_count, rst_count       (TCP flags)
├── proto_tcp, proto_udp, proto_icmp, proto_other    (dummy encoding)
│
alerts
├── id, session_id, timestamp
├── alert_type, source, description
```

All tables are indexed for fast queries by session, timestamp, source IP, and protocol.

### Querying History

The dashboard includes a **Database History** section at the bottom with:
- Session listing (start/stop times, counters)
- Stored flows table (filterable by protocol and source IP)
- Stored alerts table

You can also query the API directly:

```bash
# Aggregate statistics across all sessions
curl http://localhost:5050/api/history/summary

# List past sessions
curl http://localhost:5050/api/history/sessions

# Query stored flows (with filters)
curl "http://localhost:5050/api/history/flows?protocol=TCP&limit=50"
curl "http://localhost:5050/api/history/flows?src_ip=10.0.0.1"

# Query stored alerts
curl http://localhost:5050/api/history/alerts

# Delete all history
curl -X POST http://localhost:5050/api/history/clear
```

---

## Flow Grouping

Every packet is assigned to a flow identified by:

```
(Source IP, Destination IP, Source Port, Destination Port, Protocol)
```

Flows live in an **in-memory LRU table** during capture. When a flow expires or the table reaches capacity, it is persisted to the database and removed from memory.

---

## Extracted Features (14 per flow)

### Temporal Characteristics

| Feature | Description |
|---|---|
| `flow_duration` | Seconds from first to last packet in the flow |
| `iat_mean` | Mean inter-arrival time between consecutive packets |
| `iat_variance` | Variance of inter-arrival times (low variance → automated traffic) |

### Volume Characteristics

| Feature | Description |
|---|---|
| `total_bytes` | Total bytes transferred in the flow (detects data exfiltration) |
| `avg_bytes_per_pkt` | Average payload size per packet |
| `packet_count` | Number of packets in the flow |

### Protocol Characteristics

| Feature | Description |
|---|---|
| `syn_count` | TCP SYN flags (high SYN without ACK → port scan) |
| `ack_count` | TCP ACK flags |
| `fin_count` | TCP FIN flags |
| `rst_count` | TCP RST flags (connection resets) |
| `proto_tcp` | Dummy-encoded: 1 if TCP |
| `proto_udp` | Dummy-encoded: 1 if UDP |
| `proto_icmp` | Dummy-encoded: 1 if ICMP |
| `proto_other` | Dummy-encoded: 1 if none of the above |

All statistics computed **incrementally** via Welford's algorithm — no raw packet data stored.

---

## API Endpoints

### Live Data

| Endpoint | Description |
|---|---|
| `GET /` | Dashboard UI |
| `GET /api/metrics` | Full snapshot: overview, flows, alerts, charts |
| `GET /api/flows` | Active flows with feature vectors |
| `GET /api/features` | Raw ML-ready feature vectors (JSON array) |
| `GET /api/start` | Start packet sniffer |
| `GET /api/stop` | Stop sniffer + flush data to DB |
| `GET /api/status` | Check if sniffer is running |

### History (from SQLite)

| Endpoint | Description |
|---|---|
| `GET /api/history/summary` | Aggregated stats across all sessions |
| `GET /api/history/sessions` | Past capture sessions |
| `GET /api/history/flows` | Stored flows (filterable: `session_id`, `protocol`, `src_ip`, `limit`, `offset`) |
| `GET /api/history/alerts` | Stored alerts (filterable: `session_id`, `limit`) |
| `POST /api/history/clear` | Delete all historical data |

---

## Alert Rules

| Rule | Trigger |
|---|---|
| **Port Scan** | `syn_count > 15` and `ack_count < 30% of syn_count` |
| **Data Exfiltration** | `total_bytes > 50 MB` in a single flow |
| **RST Flood** | `rst_count > 50` in a single flow |

Alerts are de-duplicated per flow, persisted to DB, and visible in both the live dashboard and history viewer.

---

## Quick Start

### Windows

1. Install Python 3.10+ and [Npcap](https://npcap.com/) (check "WinPcap API-compatible Mode").
2. Right-click `start.bat` → **Run as administrator**.
3. Open `http://localhost:5050` and click **Start Monitoring**.
4. Press `Ctrl+C` or click **Stop** — all data is auto-saved to `sentinel_data.db`.

### Linux / macOS

```bash
pip install -r requirements.txt
sudo python dashboard_server.py
```

Open `http://localhost:5050`.

---

## Design Decisions

- **SQLite with WAL mode** — safe concurrent reads from Flask while the sniffer writes. No external database server required.
- **Graceful shutdown** — `atexit`, `SIGINT`, and `SIGTERM` handlers all trigger `flush_to_db()`.
- **No packet cache** — raw packets are never stored; only incremental statistics and computed features.
- **Welford's algorithm** — numerically stable online mean/variance without storing history.
- **Thread-safe** — `FlowTable`, `SentinelDB`, and all collectors use locks.
- **Bounded memory** — configurable `max_flows` and `timeout` prevent unbounded growth; evicted flows go to DB.
- **Session tracking** — each start/stop cycle creates a session in the DB, making it easy to compare captures over time.
