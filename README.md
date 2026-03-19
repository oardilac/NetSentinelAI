# SentinelAI — Flow-Based Network Security Monitor

Real-time network traffic analyzer that groups packets into **flows** by 5-tuple and extracts incremental security features — no database, no packet cache.

---

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌────────────────────┐
│  Scapy       │────▶│  FlowTable       │────▶│  Dashboard / API   │
│  Sniffer     │     │  (5-tuple keyed) │     │  (Flask + Chart.js)│
└──────────────┘     └──────────────────┘     └────────────────────┘
      │                      │
      │  packet-by-packet    │  IncrementalStat
      │  callback            │  (Welford's algorithm)
      ▼                      ▼
  network_monitor.py    flow_extractor.py + inc_stat.py
```

### File Overview

| File | Purpose |
|---|---|
| `inc_stat.py` | Welford-based incremental mean / variance / std calculator |
| `flow_extractor.py` | `FlowRecord` dataclass + `FlowTable` (LRU, thread-safe, bounded) |
| `network_monitor.py` | Scapy sniffer, packet parser, alert engine, metrics aggregator |
| `dashboard_server.py` | Flask REST API + serves `dashboard.html` |
| `dashboard.html` | Single-page dashboard with live flow table, charts, and alerts |

---

## Flow Grouping

Every packet is assigned to a flow identified by:

```
(Source IP, Destination IP, Source Port, Destination Port, Protocol)
```

Flows are stored in an **in-memory LRU table** (no database). When a flow exceeds the idle timeout (default 120 s) or the table reaches capacity (default 100 000 flows), the oldest entries are evicted.

---

## Extracted Features

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
| `syn_count` | Number of TCP SYN flags (high SYN without ACK → port scan) |
| `ack_count` | Number of TCP ACK flags |
| `fin_count` | Number of TCP FIN flags |
| `rst_count` | Number of TCP RST flags (connection resets) |
| `proto_tcp` | Dummy-encoded: 1 if protocol is TCP |
| `proto_udp` | Dummy-encoded: 1 if protocol is UDP |
| `proto_icmp` | Dummy-encoded: 1 if protocol is ICMP |
| `proto_other` | Dummy-encoded: 1 if none of the above |

All statistics are computed **incrementally** using Welford's online algorithm (`inc_stat.py`), so no raw packet data is ever stored.

---

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Dashboard UI |
| `GET /api/metrics` | Full snapshot: overview, flows, alerts, charts |
| `GET /api/flows` | Active flows with computed feature vectors |
| `GET /api/features` | Raw feature vectors for all active flows (ML-ready) |
| `GET /api/start` | Start the packet sniffer |
| `GET /api/stop` | Stop the packet sniffer |
| `GET /api/status` | Check if sniffer is running |

### ML Pipeline Integration

Call `GET /api/features` to obtain a JSON array of feature dictionaries, ready to feed into a scaler (e.g. `MinMaxScaler`) and a classifier:

```json
[
  {
    "flow_duration": 12.345,
    "iat_mean": 0.0412,
    "iat_variance": 0.0003,
    "total_bytes": 148230,
    "avg_bytes_per_pkt": 523.15,
    "packet_count": 283,
    "syn_count": 1,
    "ack_count": 141,
    "fin_count": 1,
    "rst_count": 0,
    "proto_tcp": 1,
    "proto_udp": 0,
    "proto_icmp": 0,
    "proto_other": 0
  }
]
```

---

## Alert Rules

The `AlertEngine` checks every expired (and periodically, every active) flow:

| Rule | Trigger |
|---|---|
| **Port Scan** | `syn_count > 15` and `ack_count < 30% of syn_count` |
| **Data Exfiltration** | `total_bytes > 50 MB` in a single flow |
| **RST Flood** | `rst_count > 50` in a single flow |

Alerts are de-duplicated per flow key and displayed in the dashboard.

---

## Quick Start

### Windows

1. Install Python 3.10+ and [Npcap](https://npcap.com/) (check "WinPcap API-compatible Mode").
2. Right-click `start.bat` → **Run as administrator**.
3. Open `http://localhost:5050` and click **Start Monitoring**.

### Linux / macOS

```bash
pip install -r requirements.txt
sudo python dashboard_server.py
```

Open `http://localhost:5050`.

---

## Design Decisions

- **No database** — all state lives in memory via `OrderedDict` with LRU eviction.
- **No packet cache** — raw packets are never stored; only incremental statistics are kept.
- **Welford's algorithm** — numerically stable online computation of mean and variance without storing any history.
- **Thread-safe** — `FlowTable` and all collectors use `threading.Lock`.
- **Bounded memory** — configurable `max_flows` and `timeout` prevent unbounded growth.
