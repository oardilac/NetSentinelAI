"""
Flow Grouper & Feature Extractor
=================================
Groups live packets by 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
and computes per-flow features **incrementally** — no database, no cache.

Feature categories
------------------
* **Temporal**  – flow duration, inter-arrival time mean & variance.
* **Volume**    – total bytes, average bytes per packet.
* **Protocol**  – SYN / ACK / FIN / RST flag counts, one-hot (dummy) protocol encoding.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List, Optional, Tuple

from inc_stat import IncrementalStat

# ──────────────────────────────────────────────
# Flow record (one per 5-tuple)
# ──────────────────────────────────────────────

@dataclass
class FlowRecord:
    """Holds all incremental state for a single network flow."""

    # Identity
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    # Timestamps
    start_time: float = 0.0
    last_time: float = 0.0

    # Counters
    packet_count: int = 0
    total_bytes: int = 0

    # TCP flag counters
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0

    # Incremental stats (no raw storage)
    iat_stat: IncrementalStat = field(default_factory=IncrementalStat)
    pkt_size_stat: IncrementalStat = field(default_factory=IncrementalStat)

    # ── derived features ──

    @property
    def duration(self) -> float:
        """Total time from first to last packet (seconds)."""
        return self.last_time - self.start_time

    @property
    def iat_mean(self) -> float:
        return self.iat_stat.mean

    @property
    def iat_variance(self) -> float:
        return self.iat_stat.variance

    @property
    def avg_bytes_per_packet(self) -> float:
        return self.total_bytes / self.packet_count if self.packet_count else 0.0

    def get_feature_vector(self) -> Dict[str, float]:
        """Return the full feature dictionary for this flow."""
        features: Dict[str, float] = {
            # Temporal
            "flow_duration":    round(self.duration, 6),
            "iat_mean":         round(self.iat_mean, 6),
            "iat_variance":     round(self.iat_variance, 6),
            # Volume
            "total_bytes":      self.total_bytes,
            "avg_bytes_per_pkt": round(self.avg_bytes_per_packet, 2),
            "packet_count":     self.packet_count,
            # Protocol flags (TCP)
            "syn_count":        self.syn_count,
            "ack_count":        self.ack_count,
            "fin_count":        self.fin_count,
            "rst_count":        self.rst_count,
            # Protocol dummy encoding
            "proto_tcp":        1 if self.protocol == "TCP" else 0,
            "proto_udp":        1 if self.protocol == "UDP" else 0,
            "proto_icmp":       1 if self.protocol == "ICMP" else 0,
            "proto_other":      1 if self.protocol not in ("TCP", "UDP", "ICMP") else 0,
        }
        return features

    def to_summary(self) -> Dict:
        """Compact JSON-friendly summary for the dashboard."""
        vec = self.get_feature_vector()
        vec["src_ip"] = self.src_ip
        vec["dst_ip"] = self.dst_ip
        vec["src_port"] = self.src_port
        vec["dst_port"] = self.dst_port
        vec["protocol"] = self.protocol
        vec["flow_key"] = f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port} [{self.protocol}]"
        return vec


# ──────────────────────────────────────────────
# Flow table with LRU eviction
# ──────────────────────────────────────────────

FlowKey = Tuple[str, str, int, int, str]

class FlowTable:
    """Thread-safe, bounded flow table with LRU eviction and timeout expiry.

    No external database — everything lives in memory and is discarded
    once a flow expires or the table reaches its capacity limit.
    """

    def __init__(
        self,
        max_flows: int = 100_000,
        timeout: float = 120.0,
    ):
        self.max_flows = max_flows
        self.timeout = timeout
        self._lock = Lock()
        self._flows: OrderedDict[FlowKey, FlowRecord] = OrderedDict()
        self._expired: List[FlowRecord] = []  # recently expired, for dashboard

    # ── public API ──

    def update(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        pkt_len: int,
        timestamp: float,
        tcp_flags: Optional[int] = None,
    ) -> FlowRecord:
        """Register a packet into the flow table. Returns the updated FlowRecord."""
        key: FlowKey = (src_ip, dst_ip, src_port, dst_port, protocol)

        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                # Evict oldest if at capacity
                if len(self._flows) >= self.max_flows:
                    _, evicted = self._flows.popitem(last=False)
                    self._expired.append(evicted)

                flow = FlowRecord(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    start_time=timestamp,
                    last_time=timestamp,
                )
                self._flows[key] = flow
            else:
                # Move to end (most-recently-used)
                self._flows.move_to_end(key)

                # Inter-arrival time
                iat = timestamp - flow.last_time
                if iat > 0:
                    flow.iat_stat.update(iat)

                flow.last_time = timestamp

            # Common updates
            flow.packet_count += 1
            flow.total_bytes += pkt_len
            flow.pkt_size_stat.update(pkt_len)

            # TCP flags
            if tcp_flags is not None:
                if tcp_flags & 0x02:  # SYN
                    flow.syn_count += 1
                if tcp_flags & 0x10:  # ACK
                    flow.ack_count += 1
                if tcp_flags & 0x01:  # FIN
                    flow.fin_count += 1
                if tcp_flags & 0x04:  # RST
                    flow.rst_count += 1

        return flow

    def expire_old_flows(self, now: Optional[float] = None) -> List[FlowRecord]:
        """Move flows older than *timeout* seconds to the expired list."""
        now = now or time.time()
        expired_batch: List[FlowRecord] = []
        with self._lock:
            keys_to_remove = [
                k for k, f in self._flows.items()
                if (now - f.last_time) > self.timeout
            ]
            for k in keys_to_remove:
                expired_batch.append(self._flows.pop(k))
            self._expired.extend(expired_batch)
            # Keep only last 500 expired for dashboard viewing
            if len(self._expired) > 500:
                self._expired = self._expired[-500:]
        return expired_batch

    def get_active_flows(self) -> List[Dict]:
        """Snapshot of all currently active flows (for dashboard)."""
        with self._lock:
            return [f.to_summary() for f in self._flows.values()]

    def get_expired_flows(self, limit: int = 50) -> List[Dict]:
        """Most recently expired flows."""
        with self._lock:
            return [f.to_summary() for f in self._expired[-limit:]]

    def get_active_count(self) -> int:
        with self._lock:
            return len(self._flows)

    def get_all_feature_vectors(self) -> List[Dict[str, float]]:
        """Return raw feature vectors for every active flow (for ML pipeline)."""
        with self._lock:
            return [f.get_feature_vector() for f in self._flows.values()]
