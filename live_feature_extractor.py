"""
Live bidirectional flow feature extractor for CIC-IDS2017 compatibility.

Processes network packets and extracts CIC-IDS2017 features per flow:
- Forward/backward packet and byte counts
- Forward/backward packet length statistics (max, min, mean, std)
- Inter-arrival time (IAT) statistics per direction
- TCP flag counts per direction
- Port-based features (one-hot encoding)
- Active/Idle time statistics (computed but not emitted — not in SHAP top-10 feature set)

Key design:
- Bidirectional flow lookup: forward_key vs reverse_key
- IncrementalStat (Welford) for online statistics
- Destination port from first forward packet
- get_feature_vector() returns only the SHAP-selected features loaded from feature_columns.json
"""

import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple
from collections import OrderedDict
from threading import Lock

from inc_stat import IncrementalStat
from feature_schema import encode_port, FEATURE_COLUMNS

_MICROSECONDS = 1_000_000.0
MIN_FLOW_DURATION_SECS = 0.001
MAX_EXPIRED_FLOWS_CACHE = 500

logger = logging.getLogger(__name__)


@dataclass
class BidirectionalFlowRecord:
    """
    Represents a bidirectional flow with forward and backward packet statistics.

    A flow is uniquely identified by a 5-tuple:
    (src_ip, dst_ip, src_port, dst_port, protocol)

    The direction of the FIRST packet defines forward; the opposite is backward.
    """

    # Flow identifier
    key: Tuple[str, str, int, int, int]  # (src_ip, dst_ip, src_port, dst_port, proto)
    dst_port: int  # Destination port from first forward packet

    # Timestamps
    start_time: float  # Flow start (first packet time)
    last_seen: float  # Last packet time

    # Counters: packets and bytes per direction
    fwd_pkt_count: int = 0
    bwd_pkt_count: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    # Packet length statistics (using IncrementalStat)
    fwd_pkt_len_stat: IncrementalStat = field(default_factory=IncrementalStat)
    bwd_pkt_len_stat: IncrementalStat = field(default_factory=IncrementalStat)
    all_pkt_len_stat: IncrementalStat = field(default_factory=IncrementalStat)

    # Inter-Arrival Time (IAT) statistics
    fwd_iat_stat: IncrementalStat = field(default_factory=IncrementalStat)
    bwd_iat_stat: IncrementalStat = field(default_factory=IncrementalStat)
    flow_iat_stat: IncrementalStat = field(default_factory=IncrementalStat)

    last_fwd_time: Optional[float] = None
    last_bwd_time: Optional[float] = None
    last_pkt_time: Optional[float] = None
    fwd_iat_total: float = 0.0
    bwd_iat_total: float = 0.0

    # TCP Flags per direction
    fwd_fin: int = 0
    bwd_fin: int = 0
    fwd_syn: int = 0
    bwd_syn: int = 0
    fwd_rst: int = 0
    bwd_rst: int = 0
    fwd_psh: int = 0
    bwd_psh: int = 0
    fwd_ack: int = 0
    bwd_ack: int = 0
    fwd_urg: int = 0
    bwd_urg: int = 0
    fwd_ece: int = 0
    bwd_ece: int = 0

    # Header lengths
    fwd_header_len: int = 0
    bwd_header_len: int = 0

    # TCP window (from SYN packets)
    init_win_fwd: int = -1
    init_win_bwd: int = -1

    # Data packet count (payload > 0)
    act_data_pkt_fwd: int = 0

    # Min segment size forward (min TCP header length)
    min_seg_size_fwd: int = 0

    def update(
        self,
        pkt_time: float,
        _pkt_len: int,
        payload_len: int,
        tcp_flags: int,
        header_len: int,
        direction: str = "fwd",
        tcp_window: int = -1,
    ):
        """
        Update flow statistics with a new packet.

        Args:
            pkt_time: packet timestamp
            pkt_len: total packet length (accepted for API compatibility, not used — byte
                     statistics track payload_len only, consistent with CICFlowMeter)
            payload_len: application data length
            tcp_flags: TCP flags byte (6 bits)
            header_len: IP+TCP header length
            direction: "fwd" or "bwd"
        """
        self.last_seen = pkt_time

        if direction == "fwd":
            self.fwd_pkt_count += 1
            self.fwd_bytes += payload_len

            # Packet length stats
            self.fwd_pkt_len_stat.update(payload_len)
            self.all_pkt_len_stat.update(payload_len)

            # IAT (inter-arrival time)
            if self.last_fwd_time is not None:
                iat = pkt_time - self.last_fwd_time
                self.fwd_iat_stat.update(iat)
                self.fwd_iat_total += iat
            self.last_fwd_time = pkt_time

            # Header length
            self.fwd_header_len += header_len

            # Data packet count
            if payload_len > 0:
                self.act_data_pkt_fwd += 1

            # Min segment size (min fwd header length)
            if header_len > 0 and (self.min_seg_size_fwd == 0 or header_len < self.min_seg_size_fwd):
                self.min_seg_size_fwd = header_len

            # TCP flags
            if tcp_flags & 0x01:  # FIN
                self.fwd_fin += 1
            if tcp_flags & 0x02:  # SYN
                self.fwd_syn += 1
                # Capture initial window size from SYN packet
                if self.init_win_fwd == -1 and tcp_window >= 0:
                    self.init_win_fwd = tcp_window
            if tcp_flags & 0x04:  # RST
                self.fwd_rst += 1
            if tcp_flags & 0x08:  # PSH
                self.fwd_psh += 1
            if tcp_flags & 0x10:  # ACK
                self.fwd_ack += 1
            if tcp_flags & 0x20:  # URG
                self.fwd_urg += 1
            if tcp_flags & 0x40:  # ECE
                self.fwd_ece += 1

        else:  # backward
            self.bwd_pkt_count += 1
            self.bwd_bytes += payload_len

            # Packet length stats
            self.bwd_pkt_len_stat.update(payload_len)
            self.all_pkt_len_stat.update(payload_len)

            # IAT
            if self.last_bwd_time is not None:
                iat = pkt_time - self.last_bwd_time
                self.bwd_iat_stat.update(iat)
                self.bwd_iat_total += iat
            self.last_bwd_time = pkt_time

            # Header length
            self.bwd_header_len += header_len

            # TCP flags
            if tcp_flags & 0x01:  # FIN
                self.bwd_fin += 1
            if tcp_flags & 0x02:  # SYN
                self.bwd_syn += 1
                if self.init_win_bwd == -1 and tcp_window >= 0:
                    self.init_win_bwd = tcp_window
            if tcp_flags & 0x04:  # RST
                self.bwd_rst += 1
            if tcp_flags & 0x08:  # PSH
                self.bwd_psh += 1
            if tcp_flags & 0x10:  # ACK
                self.bwd_ack += 1
            if tcp_flags & 0x20:  # URG
                self.bwd_urg += 1
            if tcp_flags & 0x40:  # ECE
                self.bwd_ece += 1

        # Update overall flow IAT
        if self.last_pkt_time is not None:
            iat = pkt_time - self.last_pkt_time
            self.flow_iat_stat.update(iat)
        self.last_pkt_time = pkt_time

    def get_feature_vector(self) -> Dict[str, float]:
        """
        Extract CIC-IDS2017 features and return the SHAP-selected subset.

        Computes all measurable features then filters to the subset defined by
        FEATURE_COLUMNS (loaded from feature_columns.json at import time).
        Active/idle features are tracked internally but not emitted because they
        are not part of the current SHAP top-10 feature set.

        Returns:
            dict with feature names (CIC-IDS2017 names) and float values
        """
        features = OrderedDict()

        # Compute flow duration in microseconds (like CIC-IDS2017)
        flow_duration_us = (self.last_seen - self.start_time) * 1e6

        # ── Basic Flow Statistics
        features["Flow Duration"] = flow_duration_us

        features["Total Fwd Packets"] = float(self.fwd_pkt_count)
        features["Total Backward Packets"] = float(self.bwd_pkt_count)

        features["Total Length of Fwd Packets"] = float(self.fwd_bytes)
        features["Total Length of Bwd Packets"] = float(self.bwd_bytes)

        # ── Fwd Packet Length Statistics
        fwd_pkt_stats = self.fwd_pkt_len_stat
        features["Fwd Packet Length Max"] = float(fwd_pkt_stats.max_val) if fwd_pkt_stats.count > 0 else 0.0
        features["Fwd Packet Length Min"] = float(fwd_pkt_stats.min_val) if fwd_pkt_stats.count > 0 else 0.0
        features["Fwd Packet Length Mean"] = float(fwd_pkt_stats.mean) if fwd_pkt_stats.count > 0 else 0.0
        features["Fwd Packet Length Std"] = float(fwd_pkt_stats.std) if fwd_pkt_stats.count > 0 else 0.0

        # ── Bwd Packet Length Statistics
        bwd_pkt_stats = self.bwd_pkt_len_stat
        features["Bwd Packet Length Max"] = float(bwd_pkt_stats.max_val) if bwd_pkt_stats.count > 0 else 0.0
        features["Bwd Packet Length Min"] = float(bwd_pkt_stats.min_val) if bwd_pkt_stats.count > 0 else 0.0
        features["Bwd Packet Length Mean"] = float(bwd_pkt_stats.mean) if bwd_pkt_stats.count > 0 else 0.0
        features["Bwd Packet Length Std"] = float(bwd_pkt_stats.std) if bwd_pkt_stats.count > 0 else 0.0

        # ── Flow Rate Features (use minimum duration to avoid extreme rates for zero-duration flows)
        _eff_dur = max((self.last_seen - self.start_time), MIN_FLOW_DURATION_SECS)
        features["Flow Bytes/s"]   = float(self.fwd_bytes + self.bwd_bytes) / _eff_dur
        features["Flow Packets/s"] = float(self.fwd_pkt_count + self.bwd_pkt_count) / _eff_dur

        # ── IAT (Flow level) — convert to microseconds to match CIC-IDS2017 training data
        flow_iat_stats = self.flow_iat_stat
        features["Flow IAT Mean"] = float(flow_iat_stats.mean) * _MICROSECONDS if flow_iat_stats.count > 0 else 0.0
        features["Flow IAT Std"] = float(flow_iat_stats.std) * _MICROSECONDS if flow_iat_stats.count > 0 else 0.0
        features["Flow IAT Max"] = float(flow_iat_stats.max_val) * _MICROSECONDS if flow_iat_stats.count > 0 else 0.0
        features["Flow IAT Min"] = float(flow_iat_stats.min_val) * _MICROSECONDS if flow_iat_stats.count > 0 else 0.0

        # ── IAT (Fwd) — convert to microseconds
        fwd_iat_stats = self.fwd_iat_stat
        features["Fwd IAT Total"] = float(self.fwd_iat_total) * _MICROSECONDS
        features["Fwd IAT Mean"] = float(fwd_iat_stats.mean) * _MICROSECONDS if fwd_iat_stats.count > 0 else 0.0
        features["Fwd IAT Std"] = float(fwd_iat_stats.std) * _MICROSECONDS if fwd_iat_stats.count > 0 else 0.0
        features["Fwd IAT Max"] = float(fwd_iat_stats.max_val) * _MICROSECONDS if fwd_iat_stats.count > 0 else 0.0
        features["Fwd IAT Min"] = float(fwd_iat_stats.min_val) * _MICROSECONDS if fwd_iat_stats.count > 0 else 0.0

        # ── IAT (Bwd) — convert to microseconds
        bwd_iat_stats = self.bwd_iat_stat
        features["Bwd IAT Total"] = float(self.bwd_iat_total) * _MICROSECONDS
        features["Bwd IAT Mean"] = float(bwd_iat_stats.mean) * _MICROSECONDS if bwd_iat_stats.count > 0 else 0.0
        features["Bwd IAT Std"] = float(bwd_iat_stats.std) * _MICROSECONDS if bwd_iat_stats.count > 0 else 0.0
        features["Bwd IAT Max"] = float(bwd_iat_stats.max_val) * _MICROSECONDS if bwd_iat_stats.count > 0 else 0.0
        features["Bwd IAT Min"] = float(bwd_iat_stats.min_val) * _MICROSECONDS if bwd_iat_stats.count > 0 else 0.0

        # ── TCP Flags (Fwd/Bwd)
        features["Fwd PSH Flags"] = float(self.fwd_psh)
        features["Bwd PSH Flags"] = float(self.bwd_psh)
        features["Fwd URG Flags"] = float(self.fwd_urg)
        features["Bwd URG Flags"] = float(self.bwd_urg)

        # ── Header Lengths
        features["Fwd Header Length"] = float(self.fwd_header_len)
        features["Bwd Header Length"] = float(self.bwd_header_len)

        # ── Packet rates per direction (use same _eff_dur from flow rate section above)
        features["Fwd Packets/s"] = float(self.fwd_pkt_count) / _eff_dur
        features["Bwd Packets/s"] = float(self.bwd_pkt_count) / _eff_dur

        # ── Overall Packet Length Statistics
        all_pkt_stats = self.all_pkt_len_stat
        features["Min Packet Length"] = float(all_pkt_stats.min_val) if all_pkt_stats.count > 0 else 0.0
        features["Max Packet Length"] = float(all_pkt_stats.max_val) if all_pkt_stats.count > 0 else 0.0
        features["Packet Length Mean"] = float(all_pkt_stats.mean) if all_pkt_stats.count > 0 else 0.0
        features["Packet Length Std"] = float(all_pkt_stats.std) if all_pkt_stats.count > 0 else 0.0
        features["Packet Length Variance"] = float(all_pkt_stats.variance) if all_pkt_stats.count > 0 else 0.0

        # ── TCP Flag Counts (total fwd + bwd)
        features["FIN Flag Count"] = float(self.fwd_fin + self.bwd_fin)
        features["SYN Flag Count"] = float(self.fwd_syn + self.bwd_syn)
        features["RST Flag Count"] = float(self.fwd_rst + self.bwd_rst)
        features["PSH Flag Count"] = float(self.fwd_psh + self.bwd_psh)
        features["ACK Flag Count"] = float(self.fwd_ack + self.bwd_ack)
        features["URG Flag Count"] = float(self.fwd_urg + self.bwd_urg)
        features["ECE Flag Count"] = float(self.fwd_ece + self.bwd_ece)

        # ── Down/Up Ratio (bwd_bytes / fwd_bytes, or 0 if no fwd)
        if self.fwd_bytes > 0:
            features["Down/Up Ratio"] = float(self.bwd_bytes) / float(self.fwd_bytes)
        else:
            features["Down/Up Ratio"] = 0.0

        # ── Average Packet Sizes
        total_pkts = self.fwd_pkt_count + self.bwd_pkt_count
        total_bytes = self.fwd_bytes + self.bwd_bytes
        if total_pkts > 0:
            features["Average Packet Size"] = float(total_bytes) / float(total_pkts)
        else:
            features["Average Packet Size"] = 0.0

        if self.fwd_pkt_count > 0:
            features["Avg Fwd Segment Size"] = float(self.fwd_bytes) / float(self.fwd_pkt_count)
        else:
            features["Avg Fwd Segment Size"] = 0.0

        if self.bwd_pkt_count > 0:
            features["Avg Bwd Segment Size"] = float(self.bwd_bytes) / float(self.bwd_pkt_count)
        else:
            features["Avg Bwd Segment Size"] = 0.0

        # ── Fwd Header Length.1 (CICFlowMeter bug: same as Fwd Header Length)
        features["Fwd Header Length.1"] = features["Fwd Header Length"]

        # ── Subflow Features (= total flow features, no segmentation)
        features["Subflow Fwd Packets"] = float(self.fwd_pkt_count)
        features["Subflow Fwd Bytes"] = float(self.fwd_bytes)
        features["Subflow Bwd Packets"] = float(self.bwd_pkt_count)
        features["Subflow Bwd Bytes"] = float(self.bwd_bytes)

        # ── TCP Init Windows
        features["Init_Win_bytes_forward"] = float(self.init_win_fwd) if self.init_win_fwd >= 0 else 0.0
        features["Init_Win_bytes_backward"] = float(self.init_win_bwd) if self.init_win_bwd >= 0 else 0.0

        # ── Data packet count
        features["act_data_pkt_fwd"] = float(self.act_data_pkt_fwd)

        # ── Min segment size
        features["min_seg_size_forward"] = float(self.min_seg_size_fwd) if self.min_seg_size_fwd > 0 else 0.0

        # ── Port Encoding (17 features from dst_port)
        port_features = encode_port(self.dst_port)
        features.update(port_features)

        logger.debug(f"[GET_FEATURE_VECTOR] Generated {len(features)} features, selecting {len(FEATURE_COLUMNS)} core features")

        return {k: features.get(k, 0.0) for k in FEATURE_COLUMNS}

    def to_summary(self) -> dict:
        """Return a dashboard-friendly summary dict.

        Includes 5-tuple identity, convenience fields used by AlertEngine and database,
        plus the full 94-feature dict under 'features' for ML inference.
        """
        fv = self.get_feature_vector()
        src_ip, dst_ip, src_port, dst_port, proto_code = self.key
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        protocol = proto_map.get(proto_code, "OTHER")
        total_pkts = self.fwd_pkt_count + self.bwd_pkt_count
        total_bytes = self.fwd_bytes + self.bwd_bytes

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "flow_key": f"{src_ip}:{src_port} → {dst_ip}:{dst_port} [{protocol}]",
            "total_bytes": total_bytes,
            "syn_count": self.fwd_syn + self.bwd_syn,
            "ack_count": self.fwd_ack + self.bwd_ack,
            "rst_count": self.fwd_rst + self.bwd_rst,
            "flow_duration": self.last_seen - self.start_time,
            "packet_count": total_pkts,
            "avg_bytes_per_pkt": total_bytes / total_pkts if total_pkts > 0 else 0.0,
            "fin_count": self.fwd_fin + self.bwd_fin,
            "iat_mean": fv.get("Flow IAT Mean", 0.0) / 1_000_000,
            "iat_variance": self.flow_iat_stat.variance,
            "proto_tcp": 1 if protocol == "TCP" else 0,
            "proto_udp": 1 if protocol == "UDP" else 0,
            "proto_icmp": 1 if protocol == "ICMP" else 0,
            "proto_other": 1 if protocol not in ("TCP", "UDP", "ICMP") else 0,
            "features": fv,
            "ml_class": None,
            "ml_confidence": None,
        }


class BidirectionalFlowTable:
    """
    Thread-safe flow table with bidirectional flow lookup and timeout-based expiry.

    Maintains flows indexed by forward 5-tuple, handles reverse flow lookup.
    Uses OrderedDict for O(1) LRU eviction and threading.Lock for thread safety.
    """

    def __init__(self, timeout_sec: float = 120.0, max_flows: int = 100000):
        """
        Args:
            timeout_sec: inactive flows expire after this duration
            max_flows: maximum concurrent flows (LRU eviction)
        """
        self.timeout = timeout_sec
        self.max_flows = max_flows
        self.flows: OrderedDict[Tuple[str, str, int, int, int], BidirectionalFlowRecord] = OrderedDict()
        self._lock = Lock()
        self._expired: list = []  # Recently expired flows, kept for dashboard viewing

    def get_or_create_flow(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        pkt_time: float,
    ) -> Tuple[BidirectionalFlowRecord, str]:
        """
        Lookup or create a flow using bidirectional key logic.

        Returns:
            (flow_record, direction) where direction is "fwd" or "bwd"
        """
        with self._lock:
            proto_code = self._proto_to_code(protocol)
            forward_key = (src_ip, dst_ip, src_port, dst_port, proto_code)
            reverse_key = (dst_ip, src_ip, dst_port, src_port, proto_code)

            # Check forward key
            if forward_key in self.flows:
                self.flows.move_to_end(forward_key)  # Mark as recently used for LRU
                return self.flows[forward_key], "fwd"

            # Check reverse key
            if reverse_key in self.flows:
                self.flows.move_to_end(reverse_key)  # Mark as recently used
                return self.flows[reverse_key], "bwd"

            # Create new flow
            flow = BidirectionalFlowRecord(
                key=forward_key,
                dst_port=dst_port,
                start_time=pkt_time,
                last_seen=pkt_time,
            )
            self.flows[forward_key] = flow

            # LRU eviction if needed
            if len(self.flows) > self.max_flows:
                oldest_key, evicted_flow = self.flows.popitem(last=False)
                self._expired.append(evicted_flow)
                if len(self._expired) > 500:
                    self._expired = self._expired[-500:]

            return flow, "fwd"

    def update_flow(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        pkt_time: float,
        pkt_len: int,
        payload_len: int = 0,
        tcp_flags: int = 0,
        header_len: int = 0,
        tcp_window: int = -1,
    ):
        """
        Update a flow with packet information. Creates flow if needed.
        """
        flow, direction = self.get_or_create_flow(
            src_ip, dst_ip, src_port, dst_port, protocol, pkt_time
        )
        flow.update(pkt_time, pkt_len, payload_len, tcp_flags, header_len, direction, tcp_window)

    def expire_old_flows(self, current_time: float) -> list:
        """
        Remove and return flows inactive for > timeout seconds.

        Returns:
            list of (BidirectionalFlowRecord, timedelta_sec) tuples
        """
        with self._lock:
            expired = []
            keys_to_remove = []

            for key, flow in self.flows.items():
                age = current_time - flow.last_seen
                if age > self.timeout:
                    expired.append((flow, age))
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                flow = self.flows.pop(key)
                self._expired.append(flow)

            # Trim _expired cache to recent flows only
            if len(self._expired) > MAX_EXPIRED_FLOWS_CACHE:
                self._expired = self._expired[-MAX_EXPIRED_FLOWS_CACHE:]

            return expired

    def get_active_flows(self) -> list:
        """Return list of to_summary() dicts for all active flows."""
        with self._lock:
            return [flow.to_summary() for flow in self.flows.values()]

    def get_active_count(self) -> int:
        """Return number of currently active flows."""
        with self._lock:
            return len(self.flows)

    def get_expired_flows(self, limit: int = 50) -> list:
        """Return the most recently expired flows as summary dicts."""
        with self._lock:
            return [flow.to_summary() for flow in self._expired[-limit:]]

    def get_all_feature_vectors(self) -> list:
        """Return SHAP-selected feature dicts for all active flows (ML pipeline)."""
        with self._lock:
            return [flow.get_feature_vector() for flow in self.flows.values()]

    def _proto_to_code(self, protocol: str) -> int:
        """Convert protocol name to IANA code."""
        protos = {"tcp": 6, "udp": 17, "icmp": 1}
        return protos.get(protocol.lower(), 0)


__all__ = [
    "BidirectionalFlowRecord",
    "BidirectionalFlowTable",
]
