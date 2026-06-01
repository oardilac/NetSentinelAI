#!/usr/bin/env python3
"""
Network Security Monitor — Flow-Based Engine
=============================================
Captures live traffic via Scapy, groups packets into flows by 5-tuple
(src_ip, dst_ip, src_port, dst_port, protocol), and extracts incremental
features.  Expired and active flows are **persisted to a local SQLite
database** so that data survives program interruptions and restarts.

Detected threat patterns:
  - Port scanning  (many SYN without ACK)
  - Data exfiltration  (high total bytes in a single flow)
  - DDoS indicators  (burst of flows from single source)
  - Protocol anomalies  (unusual flag combinations)
"""

from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR
from datetime import datetime
from collections import defaultdict, deque
from typing import Tuple
from threading import Lock, Event
import time
import logging

from live_feature_extractor import BidirectionalFlowTable
from database import SentinelDB
import ml_engine

logger = logging.getLogger(__name__)

# Module-level constants
FLOW_EXPIRY_INTERVAL_SECS = 10.0
SYN_SCAN_THRESHOLD = 15
EXFIL_BYTE_THRESHOLD = 50_000_000  # 50 MB
RST_THRESHOLD = 50
DOS_PACKETS_PER_SEC_THRESHOLD = 1000  # Heuristic: > 1000 packets/sec suggests DoS
DOS_BYTES_PER_SEC_THRESHOLD = 100_000_000  # Heuristic: > 100 MB/s suggests DoS


# ──────────────────────────────────────────────
# Alert Engine
# ──────────────────────────────────────────────

class AlertEngine:
    """Simple rule-based alerting on flow features."""

    ALERT_TTL_SECS = 60  # Allow repeated alerts on same flow after 60 seconds

    def __init__(self, max_alerts: int = 200, max_seen: int = 10000):
        self._alerts: deque = deque(maxlen=max_alerts)
        self._lock = Lock()
        self._seen: dict = {}  # {alert_key: timestamp} — deduplicate alerts with TTL
        self._max_seen = max_seen

    def _add_seen(self, key: str) -> None:
        """Track a seen alert key with timestamp for TTL-based expiry.

        Uses lazy expiration (removes expired entries incrementally on each call)
        instead of rebuilding the entire dict, improving O(1) amortized performance.
        """
        now = time.time()
        # Lazy expiration: remove only expired entries (vs rebuilding the entire dict)
        expired = [k for k, ts in self._seen.items() if now - ts >= self.ALERT_TTL_SECS]
        for k in expired:
            del self._seen[k]

        # Enforce max size by removing oldest entry if needed
        if len(self._seen) >= self._max_seen:
            oldest_key = min(self._seen.items(), key=lambda x: x[1])[0]
            del self._seen[oldest_key]

        self._seen[key] = now

    def evaluate_flow(self, flow_summary: dict, ml_result: dict = None) -> None:
        """Check a single flow summary against alert rules.

        Combines heuristic rules with ML predictions for better detection accuracy.
        """
        fk = flow_summary.get("flow_key", "")
        src = flow_summary.get("src_ip", "?")
        ml_class = ml_result.get("class") if ml_result else None
        ml_confidence = ml_result.get("confidence", 0) if ml_result else 0

        # Rule 1: Port scan — combine heuristics + ML
        syn = flow_summary.get("syn_count", 0)
        ack = flow_summary.get("ack_count", 0)
        is_port_scan_heuristic = syn > SYN_SCAN_THRESHOLD and ack < syn * 0.3
        is_port_scan_ml = bool(ml_result) and (
            "scan" in (ml_class or "").lower() or "portscan" in (ml_class or "").lower()
        ) and ml_confidence > 0.7

        alert_key = f"scan:{fk}"
        if (is_port_scan_heuristic or is_port_scan_ml) and alert_key not in self._seen:
            reason = []
            if is_port_scan_heuristic:
                reason.append(f"High SYN/ACK ratio ({syn} SYN, {ack} ACK)")
            if is_port_scan_ml:
                reason.append(f"ML detected port scan ({ml_confidence:.0%} confidence)")
            description = " + ".join(reason) if reason else "Possible port scan"
            self._add("port_scan", src, description)
            self._add_seen(alert_key)

        # Rule 2: Brute force attack — combine heuristics + ML
        rst = flow_summary.get("rst_count", 0)
        is_brute_force_heuristic = rst > RST_THRESHOLD
        is_brute_force_ml = bool(ml_result) and (
            "patator" in (ml_class or "").lower() or "brute" in (ml_class or "").lower()
        ) and ml_confidence > 0.7

        alert_key = f"brute:{fk}"
        if (is_brute_force_heuristic or is_brute_force_ml) and alert_key not in self._seen:
            reason = []
            if is_brute_force_heuristic:
                reason.append(f"{rst} RST packets (connection abuse)")
            if is_brute_force_ml:
                reason.append(f"ML detected brute force ({ml_confidence:.0%} confidence)")
            description = " + ".join(reason) if reason else "Possible brute force attack"
            self._add("brute_force", src, description)
            self._add_seen(alert_key)

        # Rule 3: DoS/DDoS attack — combine heuristics + ML
        total_bytes = flow_summary.get("total_bytes", 0)
        total_packets = flow_summary.get("packet_count", 0)
        flow_duration_sec = flow_summary.get("flow_duration", 1)

        # Heuristic: high packet or byte rate
        pps = (total_packets / flow_duration_sec) if flow_duration_sec > 0 else 0
        bps = (total_bytes / flow_duration_sec) if flow_duration_sec > 0 else 0
        is_dos_heuristic = pps > DOS_PACKETS_PER_SEC_THRESHOLD or bps > DOS_BYTES_PER_SEC_THRESHOLD

        # ML-based detection
        is_dos_ml = bool(ml_result) and (
            "dos" in (ml_class or "").lower() or "ddos" in (ml_class or "").lower()
        ) and ml_confidence > 0.7

        alert_key = f"dos:{fk}"
        if (is_dos_heuristic or is_dos_ml) and alert_key not in self._seen:
            reason = []
            if is_dos_heuristic:
                if pps > DOS_PACKETS_PER_SEC_THRESHOLD:
                    reason.append(f"{pps:.0f} packets/sec")
                if bps > DOS_BYTES_PER_SEC_THRESHOLD:
                    reason.append(f"{bps/1_000_000:.0f} MB/s")
            if is_dos_ml:
                reason.append(f"ML detected DoS/DDoS ({ml_confidence:.0%} confidence)")
            description = " + ".join(reason) if reason else "Possible DoS/DDoS attack"
            self._add("dos_ddos", src, description)
            self._add_seen(alert_key)

        # Rule 4: Data exfiltration (heuristic-based)
        alert_key = f"exfil:{fk}"
        if total_bytes > EXFIL_BYTE_THRESHOLD and alert_key not in self._seen:
            mb = round(total_bytes / (1024 * 1024), 1)
            self._add("data_exfiltration", src,
                       f"Flow transferred {mb} MB — possible data exfiltration")
            self._add_seen(alert_key)

    def add_ml_alert(self, flow_summary: dict, ml_result: dict) -> None:
        """Fire an alert for ML-detected threat."""
        flow_key = flow_summary.get("flow_key", "")
        src_ip = flow_summary.get("src_ip", "?")
        ml_class = ml_result.get("class", "Unknown")
        confidence = ml_result.get("confidence", 0)

        alert_key = f"ml:{flow_key}"
        if alert_key not in self._seen:
            # Sanitize class name for alert type
            safe_class = ml_class.lower().replace(" ", "_").replace("/", "_")
            alert_type = f"ml_{safe_class}"
            description = f"ML detected {ml_class} (confidence: {confidence:.1%})"
            self._add(alert_type, src_ip, description)
            self._add_seen(alert_key)

    def _add(self, alert_type: str, source: str, description: str) -> None:
        with self._lock:
            self._alerts.append({
                "timestamp": datetime.now().isoformat(),
                "type": alert_type,
                "source": source,
                "description": description,
            })

    def get_alerts(self, limit: int = 30) -> list:
        with self._lock:
            return list(self._alerts)[-limit:]


# ──────────────────────────────────────────────
# Security Metrics Collector (flow-based)
# ──────────────────────────────────────────────

class SecurityMetricsCollector:
    """Aggregates per-packet counters and delegates flow tracking to FlowTable.

    Accepts a SentinelDB instance to persist expired flows and alerts
    automatically.  On shutdown, call ``flush_to_db()`` to save any
    remaining active flows before the program exits.
    """

    def __init__(self, db: SentinelDB, flow_timeout: float = 120.0):
        self.lock = Lock()
        self.start_time = datetime.now()

        # Database persistence
        self.db = db
        self.session_id: int = db.create_session()
        self._flows_saved: int = 0  # running counter of flows persisted

        # Flow engine
        self.flow_table = BidirectionalFlowTable(max_flows=100_000, timeout_sec=flow_timeout)
        self.alert_engine = AlertEngine()

        # Global counters
        self.total_packets: int = 0
        self.total_bytes: int = 0

        # Protocol counters
        self.protocol_stats: dict = defaultdict(int)
        self.protocol_bytes: dict = defaultdict(int)

        # IP tracking
        self.src_ips: dict = defaultdict(int)
        self.dst_ips: dict = defaultdict(int)
        self.top_talkers_bytes: dict = defaultdict(int)

        # Port tracking
        self.dst_ports: dict = defaultdict(int)

        # DNS queries
        self.dns_queries: dict = defaultdict(int)

        # TCP flag totals
        self.tcp_flags: dict = defaultdict(int)

        # Traffic timeline (packets per second)
        self.traffic_timeline: deque = deque(maxlen=1000)
        self._cur_second: int = int(time.time())
        self._sec_pkts: int = 0
        self._sec_bytes: int = 0

        # Port scan detector (IP -> set of dst ports)
        self.port_scan_detector: dict = defaultdict(set)

        # ML classification counters (session-wide, survives flush)
        self.ml_class_counts: dict = defaultdict(int)

        # Periodic expiry counter
        self._last_expiry: float = time.time()

    # ── packet handler ──

    def process_packet(self, packet) -> None:
        """Called by Scapy for every captured packet."""
        with self.lock:
            now = time.time()
            cur_sec = int(now)

            # Timeline tick
            if cur_sec != self._cur_second:
                self.traffic_timeline.append({
                    "timestamp": self._cur_second,
                    "packets": self._sec_pkts,
                    "bytes": self._sec_bytes,
                })
                self._cur_second = cur_sec
                self._sec_pkts = 0
                self._sec_bytes = 0

            pkt_len = len(packet)
            self.total_packets += 1
            self.total_bytes += pkt_len
            self._sec_pkts += 1
            self._sec_bytes += pkt_len

            # ── IP layer ──
            if packet.haslayer(IP):
                self._process_ip(packet, pkt_len, now)
            elif packet.haslayer(IPv6):
                self._process_ipv6(packet, pkt_len, now)

            # ARP (no flow, just counter)
            if packet.haslayer(ARP):
                self.protocol_stats["ARP"] += 1
                self.protocol_bytes["ARP"] += pkt_len

            # Periodic flow expiry
            if now - self._last_expiry > FLOW_EXPIRY_INTERVAL_SECS:
                self._expire_and_alert(now)
                self._last_expiry = now

    def _parse_tcp(self, packet, ip_header_len: int, src_ip: str, dst_port: int, pkt_len: int) -> Tuple[str, int, int, int, int]:
        """Parse TCP layer and return (proto, src_port, dst_port, header_len, tcp_window)."""
        layer = packet[TCP]
        tcp_flags = int(layer.flags)
        self._count_flags(tcp_flags, src_ip, dst_port)
        self.protocol_stats["TCP"] += 1
        self.protocol_bytes["TCP"] += pkt_len
        self.dst_ports[layer.dport] += 1
        header_len = ip_header_len + layer.dataofs * 4
        return "TCP", layer.sport, layer.dport, header_len, int(layer.window)

    def _parse_udp(self, packet, ip_header_len: int, pkt_len: int) -> Tuple[str, int, int, int, int]:
        """Parse UDP layer (and DNS if present) and return (proto, src_port, dst_port, header_len, tcp_window)."""
        layer = packet[UDP]
        self.protocol_stats["UDP"] += 1
        self.protocol_bytes["UDP"] += pkt_len
        self.dst_ports[layer.dport] += 1
        if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet[DNS].qr == 0:
            qname = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            self.dns_queries[qname] += 1
            self.protocol_stats["DNS"] += 1
        header_len = ip_header_len + 8
        return "UDP", layer.sport, layer.dport, header_len, -1

    def _parse_icmp(self, ip_header_len: int, pkt_len: int) -> Tuple[str, int, int, int, int]:
        """Parse ICMP layer and return (proto, src_port, dst_port, header_len, tcp_window)."""
        self.protocol_stats["ICMP"] += 1
        self.protocol_bytes["ICMP"] += pkt_len
        return "ICMP", 0, 0, ip_header_len, -1

    def _process_packet_layer(self, src_ip: str, dst_ip: str, packet, pkt_len: int, now: float, ip_header_len: int) -> None:
        """Common logic for processing IPv4 and IPv6 packets."""
        self.src_ips[src_ip] += 1
        self.dst_ips[dst_ip] += 1
        self.top_talkers_bytes[src_ip] += pkt_len

        if packet.haslayer(TCP):
            proto, src_port, dst_port, header_len, tcp_window = self._parse_tcp(packet, ip_header_len, src_ip, packet[TCP].dport, pkt_len)
            tcp_flags = int(packet[TCP].flags)
        elif packet.haslayer(UDP):
            proto, src_port, dst_port, header_len, tcp_window = self._parse_udp(packet, ip_header_len, pkt_len)
            tcp_flags = 0
        elif packet.haslayer(ICMP):
            proto, src_port, dst_port, header_len, tcp_window = self._parse_icmp(ip_header_len, pkt_len)
            tcp_flags = 0
        else:
            proto, src_port, dst_port, header_len, tcp_window = "OTHER", 0, 0, ip_header_len, -1
            tcp_flags = 0
            self.protocol_stats["OTHER"] += 1
            self.protocol_bytes["OTHER"] += pkt_len

        # Calculate payload length
        payload_len = len(packet.payload.payload) if packet.haslayer(TCP) or packet.haslayer(UDP) else 0

        # Register in flow table
        self.flow_table.update_flow(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            pkt_time=now,
            pkt_len=pkt_len,
            payload_len=payload_len,
            tcp_flags=tcp_flags,
            header_len=header_len,
            tcp_window=tcp_window,
        )

    def _process_ip(self, packet, pkt_len: int, now: float) -> None:
        ip = packet[IP]
        ip_header_len = ip.ihl * 4
        self._process_packet_layer(ip.src, ip.dst, packet, pkt_len, now, ip_header_len)

    def _process_ipv6(self, packet, pkt_len: int, now: float) -> None:
        ip6 = packet[IPv6]
        ip_header_len = 40  # IPv6 header is always 40 bytes
        self._process_packet_layer(ip6.src, ip6.dst, packet, pkt_len, now, ip_header_len)

    def _count_flags(self, flags: int, src_ip: str, dst_port: int) -> None:
        if flags & 0x02:
            self.tcp_flags["SYN"] += 1
            self.port_scan_detector[src_ip].add(dst_port)
        if flags & 0x10:
            self.tcp_flags["ACK"] += 1
        if flags & 0x01:
            self.tcp_flags["FIN"] += 1
        if flags & 0x04:
            self.tcp_flags["RST"] += 1
        if flags & 0x08:
            self.tcp_flags["PSH"] += 1
        if flags & 0x20:
            self.tcp_flags["URG"] += 1

    def _run_ml_on_flow(self, flow: dict) -> None:
        """Run ML inference on a flow summary dict, updating ml_class and ml_confidence in-place."""
        try:
            features = flow.get("features", {})
            if features:
                total_pkts = features.get("Total Fwd Packets", 0) + features.get("Total Backward Packets", 0)
                if total_pkts < 1:
                    flow["ml_class"] = None
                    flow["ml_confidence"] = None
                    flow["ml_failure"] = False
                else:
                    ml_result = ml_engine.predict_flow(features)
                    flow["ml_class"] = ml_result.get("class")
                    flow["ml_confidence"] = ml_result.get("confidence", 0.0)
                    flow["ml_failure"] = ml_result.get("is_ml_failure", False)
                    if flow["ml_class"]:
                        self.ml_class_counts[flow["ml_class"]] += 1
                    logger.debug(f"ML: {flow.get('src_ip')}:{flow.get('src_port')} → {flow.get('dst_ip')}:{flow.get('dst_port')} | class={ml_result.get('class')} | conf={flow['ml_confidence']:.3f}")
            else:
                flow["ml_class"] = None
                flow["ml_confidence"] = None
                flow["ml_failure"] = False
        except Exception as e:
            logger.error(f"ML prediction failed: {e}", exc_info=True)
            flow["ml_class"] = None
            flow["ml_confidence"] = None
            flow["ml_failure"] = True

    def _expire_and_alert(self, now: float) -> None:
        """Expire old flows, run alert rules (rule-based + ML), and persist to the database."""
        expired_pairs = self.flow_table.expire_old_flows(now)
        if not expired_pairs:
            return

        summaries = [rec.to_summary() for rec, _age in expired_pairs]

        # Run ML inference outside the lock to avoid blocking packet capture
        for s in summaries:
            self._run_ml_on_flow(s)

        # Run alert rules under the lock to safely access alert_engine
        with self.lock:
            for s in summaries:
                ml_result = {"class": s.get("ml_class"), "confidence": s.get("ml_confidence")} if s.get("ml_class") else None

                # Fire alert if ML engine failed
                if s.get("ml_failure"):
                    self.alert_engine._add("ml_engine_failure", s.get("src_ip", "?"),
                                          "ML engine returned error — detection capability degraded")

                # Rule-based + ML-aware alerts
                self.alert_engine.evaluate_flow(s, ml_result=ml_result)

                # Fire ML alert if non-Normal class detected
                if ml_result and ml_result.get("class") != "Normal":
                    self.alert_engine.add_ml_alert(s, ml_result)

            # Persist expired flows to SQLite
            saved = self.db.save_flows(summaries, session_id=self.session_id)
            self._flows_saved += saved

    # ── metrics API ──

    def get_metrics(self) -> dict:
        """Return all metrics as a JSON-serialisable dict."""
        with self.lock:
            uptime = (datetime.now() - self.start_time).total_seconds()
            pps = self.total_packets / max(uptime, 1)
            bps = self.total_bytes / max(uptime, 1)

            active_flows = self.flow_table.get_active_flows()

            # Run ML on active flows to ensure ml_class is set for real-time display
            for flow in active_flows:
                # Skip if already classified or insufficient packets
                if flow.get("ml_class") is None:
                    features = flow.get("features", {})
                    if features:
                        total_pkts = features.get("Total Fwd Packets", 0) + features.get("Total Backward Packets", 0)
                        if total_pkts >= 2:
                            try:
                                self._run_ml_on_flow(flow)
                                # Also write back to the live BidirectionalFlowRecord
                                flow_key = flow.get("_flow_key")
                                if flow_key and hasattr(self, "flow_table"):
                                    live_flow = self.flow_table.flows.get(flow_key)
                                    if live_flow:
                                        live_flow.ml_class = flow.get("ml_class")
                                        live_flow.ml_confidence = flow.get("ml_confidence")
                                        logger.debug(f"Updated flow {flow_key} with ml_class={flow.get('ml_class')}")
                            except Exception as e:
                                logger.error(f"ML classification failed in get_metrics: {e}", exc_info=True)


            return {
                "overview": {
                    "total_packets": self.total_packets,
                    "total_bytes": self.total_bytes,
                    "total_mb": round(self.total_bytes / (1024 * 1024), 2),
                    "uptime_seconds": round(uptime, 1),
                    "packets_per_second": round(pps, 2),
                    "bytes_per_second": round(bps, 2),
                    "mbps": round((bps * 8) / (1024 * 1024), 3),
                    "active_flows": self.flow_table.get_active_count(),
                    "flows_saved_to_db": self._flows_saved,
                    "session_id": self.session_id,
                },
                "protocols": {
                    "stats": dict(self.protocol_stats),
                    "bytes": dict(self.protocol_bytes),
                },
                "tcp_flags": dict(self.tcp_flags),
                "top_sources": self._top_n(self.src_ips, 10),
                "top_destinations": self._top_n(self.dst_ips, 10),
                "top_talkers": self._top_n(self.top_talkers_bytes, 10),
                "top_dst_ports": self._top_n(self.dst_ports, 10),
                "top_dns_queries": self._top_n(self.dns_queries, 10),
                "potential_port_scans": self._scan_suspects(),
                "traffic_timeline": list(self.traffic_timeline)[-60:],
                "alerts": self.alert_engine.get_alerts(30),
                "active_flows": sorted(
                    active_flows,
                    key=lambda f: f.get("total_bytes", 0),
                    reverse=True,
                )[:50],
                "expired_flows": self.flow_table.get_expired_flows(30),
                "timestamp": datetime.now().isoformat(),
            }

    def get_flow_features(self) -> list:
        """Return raw feature vectors for every active flow (ML pipeline)."""
        return self.flow_table.get_all_feature_vectors()

    def flush_to_db(self) -> None:
        """Save ALL remaining active flows and alerts to the database.

        Call this before shutdown to ensure nothing is lost.
        """
        with self.lock:
            # Save active flows (with ML predictions)
            active = self.flow_table.get_active_flows()

            # Add ML predictions to active flows
            for flow in active:
                self._run_ml_on_flow(flow)

            saved = self.db.save_flows(active, session_id=self.session_id)
            self._flows_saved += saved

            # Save alerts
            alerts = self.alert_engine.get_alerts(200)
            self.db.save_alerts(alerts, session_id=self.session_id)

            # Close the session with final counters
            self.db.close_session(
                session_id=self.session_id,
                total_packets=self.total_packets,
                total_bytes=self.total_bytes,
                flow_count=self._flows_saved,
            )
            print(f"[DB] Flushed {saved} active flows + {len(alerts)} alerts to database")

    @staticmethod
    def _top_n(d: dict, n: int = 10) -> list:
        items = sorted(d.items(), key=lambda x: x[1], reverse=True)
        return [{"name": k, "value": v} for k, v in items[:n]]

    def _scan_suspects(self) -> list:
        suspects = []
        for ip, ports in self.port_scan_detector.items():
            if len(ports) >= 10:
                suspects.append({
                    "ip": ip,
                    "ports_scanned": len(ports),
                    "ports": sorted(list(ports))[:20],
                })
        return sorted(suspects, key=lambda x: x["ports_scanned"], reverse=True)[:10]


# ──────────────────────────────────────────────
# Network Sniffer wrapper
# ──────────────────────────────────────────────

class NetworkSniffer:
    """Wraps Scapy sniff with a SecurityMetricsCollector and SQLite persistence."""

    def __init__(self, interface=None, db: SentinelDB = None):
        self.interface = interface
        self.db = db or SentinelDB()
        self.metrics = SecurityMetricsCollector(db=self.db, flow_timeout=600.0)
        self.running = False
        self._async_sniffer = None
        self._shutdown_complete = Event()

    def start_sniffing(self):
        self.running = True
        iface = self.interface
        if iface is None:
            try:
                from scapy.arch import get_if_list
                import platform
                all_ifaces = get_if_list()

                # Platform-specific interface filtering
                if platform.system() == "Windows":
                    # Windows: use first non-loopback interface, or default
                    iface = next((i for i in all_ifaces if i and 'loopback' not in i.lower()), None)
                else:
                    # macOS/Linux: lo0 (loopback) and en* (ethernet)
                    iface = [i for i in all_ifaces if i.startswith(('lo', 'en'))]
            except Exception as e:
                logger.debug(f"Interface detection failed: {e}")
                iface = None
        print(f"[+] Starting capture on interface: {iface or 'default'}")
        try:
            self._async_sniffer = AsyncSniffer(
                iface=iface,
                prn=self.metrics.process_packet,
                store=False,
            )
            self._async_sniffer.start()
            self._async_sniffer.join()
        except Exception as e:
            print(f"[ERROR] Capture error: {e}")
            logger.error(f"Capture error details: {e}")
            self.running = False
        finally:
            self._shutdown_complete.set()

    def shutdown(self):
        """Stop sniffing and flush all data to the database."""
        self.running = False
        if self._async_sniffer and self._async_sniffer.running:
            self._async_sniffer.stop()
        # Wait for start_sniffing thread to fully terminate (max 5 seconds)
        self._shutdown_complete.wait(timeout=5.0)
        print("[*] Flushing data to database before shutdown...")
        try:
            self.metrics.flush_to_db()
        except Exception as e:
            print(f"[ERROR] Flush failed: {e}")


# Global singleton
_sniffer = None
_db = None


def get_db() -> SentinelDB:
    """Return the global database instance."""
    global _db
    if _db is None:
        _db = SentinelDB()
    return _db


def get_sniffer() -> NetworkSniffer:
    """Return the global sniffer instance."""
    global _sniffer
    if _sniffer is None:
        _sniffer = NetworkSniffer(db=get_db())
    return _sniffer
