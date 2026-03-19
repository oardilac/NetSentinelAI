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

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR
from datetime import datetime
from collections import defaultdict, deque
from threading import Thread, Lock
import time

from flow_extractor import FlowTable
from database import SentinelDB


# ──────────────────────────────────────────────
# Alert Engine
# ──────────────────────────────────────────────

class AlertEngine:
    """Simple rule-based alerting on flow features."""

    def __init__(self, max_alerts: int = 200):
        self._alerts: deque = deque(maxlen=max_alerts)
        self._lock = Lock()
        self._seen: set = set()  # deduplicate alerts per flow_key

        # Thresholds
        self.scan_syn_threshold = 15
        self.exfil_byte_threshold = 50_000_000  # 50 MB
        self.rst_threshold = 50

    def evaluate_flow(self, flow_summary: dict) -> None:
        """Check a single flow summary against alert rules."""
        fk = flow_summary.get("flow_key", "")
        src = flow_summary.get("src_ip", "?")

        # Rule 1: Port scan — many SYN, few ACK
        syn = flow_summary.get("syn_count", 0)
        ack = flow_summary.get("ack_count", 0)
        alert_key = f"scan:{fk}"
        if syn > self.scan_syn_threshold and ack < syn * 0.3 and alert_key not in self._seen:
            self._add("port_scan", src,
                       f"High SYN/ACK ratio ({syn} SYN, {ack} ACK) — possible port scan")
            self._seen.add(alert_key)

        # Rule 2: Data exfiltration
        total_bytes = flow_summary.get("total_bytes", 0)
        alert_key = f"exfil:{fk}"
        if total_bytes > self.exfil_byte_threshold and alert_key not in self._seen:
            mb = round(total_bytes / (1024 * 1024), 1)
            self._add("data_exfiltration", src,
                       f"Flow transferred {mb} MB — possible data exfiltration")
            self._seen.add(alert_key)

        # Rule 3: RST flood
        rst = flow_summary.get("rst_count", 0)
        alert_key = f"rst:{fk}"
        if rst > self.rst_threshold and alert_key not in self._seen:
            self._add("rst_flood", src,
                       f"{rst} RST packets in flow — connection abuse or scan")
            self._seen.add(alert_key)

        # Trim seen set so it doesn't grow forever
        if len(self._seen) > 10_000:
            self._seen.clear()

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
        self.flow_table = FlowTable(max_flows=100_000, timeout=flow_timeout)
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

            # Periodic flow expiry (every 10 s)
            if now - self._last_expiry > 10.0:
                self._expire_and_alert(now)
                self._last_expiry = now

    def _process_ip(self, packet, pkt_len: int, now: float) -> None:
        ip = packet[IP]
        src_ip, dst_ip = ip.src, ip.dst
        self.src_ips[src_ip] += 1
        self.dst_ips[dst_ip] += 1
        self.top_talkers_bytes[src_ip] += pkt_len

        tcp_flags = None

        if packet.haslayer(TCP):
            layer = packet[TCP]
            proto = "TCP"
            src_port, dst_port = layer.sport, layer.dport
            tcp_flags = int(layer.flags)
            self._count_flags(tcp_flags, src_ip, dst_port)
            self.protocol_stats["TCP"] += 1
            self.protocol_bytes["TCP"] += pkt_len
            self.dst_ports[dst_port] += 1

        elif packet.haslayer(UDP):
            layer = packet[UDP]
            proto = "UDP"
            src_port, dst_port = layer.sport, layer.dport
            self.protocol_stats["UDP"] += 1
            self.protocol_bytes["UDP"] += pkt_len
            self.dst_ports[dst_port] += 1

            # DNS sub-protocol
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                if packet[DNS].qr == 0:
                    qname = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                    self.dns_queries[qname] += 1
                    self.protocol_stats["DNS"] += 1

        elif packet.haslayer(ICMP):
            proto = "ICMP"
            src_port, dst_port = 0, 0
            self.protocol_stats["ICMP"] += 1
            self.protocol_bytes["ICMP"] += pkt_len
        else:
            proto = "OTHER"
            src_port, dst_port = 0, 0
            self.protocol_stats["OTHER"] += 1
            self.protocol_bytes["OTHER"] += pkt_len

        # Register in flow table
        self.flow_table.update(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            pkt_len=pkt_len,
            timestamp=now,
            tcp_flags=tcp_flags,
        )

    def _process_ipv6(self, packet, pkt_len: int, now: float) -> None:
        ip6 = packet[IPv6]
        src_ip, dst_ip = ip6.src, ip6.dst
        self.src_ips[src_ip] += 1
        self.dst_ips[dst_ip] += 1
        self.top_talkers_bytes[src_ip] += pkt_len

        tcp_flags = None

        if packet.haslayer(TCP):
            layer = packet[TCP]
            proto = "TCP"
            src_port, dst_port = layer.sport, layer.dport
            tcp_flags = int(layer.flags)
            self._count_flags(tcp_flags, src_ip, dst_port)
            self.protocol_stats["TCP"] += 1
            self.protocol_bytes["TCP"] += pkt_len
            self.dst_ports[dst_port] += 1
        elif packet.haslayer(UDP):
            layer = packet[UDP]
            proto = "UDP"
            src_port, dst_port = layer.sport, layer.dport
            self.protocol_stats["UDP"] += 1
            self.protocol_bytes["UDP"] += pkt_len
            self.dst_ports[dst_port] += 1
        else:
            proto = "OTHER"
            src_port, dst_port = 0, 0
            self.protocol_stats["OTHER"] += 1
            self.protocol_bytes["OTHER"] += pkt_len

        self.flow_table.update(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            pkt_len=pkt_len,
            timestamp=now,
            tcp_flags=tcp_flags,
        )

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

    def _expire_and_alert(self, now: float) -> None:
        """Expire old flows, run alert rules, and persist to the database."""
        expired = self.flow_table.expire_old_flows(now)
        if expired:
            summaries = [rec.to_summary() for rec in expired]
            for s in summaries:
                self.alert_engine.evaluate_flow(s)
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
            # Save active flows
            active = self.flow_table.get_active_flows()
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
        self.metrics = SecurityMetricsCollector(db=self.db)
        self.running = False

    def start_sniffing(self):
        self.running = True
        print(f"[+] Starting capture on interface: {self.interface or 'All'}")
        try:
            sniff(
                iface=self.interface,
                prn=self.metrics.process_packet,
                store=False,
                stop_filter=lambda _: not self.running,
            )
        except Exception as e:
            print(f"[ERROR] Capture error: {e}")
            self.running = False

    def stop_sniffing(self):
        self.running = False

    def shutdown(self):
        """Stop sniffing and flush all data to the database."""
        self.running = False
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
