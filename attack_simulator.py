#!/usr/bin/env python3
"""
NetSentinelAI Attack Simulator — ML-aware Edition (Fixed)

Simulates 4 attack types based on CIC-IDS2017 training patterns:
1. Port Scan — nmap on public IP + socket scan (Scapy captures physical interface)
2. DoS/DDoS Hulk — high-volume HTTP keep-alive flood
3. Brute Force SSH/FTP Patator — 200+ rapid auth attempts to mock server
4. Botnet Beaconing — periodic small payloads to mock receiver

Each attack now generates correct feature vectors for proper detection.
"""

import argparse
import socket
import subprocess
import sys
import time
import threading
import urllib.request
import urllib.error
import json
import os
import platform
from typing import Dict, List, Optional
from collections import defaultdict

try:
    import requests
except ImportError:
    print("Error: requests library not found. Install with: pip install requests")
    sys.exit(1)


# ─────────────────────────────────────────
# Mock Servers (for Brute Force & Botnet)
# ─────────────────────────────────────────

class MockAuthServer:
    """Minimal TCP server that simulates SSH/FTP auth rejection.

    Generates multi-packet flows that trigger Brute Force detection.
    """
    def __init__(self, port: int = 2222):
        self.port = port
        self._sock = None
        self._thread = None
        self._running = False

    def start(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(('127.0.0.1', self.port))
            self._sock.listen(200)
            self._sock.settimeout(1.0)
            self._running = True
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()
        except Exception as e:
            print(f"      ✗ MockAuthServer failed to start: {e}")

    def _serve(self):
        while self._running:
            try:
                conn, _ = self._sock.accept()
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle(self, conn):
        try:
            conn.send(b"SSH-2.0-OpenSSH_8.9\r\n")  # SSH banner
            data = conn.recv(64)
            if data:
                conn.send(b"auth failed\r\n")  # rejection
                conn.recv(64)  # recv payload attempt
            conn.close()
        except Exception:
            try:
                conn.close()
            except:
                pass

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except:
            pass


class MockBeaconReceiver:
    """Accepts TCP connections and holds them open to receive beacons.

    Generates sustained flows with regular IAT that trigger Botnet detection.
    """
    def __init__(self, port: int = 9999):
        self.port = port
        self._thread = None
        self._sock = None
        self._running = False

    def start(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(('127.0.0.1', self.port))
            self._sock.listen(1)
            self._sock.settimeout(2.0)
            self._running = True
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()
        except Exception as e:
            print(f"      ✗ MockBeaconReceiver failed to start: {e}")

    def _serve(self):
        while self._running:
            try:
                conn, _ = self._sock.accept()
                conn.settimeout(None)
                while self._running:
                    try:
                        data = conn.recv(128)
                        if not data:
                            break
                    except:
                        break
                conn.close()
                break  # Accept only one connection
            except socket.timeout:
                continue
            except Exception:
                break

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except:
            pass


# ─────────────────────────────────────────
# Attack Simulator
# ─────────────────────────────────────────

class AttackSimulator:
    def __init__(self, target: str, dashboard_url: str, no_flush: bool = False, attacks: str = "all"):
        self.target = target
        self.dashboard_url = dashboard_url
        self.no_flush = no_flush
        self.ml_stats: Dict[str, int] = {}
        self.nmap_path = self._find_nmap()
        self.attacks = set(attacks.lower().split(",")) if attacks != "all" else {"portscan", "dos", "bruteforce", "botnet"}
        self._botnet_receiver = None

    def _find_nmap(self) -> Optional[str]:
        """Find nmap executable path."""
        if platform.system() == "Windows":
            possible_paths = [
                r"C:\Program Files\Nmap\nmap.exe",
                r"C:\Program Files (x86)\Nmap\nmap.exe",
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    return path
        try:
            result = subprocess.run(
                ["nmap", "--version"] if platform.system() != "Windows" else ["where", "nmap"],
                capture_output=True, timeout=2
            )
            if result.returncode == 0:
                return "nmap"
        except Exception:
            pass
        return None

    def get_public_ip(self) -> Optional[str]:
        """Get public IP via api.ipify.org."""
        try:
            with urllib.request.urlopen("https://api.ipify.org", timeout=4) as resp:
                return resp.read().decode().strip()
        except Exception:
            return None

    def check_requirements(self) -> bool:
        """Verify dashboard is running."""
        if "portscan" in self.attacks and not self.nmap_path:
            print(f"⚠️  nmap not found — port scan will use socket-only fallback")

        try:
            resp = requests.get(f"{self.dashboard_url}/api/status", timeout=2)
            if not resp.json().get("running"):
                print(f"❌ Network monitor not running. Start it with /api/start first")
                return False
        except Exception as e:
            print(f"❌ Dashboard not accessible at {self.dashboard_url}: {e}")
            return False

        return True

    # ─────────────────────────────────────────
    # Attack 1: Port Scan (FIXED)
    # ─────────────────────────────────────────

    def simulate_port_scan(self, target: str) -> int:
        """Port Scan on BOTH localhost and public IP.

        Public IP traffic goes through the physical interface that Scapy captures.
        Localhost is bonus for additional flow volume.
        """
        print("\n[1/4] 🔍 Port Scan (nmap -sT + socket scan)")
        flows_generated = 0

        # Get public IP for scanning
        public_ip = self.get_public_ip()

        # Method A: nmap on public IP (real interface, Scapy captures it)
        if self.nmap_path and public_ip:
            print(f"      [A] nmap -sT -p 1-1999 on public IP {public_ip}...")
            try:
                cmd = [
                    self.nmap_path,
                    "-sT", "-p", "1-1999",
                    "-T5",
                    "--max-retries", "1",
                    "-oN", "NUL" if platform.system() == "Windows" else "/dev/null",
                    public_ip
                ]
                subprocess.run(cmd, capture_output=True, timeout=120)
                flows_generated += 1999
                print("           ✓ ~1999 flows generated")
            except Exception as e:
                print(f"           ✗ {e}")

        # Method B: nmap on localhost (bonus, may not be captured due to loopback)
        if self.nmap_path:
            print(f"      [B] nmap -sT -p 2000-2999 on localhost...")
            try:
                cmd = [
                    self.nmap_path,
                    "-sT", "-p", "2000-2999",
                    "-T5",
                    "--max-retries", "1",
                    "-oN", "NUL" if platform.system() == "Windows" else "/dev/null",
                    "127.0.0.1"
                ]
                subprocess.run(cmd, capture_output=True, timeout=60)
                flows_generated += 1000
                print("           ✓ ~1000 flows generated")
            except Exception as e:
                print(f"           ✗ {e}")

        # Method C: Socket-based scan on both targets
        print("      [C] Socket scan (connect_ex timeout)...")
        def socket_scan_worker(targets_list: list, port_start: int, count_list: list):
            for target_ip in targets_list:
                for port in range(port_start, port_start + 500):
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.05)
                        s.connect_ex((target_ip, port))
                        s.close()
                    except Exception:
                        pass
            count_list.append(len(targets_list) * 500)

        targets = list(set([target, public_ip])) if public_ip else [target]
        counts = []
        threads = [
            threading.Thread(target=socket_scan_worker, args=(targets, 3000 + i*100, counts))
            for i in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
        flows_generated += sum(counts)
        print(f"           ✓ ~{sum(counts)} flows generated")

        print(f"      Total port scan flows: ~{flows_generated}")
        return flows_generated

    # ─────────────────────────────────────────
    # Attack 2: DoS/DDoS Hulk
    # ─────────────────────────────────────────

    def simulate_dos_hulk(self, target_url: str) -> int:
        """DoS/DDoS HTTP flood with keep-alive."""
        print("\n[2/4] 💥 DoS/DDoS Hulk (HTTP keep-alive flood)")
        print(f"      Target: {target_url}")

        flows_generated = 0
        lock = threading.Lock()

        def dos_worker(session_id: int, requests_count: int = 50):
            nonlocal flows_generated
            try:
                session = requests.Session()
                session.headers.update({"Connection": "keep-alive"})
                for i in range(requests_count):
                    try:
                        resp = session.get(target_url, timeout=2)
                    except Exception:
                        pass
                with lock:
                    flows_generated += 1  # 1 flow per session
                session.close()
            except Exception:
                pass

        print("      Launching 15 sessions × 50 requests each...")
        threads = [
            threading.Thread(target=dos_worker, args=(i, 50))
            for i in range(15)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        print(f"      ✓ ~{flows_generated} keep-alive flows generated")
        return flows_generated

    # ─────────────────────────────────────────
    # Attack 3: Brute Force SSH/FTP (FIXED)
    # ─────────────────────────────────────────

    def simulate_brute_force(self, target: str) -> int:
        """Brute Force SSH/FTP Patator using MockAuthServer."""
        print("\n[3/4] 🔐 Brute Force SSH/FTP Patator (mock server)")

        # Start mock auth server
        auth_server = MockAuthServer(port=2222)
        auth_server.start()
        time.sleep(0.5)  # Let server fully start

        # Run brute force against the mock server
        flows_ssh = self._brute_force_ssh("127.0.0.1", port=2222, count=150)
        flows_ftp = self._brute_force_ftp("127.0.0.1", port=2222, count=150)

        auth_server.stop()
        total = flows_ssh + flows_ftp
        print(f"      Total brute force flows: {total}")
        return total

    def _brute_force_ssh(self, target: str, port: int = 2222, count: int = 150) -> int:
        """SSH Patator simulation against mock server."""
        print(f"      SSH Patator ({count} attempts to :{port})...")
        success = 0
        for i in range(count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((target, port))
                s.send(b"SSH-2.0-OpenSSH_7.4\r\n")
                s.recv(64)
                s.send(b"admin\r\n")
                s.recv(64)
                s.send(b"password123\r\n")
                s.recv(64)
                s.close()
                success += 1
            except Exception:
                pass
            time.sleep(0.03)  # ~33 attempts/sec
            if (i + 1) % 30 == 0:
                print(f"        {i+1}/{count}...", end="\r")
        print(f"        ✓ SSH: {success}/{count} flows")
        return count

    def _brute_force_ftp(self, target: str, port: int = 2222, count: int = 150) -> int:
        """FTP Patator simulation against mock server."""
        print(f"      FTP Patator ({count} attempts to :{port})...")
        success = 0
        for i in range(count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((target, port))
                s.recv(64)  # auth banner
                s.send(b"USER admin\r\n")
                s.recv(64)
                s.send(b"PASS password123\r\n")
                s.recv(64)
                s.close()
                success += 1
            except Exception:
                pass
            time.sleep(0.03)
            if (i + 1) % 30 == 0:
                print(f"        {i+1}/{count}...", end="\r")
        print(f"        ✓ FTP: {success}/{count} flows")
        return count

    # ─────────────────────────────────────────
    # Attack 4: Botnet Beaconing (FIXED)
    # ─────────────────────────────────────────

    def simulate_botnet(self, target: str, duration: int = 60) -> int:
        """Botnet beaconing using MockBeaconReceiver."""
        print("\n[4/4] 🤖 Botnet Beaconing (background thread)")
        print(f"      {duration}s periodic beacon to mock receiver")

        # Start beacon receiver
        self._botnet_receiver = MockBeaconReceiver(port=9999)
        self._botnet_receiver.start()
        time.sleep(0.5)

        def beacon_worker():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect(("127.0.0.1", 9999))  # Now succeeds
                beacon_payload = b"BEACON" * 10  # 60 bytes

                for i in range(duration):
                    try:
                        s.send(beacon_payload)
                    except Exception:
                        break
                    time.sleep(1.0)  # exactly 1s interval → iat_mean≈1.0

                s.close()
            except Exception:
                pass

        thread = threading.Thread(target=beacon_worker, daemon=True)
        thread.start()
        return 1

    # ─────────────────────────────────────────
    # Flush and results
    # ─────────────────────────────────────────

    def flush_and_wait(self) -> Dict[str, int]:
        """Force flow expiry and wait for ML classification."""
        print("\n[*] Forcing flow expiry and ML classification...")
        try:
            resp = requests.post(f"{self.dashboard_url}/api/flush-flows", timeout=2)
            result = resp.json()
            print(f"    ✓ Flushed: {result.get('classified', 0)} flows classified")
        except Exception as e:
            print(f"    ✗ Flush failed: {e}")

        print("[*] Retrieving ML detection results...")
        for attempt in range(15):
            try:
                resp = requests.get(f"{self.dashboard_url}/api/metrics", timeout=2)
                stats = resp.json().get("ml_stats", {})
                if any(v > 0 for k, v in stats.items() if k != "Normal"):
                    print(f"    ✓ Attacks detected!")
                    return stats
                if attempt > 0:
                    print(f"    Waiting... ({attempt}s)", end="\r")
            except Exception:
                pass
            time.sleep(1)

        return {}

    def show_results(self):
        """Display ML classification results."""
        print("\n" + "=" * 60)
        print("  ⚔️  ML DETECTION RESULTS — CIC-IDS2017 TRAINED MODEL")
        print("=" * 60)

        expected = {
            "Port Scan": any(x in self.attacks for x in ["portscan", "all"]),
            "DoS/DDoS": any(x in self.attacks for x in ["dos", "all"]),
            "Brute Force": any(x in self.attacks for x in ["bruteforce", "all"]),
            "Botnet": any(x in self.attacks for x in ["botnet", "all"]),
        }

        detected = {k: v for k, v in self.ml_stats.items() if k != "Normal"}

        print(f"\n{'Attack Class':<20} {'Expected':<15} {'Detected':<15} {'Status':<10}")
        print("-" * 60)

        for attack_class in ["Port Scan", "DoS/DDoS", "Brute Force", "Botnet"]:
            exp = "✓" if expected.get(attack_class, False) else "—"
            det = detected.get(attack_class, 0)
            det_str = str(det) if det > 0 else "0"
            status = "✅ OK" if (det > 0) == expected.get(attack_class, False) else "❌ MISS"
            print(f"{attack_class:<20} {exp:<15} {det_str:<15} {status:<10}")

        print("-" * 60)
        normal = self.ml_stats.get("Normal", 0)
        print(f"{'Normal (benign)':<20} {'—':<15} {normal:<15}")
        print("=" * 60 + "\n")

    def run(self):
        """Execute the full attack simulation."""
        print("\n" + "=" * 60)
        print("  🚀 NetSentinelAI — ML-aware Attack Simulator (Fixed)")
        print("=" * 60)
        print(f"  Target     : {self.target}")
        print(f"  Dashboard  : {self.dashboard_url}")
        print(f"  Attacks    : {', '.join(sorted(self.attacks))}")
        print("=" * 60)

        if not self.check_requirements():
            print("\n❌ Pre-flight checks failed")
            return False

        # Run attacks
        if "portscan" in self.attacks:
            self.simulate_port_scan(self.target)

        if "dos" in self.attacks:
            self.simulate_dos_hulk(f"{self.dashboard_url}/")

        if "bruteforce" in self.attacks:
            self.simulate_brute_force(self.target)

        botnet_thread = None
        if "botnet" in self.attacks:
            botnet_thread = threading.Thread(target=lambda: self.simulate_botnet(self.target), daemon=True)
            botnet_thread.start()

        # Wait for botnet to finish (60s)
        if botnet_thread:
            botnet_thread.join(timeout=65)
            if self._botnet_receiver:
                self._botnet_receiver.stop()

        # Flush and get results
        print()
        self.ml_stats = self.flush_and_wait()

        # Show results
        print()
        self.show_results()

        return True


def main():
    parser = argparse.ArgumentParser(
        description="ML-aware attack simulator for NetSentinelAI (Fixed)"
    )
    parser.add_argument(
        "--target",
        default="127.0.0.1",
        help="Target IP (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--dashboard",
        default="http://localhost:5050",
        help="Dashboard URL (default: http://localhost:5050)"
    )
    parser.add_argument(
        "--attacks",
        default="all",
        help="Attack types: portscan,dos,bruteforce,botnet,all (default: all)"
    )

    args = parser.parse_args()

    simulator = AttackSimulator(
        target=args.target,
        dashboard_url=args.dashboard,
        attacks=args.attacks
    )

    success = simulator.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
