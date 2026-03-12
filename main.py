# PySentry - Main Engine
# Written by; @dukebismaya

from core.capture import PacketCapture
from core.detection import DetectionEngine
from core.analyzer import TrafficAnalyzer
from core.alerts import AlertSystem
from scapy.all import IP, TCP
import queue
import os
import atexit

class PySentryIDS:
    def __init__(self, interface="Wi-Fi"):
        self.capture  = PacketCapture()
        self.analyzer = TrafficAnalyzer()
        self.detector = DetectionEngine()
        self.alerts = AlertSystem()
        self.interface = interface
        
    def start(self):
        print(f"🛡️ Starting PySentry IDS on interface: {self.interface}...")
        
        with open(".engine_status", "w") as f:
            f.write("RUNNING")
            
        def cleanup():
            if os.path.exists(".engine_status"):
                os.remove(".engine_status")
            # Clean up the logs when closing
            if hasattr(self.alerts, 'log_file') and os.path.exists(self.alerts.log_file):
                with open(self.alerts.log_file, 'w') as f:
                    f.write("")
        atexit.register(cleanup)
        
        self.capture.start_capture(self.interface)
        try:
            while True:
                try:
                    packet = self.capture.packet_queue.get(timeout=1)
                    features = self.analyzer.analyze_packet(packet)
                    
                    if features:
                        threats = self.detector.detect_threats(features)
                        for threat in threats:
                            packet_info = {'source_ip': packet[IP].src, 'destination_ip': packet[IP].dst}
                            self.alerts.generate_alert(threat, packet_info)
                except queue.Empty:
                    continue
        
        except KeyboardInterrupt:
            print("\n🛑 Shutting down PySentry ...")
            self.capture.stop()
            if os.path.exists(".engine_status"):
                os.remove(".engine_status")
            if hasattr(self.alerts, 'log_file') and os.path.exists(self.alerts.log_file):
                with open(self.alerts.log_file, 'w') as f:
                    f.write("")
            
if __name__ == "__main__":
    # Change the Interface to Wi-Fi or Ethernet based on how you connect the internet
    # In Windows run this in a Powershell: Get-NetAdapter | Where-Object Status -eq "Up"
    # For Mac/Linux "eth0" or "en0" is usually correct
    ids = PySentryIDS(interface="en0")
    ids.start()