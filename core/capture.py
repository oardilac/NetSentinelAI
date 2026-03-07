# Pakcet capture engine - The Sniffer 
# Written by: @dukebismaya

from scapy.all import IP, sniff, TCP   
import threading
import queue

class PacketCapture:
    def __init__(self) -> None:
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()
        
    def packet_callback(self, packet):
        # We only care about IP and TCP
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)
    
    
    def start_capture(self, interface="eth0"):
        def capture_thread():
            sniff(iface=interface, prn=self.packet_callback, store=0,
                    stop_filter=lambda _: self.stop_capture.is_set())
            
        self.thread = threading.Thread(target=capture_thread)
        self.thread.daemon = True # Stop the thread when main program terminates
        self.thread.start()
    
    def stop(self):
        self.stop_capture.set()