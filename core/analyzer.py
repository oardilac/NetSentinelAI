# Written by: @dukebismaya
# The Number Cruncher -  Takes raw packets and calculates the math (packet rates, sizes) safely

from typing import NamedTuple, Any
from collections import defaultdict
from scapy.all import IP, TCP
import time

class Connection(NamedTuple):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
class TrafficAnalyzer:
    def __init__(self) -> None:
        self.flow_stats: dict[Connection, dict[str, Any]] = defaultdict(lambda: {'packet_count': 0, 'byte_count': 0, 'start_time': None, 'last_time': None})
        
    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            # Create a unique key for this connection
            flow_key = Connection(
                src_ip=packet[IP].src,
                dst_ip=packet[IP].dst,
                src_port=packet[TCP].sport,
                dst_port=packet[TCP].dport
            )
            stats = self.flow_stats[flow_key]
            
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = time.time()
            
            if not stats['start_time']:
                stats['start_time'] =current_time
            stats['last_time'] = current_time
            
            duration  = stats['last_time'] - stats['start_time']
            duration = duration if duration>0 else 0.0001
            
            return {
                'packet_size': len(packet),
                'packet_rate': stats['packet_count']/duration,
                'byte_rate': stats['byte_count']/duration,
                'tcp_flag': packet[TCP].flags
            }
            
        return None
            