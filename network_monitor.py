#!/usr/bin/env python3
"""
Network Security Monitor - Sniffer con métricas de seguridad
Optimizado para Windows y monitoreo de amenazas en red privada

Recolecta métricas útiles para detectar:
- Port scanning
- Tráfico inusual
- Conexiones sospechosas
- Anomalías de protocolo
- Patrones de DDoS
"""

from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, ICMP, ARP, Raw
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Thread, Lock
import json
import time
import socket

class SecurityMetricsCollector:
    """Recolecta métricas de seguridad del tráfico de red"""
    
    def __init__(self, time_window=300):  # 5 minutos por defecto
        self.time_window = time_window  # Ventana de tiempo en segundos
        self.lock = Lock()
        
        # Métricas generales
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = datetime.now()
        
        # Métricas por protocolo
        self.protocol_stats = defaultdict(int)
        self.protocol_bytes = defaultdict(int)
        
        # Tracking de IPs
        self.src_ips = defaultdict(int)  # Contador de paquetes por IP origen
        self.dst_ips = defaultdict(int)  # Contador de paquetes por IP destino
        self.ip_pairs = defaultdict(int)  # Pares de comunicación
        
        # Detección de port scanning
        self.port_scan_detector = defaultdict(set)  # IP -> set de puertos destino
        self.port_scan_time = defaultdict(lambda: deque())  # IP -> timestamps
        
        # Tracking de puertos
        self.dst_ports = defaultdict(int)  # Puertos destino más comunes
        self.src_ports = defaultdict(int)  # Puertos origen más comunes
        
        # DNS queries
        self.dns_queries = defaultdict(int)  # Dominios consultados
        
        # Flags TCP sospechosas
        self.tcp_flags = defaultdict(int)  # SYN, FIN, RST, etc.
        
        # Conexiones fallidas
        self.failed_connections = defaultdict(int)  # RST packets por IP
        
        # Tráfico por tiempo (para gráficas)
        self.traffic_timeline = deque(maxlen=1000)  # Últimos 1000 segundos
        self.current_second = int(time.time())
        self.second_packets = 0
        self.second_bytes = 0
        
        # Top talkers (IPs más activas)
        self.top_talkers_bytes = defaultdict(int)
        
        # ICMP tracking (posible reconnaissance)
        self.icmp_types = defaultdict(int)
        
        # ARP tracking (posible ARP spoofing)
        self.arp_requests = defaultdict(int)
        
        # Alertas/anomalías detectadas
        self.alerts = deque(maxlen=100)  # Últimas 100 alertas
        
    def process_packet(self, packet):
        """Procesa cada paquete y actualiza métricas"""
        with self.lock:
            current_time = datetime.now()
            current_second = int(time.time())
            
            # Actualizar timeline si cambió el segundo
            if current_second != self.current_second:
                self.traffic_timeline.append({
                    'timestamp': self.current_second,
                    'packets': self.second_packets,
                    'bytes': self.second_bytes
                })
                self.current_second = current_second
                self.second_packets = 0
                self.second_bytes = 0
            
            # Métricas generales
            self.total_packets += 1
            packet_size = len(packet)
            self.total_bytes += packet_size
            self.second_packets += 1
            self.second_bytes += packet_size
            
            # Procesar según tipo de paquete
            if packet.haslayer(IP):
                self._process_ip_packet(packet, current_time)
            
            if packet.haslayer(ARP):
                self._process_arp_packet(packet, current_time)
    
    def _process_ip_packet(self, packet, current_time):
        """Procesa paquetes IP"""
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_size = len(packet)
        
        # Tracking de IPs
        self.src_ips[src_ip] += 1
        self.dst_ips[dst_ip] += 1
        self.ip_pairs[f"{src_ip}->{dst_ip}"] += 1
        self.top_talkers_bytes[src_ip] += packet_size
        
        # Procesar TCP
        if packet.haslayer(TCP):
            self._process_tcp_packet(packet, src_ip, dst_ip, current_time)
        
        # Procesar UDP
        elif packet.haslayer(UDP):
            self._process_udp_packet(packet, src_ip, dst_ip)
        
        # Procesar ICMP
        elif packet.haslayer(ICMP):
            self._process_icmp_packet(packet, src_ip)
    
    def _process_tcp_packet(self, packet, src_ip, dst_ip, current_time):
        """Procesa paquetes TCP"""
        tcp_layer = packet[TCP]
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        flags = tcp_layer.flags
        
        self.protocol_stats['TCP'] += 1
        self.protocol_bytes['TCP'] += len(packet)
        self.dst_ports[dst_port] += 1
        self.src_ports[src_port] += 1
        
        # Analizar flags TCP
        flag_str = str(flags)
        self.tcp_flags[flag_str] += 1
        
        # Detectar posible port scanning
        if flags & 0x02:  # SYN flag
            self.port_scan_detector[src_ip].add(dst_port)
            self.port_scan_time[src_ip].append(current_time)
            
            # Alerta si una IP escanea muchos puertos en poco tiempo
            if len(self.port_scan_detector[src_ip]) > 20:  # Más de 20 puertos diferentes
                recent_scans = [t for t in self.port_scan_time[src_ip] 
                               if (current_time - t).seconds < 60]
                if len(recent_scans) > 15:  # 15+ en 1 minuto
                    self._add_alert('port_scan', src_ip, 
                                   f'Posible port scan: {len(self.port_scan_detector[src_ip])} puertos')
        
        # Detectar conexiones fallidas (RST)
        if flags & 0x04:  # RST flag
            self.failed_connections[f"{src_ip}->{dst_ip}:{dst_port}"] += 1
        
        # Detectar HTTP
        if dst_port in [80, 8080] or src_port in [80, 8080]:
            self.protocol_stats['HTTP'] += 1
            self.protocol_bytes['HTTP'] += len(packet)
        
        # Detectar HTTPS
        if dst_port == 443 or src_port == 443:
            self.protocol_stats['HTTPS'] += 1
            self.protocol_bytes['HTTPS'] += len(packet)
    
    def _process_udp_packet(self, packet, src_ip, dst_ip):
        """Procesa paquetes UDP"""
        udp_layer = packet[UDP]
        dst_port = udp_layer.dport
        src_port = udp_layer.sport
        
        self.protocol_stats['UDP'] += 1
        self.protocol_bytes['UDP'] += len(packet)
        self.dst_ports[dst_port] += 1
        self.src_ports[src_port] += 1
        
        # Procesar DNS
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns_layer = packet[DNS]
            if dns_layer.qr == 0:  # Query
                query_name = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                self.dns_queries[query_name] += 1
                self.protocol_stats['DNS'] += 1
                self.protocol_bytes['DNS'] += len(packet)
    
    def _process_icmp_packet(self, packet, src_ip):
        """Procesa paquetes ICMP"""
        icmp_layer = packet[ICMP]
        icmp_type = icmp_layer.type
        
        self.protocol_stats['ICMP'] += 1
        self.protocol_bytes['ICMP'] += len(packet)
        self.icmp_types[f"Type_{icmp_type}"] += 1
        
        # Detectar exceso de ICMP (posible reconocimiento)
        if self.icmp_types[f"Type_{icmp_type}"] > 100:
            if self.icmp_types[f"Type_{icmp_type}"] % 50 == 0:  # Alerta cada 50
                self._add_alert('icmp_flood', src_ip, 
                               f'Alto volumen de ICMP Type {icmp_type}')
    
    def _process_arp_packet(self, packet, current_time):
        """Procesa paquetes ARP"""
        arp_layer = packet[ARP]
        src_ip = arp_layer.psrc
        
        self.protocol_stats['ARP'] += 1
        self.protocol_bytes['ARP'] += len(packet)
        
        if arp_layer.op == 1:  # ARP request
            self.arp_requests[src_ip] += 1
            
            # Detectar exceso de ARP requests (posible ARP scan)
            if self.arp_requests[src_ip] > 50:
                if self.arp_requests[src_ip] % 25 == 0:
                    self._add_alert('arp_scan', src_ip, 
                                   f'Exceso de ARP requests: {self.arp_requests[src_ip]}')
    
    def _add_alert(self, alert_type, source, description):
        """Añade una alerta al sistema"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'source': source,
            'description': description
        }
        self.alerts.append(alert)
    
    def get_metrics(self):
        """Retorna todas las métricas en formato JSON-friendly"""
        with self.lock:
            uptime = (datetime.now() - self.start_time).total_seconds()
            packets_per_sec = self.total_packets / max(uptime, 1)
            bytes_per_sec = self.total_bytes / max(uptime, 1)
            
            return {
                'overview': {
                    'total_packets': self.total_packets,
                    'total_bytes': self.total_bytes,
                    'total_mb': round(self.total_bytes / (1024*1024), 2),
                    'uptime_seconds': round(uptime, 1),
                    'packets_per_second': round(packets_per_sec, 2),
                    'bytes_per_second': round(bytes_per_sec, 2),
                    'mbps': round((bytes_per_sec * 8) / (1024*1024), 3)
                },
                'protocols': {
                    'stats': dict(self.protocol_stats),
                    'bytes': dict(self.protocol_bytes)
                },
                'top_sources': self._get_top_n(self.src_ips, 10),
                'top_destinations': self._get_top_n(self.dst_ips, 10),
                'top_talkers': self._get_top_n(self.top_talkers_bytes, 10),
                'top_dst_ports': self._get_top_n(self.dst_ports, 10),
                'top_dns_queries': self._get_top_n(self.dns_queries, 10),
                'tcp_flags': dict(self.tcp_flags),
                'icmp_types': dict(self.icmp_types),
                'potential_port_scans': self._get_port_scan_suspects(),
                'failed_connections': self._get_top_n(self.failed_connections, 10),
                'traffic_timeline': list(self.traffic_timeline)[-60:],  # Último minuto
                'alerts': list(self.alerts)[-20:],  # Últimas 20 alertas
                'timestamp': datetime.now().isoformat()
            }
    
    def _get_top_n(self, data_dict, n=10):
        """Retorna los top N elementos de un diccionario"""
        sorted_items = sorted(data_dict.items(), key=lambda x: x[1], reverse=True)
        return [{'name': k, 'value': v} for k, v in sorted_items[:n]]
    
    def _get_port_scan_suspects(self):
        """Identifica IPs que pueden estar haciendo port scanning"""
        suspects = []
        for ip, ports in self.port_scan_detector.items():
            if len(ports) >= 10:  # 10 o más puertos diferentes
                suspects.append({
                    'ip': ip,
                    'ports_scanned': len(ports),
                    'ports': list(ports)[:20]  # Primeros 20 puertos
                })
        return sorted(suspects, key=lambda x: x['ports_scanned'], reverse=True)[:10]


class NetworkSniffer:
    """Sniffer de red con servidor de métricas"""
    
    def __init__(self, interface=None):
        self.interface = interface
        self.metrics = SecurityMetricsCollector()
        self.running = False
    
    def start_sniffing(self):
        """Inicia la captura de paquetes"""
        self.running = True
        print(f"[+] Iniciando captura en interfaz: {self.interface or 'Todas'}")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.metrics.process_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"[ERROR] Error en captura: {e}")
            self.running = False
    
    def stop_sniffing(self):
        """Detiene la captura"""
        self.running = False


# Instancia global del sniffer
sniffer = None

def get_sniffer():
    """Retorna la instancia global del sniffer"""
    global sniffer
    if sniffer is None:
        sniffer = NetworkSniffer()
    return sniffer
