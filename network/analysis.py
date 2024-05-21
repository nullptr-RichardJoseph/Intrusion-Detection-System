# Module for traffic analysis 
from scapy.all import IP, TCP

def analyze_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            
            # Print information about all TCP packets
            print(f"[+] TCP Packet: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
            
            # Example condition: Detect traffic on a specific port (e.g., 80 for HTTP)
            if tcp_dport == 80 or tcp_sport == 80:
                print(f"[!] HTTP traffic detected: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")

def detect_port_scan(packet, scan_threshold=10):
    if IP in packet and TCP in packet:
        ip_src = packet[IP].src
        tcp_dport = packet[TCP].dport

        # A simple port scan detection logic
        if tcp_dport not in detected_ports:
            detected_ports[tcp_dport] = 0
        detected_ports[tcp_dport] += 1

        if detected_ports[tcp_dport] > scan_threshold:
            print(f"[!] Port scan detected from {ip_src} on port {tcp_dport}")

detected_ports = {}