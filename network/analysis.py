# Module for traffic analysis 
from scapy.all import IP, TCP

def analyze_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            
            # Example condition: Detect traffic on a specific port (e.g., 80 for HTTP)
            if tcp_dport == 80 or tcp_sport == 80:
                print(f"[!] HTTP traffic detected: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")