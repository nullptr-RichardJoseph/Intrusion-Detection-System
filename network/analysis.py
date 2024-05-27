# Module for traffic analysis 
from scapy.all import IP, TCP, UDP, ICMP
from snort_parser import parse_snort_rules
detected_ports = {}
# Protocol number to string mapping
proto_map = {
    1: 'icmp',
    6: 'tcp',
    17: 'udp'
}

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

        elif UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport

            # Print information about UDP packets
            print(f"[+] UDP Packet: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")

            # Example condition: Detect DNS traffic on port 53
            if udp_dport == 53 or udp_sport == 53:
                print(f"[!] DNS traffic detected: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")

        elif ICMP in packet:
            # Print information about ICMP packets
            print(f"[+] ICMP Packet: {ip_src} -> {ip_dst}")

            # Example condition: Detect ICMP echo requests
            if packet[ICMP].type == 8:
                print("[!] ICMP Echo Request detected")
    


#Port Scanning feature for specific ports
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

