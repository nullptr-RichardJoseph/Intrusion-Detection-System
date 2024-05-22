# Module for traffic analysis 
from scapy.all import IP, TCP
from snort_parser import parse_snort_rules

rules=parse_snort_rules('community.rules')

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

            detect_signatures(packet)

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

#Checking of the rules match the signature of the packets
def check_rule(packet, rule):
    if IP in packet:
        proto = proto_map.get(packet[IP].proto, 'other')
        if rule.proto.lower() == 'ip' or rule.proto.lower() == proto:
            if rule.src_ip == 'any' or rule.src_ip == packet[IP].src:
                if rule.dst_ip == 'any' or rule.dst_ip == packet[IP].dst:
                    if rule.src_port == 'any' or (TCP in packet and rule.src_port == str(packet[TCP].sport)):
                        if rule.dst_port == 'any' or (TCP in packet and rule.dst_port == str(packet[TCP].dport)):
                            return True
    return False

#Calls the check_rules function
def detect_signatures(packet):
    for rule in rules:
        if check_rule(packet, rule):
            print(f"Signature match: {rule.msg} (SID: {rule.sid})")
