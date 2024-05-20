# Module for network monitoring 
from scapy.all import sniff, IP , TCP
from network.analysis import analyze_packet

def packet_callback(packet):
    if IP in packet:
        ip_src=packet[IP].src
        ip_dst= packet[IP].dst
        if TCP in packet:
            tcp_sport= packet[TCP].sport
            tcp_dport=packet[TCP].dport

            # Print information about all TCP packets
            print(f"[+] TCP Packet: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
            
            # Check if the packet is HTTP traffic (port 80)
            #uncomment if you want real time packet information
            if tcp_dport == 80 or tcp_sport == 80:
                print(f"[+] HTTP Packet: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
            
            # Analyze Packet
            analyze_packet(packet)

def start_sniffing(interface):
    print(f"[*] Starting packet capture on interface {interface}")
    try:
        sniff(iface=interface, prn=packet_callback, store=False)
    except Exception as e:
        print(f"[!] Error starting sniffing: {e}")