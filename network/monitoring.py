# Module for network monitoring 
from scapy.all import sniff, IP , TCP

def packet_callback(packet):
    if IP in packet:
        ip_src=packet[IP].src
        ip_dst= packet[IP].dst
        if TCP in packet:
            tcp_sport= packet[TCP].sport
            tcp_dport=packet[TCP].dport
            print(f" [+] TCP Packet: {ip_src}:{tcp_sport}->{ip_dst}:{tcp_dport}")

        else:
            print(f"[+] IP Packets: {ip_src}->{ip_dst}")

def start_sniffing(interface):
    print(f"[*] Starting packet capture on interface {interface}")
    sniff(iface=interface, prn=packet_callback,store=False)