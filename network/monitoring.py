# Module for network monitoring 
from scapy.all import sniff, IP , TCP
from network.analysis import analyze_packet, detect_port_scan


is_sniffing= True

def packet_callback(packet):
    # Analyze Packet
    analyze_packet(packet)
    detect_port_scan(packet)

def start_sniffing(interface, callback=packet_callback):
    global is_sniffing
    is_sniffing= True
    print(f"Starting packet capture on interface {interface}")
    def stop_sniffer(packet):
        return not is_sniffing
    sniff(iface=interface, prn=callback, store=False, stop_filter=stop_sniffer)

def stop_sniffing():
    global is_sniffer
    print("Stopping packet capture")
    is_sniffing= False

