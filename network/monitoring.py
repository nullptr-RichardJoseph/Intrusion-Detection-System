# Module for network monitoring 
from scapy.all import sniff, IP , TCP
from network.analysis import analyze_packet, detect_port_scan
from network.signature_detection import detect_signatures
from snort_parser import parse_snort_rules

is_sniffing= True
rules=parse_snort_rules('community.rules')

def packet_callback(packet):
    # Analyze Packet
    analyze_packet(packet)
    #Port scanning
    detect_port_scan(packet)
    #Signature based detection (SNORT Community Rules)
    detect_signatures(packet, rules)

    #Add Threat Intelligence Alienvault

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

