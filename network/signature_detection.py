# signature_detection.py
from scapy.all import sniff, IP , TCP

def detect_signatures(packet, rules):
    matched_rules=[]
    for rule in rules:
        if check_rule(packet, rule):
            print(f"Signature match: {rule.msg} (SID: {rule.sid}) -IP :{packet[IP].src}")

def check_rule(packet, rule):
    if IP in packet:
        proto = packet[IP].proto
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet.sport if packet.haslayer('TCP') else None
        dst_port = packet.dport if packet.haslayer('TCP') else None

        if rule.proto.lower() == 'ip' or rule.proto.lower() == proto:
            if rule.src_ip == 'any' or rule.src_ip == src_ip:
                if rule.dst_ip == 'any' or rule.dst_ip == dst_ip:
                    if rule.src_port == 'any' or rule.src_port == src_port:
                        if rule.dst_port == 'any' or rule.dst_port == dst_port:
                            return True
    return False
