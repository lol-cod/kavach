from scapy.all import *

# Define a function to parse packets
def parse_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"IP packet from {src_ip} to {dst_ip}")
    elif packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"TCP packet from port {src_port} to port {dst_port}")

# Capture packets on specified interface
sniff(iface='eth0', prn=parse_packet)
