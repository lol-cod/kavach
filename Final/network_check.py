from scapy.all import *

# Define a function to analyze packets
def analyze_packet(packet):
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        
        # Perform checks for common anomalies
        if packet.haslayer(TCP):
            if packet[TCP].flags & 2:  # SYN flag (bit 1) is set
                print(f"Potential SYN scan detected from {source_ip} to {destination_ip}")
        elif packet.haslayer(ARP):
            if packet[ARP].op == 2:  # ARP reply operation
                print(f"Potential ARP spoofing detected: {source_ip} is claiming {destination_ip}")
        else:
            print(f"Unrecognized packet type from {source_ip} to {destination_ip}")

# Start packet capture and analysis
def start_packet_capture(interface):
    sniff(iface=interface, prn=analyze_packet)

if __name__ == "__main__":
    interface = "Wi-Fi"  # Replace with the appropriate network interface name
    print(f"Intercepting packets on interface {interface}...")
    start_packet_capture(interface)
