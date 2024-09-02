#Run the below script with elevated privilege to allow the program to capture packets
#$sudo python3 Task[5].py

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Determine the protocol
        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        elif proto == 1:
            protocol = "ICMP"
        else:
            protocol = "Other"

        # Display packet details
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")

        # Display payload data
        if protocol == "TCP" or protocol == "UDP":
            payload = bytes(packet[TCP].payload)
            print(f"Payload: {payload}\n")

# Start the packet sniffer
sniff(filter="ip", prn=packet_callback, store=0)
