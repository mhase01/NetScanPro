import matplotlib.pyplot as plt
from scapy.all import *

# Track protocol distribution
protocol_distribution = {"TCP": 0, "UDP": 0, "Other": 0}

# Global variables for packet counting
total_packets = 0
tcp_packets = 0
udp_packets = 0
icmp_packets = 0

# Dictionary to store information about active TCP connections
active_connections = {}

def packet_callback(packet):
    global total_packets, tcp_packets, udp_packets, icmp_packets

    # Increment total packet count
    total_packets += 1

    # Extract and print relevant information from the packet
    if Ether in packet:
        print("Ethernet Frame:")
        print(f"Source MAC: {packet[Ether].src}, Destination MAC: {packet[Ether].dst}")

    if ARP in packet:
        print("\nARP Packet:")
        print(f"Sender IP: {packet[ARP].psrc}, Target IP: {packet[ARP].pdst}")

    if IP in packet:
        print("\nIP Packet:")
        print(f"Source IP: {packet[IP].src}, Destination IP: {packet[IP].dst}")
        print(f"Protocol: {packet[IP].proto}")

        if TCP in packet:
            tcp_packets += 1
            print("\nTCP Segment:")
            print(f"Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")
            print(f"Flags: {packet[TCP].flags}")

            # Check for TCP connection establishment (SYN flag set)
            if packet[TCP].flags.S and not packet[TCP].flags.A:
                print("TCP Connection Established")

                # Store information about the active connection
                connection_key = f"{packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}"
                active_connections[connection_key] = {
                    "start_time": packet.time,
                    "last_packet_time": packet.time,
                }

            # Check for TCP connection termination (FIN flag set)
            elif packet[TCP].flags.F and packet[TCP].flags.A:
                print("TCP Connection Terminated")

                # Retrieve and print information about the terminated connection
                connection_key = f"{packet[IP].dst}:{packet[TCP].dport} -> {packet[IP].src}:{packet[TCP].sport}"
                if connection_key in active_connections:
                    connection_info = active_connections.pop(connection_key)
                    connection_duration = packet.time - connection_info["start_time"]
                    print(f"Connection Duration: {connection_duration} seconds")

            # Print TCP payload information
            if Raw in packet:
                print(f"TCP Payload: {repr(packet[Raw].load)}")

            # Print additional TCP-specific analysis here

        elif UDP in packet:
            udp_packets += 1
            print("\nUDP Segment:")
            print(f"Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")

            # Print UDP payload information
            if Raw in packet:
                print(f"UDP Payload: {repr(packet[Raw].load)}")

            # Print additional UDP-specific analysis here

        elif ICMP in packet:
            icmp_packets += 1
            print("\nICMP Packet:")
            print(f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}")

            # Print additional ICMP-specific analysis here

    # Update your logic for tracking bandwidth, protocol distribution, etc.
    # Example: Counting the protocol distribution
    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    else:
        protocol = "Other"

    protocol_distribution[protocol] += 1

    # Print protocol distribution and update visualization
    print_protocol_distribution()
    plot_protocol_distribution()

def print_protocol_distribution():
    print("Protocol Distribution:")
    for protocol, count in protocol_distribution.items():
        print(f"{protocol}: {count}")

def plot_protocol_distribution():
    labels = protocol_distribution.keys()
    values = protocol_distribution.values()

    plt.figure(figsize=(8, 6))
    plt.pie(values, labels=labels, autopct="%1.1f%%", startangle=140)
    plt.title("Protocol Distribution")
    plt.show()

# Start sniffing
try:
    sniff(prn=packet_callback, store=0, iface='Wi-Fi')
except KeyboardInterrupt:
    # Handle keyboard interruption (Ctrl+C) gracefully
    print("\nPacket Sniffer Stopped.")
    print(f"Total packets captured: {total_packets}")
    print(f"TCP packets: {tcp_packets}")
    print(f"UDP packets: {udp_packets}")
    print(f"ICMP packets: {icmp_packets}")
