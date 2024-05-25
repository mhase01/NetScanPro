# Packet Sniffer Project - README

## Overview

This project involves the design and implementation of a packet sniffer using Python and the Scapy library. A packet sniffer captures and analyzes data packets traversing a network, providing insights into network traffic at different layers of the OSI model. This tool is useful for network administrators, security professionals, and students aiming to understand network communication and protocol behavior.

## Features

- **Packet Capture**: Captures Ethernet frames, ARP packets, IP packets, TCP segments, UDP segments, and ICMP packets.
- **Protocol Analysis**: Analyzes and displays details about Ethernet, ARP, IP, TCP, UDP, and ICMP protocols.
- **TCP Connection Tracking**: Identifies and tracks TCP connection establishment and termination.
- **Protocol Distribution Visualization**: Plots the distribution of captured protocols using a pie chart.

## Tools and Libraries Used

- **Python**: Versatile programming language used for scripting and automation.
- **Scapy**: Powerful packet manipulation and analysis library in Python.
- **Matplotlib**: Library for creating static, animated, and interactive visualizations in Python.

## Implementation Overview

The implementation leverages the Scapy library to capture and analyze packets on a specified network interface. The core functionality is based on the `sniff` function from Scapy, which allows for real-time packet capture and processing.

### Key Components

1. **Packet Callback Function**: Processes each captured packet, extracting and displaying relevant information.
2. **Protocol Distribution Tracking**: Maintains a count of different protocols observed in the captured packets.
3. **Visualization**: Uses Matplotlib to plot the distribution of captured protocols.

## Setup Instructions

### Prerequisites

- Python 3.x
- Scapy library (`pip install scapy`)
- Matplotlib library (`pip install matplotlib`)

### Running the Packet Sniffer

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/packet-sniffer.git
   cd packet-sniffer
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Packet Sniffer**:
   ```bash
   python packet_sniffer.py
   ```

### Example Output

- **Ethernet Frame**:
  ```
  Ethernet Frame:
  Source MAC: XX:XX:XX:XX:XX:XX Destination MAC: XX:XX:XX:XX:XX:XX
  ```

- **ARP Packet**:
  ```
  ARP Packet:
  Sender IP: 192.168.0.1 Target IP: 192.168.0.2
  ```

- **IP Packet**:
  ```
  IP Packet:
  Source IP: 192.168.0.1 Destination IP: 192.168.0.2
  Protocol: TCP
  ```

- **TCP Segment**:
  ```
  TCP Segment:
  Source Port: 12345 Destination Port: 80
  Flags: S
  TCP Connection Established
  ```

- **Protocol Distribution Pie Chart**:
  ![Protocol Distribution](protocol_distribution.png)

## Results and Discussion

The packet sniffer successfully captures and analyzes network packets, providing detailed insights into the communication occurring at different layers of the OSI model. The tool can identify and track TCP connections, visualize protocol distribution, and handle various packet types.

### Limitations

- **Scope**: This packet sniffer provides basic functionality and lacks advanced features found in more sophisticated tools.
- **Error Handling**: Robust error handling mechanisms are not extensively implemented.

## Future Enhancements

- **Enhanced Filtering**: Implement advanced filters to capture specific packet types or protocols.
- **Improved Error Handling**: Strengthen error handling to ensure stable execution under various network conditions.
- **Security Measures**: Incorporate security measures to prevent misuse of the packet sniffer.

## Conclusion

The development of this packet sniffer provides a foundational understanding of network traffic analysis using Python and Scapy. It captures and dissects packets across different network layers, offering valuable insights into network communication protocols.


---

This README file guides you through the setup and usage of a basic packet sniffer implemented in Python. For any issues or suggestions, please open an issue or submit a pull request.
