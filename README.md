
## Network Packet Sniffer Tool

### Description
The Enhanced Packet Sniffer Tool is a Python application that captures and analyzes network packets in real-time. This tool provides detailed information about the packets traversing the network, including source/destination IPs, protocols, and payload data.

### Overview
Packet sniffing is a critical technique used in network analysis and cybersecurity. This project enhances basic sniffing functionality by incorporating features such as real-time filtering, logging, and traffic visualization.

### Features
- Real-time Packet Capture: Monitors network traffic in real-time.
- Detailed Protocol Analysis: Extracts and displays information about TCP, UDP, and ICMP packets.
- Logging: Saves captured packet data to a file for further analysis.
- Traffic Visualization: Displays packet statistics in real-time using graphs.

### Installation
#### Prerequisites
- Python 3.x
- `scapy` and `matplotlib` libraries

#### Running the Application
Clone the repository or download the source code.

Ensure that Python is installed on your system.

Run the following command in your terminal to start the application:
```bash
sudo python packet_sniffer.py
```

### How to Use
1. **Start the Application**: Run the script to launch the Enhanced Packet Sniffer Tool.
2. **Monitor Network Traffic**: The application will start capturing packets based on specified filters.
3. **Analyze Data**: Review real-time statistics and captured data.

### Key Components
- **Packet Capture Logic**: Uses the `scapy` library for efficient packet sniffing.
- **Statistical Analysis**: Implements functions for aggregating packet statistics by protocol and IP.

### License
This project is licensed under the MIT License - see the LICENSE file for details.

---
