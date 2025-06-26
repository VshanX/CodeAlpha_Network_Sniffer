# Network Packet Sniffer

A comprehensive Python-based network packet sniffer built with Scapy that captures and analyzes network traffic in real-time.

## Features

- **Real-time packet capture** on any network interface
- **Protocol detection** for TCP, UDP, HTTP, HTTPS, DNS, ICMP, ARP, and more
- **Detailed packet analysis** including source/destination IPs, protocols, and payload summaries
- **Beautiful tabular output** using the tabulate library
- **Colored console output** for better readability
- **Protocol statistics** showing traffic distribution
- **Error handling** for permissions and interface issues
- **Cross-platform compatibility** (Windows, Linux, macOS)

## Requirements

- Python 3.6 or higher
- Administrator/Root privileges (required for packet capture)
- Required Python packages:
  - scapy
  - tabulate
  - colorama

## Installation

1. Clone or download the script
2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```
   
   Or install individually:
   ```bash
   pip install scapy tabulate colorama
   ```

## Usage

### Windows
Run as Administrator:
```cmd
python network_sniffer.py
```

### Linux/macOS
Run with sudo:
```bash
sudo python network_sniffer.py
```

## Program Flow

1. **Interface Selection**: The program displays available network interfaces and prompts you to select one
2. **Capture Configuration**: Set packet limit and timeout (optional)
3. **Real-time Capture**: Packets are captured and displayed in real-time
4. **Summary Display**: After capture, a detailed summary table and statistics are shown

## Sample Output

```
================================================================================
                    NETWORK PACKET SNIFFER
                   Built with Python & Scapy
================================================================================

Available Network Interfaces:
==================================================
1. Ethernet (IP: 192.168.1.100)
2. Wi-Fi (IP: 192.168.1.105)
3. Loopback (IP: 127.0.0.1)

Select interface (1-3) or press Enter for default: 2

Starting packet capture on interface: Wi-Fi
Press Ctrl+C to stop capture...
--------------------------------------------------------------------------------
[14:23:45.123] HTTP     192.168.1.100   → 93.184.216.34   ( 567 bytes) GET /index.html HTTP/1.1
[14:23:45.145] DNS      192.168.1.100   → 8.8.8.8         ( 78 bytes) Query: www.example.com
[14:23:45.167] DNS      8.8.8.8         → 192.168.1.100   ( 94 bytes) Response: 1 answers
[14:23:45.189] HTTPS    192.168.1.100   → 172.217.14.110  ( 1420 bytes) TLS Port 52341 → 443
[14:23:45.234] ICMP     192.168.1.1     → 192.168.1.100   ( 64 bytes) Type: 0, Code: 0

================================================================================
NETWORK PACKET CAPTURE SUMMARY
================================================================================
+---+---------------+----------+-----------------+-----------------+--------+------------------------------------------+
| # | Timestamp     | Protocol | Source IP       | Dest IP         | Length | Payload Summary                          |
+===+===============+==========+=================+=================+========+==========================================+
| 1 | 14:23:45.123  | HTTP     | 192.168.1.100   | 93.184.216.34   | 567    | GET /index.html HTTP/1.1                 |
| 2 | 14:23:45.145  | DNS      | 192.168.1.100   | 8.8.8.8         | 78     | Query: www.example.com                   |
| 3 | 14:23:45.167  | DNS      | 8.8.8.8         | 192.168.1.100   | 94     | Response: 1 answers                      |
| 4 | 14:23:45.189  | HTTPS    | 192.168.1.100   | 172.217.14.110  | 1420   | TLS Port 52341 → 443                    |
| 5 | 14:23:45.234  | ICMP     | 192.168.1.1     | 192.168.1.100   | 64     | Type: 0, Code: 0                        |
+---+---------------+----------+-----------------+-----------------+--------+------------------------------------------+

PROTOCOL STATISTICS:
----------------------------------------
+----------+-------+------------+
| Protocol | Count | Percentage |
+==========+=======+============+
| HTTPS    | 15    | 42.9%      |
| HTTP     | 8     | 22.9%      |
| DNS      | 6     | 17.1%      |
| TCP      | 4     | 11.4%      |
| ICMP     | 2     | 5.7%       |
+----------+-------+------------+

Total packets captured: 35
```

## Supported Protocols

- **TCP**: Transmission Control Protocol
- **UDP**: User Datagram Protocol
- **HTTP**: HyperText Transfer Protocol
- **HTTPS**: HTTP Secure (TLS/SSL)
- **DNS**: Domain Name System
- **ICMP**: Internet Control Message Protocol
- **ARP**: Address Resolution Protocol
- **IPv6**: Internet Protocol version 6
- **DHCP**: Dynamic Host Configuration Protocol
- **SSH**: Secure Shell
- **FTP**: File Transfer Protocol
- **SMTP**: Simple Mail Transfer Protocol

## Security Considerations

- **Administrative Privileges**: This tool requires administrator/root privileges to capture packets
- **Legal Compliance**: Only use this tool on networks you own or have explicit permission to monitor
- **Privacy**: Be mindful of privacy laws and regulations in your jurisdiction
- **Ethical Use**: Use this tool for educational, debugging, or authorized security testing purposes only

## Troubleshooting

### Permission Errors
- **Windows**: Run Command Prompt or PowerShell as Administrator
- **Linux/macOS**: Use `sudo` when running the script

### Interface Issues
- Check if the selected interface is active and connected
- Try using the default interface option
- Ensure network adapters are properly configured

### Import Errors
- Verify all required packages are installed: `pip list`
- Reinstall packages if necessary: `pip install --upgrade scapy tabulate colorama`

## Code Structure

The script is organized into several key components:

- `NetworkSniffer` class: Main sniffer functionality
- `packet_handler()`: Processes captured packets
- `extract_packet_info()`: Extracts relevant packet details
- `display_summary_table()`: Formats and displays results
- Error handling and permission checking
- Interface selection and configuration

## Educational Value

This tool is excellent for:
- Learning network protocols and packet structure
- Understanding network traffic patterns
- Debugging network connectivity issues
- Network security education and training
- Protocol analysis and research

## License

This project is for educational purposes. Use responsibly and in compliance with local laws and regulations.

## Author

Network Security Specialist
Date: June 26, 2025
