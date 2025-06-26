from colorama import init, Fore, Back, Style
from tabulate import tabulate

# Initialize colorama
init(autoreset=True)

def print_banner():
    """Print application banner"""
    banner = f"""
{Fore.CYAN}{'='*80}
{Fore.CYAN}                    NETWORK PACKET SNIFFER DEMO
{Fore.CYAN}                   Sample Output Demonstration
{Fore.CYAN}{'='*80}
{Fore.YELLOW}This demo shows the expected output format of the network sniffer.
{Fore.YELLOW}No actual packet capture is performed - this is just a demonstration.
{Fore.CYAN}{'='*80}
"""
    print(banner)

def generate_sample_output():
    """Generate comprehensive sample output for demonstration"""
    
    print(f"\n{Fore.GREEN}Starting packet capture on interface: Wi-Fi")
    print(f"{Fore.GREEN}Press Ctrl+C to stop capture...")
    print(f"{Fore.CYAN}{'-'*80}")
    
    # Simulate real-time packet display
    sample_packets = [
        ("14:23:45.123", "HTTP", "192.168.1.100", "93.184.216.34", "567", "GET /index.html HTTP/1.1"),
        ("14:23:45.145", "DNS", "192.168.1.100", "8.8.8.8", "78", "Query: www.example.com"),
        ("14:23:45.167", "DNS", "8.8.8.8", "192.168.1.100", "94", "Response: 1 answers"),
        ("14:23:45.189", "HTTPS", "192.168.1.100", "172.217.14.110", "1420", "TLS Port 52341 → 443"),
        ("14:23:45.234", "ICMP", "192.168.1.1", "192.168.1.100", "64", "Type: 0, Code: 0"),
        ("14:23:45.267", "TCP", "192.168.1.100", "52.96.7.51", "1024", "Port 58394 → 443"),
        ("14:23:45.289", "UDP", "192.168.1.100", "192.168.1.1", "342", "Port 68 → 67"),
        ("14:23:45.312", "ARP", "192.168.1.1", "192.168.1.100", "42", "Who has 192.168.1.100? Tell 192.168.1.1"),
        ("14:23:45.334", "HTTPS", "192.168.1.100", "104.16.249.13", "1316", "TLS Port 49283 → 443"),
        ("14:23:45.356", "DNS", "192.168.1.100", "1.1.1.1", "89", "Query: github.com"),
    ]
    
    for timestamp, protocol, src_ip, dst_ip, length, payload in sample_packets:
        color = Fore.GREEN
        if protocol in ['HTTP', 'HTTPS']:
            color = Fore.CYAN
        elif protocol == 'DNS':
            color = Fore.YELLOW
        elif protocol == 'ICMP':
            color = Fore.MAGENTA
        elif protocol == 'ARP':
            color = Fore.RED
        
        print(f"{color}[{timestamp}] "
              f"{protocol:8} "
              f"{src_ip:15} → {dst_ip:15} "
              f"({length:4} bytes) "
              f"{payload}")
    
    print(f"\n{Fore.YELLOW}Stopping packet capture...")
    
    # Display summary table
    print(f"\n{Fore.CYAN}{'='*100}")
    print(f"{Fore.CYAN}NETWORK PACKET CAPTURE SUMMARY")
    print(f"{Fore.CYAN}{'='*100}")
    
    # Prepare table data for more comprehensive demo
    table_data = [
        [1, "14:23:45.123", "HTTP", "192.168.1.100", "93.184.216.34", 567, "GET /index.html HTTP/1.1"],
        [2, "14:23:45.145", "DNS", "192.168.1.100", "8.8.8.8", 78, "Query: www.example.com"],
        [3, "14:23:45.167", "DNS", "8.8.8.8", "192.168.1.100", 94, "Response: 1 answers"],
        [4, "14:23:45.189", "HTTPS", "192.168.1.100", "172.217.14.110", 1420, "TLS Port 52341 → 443"],
        [5, "14:23:45.234", "ICMP", "192.168.1.1", "192.168.1.100", 64, "Type: 0, Code: 0"],
        [6, "14:23:45.267", "TCP", "192.168.1.100", "52.96.7.51", 1024, "Port 58394 → 443"],
        [7, "14:23:45.289", "UDP", "192.168.1.100", "192.168.1.1", 342, "Port 68 → 67"],
        [8, "14:23:45.312", "ARP", "192.168.1.1", "192.168.1.100", 42, "Who has 192.168.1.100? Tell 192.168.1.1"],
        [9, "14:23:45.334", "HTTPS", "192.168.1.100", "104.16.249.13", 1316, "TLS Port 49283 → 443"],
        [10, "14:23:45.356", "DNS", "192.168.1.100", "1.1.1.1", 89, "Query: github.com"],
        [11, "14:23:45.378", "HTTP", "192.168.1.100", "151.101.1.140", 734, "GET /api/v1/data HTTP/1.1"],
        [12, "14:23:45.401", "HTTPS", "192.168.1.100", "142.250.191.14", 1287, "TLS Port 44829 → 443"],
        [13, "14:23:45.423", "DNS", "1.1.1.1", "192.168.1.100", 105, "Response: 2 answers"],
        [14, "14:23:45.445", "TCP", "192.168.1.100", "192.30.255.112", 892, "Port 39847 → 22"],
        [15, "14:23:45.467", "ICMP", "192.168.1.100", "8.8.8.8", 64, "Type: 8, Code: 0"],
    ]
    
    headers = ['#', 'Timestamp', 'Protocol', 'Source IP', 'Dest IP', 'Length', 'Payload Summary']
    
    print(tabulate(table_data, headers=headers, tablefmt='grid'))
    
    # Display protocol statistics
    print(f"\n{Fore.CYAN}PROTOCOL STATISTICS:")
    print(f"{Fore.CYAN}{'-'*40}")
    
    stats_data = [
        ['HTTPS', 3, '20.0%'],
        ['DNS', 3, '20.0%'],
        ['HTTP', 2, '13.3%'],
        ['TCP', 2, '13.3%'],
        ['ICMP', 2, '13.3%'],
        ['UDP', 1, '6.7%'],
        ['ARP', 1, '6.7%'],
        ['IPv6', 1, '6.7%'],
    ]
    
    print(tabulate(stats_data, headers=['Protocol', 'Count', 'Percentage'], tablefmt='grid'))
    
    print(f"\n{Fore.GREEN}Total packets captured: 15")
    print(f"{Fore.GREEN}Capture duration: 0.344 seconds")
    print(f"{Fore.GREEN}Average packet size: 547 bytes")
    
    # Additional network information
    print(f"\n{Fore.CYAN}NETWORK INTERFACE INFORMATION:")
    print(f"{Fore.CYAN}{'-'*50}")
    interface_info = [
        ['Interface', 'Wi-Fi'],
        ['IP Address', '192.168.1.100'],
        ['Subnet Mask', '255.255.255.0'],
        ['Gateway', '192.168.1.1'],
        ['DNS Servers', '8.8.8.8, 1.1.1.1'],
    ]
    print(tabulate(interface_info, headers=['Property', 'Value'], tablefmt='grid'))
    
    print(f"\n{Fore.GREEN}Packet capture completed. Thank you for using Network Sniffer!")

def main():
    """Main demo function"""
    print_banner()
    
    print(f"\n{Fore.CYAN}Available Network Interfaces:")
    print(f"{Fore.CYAN}{'='*50}")
    
    interfaces = [
        "1. Ethernet (IP: 192.168.1.100)",
        "2. Wi-Fi (IP: 192.168.1.105)", 
        "3. Loopback (IP: 127.0.0.1)",
        "4. Bluetooth Network Connection (IP: Not available)"
    ]
    
    for iface in interfaces:
        print(f"{Fore.YELLOW}{iface}")
    
    print(f"\n{Fore.GREEN}Selected interface: Wi-Fi")
    
    print(f"\n{Fore.CYAN}Capture Options:")
    print(f"{Fore.GREEN}Packet limit: 15")
    print(f"{Fore.GREEN}Timeout: 30 seconds")
    
    generate_sample_output()

if __name__ == "__main__":
    main()
