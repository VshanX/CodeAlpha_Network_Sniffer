import sys
import time
import threading
from datetime import datetime
from collections import defaultdict
import signal
import os

try:
    from scapy.all import *
    from tabulate import tabulate
    from colorama import init, Fore, Back, Style
except ImportError as e:
    print(f"Error: Missing required library - {e}")
    print("Please install required packages:")
    print("pip install scapy tabulate colorama")
    sys.exit(1)

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class NetworkSniffer:
    """Network packet sniffer class using Scapy"""
    
    def __init__(self):
        self.packets_captured = []
        self.packet_count = 0
        self.running = False
        self.interface = None
        self.stats = defaultdict(int)
        
    def check_permissions(self):
        """Check if the script is running with required privileges"""
        try:
            # Try to create a simple packet to test permissions
            test_packet = IP(dst="8.8.8.8")/ICMP()
            return True
        except OSError:
            return False
    
    def get_available_interfaces(self):
        """Get list of available network interfaces"""
        try:
            interfaces = get_if_list()
            return interfaces
        except Exception as e:
            print(f"{Fore.RED}Error getting interfaces: {e}")
            return []
    
    def select_interface(self):
        """Prompt user to select a network interface"""
        interfaces = self.get_available_interfaces()
        
        if not interfaces:
            print(f"{Fore.RED}No network interfaces found!")
            return None
        
        print(f"\n{Fore.CYAN}Available Network Interfaces:")
        print(f"{Fore.CYAN}{'='*50}")
        
        for i, iface in enumerate(interfaces, 1):
            try:
                # Try to get interface info
                ip = get_if_addr(iface)
                print(f"{Fore.YELLOW}{i}. {iface} (IP: {ip})")
            except:
                print(f"{Fore.YELLOW}{i}. {iface} (IP: Not available)")
        
        while True:
            try:
                choice = input(f"\n{Fore.GREEN}Select interface (1-{len(interfaces)}) or press Enter for default: ")
                
                if choice == "":
                    # Use default interface
                    self.interface = conf.iface
                    print(f"{Fore.GREEN}Using default interface: {self.interface}")
                    break
                
                choice = int(choice)
                if 1 <= choice <= len(interfaces):
                    self.interface = interfaces[choice - 1]
                    print(f"{Fore.GREEN}Selected interface: {self.interface}")
                    break
                else:
                    print(f"{Fore.RED}Invalid choice. Please select 1-{len(interfaces)}")
            
            except ValueError:
                print(f"{Fore.RED}Invalid input. Please enter a number.")
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Cancelled by user.")
                return None
        
        return self.interface
    
    def extract_packet_info(self, packet):
        """Extract relevant information from a packet"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Initialize packet info
        packet_info = {
            'timestamp': timestamp,
            'src_ip': 'N/A',
            'dst_ip': 'N/A',
            'protocol': 'Unknown',
            'length': len(packet),
            'payload_summary': 'N/A'
        }
        
        # Extract IP information
        if packet.haslayer(IP):
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            
            # Determine protocol
            if packet.haslayer(TCP):
                packet_info['protocol'] = 'TCP'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                packet_info['payload_summary'] = f"Port {src_port} → {dst_port}"
                
                # Check for HTTP traffic
                if src_port == 80 or dst_port == 80 or src_port == 8080 or dst_port == 8080:
                    packet_info['protocol'] = 'HTTP'
                    if packet.haslayer(Raw):
                        raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
                        packet_info['payload_summary'] = raw_data[:50].replace('\n', ' ').replace('\r', '')
                
                # Check for HTTPS traffic
                elif src_port == 443 or dst_port == 443:
                    packet_info['protocol'] = 'HTTPS'
                    packet_info['payload_summary'] = f"TLS Port {src_port} → {dst_port}"
                
                # Check for other common protocols
                elif src_port == 22 or dst_port == 22:
                    packet_info['protocol'] = 'SSH'
                elif src_port == 21 or dst_port == 21:
                    packet_info['protocol'] = 'FTP'
                elif src_port == 25 or dst_port == 25:
                    packet_info['protocol'] = 'SMTP'
                
            elif packet.haslayer(UDP):
                packet_info['protocol'] = 'UDP'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                packet_info['payload_summary'] = f"Port {src_port} → {dst_port}"
                
                # Check for DNS traffic
                if src_port == 53 or dst_port == 53:
                    packet_info['protocol'] = 'DNS'
                    if packet.haslayer(DNS):
                        if packet[DNS].qr == 0:  # Query
                            packet_info['payload_summary'] = f"Query: {packet[DNS].qd.qname.decode()}"
                        else:  # Response
                            packet_info['payload_summary'] = f"Response: {packet[DNS].ancount} answers"
                
                # Check for DHCP traffic
                elif src_port == 67 or dst_port == 67 or src_port == 68 or dst_port == 68:
                    packet_info['protocol'] = 'DHCP'
            
            elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                packet_info['payload_summary'] = f"Type: {icmp_type}, Code: {icmp_code}"
        
        # Handle IPv6
        elif packet.haslayer(IPv6):
            packet_info['src_ip'] = packet[IPv6].src
            packet_info['dst_ip'] = packet[IPv6].dst
            packet_info['protocol'] = 'IPv6'
        
        # Handle ARP
        elif packet.haslayer(ARP):
            packet_info['src_ip'] = packet[ARP].psrc
            packet_info['dst_ip'] = packet[ARP].pdst
            packet_info['protocol'] = 'ARP'
            packet_info['payload_summary'] = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"
        
        return packet_info
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        try:
            self.packet_count += 1
            packet_info = self.extract_packet_info(packet)
            self.packets_captured.append(packet_info)
            self.stats[packet_info['protocol']] += 1
            
            # Display packet info in real-time (optional)
            if self.packet_count <= 100:  # Limit real-time display to avoid clutter
                self.display_packet(packet_info)
            
        except Exception as e:
            print(f"{Fore.RED}Error processing packet: {e}")
    
    def display_packet(self, packet_info):
        """Display individual packet information"""
        color = Fore.GREEN
        if packet_info['protocol'] in ['HTTP', 'HTTPS']:
            color = Fore.CYAN
        elif packet_info['protocol'] == 'DNS':
            color = Fore.YELLOW
        elif packet_info['protocol'] == 'ICMP':
            color = Fore.MAGENTA
        
        print(f"{color}[{packet_info['timestamp']}] "
              f"{packet_info['protocol']:8} "
              f"{packet_info['src_ip']:15} → {packet_info['dst_ip']:15} "
              f"({packet_info['length']:4} bytes) "
              f"{packet_info['payload_summary'][:40]}")
    
    def display_summary_table(self):
        """Display captured packets in a formatted table"""
        if not self.packets_captured:
            print(f"{Fore.YELLOW}No packets captured.")
            return
        
        print(f"\n{Fore.CYAN}{'='*100}")
        print(f"{Fore.CYAN}NETWORK PACKET CAPTURE SUMMARY")
        print(f"{Fore.CYAN}{'='*100}")
        
        # Prepare table data
        table_data = []
        for i, packet in enumerate(self.packets_captured[:50], 1):  # Show first 50 packets
            table_data.append([
                i,
                packet['timestamp'],
                packet['protocol'],
                packet['src_ip'],
                packet['dst_ip'],
                packet['length'],
                packet['payload_summary'][:40] + '...' if len(packet['payload_summary']) > 40 else packet['payload_summary']
            ])
        
        headers = ['#', 'Timestamp', 'Protocol', 'Source IP', 'Dest IP', 'Length', 'Payload Summary']
        
        print(tabulate(table_data, headers=headers, tablefmt='grid'))
        
        # Display statistics
        print(f"\n{Fore.CYAN}PROTOCOL STATISTICS:")
        print(f"{Fore.CYAN}{'-'*40}")
        
        stats_data = []
        for protocol, count in sorted(self.stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / self.packet_count) * 100
            stats_data.append([protocol, count, f"{percentage:.1f}%"])
        
        print(tabulate(stats_data, headers=['Protocol', 'Count', 'Percentage'], tablefmt='grid'))
        print(f"\n{Fore.GREEN}Total packets captured: {self.packet_count}")
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n{Fore.YELLOW}Stopping packet capture...")
        self.running = False
    
    def start_capture(self, packet_count=0, timeout=None):
        """Start packet capture"""
        if not self.interface:
            print(f"{Fore.RED}No interface selected!")
            return
        
        print(f"\n{Fore.GREEN}Starting packet capture on interface: {self.interface}")
        print(f"{Fore.GREEN}Press Ctrl+C to stop capture...")
        print(f"{Fore.CYAN}{'-'*80}")
        
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        
        self.running = True
        
        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                count=packet_count if packet_count > 0 else 0,
                timeout=timeout,
                stop_filter=lambda x: not self.running
            )
        
        except PermissionError:
            print(f"{Fore.RED}Permission denied! Please run as administrator/root.")
            return False
        except Exception as e:
            print(f"{Fore.RED}Error during packet capture: {e}")
            return False
        
        return True

def print_banner():
    """Print application banner"""
    banner = f"""
{Fore.CYAN}{'='*80}
{Fore.CYAN}                    NETWORK PACKET SNIFFER
{Fore.CYAN}                   Built with Python & Scapy
{Fore.CYAN}{'='*80}
{Fore.YELLOW}This tool captures and analyzes network traffic packets in real-time.
{Fore.YELLOW}Ensure you have administrator/root privileges before running.
{Fore.CYAN}{'='*80}
"""
    print(banner)

def main():
    """Main function"""
    print_banner()
    
    # Create sniffer instance
    sniffer = NetworkSniffer()
    
    # Check permissions
    if not sniffer.check_permissions():
        print(f"{Fore.RED}Warning: May need administrator/root privileges for full functionality.")
        
        # On Windows, check if running as administrator
        if os.name == 'nt':
            try:
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    print(f"{Fore.RED}Please run this script as Administrator on Windows.")
                    input("Press Enter to continue anyway...")
            except:
                pass
    
    # Select network interface
    if not sniffer.select_interface():
        print(f"{Fore.RED}No interface selected. Exiting.")
        return
    
    # Get capture parameters
    try:
        print(f"\n{Fore.CYAN}Capture Options:")
        packet_limit = input(f"{Fore.GREEN}Enter packet limit (0 for unlimited): ")
        packet_limit = int(packet_limit) if packet_limit.isdigit() else 0
        
        timeout = input(f"{Fore.GREEN}Enter timeout in seconds (Enter for none): ")
        timeout = int(timeout) if timeout.isdigit() else None
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Cancelled by user.")
        return
    
    # Start packet capture
    if sniffer.start_capture(packet_count=packet_limit, timeout=timeout):
        # Display results
        sniffer.display_summary_table()
    
    print(f"\n{Fore.GREEN}Packet capture completed. Thank you for using Network Sniffer!")

# Sample output demonstration
def generate_sample_output():
    """Generate sample output for demonstration"""
    sample_output = f"""
{Fore.CYAN}{'='*100}
{Fore.CYAN}SAMPLE OUTPUT - NETWORK PACKET CAPTURE SUMMARY
{Fore.CYAN}{'='*100}

{Fore.GREEN}[14:23:45.123] HTTP     192.168.1.100   → 93.184.216.34   ( 567 bytes) GET /index.html HTTP/1.1
{Fore.YELLOW}[14:23:45.145] DNS      192.168.1.100   → 8.8.8.8         ( 78 bytes) Query: www.example.com
{Fore.YELLOW}[14:23:45.167] DNS      8.8.8.8         → 192.168.1.100   ( 94 bytes) Response: 1 answers
{Fore.CYAN}[14:23:45.189] HTTPS    192.168.1.100   → 172.217.14.110   ( 1420 bytes) TLS Port 52341 → 443
{Fore.MAGENTA}[14:23:45.234] ICMP     192.168.1.1     → 192.168.1.100   ( 64 bytes) Type: 0, Code: 0

+---+---------------+----------+-----------------+-----------------+--------+------------------------------------------+
| # | Timestamp     | Protocol | Source IP       | Dest IP         | Length | Payload Summary                          |
+===+===============+==========+=================+=================+========+==========================================+
| 1 | 14:23:45.123  | HTTP     | 192.168.1.100   | 93.184.216.34   | 567    | GET /index.html HTTP/1.1                 |
| 2 | 14:23:45.145  | DNS      | 192.168.1.100   | 8.8.8.8         | 78     | Query: www.example.com                   |
| 3 | 14:23:45.167  | DNS      | 8.8.8.8         | 192.168.1.100   | 94     | Response: 1 answers                      |
| 4 | 14:23:45.189  | HTTPS    | 192.168.1.100   | 172.217.14.110  | 1420   | TLS Port 52341 → 443                    |
| 5 | 14:23:45.234  | ICMP     | 192.168.1.1     | 192.168.1.100   | 64     | Type: 0, Code: 0                        |
+---+---------------+----------+-----------------+-----------------+--------+------------------------------------------+

{Fore.CYAN}PROTOCOL STATISTICS:
{Fore.CYAN}{'-'*40}
+----------+-------+------------+
| Protocol | Count | Percentage |
+==========+=======+============+
| HTTPS    | 15    | 42.9%      |
| HTTP     | 8     | 22.9%      |
| DNS      | 6     | 17.1%      |
| TCP      | 4     | 11.4%      |
| ICMP     | 2     | 5.7%       |
+----------+-------+------------+

{Fore.GREEN}Total packets captured: 35
"""
    print(sample_output)

if __name__ == "__main__":
    # Uncomment the line below to see sample output
    # generate_sample_output()
    
    main()
