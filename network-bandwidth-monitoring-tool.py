import sys
import time
import argparse
import psutil
from collections import defaultdict
from datetime import datetime
import socket
import threading
import csv
import platform
import os
from typing import Dict, List, Tuple, Optional

class BandwidthMonitorCLI:
    def __init__(self):
        self.monitoring = False
        self.start_time = None
        self.traffic_data = defaultdict(lambda: {'upload': 0, 'download': 0})
        self.historical_data = []
        self.update_interval = 2  # seconds
        self.old_stats = {}
        self.current_interface = None
        self.target_ip = None
        self.running = True
        self.display_thread = None
        self.monitor_thread = None
        self.data_lock = threading.Lock()

    def clear_screen(self):
        """Clear the terminal screen"""
        if platform.system() == "Windows":
            os.system('cls')
        else:
            os.system('clear')

    def get_network_interfaces(self) -> List[str]:
        """Get available network interfaces"""
        return list(psutil.net_if_addrs().keys())

    def validate_ip(self, ip: str) -> bool:
        """Validate an IP address"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False

    def get_network_stats(self) -> Dict:
        """Get current network statistics per connection"""
        stats = {}
        connections = psutil.net_connections(kind='inet')
        
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
                ip = conn.raddr.ip
                if ip not in stats:
                    stats[ip] = {
                        'pid': conn.pid,
                        'upload': 0,
                        'download': 0,
                        'port': conn.raddr.port,
                        'protocol': self.determine_protocol(conn.raddr.port)
                    }
        return stats

    def determine_protocol(self, port: int) -> str:
        """Determine protocol based on port number"""
        common_ports = {
            20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP",
            993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP"
        }
        return common_ports.get(port, "Other")

    def monitor_bandwidth(self):
        """Background thread to monitor bandwidth"""
        while self.monitoring and self.running:
            time.sleep(self.update_interval)
            
            # Get current stats
            new_stats = self.get_network_stats()
            io_counters = psutil.net_io_counters(pernic=True).get(self.current_interface, None)
            
            if not io_counters:
                continue
            
            # Calculate deltas
            for ip, data in new_stats.items():
                if self.target_ip.lower() != 'all' and ip != self.target_ip:
                    continue
                
                if ip in self.old_stats:
                    # Calculate bytes transferred since last check
                    upload = max(0, data.get('upload', 0) - self.old_stats[ip].get('upload', 0))
                    download = max(0, data.get('download', 0) - self.old_stats[ip].get('download', 0))
                    
                    # Update traffic data
                    with self.data_lock:
                        self.traffic_data[ip]['upload'] += upload
                        self.traffic_data[ip]['download'] += download
            
            self.old_stats = new_stats

    def display_stats(self):
        """Display statistics in the terminal"""
        while self.monitoring and self.running:
            self.clear_screen()
            self.print_banner()
            self.print_current_stats()
            time.sleep(1)

    def print_banner(self):
        """Print the application banner"""
        print("╔══════════════════════════════════════════════════╗")
        print("║           NETWORK BANDWIDTH MONITOR (CLI)        ║")
        print("╠══════════════════════════════════════════════════╣")
        print(f"║ Interface: {self.current_interface:<20} Target IP: {self.target_ip:<15} ║")
        print(f"║ Status: {'ACTIVE' if self.monitoring else 'INACTIVE':<10} Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'N/A':<20} ║")
        print("╚══════════════════════════════════════════════════╝")
        print()

    def print_current_stats(self):
        """Print current bandwidth statistics"""
        with self.data_lock:
            if not self.traffic_data:
                print("No traffic data available yet...")
                return
            
            # Sort by total bandwidth
            sorted_data = sorted(
                self.traffic_data.items(),
                key=lambda x: x[1]['download'] + x[1]['upload'],
                reverse=True
            )
            
            print("┌───────────────────┬─────────────┬─────────────┬─────────────┐")
            print("│ IP Address        │ Download    │ Upload      │ Total       │")
            print("├───────────────────┼─────────────┼─────────────┼─────────────┤")
            
            for ip, data in sorted_data:
                download_mb = data['download'] / (1024 * 1024)
                upload_mb = data['upload'] / (1024 * 1024)
                total_mb = download_mb + upload_mb
                
                print(f"│ {ip:<17} │ {download_mb:>9.2f} MB │ {upload_mb:>9.2f} MB │ {total_mb:>9.2f} MB │")
            
            print("└───────────────────┴─────────────┴─────────────┴─────────────┘")
            
            # Print summary
            total_download = sum(data['download'] for data in self.traffic_data.values()) / (1024 * 1024)
            total_upload = sum(data['upload'] for data in self.traffic_data.values()) / (1024 * 1024)
            print(f"\nTotal Download: {total_download:.2f} MB | Total Upload: {total_upload:.2f} MB")
            
            # Print commands
            print("\nCommands: [s]top monitoring, [e]xport data, [q]uit")

    def start_monitoring(self, interface: str, target_ip: str):
        """Start monitoring bandwidth"""
        if self.monitoring:
            print("Monitoring is already active!")
            return
        
        self.current_interface = interface
        self.target_ip = target_ip
        self.monitoring = True
        self.start_time = datetime.now()
        self.traffic_data.clear()
        self.old_stats = self.get_network_stats()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_bandwidth, daemon=True)
        self.monitor_thread.start()
        
        # Start display thread
        self.display_thread = threading.Thread(target=self.display_stats, daemon=True)
        self.display_thread.start()
        
        # Handle user input
        self.handle_user_input()

    def stop_monitoring(self):
        """Stop monitoring bandwidth"""
        if not self.monitoring:
            print("Monitoring is not active!")
            return
        
        self.monitoring = False
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        # Save the collected data to historical records
        timestamp = datetime.now()
        with self.data_lock:
            for ip, data in self.traffic_data.items():
                self.historical_data.append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'download': data['download'] / (1024 * 1024),  # Convert to MB
                    'upload': data['upload'] / (1024 * 1024),      # Convert to MB
                    'total': (data['download'] + data['upload']) / (1024 * 1024),
                    'interface': self.current_interface,
                    'duration_seconds': duration.total_seconds()
                })
        
        print(f"\nMonitoring stopped. Duration: {duration}")
        time.sleep(2)

    def export_data(self):
        """Export collected data to CSV"""
        if not self.historical_data:
            print("No data available to export!")
            time.sleep(2)
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"bandwidth_data_{timestamp}.csv"
        
        try:
            with open(filename, 'w', newline='') as csvfile:
                fieldnames = ['timestamp', 'ip', 'download_mb', 'upload_mb', 
                             'total_mb', 'interface', 'duration_seconds']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for record in self.historical_data:
                    writer.writerow({
                        'timestamp': record['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                        'ip': record['ip'],
                        'download_mb': record['download'],
                        'upload_mb': record['upload'],
                        'total_mb': record['total'],
                        'interface': record['interface'],
                        'duration_seconds': record['duration_seconds']
                    })
            
            print(f"\nData exported to {filename}")
            time.sleep(2)
        except Exception as e:
            print(f"\nError exporting data: {str(e)}")
            time.sleep(2)

    def handle_user_input(self):
        """Handle user input during monitoring"""
        while self.monitoring and self.running:
            try:
                # Non-blocking input check
                if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                    cmd = sys.stdin.readline().strip().lower()
                    
                    if cmd == 's':
                        self.stop_monitoring()
                    elif cmd == 'e':
                        self.export_data()
                    elif cmd == 'q':
                        self.running = False
                        self.monitoring = False
            except:
                pass
            
            time.sleep(0.1)

    def interactive_setup(self):
        """Interactive setup for monitoring"""
        self.clear_screen()
        print("╔══════════════════════════════════════════════════╗")
        print("║           NETWORK BANDWIDTH MONITOR (CLI)        ║")
        print("╚══════════════════════════════════════════════════╝")
        print("\nInteractive Setup\n")
        
        # Select network interface
        interfaces = self.get_network_interfaces()
        if not interfaces:
            print("No network interfaces found!")
            return
        
        print("Available network interfaces:")
        for i, interface in enumerate(interfaces, 1):
            print(f"{i}. {interface}")
        
        while True:
            try:
                choice = int(input("\nSelect interface (number):"))
                if 1 <= choice <= len(interfaces):
                    selected_interface = interfaces[choice - 1]
                    break
                print("Invalid selection!")
            except ValueError:
                print("Please enter a number!")
        
        # Enter target IP
        print("\nEnter target IP address to monitor (or 'all' for all IPs):")
        while True:
            ip = input("IP: ").strip()
            if ip.lower() == 'all' or self.validate_ip(ip):
                break
            print("Invalid IP address format!")
        
        # Start monitoring
        self.start_monitoring(selected_interface, ip)

    def run_from_args(self, args):
        """Run the monitor with command-line arguments"""
        if not args.interface:
            print("Available network interfaces:")
            interfaces = self.get_network_interfaces()
            for i, interface in enumerate(interfaces, 1):
                print(f"{i}. {interface}")
            return
        
        if not args.ip:
            print("Please specify an IP address to monitor or 'all' for all IPs")
            return
        
        if not self.validate_ip(args.ip) and args.ip.lower() != 'all':
            print("Invalid IP address format!")
            return
        
        self.start_monitoring(args.interface, args.ip)

    def cleanup(self):
        """Clean up resources"""
        self.running = False
        self.monitoring = False
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=1)
        
        if self.display_thread and self.display_thread.is_alive():
            self.display_thread.join(timeout=1)

def main():
    parser = argparse.ArgumentParser(description="Network Bandwidth Monitor (CLI)")
    parser.add_argument('-i', '--interface', help="Network interface to monitor")
    parser.add_argument('-ip', '--ip', help="IP address to monitor (or 'all' for all IPs)")
    
    args = parser.parse_args()
    
    monitor = BandwidthMonitorCLI()
    
    try:
        if args.interface or args.ip:
            monitor.run_from_args(args)
        else:
            monitor.interactive_setup()
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
    finally:
        monitor.cleanup()

if __name__ == "__main__":
    import select
    main()