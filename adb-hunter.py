#!/usr/bin/env python3

import re
import socket
import argparse
import ipaddress
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from datetime import datetime

class GlobalADBScanner:
    def __init__(self):
        self.found_count = 0
        self.scanned_count = 0
        self.total_targets = 0
        self.start_time = None
        self.lock = threading.Lock()
        self.console_width = 80
        self.running = True
        
        # Color codes
        self.COLOR_RED = "\033[91m"
        self.COLOR_GREEN = "\033[92m"
        self.COLOR_YELLOW = "\033[93m"
        self.COLOR_BLUE = "\033[94m"
        self.COLOR_MAGENTA = "\033[95m"
        self.COLOR_CYAN = "\033[96m"
        self.COLOR_WHITE = "\033[97m"
        self.COLOR_RESET = "\033[0m"
        self.COLOR_BOLD = "\033[1m"
        
        # List of regions to target
        self.regions = [
            "north america", "europe", "asia", 
            "south america", "africa", "australia"
        ]
        
        # Common ports that might have ADB
        self.ports = [5555, 5554, 5556, 5557]

    def generate_random_ips(self, count, region=None):
        """
        Generate random IP addresses, optionally biased toward a specific region
        """
        ips = []
        
        for _ in range(count):
            # Different IP ranges for different regions
            if region == "north america":
                first_octet = random.choice([
                    3, 4, 6, 8, 9, 12, 15, 16, 17, 18, 19, 20, 23, 24, 26, 28, 29, 30, 31, 32,
                    33, 34, 35, 38, 40, 44, 45, 47, 48, 50, 52, 54, 55, 56, 63, 64, 65, 66, 67,
                    68, 69, 70, 71, 72, 73, 74, 75, 76, 96, 97, 98, 99, 100, 104, 107, 108, 128,
                    129, 130, 131, 132, 134, 135, 136, 137, 138, 139, 140, 142, 143, 144, 146,
                    147, 148, 149, 152, 155, 156, 157, 158, 159, 160, 161, 162, 164, 165, 166,
                    167, 168, 169, 170, 172, 173, 174, 184, 192, 198, 199, 204, 205, 206, 207,
                    208, 209, 216
                ])
            elif region == "europe":
                first_octet = random.choice([
                    2, 5, 31, 37, 46, 51, 53, 57, 58, 59, 60, 62, 77, 78, 79, 80, 81, 82, 83, 84,
                    85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 141, 145, 151, 153, 154, 176,
                    177, 178, 179, 185, 188, 193, 194, 195, 212, 213, 217
                ])
            elif region == "asia":
                first_octet = random.choice([
                    1, 14, 27, 36, 39, 42, 43, 49, 61, 101, 102, 103, 106, 110, 111, 112, 113, 114,
                    115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 133, 150, 163, 175,
                    180, 182, 183, 186, 187, 189, 190, 191, 196, 197, 200, 202, 203, 210, 211, 218,
                    219, 220, 221, 222, 223
                ])
            else:
                # Global IP (any valid non-private first octet)
                first_octet = random.randint(1, 223)
                while first_octet in (10, 127, 169, 172, 192):
                    first_octet = random.randint(1, 223)
            
            # Generate the rest of the IP
            ip = f"{first_octet}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            ips.append(ip)
        
        return ips

    def parse_targets(self, targets):
        """Parse targets which can be single IP, CIDR, or IP range"""
        all_ips = []
        
        for target in targets:
            if '-' in target:
                # IP range format (e.g., 192.168.1.1-192.168.1.100)
                ips = self.handle_ip_range(target)
                all_ips.extend(ips)
            elif '/' in target:
                # CIDR format
                ips = self.handle_cidr(target)
                all_ips.extend(ips)
            else:
                # Single IP
                all_ips.append(target)
                print(f"{self.COLOR_CYAN}Single IP target: {target}{self.COLOR_RESET}")
        
        return all_ips

    def handle_ip_range(self, ip_range):
        """Handle IP range format (192.168.1.1-192.168.1.100)"""
        try:
            start_ip, end_ip = ip_range.split('-')
            start_int = int(ipaddress.IPv4Address(start_ip.strip()))
            end_int = int(ipaddress.IPv4Address(end_ip.strip()))
            
            range_size = end_int - start_int + 1
            
            print(f"{self.COLOR_CYAN}IP range {ip_range} contains {range_size:,} IPs - generating all targets...{self.COLOR_RESET}")
            
            # Generate all IPs in the range - no limits!
            ips = [str(ipaddress.IPv4Address(ip_int)) for ip_int in range(start_int, end_int + 1)]
            return ips
                
        except Exception as e:
            print(f"{self.COLOR_RED}Error parsing IP range {ip_range}: {e}{self.COLOR_RESET}")
            return []

    def handle_cidr(self, cidr):
        """Handle CIDR notation"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            network_ips = [str(ip) for ip in network.hosts()]
            network_size = len(network_ips)
            
            print(f"{self.COLOR_CYAN}CIDR {cidr} contains {network_size:,} IPs - generating all targets...{self.COLOR_RESET}")
            return network_ips
                
        except Exception as e:
            print(f"{self.COLOR_RED}Invalid CIDR range: {cidr} - {e}{self.COLOR_RESET}")
            return []

    def get_ip_range_info(self, target):
        """Get information about an IP range including approximate region"""
        try:
            # Get a sample IP from the range to determine region
            if '-' in target:
                sample_ip = target.split('-')[0].strip()
            elif '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                sample_ip = str(list(network.hosts())[0]) if network.num_addresses > 1 else str(network.network_address)
            else:
                sample_ip = target
                
            # Get geolocation for the sample IP
            country, city, isp = self.get_geolocation(sample_ip)
            return country, city, isp
        except:
            return "Unknown", "Unknown", "Unknown"

    def retrieve(self, ip, port=5555):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((str(ip), port))
            if result != 0:
                return None, port
                
            sock.send(b"\x43\x4e\x58\x4e\x00\x00\x00\x01\x00\x10\x00\x00\x07\x00\x00\x00\x32\x02\x00\x00\xbc\xb1\xa7\xb1\x68\x6f\x73\x74\x3a\x3a\x00")
            data = sock.recv(2048)
            sock.close()
            return data.decode('utf-8', 'ignore'), port
        except Exception:
            return None, port

    def scanner(self, ip, data, port, output_file=None):
        if data and 'product' in data:
            try:
                product_name = re.search(r"product\.name=(.*?);", data)
                product_model = re.search(r"ro\.product\.model=(.*?);", data)
                product_device = re.search(r";ro\.product\.device=(.*?);", data)
                
                # Get geolocation info
                country, city, isp = self.get_geolocation(ip)
                
                if product_name and product_model and product_device:
                    result = f"{self.COLOR_GREEN}{self.COLOR_BOLD}[+]{self.COLOR_RESET} {self.COLOR_GREEN}ADB Found{self.COLOR_RESET} | " \
                             f"{self.COLOR_CYAN}Target:{self.COLOR_RESET} {ip}:{port} | " \
                             f"{self.COLOR_MAGENTA}Product:{self.COLOR_RESET} {product_name.group(1)} | " \
                             f"{self.COLOR_MAGENTA}Model:{self.COLOR_RESET} {product_model.group(1)} | " \
                             f"{self.COLOR_MAGENTA}Device:{self.COLOR_RESET} {product_device.group(1)} | " \
                             f"{self.COLOR_YELLOW}Location:{self.COLOR_RESET} {city}, {country} | " \
                             f"{self.COLOR_YELLOW}ISP:{self.COLOR_RESET} {isp}"
                    
                    # Print result
                    print(result)
                    
                    # Write to file if specified (without color codes)
                    if output_file:
                        clean_result = f"[+] ADB Found | Target: {ip}:{port} | " \
                                       f"Product: {product_name.group(1)} | " \
                                       f"Model: {product_model.group(1)} | " \
                                       f"Device: {product_device.group(1)} | " \
                                       f"Location: {city}, {country} | " \
                                       f"ISP: {isp}"
                        with self.lock:
                            with open(output_file, "a") as file:
                                file.write(clean_result + "\n")
                    
                    # Update found count
                    self.found_count += 1
                    
                    # Update status line
                    self.print_status()
            except Exception as e:
                pass

    def get_geolocation(self, ip):
        """Get approximate geolocation for an IP address"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = response.json()
            if data['status'] == 'success':
                return data.get('country', 'Unknown'), data.get('city', 'Unknown'), data.get('isp', 'Unknown')
        except:
            pass
        return "Unknown", "Unknown", "Unknown"

    def print_status(self):
        elapsed = time.time() - self.start_time
        rate = self.scanned_count / elapsed if elapsed > 0 else 0
        
        status = f"{self.COLOR_BLUE}Found:{self.COLOR_RESET} {self.COLOR_GREEN}{self.found_count}{self.COLOR_RESET} | " \
                 f"{self.COLOR_BLUE}Scanned:{self.COLOR_RESET} {self.COLOR_YELLOW}{self.scanned_count}{self.COLOR_RESET}/{self.COLOR_YELLOW}{self.total_targets}{self.COLOR_RESET} | " \
                 f"{self.COLOR_BLUE}Elapsed:{self.COLOR_RESET} {self.COLOR_CYAN}{elapsed:.1f}s{self.COLOR_RESET} | " \
                 f"{self.COLOR_BLUE}Rate:{self.COLOR_RESET} {self.COLOR_MAGENTA}{rate:.1f} targets/s{self.COLOR_RESET}"
        
        # Clear line and print status
        print("\r" + " " * self.console_width, end="")
        print(f"\r{status}", end="", flush=True)

    def scan_batch(self, ips, output_file=None, ports=None, threads=50, is_continuous=False):
        """Scan a batch of IP addresses"""
        if ports is None:
            ports = self.ports
            
        targets = []
        for ip in ips:
            for port in ports:
                targets.append((ip, port))
                
        # For continuous mode, we need to accumulate the total targets
        if not is_continuous:
            self.total_targets = len(targets)
        
        print(f"{self.COLOR_CYAN}Starting scan of {len(targets):,} targets...{self.COLOR_RESET}")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.retrieve, ip, port): (ip, port) for ip, port in targets}
            
            for future in as_completed(futures):
                if not self.running:
                    break
                    
                ip, port = futures[future]
                data, port = future.result()
                self.scanned_count += 1
                
                if data:
                    self.scanner(ip, data, port, output_file)
                
                # Update status every 100 targets or when complete
                if self.scanned_count % 100 == 0 or self.scanned_count == self.total_targets:
                    self.print_status()

    def continuous_scan(self, output_file=None, regions=None, threads=50, batch_size=1000):
        """Continuously scan random IP addresses from different regions"""
        if regions is None:
            regions = self.regions
            
        print(f"{self.COLOR_CYAN}Starting continuous scan of regions: {self.COLOR_YELLOW}{', '.join(regions)}{self.COLOR_RESET}")
        print(f"{self.COLOR_CYAN}Press Ctrl+C to stop the continuous scan{self.COLOR_RESET}")
        self.start_time = time.time()
        
        # For continuous mode, we'll set total_targets to a large number for display purposes
        self.total_targets = float('inf')
        
        try:
            while self.running:
                # Select a random region for this batch
                region = random.choice(regions)
                
                # Generate a batch of random IPs from this region
                ips = self.generate_random_ips(batch_size, region)
                
                # Scan the batch
                self.scan_batch(ips, output_file, self.ports, threads, is_continuous=True)
                
                # Print status after each batch
                self.print_status()
                print(f" {self.COLOR_WHITE}|{self.COLOR_RESET} {self.COLOR_CYAN}Next batch:{self.COLOR_RESET} {self.COLOR_YELLOW}{batch_size}{self.COLOR_RESET} {self.COLOR_CYAN}IPs from{self.COLOR_RESET} {self.COLOR_MAGENTA}{region}{self.COLOR_RESET}")
                
                # Small delay between batches
                time.sleep(1)
                
        except KeyboardInterrupt:
            print(f"\n{self.COLOR_RED}Scan interrupted by user.{self.COLOR_RESET}")
        finally:
            self.running = False

    def scan_specific_targets(self, targets, output_file=None, threads=50):
        """Scan specific IP addresses or ranges"""
        print(f"{self.COLOR_CYAN}{self.COLOR_BOLD}=== ADB Scanner - Specific Target Mode ==={self.COLOR_RESET}")
        
        for target in targets:
            country, city, isp = self.get_ip_range_info(target)
            if '-' in target:
                print(f"{self.COLOR_CYAN}Scanning IP range: {self.COLOR_YELLOW}{target}{self.COLOR_RESET}")
            elif '/' in target:
                print(f"{self.COLOR_CYAN}Scanning network: {self.COLOR_YELLOW}{target}{self.COLOR_RESET}")
            else:
                print(f"{self.COLOR_CYAN}Scanning IP: {self.COLOR_YELLOW}{target}{self.COLOR_RESET}")
            
            print(f"{self.COLOR_CYAN}Approximate location: {self.COLOR_YELLOW}{city}, {country}{self.COLOR_RESET}")
            print()
        
        # Parse all targets into individual IPs
        all_ips = self.parse_targets(targets)
                
        self.total_targets = len(all_ips) * len(self.ports)
        self.start_time = time.time()
        
        print(f"{self.COLOR_CYAN}Total targets: {self.COLOR_YELLOW}{self.total_targets:,}{self.COLOR_RESET}")
        print(f"{self.COLOR_CYAN}Threads: {self.COLOR_YELLOW}{threads}{self.COLOR_RESET}")
        print()
        
        self.scan_batch(all_ips, output_file, self.ports, threads, is_continuous=False)

    def main(self):
        parser = argparse.ArgumentParser(description="Global ADB Scanner - Find exposed Android Debug Bridge devices")
        parser.add_argument('-ip', '--ipaddress', type=str, nargs='+', help="IP address(es) to scan, CIDR notation, or IP range (e.g., 192.168.1.1-192.168.1.100).")
        parser.add_argument('-f', '--file', type=str, help="File containing IP addresses to scan.")
        parser.add_argument('-o', '--output', type=str, required=True, help="File to store results.")
        parser.add_argument('-t', '--threads', type=int, default=100, help="Number of threads (default: 100).")
        parser.add_argument('-r', '--regions', type=str, nargs='+', choices=self.regions, help="Regions to focus on.")
        parser.add_argument('-p', '--ports', type=int, nargs='+', help="Ports to scan (default: 5555, 5554, 5556, 5557).")
        parser.add_argument('-b', '--batch', type=int, default=1000, help="Batch size for continuous scanning (default: 1000).")
        parser.add_argument('-c', '--continuous', action='store_true', help="Continuous random scanning.")

        args = parser.parse_args()
        
        # Set console width for status display
        try:
            import os
            self.console_width = os.get_terminal_size().columns
        except:
            self.console_width = 80

        # Create output file immediately if specified
        if args.output:
            with open(args.output, "w") as f:
                f.write("Global ADB Scanner Results\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Update ports if specified
        if args.ports:
            self.ports = args.ports

        # Run the appropriate scan
        try:
            if args.continuous:
                # Continuous random scanning
                self.continuous_scan(
                    output_file=args.output, 
                    regions=args.regions,
                    threads=args.threads,
                    batch_size=args.batch
                )
            elif args.ipaddress:
                # Scan specific IP addresses/ranges
                self.scan_specific_targets(
                    targets=args.ipaddress,
                    output_file=args.output,
                    threads=args.threads
                )
            elif args.file:
                # Scan IPs from a file
                with open(args.file, "r") as f:
                    targets = [line.strip() for line in f if line.strip()]
                
                self.scan_specific_targets(
                    targets=targets,
                    output_file=args.output,
                    threads=args.threads
                )
            else:
                parser.print_help()
                return
            
            # Final status update
            print("\n")  # Move to next line after status
            elapsed = time.time() - self.start_time
            print(f"{self.COLOR_GREEN}Scan completed in {elapsed:.1f} seconds. Found {self.found_count} targets.{self.COLOR_RESET}")
            
            # Write summary to output file
            if args.output:
                with open(args.output, "a") as f:
                    f.write(f"\nScan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total targets scanned: {self.scanned_count}\n")
                    f.write(f"Total devices found: {self.found_count}\n")
                    f.write(f"Scan duration: {elapsed:.1f} seconds\n")
                    
        except KeyboardInterrupt:
            print(f"\n\n{self.COLOR_RED}Scan interrupted by user.{self.COLOR_RESET}")
            if args.output:
                with open(args.output, "a") as f:
                    f.write(f"\nScan interrupted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Targets scanned: {self.scanned_count}\n")
                    f.write(f"Devices found: {self.found_count}\n")
        finally:
            self.running = False

if __name__ == "__main__":
    scanner = GlobalADBScanner()
    scanner.main()