#!/usr/bin/env python3
"""
Nmap Integration Tool with Advanced Firewall Bypass Techniques
- Specialized techniques to overcome tcpwrapped responses
- Multiple evasion strategies against common firewall technologies
- Optimized for time-constrained pentesting scenarios

Author: elementalsouls
Date: 2025-06-13
"""

import subprocess
import argparse
import os
import sys
import time
import re
import ipaddress
import json
import xml.etree.ElementTree as ET
from datetime import datetime
import threading
import queue
from concurrent.futures import ThreadPoolExecutor
import random

class NmapFirewallBypass:
    def __init__(self, targets, output_dir="nmap_results", threads=5, 
                 quick_mode=False, evasion_level=2, tcp_only=False):
        self.targets = self._parse_targets(targets)
        self.output_dir = output_dir
        self.threads = threads
        self.quick_mode = quick_mode
        self.evasion_level = evasion_level  # 1=basic, 2=moderate, 3=aggressive evasion
        self.tcp_only = tcp_only
        self.scan_queue = queue.Queue()
        self.results = {}
        self.wrapped_ports = {}  # Track tcpwrapped ports for further investigation
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def _parse_targets(self, targets):
        """Parse targets from file or list."""
        all_targets = []
        
        # Check if targets is a file path
        if os.path.isfile(targets):
            with open(targets, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        all_targets.extend(self._expand_target(line))
        else:
            # Assume targets is a single target or comma-separated list
            for target in targets.split(','):
                all_targets.extend(self._expand_target(target.strip()))
                
        return all_targets
    
    def _expand_target(self, target):
        """Expand target if it's a network range."""
        expanded = []
        try:
            # Check if it's a CIDR notation (e.g., 192.168.1.0/24)
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                # For large networks, don't expand to save memory
                if network.num_addresses > 256:
                    return [target]  # Return CIDR notation for nmap to handle
                expanded = [str(ip) for ip in network.hosts()]
            else:
                expanded = [target]
        except Exception as e:
            print(f"[!] Error parsing target {target}: {str(e)}")
            expanded = []
            
        return expanded

    def analyze_host(self, host):
        """Quick analysis of a host to determine optimal scan method."""
        print(f"[*] Analyzing {host} to determine optimal scan strategy...")
        
        # Use a quick Nmap ping scan to check if host is up and responsive
        cmd = f"nmap -sn -T4 --min-parallelism 10 {host}"
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            host_is_up = "Host is up" in result.stdout
            latency = None
            
            # Extract latency if available
            if host_is_up:
                latency_match = re.search(r"Host is up \(([\d.]+)s latency\)", result.stdout)
                if latency_match:
                    latency = float(latency_match.group(1))
            
            # Check firewall characteristics with a quick ACK scan
            firewall_probe_cmd = f"nmap -sA -T4 -p 80,443,22,21 {host}"
            fw_result = subprocess.run(firewall_probe_cmd, shell=True, capture_output=True, text=True)
            
            # Analyze firewall behavior
            firewall_type = self._analyze_firewall_behavior(fw_result.stdout)
            
            return {
                "is_up": host_is_up,
                "latency": latency,
                "firewall_type": firewall_type,
                "scan_strategy": self._determine_scan_strategy(latency, firewall_type)
            }
        except Exception as e:
            print(f"[!] Error analyzing {host}: {str(e)}")
            return {"is_up": False, "scan_strategy": "default", "firewall_type": "unknown"}
    
    def _analyze_firewall_behavior(self, scan_output):
        """Analyze firewall behavior based on scan output."""
        if "filtered" in scan_output and "unfiltered" not in scan_output:
            return "strict"  # Strict firewall, blocks everything
        elif "filtered" in scan_output and "unfiltered" in scan_output:
            return "stateful"  # Stateful firewall, allows some established connections
        elif "tcpwrapped" in scan_output:
            return "application_proxy"  # Application layer proxy/firewall
        else:
            return "permissive"  # More permissive firewall or no firewall
    
    def _determine_scan_strategy(self, latency, firewall_type):
        """Determine scan strategy based on latency and firewall type."""
        if firewall_type == "strict":
            return "fragmentation"  # Use fragmentation to bypass strict firewalls
        elif firewall_type == "application_proxy":
            return "service_bypass"  # Use service-specific payloads
        elif firewall_type == "stateful":
            return "decoy"  # Use decoy scan to confuse stateful tracking
        
        # Fallback based on latency
        if latency is None:
            return "normal"
        elif latency < 0.05:
            return "aggressive"
        elif latency < 0.2:
            return "normal"
        else:
            return "conservative"

    def _get_source_port_options(self):
        """Get source port options to bypass port-based firewall rules."""
        # Common allowed source ports that firewalls often permit
        common_ports = [53, 80, 443, 20, 21, 25]
        selected_port = random.choice(common_ports)
        return f"--source-port {selected_port}"
    
    def _get_fragmentation_options(self):
        """Get packet fragmentation options based on evasion level."""
        if self.evasion_level == 1:
            return "-f"  # Basic fragmentation
        elif self.evasion_level == 2:
            return "-ff"  # More fragmentation
        else:
            return f"-f --mtu {random.choice([8, 16, 24, 32])}"  # Custom MTU
    
    def _get_decoy_options(self):
        """Get decoy scan options based on evasion level."""
        if self.evasion_level == 1:
            return "-D RND:3"  # 3 random decoys
        elif self.evasion_level == 2:
            return "-D RND:5"  # 5 random decoys
        else:
            # Custom decoys plus random ones
            return f"-D 10.0.0.1,RND:3,ME"
    
    def _get_timing_options(self, strategy):
        """Get timing options based on strategy."""
        if strategy == "aggressive":
            return "-T4 --max-retries 1 --min-rate 1000"
        elif strategy == "normal":
            return "-T3 --max-retries 2"
        elif strategy == "conservative":
            return "-T2 --max-retries 3"
        else:
            return "-T3"  # Default

    def build_nmap_command(self, host, scan_phase, host_profile=None):
        """Build Nmap command based on scan phase and host profile."""
        base_output = f"{self.output_dir}/{host.replace('/', '_').replace(':', '_')}"
        
        # Default profile if none provided
        if not host_profile:
            host_profile = {"scan_strategy": "normal", "firewall_type": "unknown"}
            
        # Get strategy specific options
        strategy = host_profile.get("scan_strategy", "normal")
        timing_opts = self._get_timing_options(strategy)
        
        # Define scan phases with firewall evasion techniques
        if scan_phase == "discovery":
            # Initial discovery scan
            scan_type = "-sS"  # Default to SYN scan
            
            # Add evasion techniques based on firewall type
            evasion_opts = ""
            if host_profile.get("firewall_type") == "strict":
                evasion_opts = self._get_fragmentation_options()
            elif host_profile.get("firewall_type") == "stateful":
                evasion_opts = self._get_decoy_options()
            elif host_profile.get("firewall_type") == "application_proxy":
                evasion_opts = self._get_source_port_options()
                
            if self.quick_mode:
                return f"nmap {scan_type} {timing_opts} {evasion_opts} --open --top-ports 1000 -oX {base_output}_discovery.xml {host}"
            else:
                return f"nmap {scan_type} {timing_opts} {evasion_opts} --open -p- -oX {base_output}_discovery.xml {host}"
        
        elif scan_phase == "service":
            # Service detection with tcpwrapped bypass techniques
            ports_arg = f"-p {self.results[host]['ports']}" if host in self.results and self.results[host].get('ports') else ""
            
            # Always use custom scripts and aggressive version detection to avoid tcpwrapped
            service_opts = "--version-all --version-intensity 9 --script banner"
            return f"nmap -sV {service_opts} {ports_arg} -oX {base_output}_service.xml {host}"
        
        elif scan_phase == "tcpwrapped_bypass":
            # Special scan for ports identified as tcpwrapped
            if host not in self.wrapped_ports or not self.wrapped_ports[host]:
                return None
                
            wrapped_ports_str = ','.join(self.wrapped_ports[host])
            
            # Use a combination of techniques specifically for tcpwrapped ports
            return f"nmap -sV --version-all --version-intensity 9 -Pn --script banner,service-scan,ssl-enum-ciphers -p {wrapped_ports_str} --scanflags PSH -oX {base_output}_wrapped_bypass.xml {host}"
        
        elif scan_phase == "full":
            # Full comprehensive scan with firewall evasion
            evasion_opts = ""
            
            # Layer evasion techniques based on evasion level
            if self.evasion_level >= 1:
                evasion_opts += self._get_fragmentation_options() + " "
            if self.evasion_level >= 2:
                evasion_opts += self._get_source_port_options() + " "
            if self.evasion_level >= 3:
                evasion_opts += self._get_decoy_options() + " "
            
            # Add data length randomization for highest evasion
            if self.evasion_level >= 3:
                evasion_opts += f"--data-length {random.randint(10, 50)} "
            
            return f"nmap -sS {timing_opts} {evasion_opts} -p- --open -oX {base_output}_full.xml {host}"
            
        elif scan_phase == "udp" and not self.tcp_only:
            # UDP scan with firewall evasion
            return f"nmap -sU {timing_opts} --top-ports 100 -oX {base_output}_udp.xml {host}"
            
        elif scan_phase == "specific_service_probe":
            # Special probes for specific services that might be hidden behind firewalls
            if host not in self.wrapped_ports or not self.wrapped_ports[host]:
                return None
                
            wrapped_ports_str = ','.join(self.wrapped_ports[host])
            special_scripts = "--script=ftp-anon,http-title,ssh-auth-methods,smtp-commands"
            
            return f"nmap -Pn -sV {special_scripts} -p {wrapped_ports_str} -oX {base_output}_special_probe.xml {host}"
        
        return None

    def parse_nmap_xml(self, xml_file):
        """Parse Nmap XML output file."""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            result = {}
            tcpwrapped_ports = []
            
            # Get host info
            for host in root.findall('.//host'):
                addr = host.find('.//address').get('addr')
                
                if addr not in result:
                    result[addr] = {"ports": []}
                
                # Get port info
                for port in host.findall('.//port'):
                    if port.get('protocol') == 'tcp' and port.find('.//state').get('state') == 'open':
                        port_id = port.get('portid')
                        result[addr]["ports"].append(port_id)
                        
                        service_elem = port.find('.//service')
                        if service_elem is not None:
                            service = service_elem.get('name', 'unknown')
                            product = service_elem.get('product', '')
                            version = service_elem.get('version', '')
                            
                            # Check for tcpwrapped
                            if service == "tcpwrapped":
                                tcpwrapped_ports.append(port_id)
                            
                            result[addr][port_id] = {
                                "service": service,
                                "product": product,
                                "version": version
                            }
            
            return result, tcpwrapped_ports
        except Exception as e:
            print(f"[!] Error parsing XML {xml_file}: {str(e)}")
            return {}, []

    def execute_nmap(self, host, scan_phase, host_profile=None):
        """Execute Nmap command and process results."""
        cmd = self.build_nmap_command(host, scan_phase, host_profile)
        if not cmd:
            return
        
        print(f"[*] Executing: {scan_phase} scan on {host}")
        print(f"[*] Command: {cmd}")
        
        try:
            start_time = time.time()
            process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            duration = time.time() - start_time
            
            if process.returncode != 0:
                print(f"[!] Scan failed for {host} ({scan_phase}): {process.stderr.decode()}")
                return False
                
            print(f"[+] {scan_phase} scan completed for {host} in {duration:.1f}s")
            
            # Parse results for discovery and service scans
            if scan_phase in ["discovery", "full", "service", "tcpwrapped_bypass", "specific_service_probe"]:
                xml_file = f"{self.output_dir}/{host.replace('/', '_').replace(':', '_')}_{scan_phase}.xml"
                if os.path.exists(xml_file):
                    scan_results, tcpwrapped = self.parse_nmap_xml(xml_file)
                    
                    # Track tcpwrapped ports for further investigation
                    if tcpwrapped:
                        if host not in self.wrapped_ports:
                            self.wrapped_ports[host] = []
                        self.wrapped_ports[host].extend(tcpwrapped)
                        print(f"[!] Found {len(tcpwrapped)} tcpwrapped ports on {host}")
                    
                    # Update results
                    for addr, info in scan_results.items():
                        if addr not in self.results:
                            self.results[addr] = {}
                        
                        # Update ports
                        if 'ports' in info and info['ports']:
                            if 'ports' not in self.results[addr]:
                                self.results[addr]['ports'] = ','.join(info['ports'])
                            else:
                                # Merge port lists without duplicates
                                existing_ports = set(self.results[addr]['ports'].split(','))
                                new_ports = set(info['ports'])
                                all_ports = existing_ports.union(new_ports)
                                self.results[addr]['ports'] = ','.join(all_ports)
                            
                            print(f"[+] Found {len(info['ports'])} open ports on {addr}")
                            
                        # Update port details
                        for port_id in info:
                            if port_id != 'ports' and isinstance(info[port_id], dict):
                                if port_id not in self.results[addr] or info[port_id]['service'] != 'tcpwrapped':
                                    self.results[addr][port_id] = info[port_id]
            
            return True
        except Exception as e:
            print(f"[!] Error running {scan_phase} scan on {host}: {str(e)}")
            return False

    def worker(self):
        """Worker thread to process scan queue."""
        while True:
            try:
                task = self.scan_queue.get(block=False)
                if task is None:
                    break
                    
                host, scan_phase, host_profile = task
                self.execute_nmap(host, scan_phase, host_profile)
                
            except queue.Empty:
                break
            finally:
                if 'task' in locals():
                    self.scan_queue.task_done()

    def handle_tcpwrapped_ports(self):
        """Special handling for tcpwrapped ports."""
        if not self.wrapped_ports:
            return
            
        print("\n[*] Applying specialized techniques for tcpwrapped ports...")
        
        # First attempt: Custom service detection
        for host in self.wrapped_ports:
            if self.wrapped_ports[host]:
                self.scan_queue.put((host, "tcpwrapped_bypass", None))
        
        # Run these scans
        threads = []
        for _ in range(min(self.threads, len(self.wrapped_ports))):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)
            
        for t in threads:
            t.join()
            
        # Check if we still have tcpwrapped ports
        still_wrapped_hosts = {h: ports for h, ports in self.wrapped_ports.items() if ports}
        if still_wrapped_hosts:
            print("\n[*] Attempting service-specific probes for remaining tcpwrapped ports...")
            
            # Second attempt: Service-specific probing
            for host in still_wrapped_hosts:
                self.scan_queue.put((host, "specific_service_probe", None))
                
            # Run these scans
            threads = []
            for _ in range(min(self.threads, len(still_wrapped_hosts))):
                t = threading.Thread(target=self.worker)
                t.start()
                threads.append(t)
                
            for t in threads:
                t.join()

    def start(self):
        """Start the scanning process."""
        start_time = time.time()
        print(f"[*] Starting Nmap pentest with firewall bypass techniques")
        print(f"[*] Current time (UTC): {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] User: {os.getlogin() if hasattr(os, 'getlogin') else 'elementalsouls'}")
        print(f"[*] Targets: {len(self.targets)} hosts")
        print(f"[*] Evasion level: {self.evasion_level} (1=basic, 2=moderate, 3=aggressive)")
        
        # Phase 1: Host Analysis
        host_profiles = {}
        print("\n[*] Analyzing hosts to determine optimal scan strategies...")
        for host in self.targets:
            host_profiles[host] = self.analyze_host(host)
        
        # Phase 2: Initial Discovery Scans
        print("\n[*] Starting discovery scans with firewall evasion techniques...")
        for host in self.targets:
            # Skip hosts that appear down in initial analysis
            if not host_profiles[host].get('is_up', True) and self.evasion_level < 3:
                print(f"[!] Host {host} appears down, skipping (use -e 3 to force scan)")
                continue
                
            # Add discovery task to queue
            self.scan_queue.put((host, "discovery", host_profiles.get(host)))

        # Start worker threads for discovery phase
        threads = []
        for _ in range(min(self.threads, len(self.targets))):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)
            
        # Wait for all discovery scans to complete
        for t in threads:
            t.join()
            
        # Phase 3: Service Detection
        print("\n[*] Starting service detection with tcpwrapped bypassing...")
        for host in self.results:
            if 'ports' in self.results[host] and self.results[host]['ports']:
                self.scan_queue.put((host, "service", host_profiles.get(host)))
                
        # Start worker threads for service detection
        threads = []
        for _ in range(min(self.threads, len(self.results))):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)
            
        # Wait for all service scans to complete
        for t in threads:
            t.join()
            
        # Phase 4: Handle tcpwrapped ports with specialized techniques
        self.handle_tcpwrapped_ports()
        
        # Phase 5: Optional UDP Scan
        if not self.tcp_only:
            print("\n[*] Starting UDP scans for top ports...")
            for host in self.results:
                self.scan_queue.put((host, "udp", host_profiles.get(host)))
                
            # Start worker threads for UDP scans
            threads = []
            for _ in range(min(self.threads, len(self.results))):
                t = threading.Thread(target=self.worker)
                t.start()
                threads.append(t)
                
            # Wait for all UDP scans to complete
            for t in threads:
                t.join()
        
        # Generate summary report
        duration = time.time() - start_time
        self.generate_report(duration)
        
    def generate_report(self, duration):
        """Generate summary report of findings."""
        total_hosts = len(self.results)
        total_ports = sum(len(self.results[host].get('ports', '').split(',')) 
                          for host in self.results if 'ports' in self.results[host] and self.results[host].get('ports', ''))
        
        # Count remaining tcpwrapped ports after all bypass attempts
        remaining_tcpwrapped = 0
        for host in self.results:
            for port_id, port_info in self.results[host].items():
                if port_id != 'ports' and isinstance(port_info, dict) and port_info.get('service') == 'tcpwrapped':
                    remaining_tcpwrapped += 1
        
        print("\n" + "="*70)
        print(f"Scan Summary Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
        print(f"Total scan duration: {duration/60:.1f} minutes")
        print(f"Hosts scanned: {len(self.targets)}")
        print(f"Hosts with open ports: {total_hosts}")
        print(f"Total open ports discovered: {total_ports}")
        if remaining_tcpwrapped > 0:
            print(f"Remaining tcpwrapped ports: {remaining_tcpwrapped} (see recommendations below)")
        print("-"*70)
        
        # Display results by host
        for host in sorted(self.results.keys()):
            if 'ports' not in self.results[host] or not self.results[host]['ports']:
                continue
                
            ports = self.results[host]['ports'].split(',')
            print(f"\nHost: {host} - {len(ports)} open ports")
            print(f"{'PORT':<10} {'SERVICE':<15} {'DETAILS'}")
            print("-"*60)
            
            for port in sorted(ports, key=int):
                port_info = self.results[host].get(port, {})
                service = port_info.get('service', 'unknown')
                
                details = []
                if port_info.get('product'):
                    details.append(port_info['product'])
                if port_info.get('version'):
                    details.append(port_info['version'])
                    
                details_str = " - ".join(details)
                if len(details_str) > 30:
                    details_str = details_str[:27] + "..."
                
                # Highlight tcpwrapped services
                if service == "tcpwrapped":
                    service = f"tcpwrapped*"
                    
                print(f"{port:<10} {service:<15} {details_str}")
        
        # Save final results to JSON
        results_file = f"{self.output_dir}/firewall_bypass_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
            
        print("\n" + "="*70)
        print(f"[+] Full results saved to {results_file}")
        print(f"[+] XML scan results available in {self.output_dir} directory")
        
        # If there are remaining tcpwrapped ports, provide recommendations
        if remaining_tcpwrapped > 0:
            print("\n" + "="*70)
            print("RECOMMENDATIONS FOR REMAINING TCPWRAPPED PORTS")
            print("="*70)
            print("The following techniques can be used for manual verification:")
            print("\n1. Direct Service Probing:")
            print("   - Use netcat with appropriate payloads:")
            print("     $ nc -v [host] [port]")
            print("     $ echo -e \"GET / HTTP/1.0\\r\\n\\r\\n\" | nc -v [host] [port]")
            print("\n2. Try all possible Nmap service probes:")
            print("   $ nmap --script unusual-port -p [port] [host]")
            print("   $ nmap --script ssl-enum-ciphers -p [port] [host]")
            print("\n3. Custom payload techniques:")
            print("   $ openssl s_client -connect [host]:[port]")
            print("   $ curl -v --insecure https://[host]:[port]")
            print("   $ curl -v telnet://[host]:[port]")
            print("\n4. Manual tools:")
            print("   - Use Wireshark to analyze response packets")
            print("   - Try tools like socat with different protocols")
            print("     $ socat - OPENSSL:[host]:[port],verify=0")
            
        print("="*70)

def main():
    parser = argparse.ArgumentParser(description="Nmap Integration Tool with Firewall Bypass")
    parser.add_argument("targets", help="Target IP(s), CIDR range, or file with targets")
    parser.add_argument("-o", "--output-dir", default="nmap_results", help="Output directory for scan results")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    parser.add_argument("-q", "--quick", action="store_true", help="Quick mode: Only scan top ports")
    parser.add_argument("-e", "--evasion", type=int, choices=[1, 2, 3], default=2, 
                        help="Evasion level: 1=basic, 2=moderate, 3=aggressive (default: 2)")
    parser.add_argument("--tcp-only", action="store_true", help="Skip UDP scanning")
    
    args = parser.parse_args()
    
    scanner = NmapFirewallBypass(
        targets=args.targets,
        output_dir=args.output_dir,
        threads=args.threads,
        quick_mode=args.quick,
        evasion_level=args.evasion,
        tcp_only=args.tcp_only
    )
    
    scanner.start()

if __name__ == "__main__":
    print("Nmap Firewall Bypass Tool v1.0")
    print("For authorized penetration testing only")
    main()