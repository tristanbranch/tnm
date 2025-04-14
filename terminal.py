import socket
import subprocess
import sys
import os
import pwd
from datetime import datetime
import time
import psutil
import nmap
import json
import shutil
from pathlib import Path
import threading
import queue
import logging

# Set up logging
logging.basicConfig(
    filename='network_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Create backup directory
BACKUP_DIR = Path("network_backups")
BACKUP_DIR.mkdir(exist_ok=True)

# System functions
def clear_screen():
    os.system('clear')

def check_root():
    """Check if the script is running with root privileges"""
    return os.geteuid() == 0

# Network scanning functions
def ping_host(host):
    """Ping a host and return the result"""
    try:
        output = subprocess.check_output(['ping', '-c', '1', host]).decode().strip()
        if 'ttl=' in output.lower():
            return True
        return False
    except:
        return False

def scan_port(host, port):
    """Scan a specific port on a host"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def scan_common_ports(host):
    """Scan common ports on a host"""
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 5900]
    open_ports = []
    for port in common_ports:
        if scan_port(host, port):
            open_ports.append(port)
    return open_ports

# Network information functions
def get_network_info():
    """Get detailed network information using Linux commands"""
    info = {}
    try:
        # Get IP addresses
        ip_output = subprocess.check_output(['ip', 'addr']).decode()
        info['interfaces'] = ip_output

        # Get routing table
        route_output = subprocess.check_output(['ip', 'route']).decode()
        info['routing'] = route_output

        # Get DNS servers
        with open('/etc/resolv.conf', 'r') as f:
            info['dns'] = f.read()

        return info
    except:
        return None

def get_device_status(host):
    """Get detailed status of a network device"""
    try:
        # Try to get device info using SNMP (if available)
        try:
            snmp_info = subprocess.check_output(['snmpwalk', '-v2c', '-c', 'public', host, '1.3.6.1.2.1.1.1.0'], 
                                             stderr=subprocess.DEVNULL).decode()
            device_type = snmp_info.split('=')[1].strip()
        except:
            device_type = "Unknown Device"

        # Check if device is responding to pings
        is_online = ping_host(host)
        
        # Check common ports to determine device type
        ports = scan_common_ports(host)
        device_ports = {
            80: "Web Server",
            443: "Secure Web Server",
            22: "SSH Server",
            23: "Telnet Server",
            25: "Mail Server",
            53: "DNS Server",
            3306: "Database Server",
            3389: "Remote Desktop"
        }
        
        detected_services = [device_ports.get(port, "Unknown") for port in ports]
        
        # Get response time
        try:
            response_time = measure_latency(host)
        except:
            response_time = None
            
        return {
            'online': is_online,
            'type': device_type,
            'services': detected_services,
            'response_time': response_time,
            'ports': ports
        }
    except:
        return None

def get_local_ip():
    """Get local IP address using ip command"""
    try:
        # Get IP address using ip command
        ip_output = subprocess.check_output(['ip', 'addr', 'show']).decode()
        # Look for inet address in the output
        for line in ip_output.split('\n'):
            if 'inet ' in line and 'inet6' not in line:
                # Extract IP address
                ip = line.strip().split()[1].split('/')[0]
                if ip != '127.0.0.1':  # Skip localhost
                    return ip
        return None
    except:
        return None

def map_network_topology():
    """Map the network topology using traceroute and device discovery"""
    try:
        # Get local network information
        local_ip = get_local_ip()
        if not local_ip:
            print("Error: Could not determine local IP address")
            return
            
        network = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
        
        print(f"\nLocal IP: {local_ip}")
        print(f"Scanning network: {network}")
        print("\nMapping network topology...")
        print("Press Ctrl+C to stop scanning at any time")
        
        # Discover active hosts with detailed scan
        nm = nmap.PortScanner()
        try:
            # Initial scan with service detection
            nm.scan(hosts=network, arguments='-sS -sV -O --version-intensity 5 -T4')
            hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        except KeyboardInterrupt:
            print("\nScan interrupted by user")
            return
        
        print("\nDiscovered Devices:")
        print("-" * 100)
        print(f"{'IP Address':<15} {'Status':<10} {'Type':<20} {'Services':<30} {'Response Time':<15} {'OS Detection'}")
        print("-" * 100)
        
        for host, status in hosts_list:
            try:
                device_info = get_device_status(host)
                if device_info:
                    status_indicator = "🟢" if device_info['online'] else "🔴"
                    services_str = ", ".join(device_info['services'])
                    response_time_str = f"{device_info['response_time']:.1f}ms" if device_info['response_time'] else "N/A"
                    
                    # Enhanced device type detection
                    device_type = device_info['type']
                    if not device_type or device_type == "Unknown Device":
                        # Try to determine device type based on services
                        if "Web Server" in device_info['services']:
                            device_type = "Web Server"
                        elif "SSH Server" in device_info['services']:
                            device_type = "Linux Server"
                        elif "Remote Desktop" in device_info['services']:
                            device_type = "Windows Server"
                        elif "Database Server" in device_info['services']:
                            device_type = "Database Server"
                        elif "Mail Server" in device_info['services']:
                            device_type = "Mail Server"
                        elif "DNS Server" in device_info['services']:
                            device_type = "DNS Server"
                        else:
                            device_type = "Network Device"
                    
                    # Get OS and service information from nmap scan
                    try:
                        if host in nm.all_hosts():
                            host_data = nm[host]
                            # Get services
                            if 'tcp' in host_data:
                                services = []
                                for port, data in host_data['tcp'].items():
                                    if data.get('state') == 'open':
                                        service_name = data.get('name', 'unknown')
                                        product = data.get('product', '')
                                        version = data.get('version', '')
                                        if product and version:
                                            services.append(f"{service_name} ({product} {version})")
                                        else:
                                            services.append(service_name)
                                services_str = ", ".join(services)
                            
                            # Get OS information
                            if 'osmatch' in host_data and host_data['osmatch']:
                                os_matches = host_data['osmatch']
                                best_match = max(os_matches, key=lambda x: float(x.get('accuracy', '0')))
                                os_info = f"{best_match['name']} ({best_match.get('accuracy', '0')}%)"
                            else:
                                # Try to determine OS from services
                                os_hints = []
                                if 'tcp' in host_data:
                                    services = host_data['tcp']
                                    if any(service.get('product', '').lower() in ['windows', 'microsoft', 'iis', 'mssql'] 
                                          or service.get('name', '').lower() in ['microsoft-ds', 'msrpc', 'netbios-ssn'] 
                                          for service in services.values()):
                                        os_hints.append("Windows")
                                    if any(service.get('product', '').lower() in ['linux', 'ubuntu', 'debian', 'centos', 'apache', 'nginx'] 
                                          or service.get('name', '').lower() in ['ssh', 'samba'] 
                                          for service in services.values()):
                                        os_hints.append("Linux")
                                    if any(service.get('product', '').lower() in ['dd-wrt', 'openwrt', 'routeros'] 
                                          or service.get('name', '').lower() in ['router', 'firewall'] 
                                          for service in services.values()):
                                        os_hints.append("Router/Firewall")
                                
                                if os_hints:
                                    os_info = f"{' or '.join(os_hints)} (Service Detection)"
                                else:
                                    os_info = "Unknown"
                        else:
                            os_info = "Unknown"
                    except Exception as e:
                        os_info = "Unknown"
                        print(f"OS detection error for {host}: {str(e)}")
                    
                    print(f"{host:<15} {status_indicator:<10} {device_type[:20]:<20} {services_str[:30]:<30} {response_time_str:<15} {os_info}")
            except KeyboardInterrupt:
                print("\nDevice scanning interrupted by user")
                break
            except Exception as e:
                print(f"{host:<15} 🔴         Error scanning device")
                continue
        
        print("\nNetwork Paths:")
        print("-" * 80)
        for host, _ in hosts_list:
            try:
                print(f"\nPath to {host}:")
                # Use traceroute with different options for better results
                try:
                    traceroute = subprocess.check_output(['traceroute', '-n', '-m', '15', '-w', '2', host], 
                                                       stderr=subprocess.DEVNULL).decode()
                    print(traceroute)
                    
                    # Analyze path for potential issues
                    hops = traceroute.split('\n')[1:]  # Skip header
                    for hop in hops:
                        if hop.strip():
                            if '*' in hop:
                                print(f"⚠️  Warning: Packet loss detected at hop {hop.split()[0]}")
                            elif '!' in hop:
                                print(f"⚠️  Warning: Network error detected at hop {hop.split()[0]}")
                except:
                    # Fallback to mtr if traceroute fails
                    try:
                        mtr = subprocess.check_output(['mtr', '-n', '-r', '-c', '1', host], 
                                                    stderr=subprocess.DEVNULL).decode()
                        print(mtr)
                    except:
                        print("Could not determine path")
                            
            except KeyboardInterrupt:
                print("\nPath scanning interrupted by user")
                break
            except:
                print("Could not determine path")
        
        print("\nNetwork Summary:")
        print("-" * 80)
        print(f"Total devices found: {len(hosts_list)}")
        online_devices = sum(1 for _, status in hosts_list if status == 'up')
        print(f"Online devices: {online_devices}")
        print(f"Offline devices: {len(hosts_list) - online_devices}")
        
        # Generate ASCII network map
        print("\nNetwork Map (ASCII):")
        print("-" * 80)
        print(f"Router ({network})")
        print("│")
        for host, status in hosts_list:
            try:
                device_info = get_device_status(host)
                if device_info:
                    status_char = "●" if device_info['online'] else "○"
                    print(f"├── {status_char} {host} ({device_info['type'][:20]})")
            except KeyboardInterrupt:
                print("\nMap generation interrupted by user")
                break
            except:
                continue
        
    except KeyboardInterrupt:
        print("\nTopology mapping interrupted by user")
        return
    except Exception as e:
        print(f"Error mapping topology: {str(e)}")
        return None

def get_device_health():
    """Monitor system health metrics"""
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        
        # Disk usage
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        
        return {
            'cpu': cpu_percent,
            'memory': memory_percent,
            'disk': disk_percent
        }
    except Exception as e:
        print(f"Error getting device health: {str(e)}")
        return None

def measure_latency(host="8.8.8.8"):
    """Measure network latency to a host"""
    try:
        start_time = time.time()
        subprocess.run(['ping', '-c', '1', host], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        latency = (time.time() - start_time) * 1000  # Convert to milliseconds
        return latency
    except:
        return None

def get_bandwidth_usage(interface):
    """Get detailed bandwidth usage statistics"""
    try:
        stats = psutil.net_if_stats()[interface]
        return {
            'speed': stats.speed,  # Speed in MB/s
            'mtu': stats.mtu,
            'is_up': stats.isup,
            'duplex': stats.duplex
        }
    except:
        return None

def monitor_network():
    """Enhanced network monitoring with multiple metrics"""
    try:
        # Get list of available interfaces
        interfaces = psutil.net_if_stats().keys()
        print("\nAvailable interfaces:", ", ".join(interfaces))
        
        interface = input("\nEnter interface to monitor (e.g. eth0): ")
        duration = input("Enter monitoring duration in seconds: ")
        
        if not duration.isdigit():
            print("Invalid duration")
            return
            
        print(f"\nMonitoring {interface} for {duration} seconds...")
        print("Press Ctrl+C to stop monitoring early")
        print("\nInitializing counters...")
        
        start_time = time.time()
        peak_upload = 0
        peak_download = 0
        total_packets_sent = 0
        total_packets_recv = 0
        
        # Get initial counters
        try:
            initial_stats = psutil.net_io_counters(pernic=True)[interface]
            initial_total_sent = initial_stats.bytes_sent
            initial_total_recv = initial_stats.bytes_recv
            initial_packets_sent = initial_stats.packets_sent
            initial_packets_recv = initial_stats.packets_recv
            print(f"Initial bytes sent: {initial_total_sent}")
            print(f"Initial bytes received: {initial_total_recv}")
        except KeyError:
            print(f"\nError: Interface {interface} not found")
            return
            
        # Get initial bandwidth info
        bandwidth_info = get_bandwidth_usage(interface)
        if bandwidth_info:
            print(f"\nInterface Speed: {bandwidth_info['speed']} MB/s")
            print(f"MTU: {bandwidth_info['mtu']}")
            print(f"Status: {'Up' if bandwidth_info['is_up'] else 'Down'}")
            print(f"Duplex: {bandwidth_info['duplex']}")
            
        # Wait a moment to get initial readings
        time.sleep(1)
        
        while time.time() - start_time < int(duration):
            try:
                # Get current stats
                current_stats = psutil.net_io_counters(pernic=True)[interface]
                
                # Calculate rates
                bytes_sent = current_stats.bytes_sent - initial_stats.bytes_sent
                bytes_recv = current_stats.bytes_recv - initial_stats.bytes_recv
                packets_sent = current_stats.packets_sent - initial_packets_sent
                packets_recv = current_stats.packets_recv - initial_packets_recv
                
                # Update peak values
                mb_sent = bytes_sent / (1024 * 1024)
                mb_recv = bytes_recv / (1024 * 1024)
                peak_upload = max(peak_upload, mb_sent)
                peak_download = max(peak_download, mb_recv)
                
                # Calculate totals
                total_sent = (current_stats.bytes_sent - initial_total_sent) / (1024 * 1024)
                total_recv = (current_stats.bytes_recv - initial_total_recv) / (1024 * 1024)
                total_packets_sent += packets_sent
                total_packets_recv += packets_recv
                
                # Get device health
                health = get_device_health()
                
                # Measure latency
                latency = measure_latency()
                
                # Clear line and print all metrics
                print("\r" + " " * 100 + "\r", end='')  # Clear line
                print(f"Network Traffic:")
                print(f"Upload: {mb_sent:.4f} MB/s | Download: {mb_recv:.4f} MB/s")
                print(f"Total Sent: {total_sent:.4f} MB | Total Received: {total_recv:.4f} MB")
                print(f"Packets Sent: {packets_sent} | Packets Received: {packets_recv}")
                print(f"Peak Upload: {peak_upload:.4f} MB/s | Peak Download: {peak_download:.4f} MB/s")
                if health:
                    print(f"System Health - CPU: {health['cpu']}% | Memory: {health['memory']}% | Disk: {health['disk']}%")
                if latency:
                    print(f"Network Latency: {latency:.2f} ms")
                print("\nPress Ctrl+C to stop monitoring", end='', flush=True)
                
                # Update initial stats
                initial_stats = current_stats
                initial_packets_sent = current_stats.packets_sent
                initial_packets_recv = current_stats.packets_recv
                time.sleep(1)
                
            except KeyboardInterrupt:
                print("\n\nMonitoring stopped by user")
                break
            except Exception as e:
                print(f"\nError during monitoring: {str(e)}")
                break
            
    except Exception as e:
        print(f"\nError monitoring network: {str(e)}")

# Firewall management functions
def manage_firewall_port(port, action):
    """Manage firewall ports using iptables"""
    if not check_root():
        return "Root privileges required for firewall management"
    
    try:
        if action == "open":
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'ACCEPT'])
            return f"Port {port} opened successfully"
        elif action == "close":
            subprocess.run(['iptables', '-D', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'ACCEPT'])
            return f"Port {port} closed successfully"
    except subprocess.CalledProcessError:
        return "Error managing firewall rule"

def backup_device_config(host, device_type):
    """Backup device configuration using SNMP or SSH"""
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = BACKUP_DIR / f"{host}_{timestamp}.txt"
        
        if device_type.lower() in ['router', 'switch', 'firewall']:
            # Try SNMP first
            try:
                config = subprocess.check_output(
                    ['snmpwalk', '-v2c', '-c', 'public', host, '1.3.6.1.4.1.9.9.96.1.1.1.1.1'],
                    stderr=subprocess.DEVNULL
                ).decode()
                with open(backup_file, 'w') as f:
                    f.write(config)
                logging.info(f"Successfully backed up {host} configuration via SNMP")
                return True
            except:
                # Try SSH if SNMP fails
                try:
                    config = subprocess.check_output(
                        ['ssh', f'admin@{host}', 'show running-config'],
                        stderr=subprocess.DEVNULL
                    ).decode()
                    with open(backup_file, 'w') as f:
                        f.write(config)
                    logging.info(f"Successfully backed up {host} configuration via SSH")
                    return True
                except:
                    logging.error(f"Failed to backup {host} configuration")
                    return False
        return False
    except Exception as e:
        logging.error(f"Error backing up {host}: {str(e)}")
        return False

def analyze_traffic_patterns(interface, duration=60):
    """Analyze network traffic patterns and identify top talkers"""
    try:
        start_time = time.time()
        traffic_data = {
            'total_bytes': 0,
            'total_packets': 0,
            'protocols': {},
            'connections': {}
        }
        
        # Get initial stats
        initial_stats = psutil.net_io_counters(pernic=True)[interface]
        
        while time.time() - start_time < duration:
            current_stats = psutil.net_io_counters(pernic=True)[interface]
            
            # Calculate traffic
            bytes_diff = current_stats.bytes_sent + current_stats.bytes_recv - \
                        (initial_stats.bytes_sent + initial_stats.bytes_recv)
            packets_diff = current_stats.packets_sent + current_stats.packets_recv - \
                         (initial_stats.packets_sent + initial_stats.packets_recv)
            
            traffic_data['total_bytes'] += bytes_diff
            traffic_data['total_packets'] += packets_diff
            
            # Get active connections
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    key = f"{conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}"
                    if key not in traffic_data['connections']:
                        traffic_data['connections'][key] = 0
                    traffic_data['connections'][key] += 1
            
            time.sleep(1)
        
        # Sort and get top talkers
        top_connections = sorted(
            traffic_data['connections'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            'total_traffic': traffic_data['total_bytes'] / (1024 * 1024),  # MB
            'total_packets': traffic_data['total_packets'],
            'top_connections': top_connections
        }
    except Exception as e:
        logging.error(f"Error analyzing traffic patterns: {str(e)}")
        return None

def monitor_device_health(host):
    """Monitor device health using SNMP"""
    try:
        health_data = {}
        
        # CPU Usage
        try:
            cpu = subprocess.check_output(
                ['snmpwalk', '-v2c', '-c', 'public', host, '1.3.6.1.4.1.9.9.109.1.1.1.1.1'],
                stderr=subprocess.DEVNULL
            ).decode()
            health_data['cpu_usage'] = int(cpu.split('=')[1].strip())
        except:
            health_data['cpu_usage'] = None
        
        # Memory Usage
        try:
            memory = subprocess.check_output(
                ['snmpwalk', '-v2c', '-c', 'public', host, '1.3.6.1.4.1.9.9.48.1.1.1.1.1'],
                stderr=subprocess.DEVNULL
            ).decode()
            health_data['memory_usage'] = int(memory.split('=')[1].strip())
        except:
            health_data['memory_usage'] = None
        
        # Temperature (if available)
        try:
            temp = subprocess.check_output(
                ['snmpwalk', '-v2c', '-c', 'public', host, '1.3.6.1.4.1.9.9.13.1.3.1.2.1'],
                stderr=subprocess.DEVNULL
            ).decode()
            health_data['temperature'] = int(temp.split('=')[1].strip())
        except:
            health_data['temperature'] = None
        
        return health_data
    except Exception as e:
        logging.error(f"Error monitoring device health for {host}: {str(e)}")
        return None

def security_scan(host):
    """Perform basic security scan of a host"""
    try:
        nm = nmap.PortScanner()
        nm.scan(host, arguments='-sV -sS -sC -O --version-intensity 5 -T4')
        
        security_info = {
            'open_ports': [],
            'vulnerabilities': [],
            'services': {},
            'os_info': None
        }
        
        if host in nm.all_hosts():
            host_data = nm[host]
            
            # Get open ports and services
            if 'tcp' in host_data:
                for port, data in host_data['tcp'].items():
                    if data.get('state') == 'open':
                        security_info['open_ports'].append(port)
                        security_info['services'][port] = {
                            'name': data.get('name', 'unknown'),
                            'product': data.get('product', ''),
                            'version': data.get('version', '')
                        }
            
            # Get OS information
            if 'osmatch' in host_data and host_data['osmatch']:
                security_info['os_info'] = host_data['osmatch'][0]['name']
            
            # Check for common vulnerabilities
            for port, service in security_info['services'].items():
                if service['name'] == 'ssh' and service['version']:
                    if '2.0' in service['version']:
                        security_info['vulnerabilities'].append(
                            f"Potentially vulnerable SSH version ({service['version']}) on port {port}"
                        )
                elif service['name'] == 'http' and service['product']:
                    if 'apache' in service['product'].lower() and '2.4' in service['version']:
                        security_info['vulnerabilities'].append(
                            f"Potentially vulnerable Apache version ({service['version']}) on port {port}"
                        )
        
        return security_info
    except Exception as e:
        logging.error(f"Error performing security scan for {host}: {str(e)}")
        return None

def enhanced_monitor_network():
    """Enhanced network monitoring with additional features"""
    try:
        # Get list of available interfaces
        interfaces = psutil.net_if_stats().keys()
        print("\nAvailable interfaces:", ", ".join(interfaces))
        
        interface = input("\nEnter interface to monitor (e.g. eth0): ")
        duration = input("Enter monitoring duration in seconds: ")
        
        if not duration.isdigit():
            print("Invalid duration")
            return
            
        print(f"\nMonitoring {interface} for {duration} seconds...")
        print("Press Ctrl+C to stop monitoring early")
        
        # Start traffic analysis in a separate thread
        traffic_queue = queue.Queue()
        def traffic_analyzer():
            traffic_data = analyze_traffic_patterns(interface, int(duration))
            traffic_queue.put(traffic_data)
        
        traffic_thread = threading.Thread(target=traffic_analyzer)
        traffic_thread.start()
        
        # Main monitoring loop
        start_time = time.time()
        peak_upload = 0
        peak_download = 0
        total_packets_sent = 0
        total_packets_recv = 0
        
        try:
            initial_stats = psutil.net_io_counters(pernic=True)[interface]
            initial_total_sent = initial_stats.bytes_sent
            initial_total_recv = initial_stats.bytes_recv
            initial_packets_sent = initial_stats.packets_sent
            initial_packets_recv = initial_stats.packets_recv
        except KeyError:
            print(f"\nError: Interface {interface} not found")
            return
        
        while time.time() - start_time < int(duration):
            try:
                current_stats = psutil.net_io_counters(pernic=True)[interface]
                
                # Calculate rates
                bytes_sent = current_stats.bytes_sent - initial_stats.bytes_sent
                bytes_recv = current_stats.bytes_recv - initial_stats.bytes_recv
                packets_sent = current_stats.packets_sent - initial_packets_sent
                packets_recv = current_stats.packets_recv - initial_packets_recv
                
                # Update peak values
                mb_sent = bytes_sent / (1024 * 1024)
                mb_recv = bytes_recv / (1024 * 1024)
                peak_upload = max(peak_upload, mb_sent)
                peak_download = max(peak_download, mb_recv)
                
                # Calculate totals
                total_sent = (current_stats.bytes_sent - initial_total_sent) / (1024 * 1024)
                total_recv = (current_stats.bytes_recv - initial_total_recv) / (1024 * 1024)
                total_packets_sent += packets_sent
                total_packets_recv += packets_recv
                
                # Get device health
                health = get_device_health()
                
                # Clear line and print all metrics
                print("\r" + " " * 100 + "\r", end='')  # Clear line
                print(f"Network Traffic:")
                print(f"Upload: {mb_sent:.4f} MB/s | Download: {mb_recv:.4f} MB/s")
                print(f"Total Sent: {total_sent:.4f} MB | Total Received: {total_recv:.4f} MB")
                print(f"Packets Sent: {packets_sent} | Packets Received: {packets_recv}")
                print(f"Peak Upload: {peak_upload:.4f} MB/s | Peak Download: {peak_download:.4f} MB/s")
                if health:
                    print(f"System Health - CPU: {health['cpu']}% | Memory: {health['memory']}% | Disk: {health['disk']}%")
                print("\nPress Ctrl+C to stop monitoring", end='', flush=True)
                
                # Update initial stats
                initial_stats = current_stats
                initial_packets_sent = current_stats.packets_sent
                initial_packets_recv = current_stats.packets_recv
                time.sleep(1)
                
            except KeyboardInterrupt:
                print("\n\nMonitoring stopped by user")
                break
            except Exception as e:
                print(f"\nError during monitoring: {str(e)}")
                break
        
        # Wait for traffic analysis to complete
        traffic_thread.join()
        
        # Get and display traffic analysis results
        try:
            traffic_data = traffic_queue.get_nowait()
            if traffic_data:
                print("\n\nTraffic Analysis Results:")
                print("-" * 80)
                print(f"Total Traffic: {traffic_data['total_traffic']:.2f} MB")
                print(f"Total Packets: {traffic_data['total_packets']}")
                print("\nTop Connections:")
                for conn, count in traffic_data['top_connections']:
                    print(f"{conn}: {count} packets")
        except queue.Empty:
            print("\nTraffic analysis not completed")
        
    except Exception as e:
        print(f"\nError monitoring network: {str(e)}")

# Main menu and program flow
def main():
    if not check_root():
        print("Warning: Some features require root privileges")
    
    while True:
        clear_screen()
        print("\n=== Network Management Tool ===")
        print("1. Ping a host")
        print("2. Scan ports on a host")
        print("3. Show network information")
        print("4. Open a port")
        print("5. Close a port")
        print("6. Map network topology")
        print("7. Monitor network traffic")
        print("8. Backup device configuration")
        print("9. Security scan")
        print("10. Device health check")
        print("11. Exit")
        print("\n")
        
        choice = input("Enter your choice (1-11): ")
        
        if choice == '1':
            host = input("Enter host to ping (e.g., google.com or IP): ")
            print("\nPinging", host, "...")
            if ping_host(host):
                print("Host is reachable!")
            else:
                print("Host is unreachable!")
                
        elif choice == '2':
            host = input("Enter host to scan: ")
            print("\nScanning common ports on", host, "...")
            open_ports = scan_common_ports(host)
            if open_ports:
                print("Open ports:", ', '.join(map(str, open_ports)))
            else:
                print("No common ports are open.")
                
        elif choice == '3':
            info = get_network_info()
            if info:
                print("\n=== Network Interfaces ===")
                print(info['interfaces'])
                print("\n=== Routing Table ===")
                print(info['routing'])
                print("\n=== DNS Configuration ===")
                print(info['dns'])
            else:
                print("Error getting network information")
                
        elif choice == '4':
            if not check_root():
                print("Root privileges required!")
            else:
                port = input("Enter port number to open: ")
                if port.isdigit():
                    print(manage_firewall_port(int(port), "open"))
                else:
                    print("Invalid port number")
                    
        elif choice == '5':
            if not check_root():
                print("Root privileges required!")
            else:
                port = input("Enter port number to close: ")
                if port.isdigit():
                    print(manage_firewall_port(int(port), "close"))
                else:
                    print("Invalid port number")
        
        elif choice == '6':
            map_network_topology()
            
        elif choice == '7':
            enhanced_monitor_network()
            
        elif choice == '8':
            host = input("Enter device IP: ")
            device_type = input("Enter device type (router/switch/firewall): ")
            if backup_device_config(host, device_type):
                print("Configuration backup successful!")
            else:
                print("Configuration backup failed!")
                
        elif choice == '9':
            host = input("Enter host to scan: ")
            print("\nPerforming security scan...")
            security_info = security_scan(host)
            if security_info:
                print("\nSecurity Scan Results:")
                print("-" * 80)
                print(f"Open Ports: {', '.join(map(str, security_info['open_ports']))}")
                if security_info['os_info']:
                    print(f"OS: {security_info['os_info']}")
                if security_info['vulnerabilities']:
                    print("\nPotential Vulnerabilities:")
                    for vuln in security_info['vulnerabilities']:
                        print(f"- {vuln}")
                print("\nServices:")
                for port, service in security_info['services'].items():
                    print(f"Port {port}: {service['name']} ({service['product']} {service['version']})")
            else:
                print("Security scan failed!")
                
        elif choice == '10':
            host = input("Enter device IP: ")
            print("\nChecking device health...")
            health_data = monitor_device_health(host)
            if health_data:
                print("\nDevice Health Status:")
                print("-" * 80)
                if health_data['cpu_usage'] is not None:
                    print(f"CPU Usage: {health_data['cpu_usage']}%")
                if health_data['memory_usage'] is not None:
                    print(f"Memory Usage: {health_data['memory_usage']}%")
                if health_data['temperature'] is not None:
                    print(f"Temperature: {health_data['temperature']}°C")
            else:
                print("Device health check failed!")
            
        elif choice == '11':
            print("\nExiting...")
            sys.exit()
            
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    # Check if running with sudo
    if not check_root():
        print("This program requires root privileges.")
        print("Attempting to restart with sudo...")
        try:
            # Restart the script with sudo
            subprocess.run(['sudo', 'python3', sys.argv[0]])
            sys.exit(0)
        except Exception as e:
            print(f"Error: Could not restart with sudo: {str(e)}")
            print("Please run this program with sudo privileges.")
            sys.exit(1)
    
    main()
