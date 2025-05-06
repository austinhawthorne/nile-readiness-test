#!/usr/bin/env python3
"""
nrt.py - Configures host interface, OSPF adjacency dynamically,
loopback interfaces, default route fallback, connectivity tests (DHCP/RADIUS,
NTP, HTTPS), then restores host to original state (including removing FRR config,
stopping FRR) and DNS changes.

This script runs in the default namespace and uses the specified interface for FRR tests,
allowing VNC to run in a separate namespace on another interface.

Usage: 
  sudo ./nrt.py [--debug] [--config CONFIG_FILE]
  
Options:
  --debug           Enable debug output
  --config FILE     Use JSON configuration file instead of interactive prompts
"""

import os
import sys
import shutil
import subprocess
import random
import ipaddress
import socket
import time
import json
import argparse
import re
from urllib.parse import urlparse
from scapy.config import conf
from scapy.all import sniff, sr1, send, Raw
from scapy.layers.inet import IP, UDP
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello
try:
    from scapy.contrib.geneve import GENEVE
except ImportError:
    print("Warning: Scapy Geneve module not available. Geneve testing will be limited.")
    GENEVE = None

# Import dhcppython for improved DHCP testing
import dhcppython.client as dhcp_client
import dhcppython.options as dhcp_options
import dhcppython.utils as dhcp_utils

# Constants for Nile Connect tests
NILE_HOSTNAME = "ne-u1.nile-global.cloud"
S3_HOSTNAME = "s3.us-west-2.amazonaws.com"
GUEST_IPS = ["145.40.90.203","145.40.64.129","145.40.113.105","147.28.179.61"]
UDP_PORT = 6081
SSL_PORT = 443


# Send a Geneve packet
def send_geneve_packet(ip: str, source_ip: str, port: int = UDP_PORT, vni: int = 3762, sport: int = 12345) -> tuple:
    """
    Send a Geneve packet to a target
    
    Args:
        ip: Target IP address
        source_ip: Source IP to use for the packet
        port: UDP port to use (default: 6081)
        vni: Virtual Network Identifier (default: 3762)
        sport: Source port (default: 12345)
        
    Returns:
        tuple: (success, packet) where success is a boolean indicating if the packet was sent successfully
               and packet is the packet that was sent
    """
    if GENEVE is None:
        print(f"  Warning: Scapy Geneve module not available.")
        print(f"  Troubleshooting: Install Scapy with Geneve support using 'pip install scapy' (version 2.4.3+)")
        return False, None
        
    try:
        # Craft the packet
        pkt = IP(src=source_ip, dst=ip)/UDP(sport=sport, dport=port)/GENEVE(vni=vni)/Raw(load="Geneve probe")
        
        print(f"  Sending Geneve probe from {source_ip} to {ip}:{port} (VNI: {vni})")
        if DEBUG:
            print(f"DEBUG: Packet details: {pkt.summary()}")
            print(f"DEBUG: Packet layers: {[layer.name for layer in pkt.layers()]}")
            
        # Send the packet
        send(pkt, verbose=0)
        return True, pkt
    except Exception as e:
        print(f"  Error sending Geneve packet: {e}")
        print(f"  Troubleshooting:")
        print(f"    - Check network connectivity to {ip}")
        print(f"    - Verify source IP {source_ip} is correctly configured on your interface")
        print(f"    - Check if you have permission to send raw packets (run as root/sudo)")
        if DEBUG:
            import traceback
            traceback.print_exc()
        return False, None

# Sniff for Geneve packets
def sniff_geneve_packet(ip: str, source_ip: str, port: int = UDP_PORT, timeout: int = 10, sport: int = 12345, iface: str = None) -> tuple:
    """
    Sniff for Geneve packets from a specific source
    
    Args:
        ip: Source IP address to filter for
        source_ip: Our source IP (for filter construction)
        port: UDP port to filter for (default: 6081)
        timeout: Sniffing timeout in seconds (default: 10)
        sport: Source port we used when sending (default: 12345)
        iface: Interface to sniff on (default: None, which uses scapy's default)
        
    Returns:
        tuple: (success, packet) where success is a boolean indicating if a Geneve packet was detected
               and packet is the detected packet
    """
    if GENEVE is None:
        print(f"  Warning: Scapy Geneve module not available.")
        return False, None
        
    try:
        # Create a filter for any packets from the target IP (no protocol or port filtering)
        filter_str = f"src host {ip}"
        
        # Get the list of available interfaces
        available_interfaces = conf.ifaces.keys()
        if DEBUG:
            print(f"DEBUG: Available interfaces: {', '.join(available_interfaces)}")
        
        # If no interface specified, try to determine the best one
        if iface is None:
            # Try to use the interface that has the source_ip
            for i in conf.ifaces.values():
                if hasattr(i, 'ip') and i.ip == source_ip:
                    iface = i.name
                    if DEBUG:
                        print(f"DEBUG: Found interface {iface} with IP {source_ip}")
                    break
        
        print(f"  Sniffing for Geneve responses from {ip} on interface {iface or 'default'} (timeout: {timeout}s)")
        if DEBUG:
            print(f"DEBUG: Using filter: {filter_str}")
            
        # Sniff for packets
        try:
            if iface:
                packets = sniff(iface=iface, filter=filter_str, timeout=timeout, count=1)
            else:
                packets = sniff(filter=filter_str, timeout=timeout, count=1)
        except OSError as ose:
            if "Network is down" in str(ose):
                print(f"  Error: Network is down on interface {iface or 'default'}")
                print(f"  Troubleshooting:")
                print(f"    - Check if the interface is up (ip link show)")
                print(f"    - Try using a different interface")
                print(f"    - Verify network connectivity")
                return False, None
            else:
                raise
        
        if not packets:
            print(f"  No response received from {ip}:{port} within {timeout} seconds")
            print(f"  Troubleshooting:")
            print(f"    - Check if UDP port {port} is open (try 'nc -vzu {ip} {port}')")
            print(f"    - Verify no firewall is blocking UDP traffic to port {port}")
            return False, None
            
        # We got a packet, analyze it
        response = packets[0]
        print(f"  Received response from {ip}")
        if DEBUG:
            print(f"DEBUG: Response summary: {response.summary()}")
            print(f"DEBUG: Response layers: {[layer.name for layer in response.layers()]}")
        
        # Check if it's a Geneve packet
        if GENEVE in response:
            print(f"  Geneve protocol detected on {ip}")
            if DEBUG:
                geneve_resp = response[GENEVE]
                print(f"DEBUG: Geneve VNI: {geneve_resp.vni}")
                print(f"DEBUG: Geneve version: {geneve_resp.ver}")
            return True, response
        
        # Check if it's a UDP packet
        elif UDP in response:
            if response[UDP].dport == sport:
                print(f"  UDP response received from {ip}:{port}, but not Geneve protocol")
                print(f"  Troubleshooting: The device at {ip} is responding on UDP but not with Geneve protocol")
            else:
                print(f"  UDP response received but not directed to our source port ({response[UDP].dport} instead of {sport})")
                print(f"  Troubleshooting: Check firewall rules and NAT configurations")
            if DEBUG:
                print(f"DEBUG: UDP payload: {response[UDP].payload}")
        
        # It's some other type of packet
        else:
            print(f"  Non-UDP response received from {ip}")
            print(f"  Response protocol: {response.summary()}")
            print(f"  Troubleshooting: The device at {ip} is responding but not with UDP/Geneve")
            
        return False, response
    except Exception as e:
        print(f"  Error sniffing for Geneve packets: {e}")
        print(f"  Troubleshooting:")
        print(f"    - Check if the interface is up and has proper IP configuration")
        print(f"    - Verify you have permission to sniff packets (run as root/sudo)")
        print(f"    - Try using a different interface")
        if DEBUG:
            import traceback
            traceback.print_exc()
        return False, None

# Test if a remote device is running Geneve on UDP port
def test_geneve_with_scapy(ip: str, source_ip: str, port: int = UDP_PORT, timeout: int = 10) -> bool:
    """
    Test if a target is running Geneve on UDP port (default 6081) using Scapy
    
    Args:
        ip: Target IP address to test
        source_ip: Source IP to use for the packet
        port: UDP port to test (default: 6081)
        timeout: Response timeout in seconds (default: 10)
        
    Returns:
        bool: True if Geneve is detected, False otherwise
    """
    if GENEVE is None:
        print(f"  Warning: Scapy Geneve module not available. Falling back to basic UDP test.")
        print(f"  Troubleshooting: Install Scapy with Geneve support using 'pip install scapy' (version 2.4.3+)")
        return check_udp_connectivity_netcat(ip, port, timeout)
    
    # Get the interface name from the IP address
    iface_name = None
    for i in conf.ifaces.values():
        if hasattr(i, 'ip') and i.ip == source_ip:
            iface_name = i.name
            if DEBUG:
                print(f"DEBUG: Found interface {iface_name} with IP {source_ip}")
            break
    
    # First send the packet
    send_success, pkt = send_geneve_packet(ip, source_ip, port)
    if not send_success:
        return False
    
    # Then sniff for a response - explicitly pass the interface
    sniff_success, response = sniff_geneve_packet(ip, source_ip, port, timeout, sport=12345, iface=iface_name)
    
    # Return True if we detected Geneve
    return sniff_success

# Check UDP connectivity using netcat
def check_udp_connectivity_netcat(ip: str, port: int = UDP_PORT, timeout: int = 5) -> bool:
    """
    Check UDP connectivity using netcat (nc -vzu) with a timeout.
    
    Args:
        ip: IP address to check
        port: UDP port to check (default: 6081)
        timeout: Timeout in seconds (default: 5)
        
    Returns:
        bool: True if connectivity successful, False otherwise
    """
    try:
        result = subprocess.run(
            ['nc', '-vzu', ip, str(port)],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        # Check for success indicators in output
        if "open" in result.stderr.lower():
            return True
            
        if result.returncode == 0:
            return True
            
        return False
    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        print(f"  Error: netcat (nc) command not found. Please install netcat.")
        return False
    except Exception as e:
        print(f"  Error: {e}")
        return False

# Check SSL certificate
def check_ssl_certificate(ip: str, hostname: str, expected_org: str) -> bool:
    """
    Test SSL certificate validity and organization.
    
    Args:
        ip: IP address to check
        hostname: Hostname for SNI
        expected_org: Expected organization in certificate issuer
        
    Returns:
        bool: True if SSL certificate is valid and contains expected organization, False otherwise
    """
    try:
        result = subprocess.run(
            ['openssl', 's_client', '-connect', f'{ip}:{SSL_PORT}', '-servername', hostname],
            capture_output=True,
            text=True
        )
        
        if "issuer=" in result.stdout:
            issuer_start = result.stdout.find("issuer=")
            issuer_end = result.stdout.find("\n", issuer_start)
            issuer = result.stdout[issuer_start:issuer_end].strip()
            
            # Check if issuer contains the expected organization
            if expected_org not in issuer:
                return False
                
            return True
        else:
            return False
    except Exception as e:
        print(f"  Error: {e}")
        return False



# Parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser(description='Nile Readiness Test')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    parser.add_argument('--config', type=str, help='Path to JSON configuration file')
    return parser.parse_args()

# Read configuration from JSON file
def read_config(config_file):
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        print(f"Loaded configuration from {config_file}")
        return config
    except Exception as e:
        print(f"Error reading config file {config_file}: {e}")
        sys.exit(1)

# Parse arguments
args = parse_args()
DEBUG = args.debug

# ANSI color codes
GREEN = '\033[32m'
RED   = '\033[31m'
RESET = '\033[0m'

# Pre-flight checks
required_bins = {
    'vtysh': 'FRR (vtysh)',
    'radclient': 'FreeRADIUS client (radclient)',
    'dig': 'DNS lookup utility (dig)',
    'ntpdate': 'NTP utility (ntpdate)',
    'curl': 'HTTPS test utility (curl)',
    'nc': 'Netcat (nc) for UDP connectivity testing',
    'openssl': 'OpenSSL for SSL certificate verification'
}
missing = [name for name in required_bins if shutil.which(name) is None]
if missing:
    print('Error: the following required tools are missing:')
    for name in missing:
        print(f'  - {required_bins[name]}')
    print()
    print('Please install them, e.g.:')
    print('  sudo apt update && sudo apt install frr freeradius-client dnsutils ntpdate curl netcat-openbsd openssl')
    sys.exit(1)

# Wrapper for subprocess.run with debug
def run_cmd(cmd, **kwargs):
    if DEBUG:
        printed = cmd if isinstance(cmd, str) else ' '.join(cmd)
        print(f'DEBUG: Running: {printed} | kwargs={kwargs}')
    
    # Use Popen instead of subprocess.run to avoid buffer deadlocks
    if kwargs.get('capture_output'):
        # Create pipes for stdout and stderr
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=kwargs.get('text', False),
            shell=kwargs.get('shell', False)
        )
        
        # Read stdout and stderr incrementally to avoid buffer deadlocks
        stdout_data = []
        stderr_data = []
        
        while True:
            # Read from stdout and stderr without blocking
            stdout_chunk = process.stdout.read(1024)
            stderr_chunk = process.stderr.read(1024)
            
            # If we got data, store it
            if stdout_chunk:
                stdout_data.append(stdout_chunk)
            if stderr_chunk:
                stderr_data.append(stderr_chunk)
            
            # Check if process has finished
            if process.poll() is not None:
                # Read any remaining data
                stdout_chunk = process.stdout.read()
                stderr_chunk = process.stderr.read()
                if stdout_chunk:
                    stdout_data.append(stdout_chunk)
                if stderr_chunk:
                    stderr_data.append(stderr_chunk)
                break
            
            # Small sleep to avoid CPU spinning
            time.sleep(0.01)
        
        # Join the data
        stdout_output = ''.join(stdout_data) if kwargs.get('text', False) else b''.join(stdout_data)
        stderr_output = ''.join(stderr_data) if kwargs.get('text', False) else b''.join(stderr_data)
        
        # Create a CompletedProcess object to match subprocess.run's return value
        proc = subprocess.CompletedProcess(
            args=cmd,
            returncode=process.returncode,
            stdout=stdout_output,
            stderr=stderr_output
        )
        
        if DEBUG:
            print('DEBUG: stdout:')
            print(proc.stdout)
            print('DEBUG: stderr:')
            print(proc.stderr)
    else:
        # If we're not capturing output, just use subprocess.run
        proc = subprocess.run(cmd, **kwargs)
    
    if kwargs.get('check') and proc.returncode != 0:
        if DEBUG:
            print(f'DEBUG: Command failed with return code {proc.returncode}')
        proc.check_returncode()
    
    return proc

# Prompt helper
def prompt_nonempty(prompt):
    while True:
        val = input(prompt).strip()
        if val:
            return val
        print('  -> This value cannot be blank.')

# Gather user input
def get_user_input(config_file=None):
    # If config file is provided, use it
    if config_file:
        config = read_config(config_file)
        test_iface = config.get('test_interface', 'enxf0a731f41761')
        ip_addr = config.get('ip_address')
        netmask = config.get('netmask')
        gateway = config.get('gateway')
        mgmt_interface = config.get('mgmt_interface', 'end0')
        mgmt1 = config.get('nsb_subnet')
        mgmt2 = config.get('sensor_subnet')
        client_subnet = config.get('client_subnet')
        run_dhcp = config.get('run_dhcp_tests', False)
        dhcp_servers = config.get('dhcp_servers', [])
        run_radius = config.get('run_radius_tests', False)
        radius_servers = config.get('radius_servers', [])
        secret = config.get('radius_secret')
        username = config.get('radius_username')
        password = config.get('radius_password')
        run_custom_dns_tests = config.get('run_custom_dns_tests', False)
        custom_dns_servers = config.get('custom_dns_servers', []) if run_custom_dns_tests else []
        run_custom_ntp_tests = config.get('run_custom_ntp_tests', False)
        custom_ntp_servers = config.get('custom_ntp_servers', []) if run_custom_ntp_tests else []
        
        # Validate required fields
        missing = []
        for field, value in [
            ('ip_address', ip_addr),
            ('netmask', netmask),
            ('gateway', gateway),
            ('nsb_subnet', mgmt1),
            ('sensor_subnet', mgmt2),
            ('client_subnet', client_subnet)
        ]:
            if not value:
                missing.append(field)
        
        if missing:
            print(f"Error: Missing required fields in config file: {', '.join(missing)}")
            sys.exit(1)
            
        # Validate RADIUS fields if RADIUS tests are enabled
        if run_radius:
            missing = []
            for field, value in [
                ('radius_servers', radius_servers),
                ('radius_secret', secret),
                ('radius_username', username),
                ('radius_password', password)
            ]:
                if not value:
                    missing.append(field)
            
            if missing:
                print(f"Error: RADIUS tests enabled but missing fields: {', '.join(missing)}")
                sys.exit(1)
        
        # Validate DHCP fields if DHCP tests are enabled
        if run_dhcp and not dhcp_servers:
            print("Error: DHCP tests enabled but no DHCP servers specified")
            sys.exit(1)
            
        print("\nUsing configuration from file:")
        print(f"  Management Interface: {mgmt_interface}")
        print(f"  NSB Testing Interface: {test_iface}")
        print(f"  IP Address: {ip_addr}")
        print(f"  Netmask: {netmask}")
        print(f"  Gateway: {gateway}")
        print(f"  NSB Subnet: {mgmt1}")
        print(f"  Sensor Subnet: {mgmt2}")
        print(f"  Client Subnet: {client_subnet}")
        print(f"  Run DHCP Tests: {run_dhcp}")
        if run_dhcp:
            print(f"  DHCP Servers: {', '.join(dhcp_servers)}")
        print(f"  Run RADIUS Tests: {run_radius}")
        if run_radius:
            print(f"  RADIUS Servers: {', '.join(radius_servers)}")
        print(f"  Run Custom DNS Tests: {run_custom_dns_tests}")
        if run_custom_dns_tests:
            print(f"  Custom DNS Servers: {', '.join(custom_dns_servers)}")
        print(f"  Run Custom NTP Tests: {run_custom_ntp_tests}")
        if run_custom_ntp_tests:
            print(f"  Custom NTP Servers: {', '.join(custom_ntp_servers)}")
    else:
        # Interactive mode
        print("\nNetwork Interface Configuration:")
        print("--------------------------------")
        mgmt_interface = prompt_nonempty('Management interface of host to keep enabled (default: end0): ') or 'end0'
        test_iface     = prompt_nonempty('Interface for Nile Readiness tests (default: enxf0a731f41761): ') or 'enxf0a731f41761'
        ip_addr       = prompt_nonempty('IP address for NSB Gateway interface: ')
        netmask       = prompt_nonempty('Netmask (e.g. 255.255.255.0): ')
        gateway       = prompt_nonempty('Router or Firewall IP: ')
        mgmt1         = prompt_nonempty('NSB subnet (CIDR, e.g. 192.168.1.0/24): ')
        mgmt2         = prompt_nonempty('Sensor subnet (CIDR): ')
        client_subnet = prompt_nonempty('Client subnet (CIDR): ')

        run_dhcp = input('Perform DHCP tests? [y/N]: ').strip().lower().startswith('y')
        dhcp_servers = []
        if run_dhcp:
            dhcp_servers = [ip.strip() for ip in prompt_nonempty(
                'DHCP server IP(s) (comma-separated): ').split(',')]

        run_radius = input('Perform RADIUS tests? [y/N]: ').strip().lower().startswith('y')
        radius_servers = []
        secret = username = password = None
        if run_radius:
            radius_servers = [ip.strip() for ip in prompt_nonempty(
                'RADIUS server IP(s) (comma-separated): ').split(',')]
            secret   = prompt_nonempty('RADIUS shared secret: ')
            username = prompt_nonempty('RADIUS test username: ')
            password = prompt_nonempty('RADIUS test password: ')

    # For interactive mode, custom_dns_servers and custom_ntp_servers are empty lists
    if not config_file:
        custom_dns_servers = []
        custom_ntp_servers = []
        
        # Ask for custom DNS servers
        custom_dns = input('Add custom DNS servers for testing? [y/N]: ').strip().lower()
        if custom_dns.startswith('y'):
            custom_dns_input = prompt_nonempty('Enter custom DNS server IP(s) (comma-separated): ')
            custom_dns_servers = [ip.strip() for ip in custom_dns_input.split(',')]
            
        # Ask for custom NTP servers
        custom_ntp = input('Add custom NTP servers for testing? [y/N]: ').strip().lower()
        if custom_ntp.startswith('y'):
            custom_ntp_input = prompt_nonempty('Enter custom NTP server(s) (comma-separated): ')
            custom_ntp_servers = [server.strip() for server in custom_ntp_input.split(',')]
    
    # Print custom DNS and NTP servers if provided
    if custom_dns_servers:
        print(f"  Custom DNS Servers: {', '.join(custom_dns_servers)}")
    if custom_ntp_servers:
        print(f"  Custom NTP Servers: {', '.join(custom_ntp_servers)}")
    
    return (test_iface, ip_addr, netmask, gateway, mgmt_interface,
            mgmt1, mgmt2, client_subnet,
            dhcp_servers, radius_servers, secret, username, password,
            run_dhcp, run_radius, custom_dns_servers, custom_ntp_servers)

# Record/restore host state
def record_state(iface):
    if DEBUG:
        print(f"Recording state of interface {iface}...")
    state = {}
    out = run_cmd(['ip','addr','show','dev',iface], capture_output=True, text=True).stdout
    state['addrs']  = [l.split()[1] for l in out.splitlines() if 'inet ' in l]
    state['routes'] = run_cmd(['ip','route','show','default'], capture_output=True, text=True).stdout.splitlines()
    with open('/etc/frr/daemons') as f: state['daemons'] = f.read()
    with open('/etc/resolv.conf') as f: state['resolv'] = f.read()
    svc = run_cmd(['systemctl','is-enabled','frr'], capture_output=True, text=True)
    state['frr_enabled'] = (svc.returncode == 0)
    return state

def restore_state(iface, state):
    print('\nRestoring original state...')
    
    # First, remove dummy interfaces
    if DEBUG:
        print("Removing dummy interfaces...")
    for name in ('mgmt1','mgmt2','client'):
        run_cmd(['ip','link','delete',f'dummy_{name}'], check=False, capture_output=True)
    
    # Flush the interface
    if DEBUG:
        print(f"Flushing interface {iface}...")
    run_cmd(['ip','addr','flush','dev',iface], check=True, capture_output=True)
    
    # Apply a temporary IP configuration if there are no addresses in the state
    # This helps with the "Nexthop has invalid gateway" error
    # Use 0.0.0.0/0 without setting a default gateway to avoid adding additional routes
    if not state['addrs']:
        if DEBUG:
            print("No original addresses found, applying temporary IP configuration...")
        run_cmd(['ip','addr','add','0.0.0.0/0','dev',iface], check=False, capture_output=True)
        run_cmd(['ip','link','set','dev',iface,'up'], check=False, capture_output=True)
    
    # Add back the original addresses
    if DEBUG:
        print("Restoring original IP addresses...")
    for addr in state['addrs']:
        run_cmd(['ip','addr','add',addr,'dev',iface], check=False, capture_output=True)
    
    # Make sure the interface is up
    if DEBUG:
        print(f"Ensuring interface {iface} is up...")
    run_cmd(['ip','link','set','dev',iface,'up'], check=False, capture_output=True)
    
    # Flush default routes
    if DEBUG:
        print("Flushing default routes...")
    run_cmd(['ip','route','flush','default'], check=False, capture_output=True)
    
    # Restore FRR configuration
    if DEBUG:
        print("Restoring FRR configuration...")
    with open('/etc/frr/daemons','w') as f: f.write(state['daemons'])
    run_cmd(['rm','-f','/etc/frr/frr.conf'], check=False, capture_output=True)
    
    # Restore DNS configuration
    if DEBUG:
        print("Restoring DNS configuration...")
    with open('/etc/resolv.conf','w') as f: f.write(state['resolv'])
    
    # Stop and disable FRR
    if DEBUG:
        print("Stopping and disabling FRR...")
    run_cmd(['systemctl','stop','frr'], check=False, capture_output=True)
    run_cmd(['systemctl','disable','frr'], check=False, capture_output=True)
    
    if DEBUG:
        print('Removed FRR config, stopped service, restored DNS.')

# Configure main interface
def configure_interface(iface, ip_addr, netmask, mgmt_interface='end0'):

    if DEBUG:
        print(f'Configuring {iface} → {ip_addr}/{netmask}')
    
    # Get a list of all network interfaces
    if DEBUG:
        print("Getting list of network interfaces...")
    interfaces_output = run_cmd(['ip', 'link', 'show'], capture_output=True, text=True).stdout
    interfaces = []
    for line in interfaces_output.splitlines():
        if ': ' in line:
            # Extract interface name (remove number and colon)
            interface_name = line.split(': ')[1].split('@')[0]
            interfaces.append(interface_name)
    
    # Check for and clean up dummy interfaces from previous runs
    if DEBUG:
        print("Checking for dummy interfaces from previous runs...")
    dummy_interfaces = ['dummy_mgmt1', 'dummy_mgmt2', 'dummy_client']
    for dummy in dummy_interfaces:
        if dummy in interfaces:
            if DEBUG:
                print(f"Removing leftover dummy interface {dummy}...")
            run_cmd(['ip', 'link', 'delete', dummy], check=False)
    
    # Check if management interface has a default gateway and remove it
    if mgmt_interface in interfaces and mgmt_interface != iface:
        if DEBUG:
            print(f"Checking if management interface {mgmt_interface} has a default gateway...")
        route_output = run_cmd(['ip', 'route', 'show', 'dev', mgmt_interface], capture_output=True, text=True).stdout
        if 'default' in route_output:
            if DEBUG:
                print(f"Removing default gateway from management interface {mgmt_interface}...")
            run_cmd(['ip', 'route', 'del', 'default', 'dev', mgmt_interface], check=False)
            if DEBUG:
                print(f"Default gateway removed from {mgmt_interface}")
    
    # Disable all interfaces except loopback and management interface
    if DEBUG:
        print(f"Disabling all interfaces except loopback and {mgmt_interface} (management interface)...")
    interfaces_to_disable = [interface for interface in interfaces 
                            if interface != 'lo' and interface != mgmt_interface and not interface.startswith('dummy_')]
    
    # First attempt to disable all interfaces
    for interface in interfaces_to_disable:
        if DEBUG:
            print(f"Disabling interface {interface}...")
        run_cmd(['ip', 'link', 'set', 'dev', interface, 'down'], check=False)
    
    # Verify interfaces are actually down and retry if needed
    if DEBUG:
        print("Verifying interfaces are down...")
    max_attempts = 3
    for attempt in range(max_attempts):
        all_down = True
        interfaces_output = run_cmd(['ip', 'link', 'show'], capture_output=True, text=True).stdout
        for interface in interfaces_to_disable:
            # Check if interface is still up
            if f"{interface}: " in interfaces_output and "state UP" in interfaces_output.split(f"{interface}: ")[1].split("\n")[0]:
                if DEBUG:
                    print(f"Interface {interface} is still up, retrying...")
                run_cmd(['ip', 'link', 'set', 'dev', interface, 'down'], check=False)
                all_down = False
        
        if all_down:
            if DEBUG:
                print("All interfaces successfully disabled.")
            break
        
        if attempt < max_attempts - 1:
            if DEBUG:
                print(f"Some interfaces still up. Waiting before retry {attempt+1}/{max_attempts}...")
            time.sleep(2)
    
    # Configure the specified interface
    if DEBUG:
        print(f'Configuring {iface}...')
    prefix = ipaddress.IPv4Network(f'0.0.0.0/{netmask}').prefixlen
    
    # Then flush and configure
    if DEBUG:
        print(f"Flushing and configuring {iface}...")
    run_cmd(['ip', 'addr', 'flush', 'dev', iface], check=True)
    run_cmd(['ip', 'addr', 'add', f'{ip_addr}/{prefix}', 'dev', iface], check=True)
    
    # Finally enable the interface
    if DEBUG:
        print(f"Enabling {iface}...")
    run_cmd(['ip', 'link', 'set', 'dev', iface, 'up'], check=True)
    
    # Wait a moment for the interface to come up
    if DEBUG:
        print("Waiting for interface to come up...")
    time.sleep(2)

# Add loopbacks
def add_loopbacks(m1,m2,client):
    for name,subnet in [('mgmt1',m1),('mgmt2',m2),('client',client)]:
        net = ipaddress.IPv4Network(subnet)
        iface = f'dummy_{name}'
        addr = str(net.network_address+1)
        prefix = net.prefixlen
        run_cmd(['ip','link','add',iface,'type','dummy'], check=False)
        run_cmd(['ip','addr','add',f'{addr}/{prefix}','dev',iface], check=False)
        run_cmd(['ip','link','set','dev',iface,'up'], check=True)
        if DEBUG:
            print(f'Loopback {iface} → {addr}/{prefix}')

# OSPF Hello sniff
def sniff_ospf_hello(iface, timeout=60):
    print(f'\nWaiting for OSPF Hello on {iface}...')
    
    # Use scapy to sniff for OSPF Hello packets
    pkts = sniff(iface=iface, filter='ip proto 89', timeout=timeout, count=1)
    if not pkts:
        print('No OSPF Hello received; aborting.')
        sys.exit(1)
    
    pkt = pkts[0]
    src = pkt[IP].src
    area = pkt[OSPF_Hdr].area
    hi = pkt[OSPF_Hello].hellointerval
    di = pkt[OSPF_Hello].deadinterval
    
    print(f"Received OSPF Hello from {src} (Area: {area}, Hello: {hi}s, Dead: {di}s)")
    
    # Don't cast area to int as it can be in dotted notation (e.g., 0.0.0.0)
    return src, area, int(hi), int(di)

# Configure OSPF - using vtysh commands directly like the original
def configure_ospf(iface, ip, prefix, m1, m2, client, up, area, hi, di):
    n1=ipaddress.IPv4Network(m1);n2=ipaddress.IPv4Network(m2);n3=ipaddress.IPv4Network(client)
    
    if DEBUG:
        print(f"Configuring FRR and OSPF for interface {iface}")
    
    # Enable ospfd in daemons file
    lines=open('/etc/frr/daemons').read().splitlines()
    with open('/etc/frr/daemons','w') as f:
        for l in lines: f.write('ospfd=yes\n' if l.startswith('ospfd=') else l+'\n')
    
    # Restart FRR
    if DEBUG:
        print("Restarting FRR...")
    run_cmd(['systemctl', 'restart', 'frr'], check=True)
    
    # Wait for FRR to start
    if DEBUG:
        print("Waiting for FRR to start...")
    time.sleep(5)
    
    # Configure OSPF using vtysh commands
    cmds=[
        'vtysh','-c','configure terminal','-c','router ospf',
        '-c',f'network {ip}/{prefix} area {area}',
        '-c',f'network {n1.network_address}/{n1.prefixlen} area {area}',
        '-c',f'network {n2.network_address}/{n2.prefixlen} area {area}',
        '-c',f'network {n3.network_address}/{n3.prefixlen} area {area}',
        '-c','exit','-c',f'interface {iface}',
        '-c',f'ip ospf hello-interval {hi}',
        '-c',f'ip ospf dead-interval {di}',
        '-c','exit','-c','end','-c','write memory'
    ]
    run_cmd(cmds, check=True, capture_output=True)
    
    # Verify interface is up and properly configured
    if DEBUG:    
        print(f"Verifying interface {iface} is up and properly configured...")
    iface_status = run_cmd(['ip', 'link', 'show', 'dev', iface], capture_output=True, text=True).stdout

    if "state UP" not in iface_status:
        if DEBUG:
            print(f"Interface {iface} is not up. Attempting to bring it up...")
        run_cmd(['ip', 'link', 'set', 'dev', iface, 'up'], check=True)
        # Wait for interface to come up
        time.sleep(2)
        # Check again
        iface_status = run_cmd(['ip', 'link', 'show', 'dev', iface], capture_output=True, text=True).stdout
        if "state UP" not in iface_status:
            print(f"WARNING: Interface {iface} could not be brought up. OSPF may not work correctly.")
    
    # Verify IP address is configured
    iface_addr = run_cmd(['ip', 'addr', 'show', 'dev', iface], capture_output=True, text=True).stdout
    if f"inet {ip}" not in iface_addr:
        if DEBUG:
            print(f"IP address {ip} not found on interface {iface}. Reconfiguring...")
        run_cmd(['ip', 'addr', 'flush', 'dev', iface], check=False)
        run_cmd(['ip', 'addr', 'add', f'{ip}/{prefix}', 'dev', iface], check=True)
    
    # Show the routing table
    route_output = run_cmd(['ip', 'route'], capture_output=True, text=True).stdout
    if DEBUG:
        print("Current routing table:")
        print(route_output)
    
    # Check connectivity to the upstream router
    print(f"Testing connectivity to upstream router {up}")
    ping_result = run_cmd(['ping', '-c', '4', up], capture_output=True)
    if ping_result.returncode == 0:
        print(f"Connectivity to upstream router {up}: {GREEN}Success{RESET}")
    else:
        print(f"Connectivity to upstream router {up}: {RED}Fail{RESET}")
        print("Warning: OSPF may not work correctly without connectivity to the upstream router")
    
    print("OSPF configuration complete")

# Show OSPF state Full/DR - using the original approach with active waiting
def show_ospf_status():
    print('\n=== Waiting for OSPF state Full/DR (30s timeout) ===')
    success = False
    for _ in range(30):
        out = run_cmd(['vtysh','-c','show ip ospf neighbor'], capture_output=True, text=True).stdout
        if any('Full/DR' in l for l in out.splitlines()[1:]):
            success = True
            print('OSPF reached Full/DR state')
            break
        time.sleep(1)
    if not success:
        print('OSPF never reached Full/DR state after 30s')
    
    # Wait a bit more to ensure stability
    time.sleep(5)
    
    # Show the routing table from FRR
    frr_routes = run_cmd(['vtysh', '-c', 'show ip route'], capture_output=True, text=True).stdout
    if DEBUG:
        print("\n=== FRR Routing Table ===")
        print(frr_routes)
    
    # Show the kernel routing table
    route_output = run_cmd(['ip', 'route'], capture_output=True, text=True).stdout
    if DEBUG:
        print(f'\n=== Kernel Routing Table ===')
        print(route_output)
    
    return success

# Add floating static default
def configure_static_route(gateway, iface):
    run_cmd(['ip','route','add','default','via',gateway,'metric','200'],check=False)

# Connectivity tests with DNS fallback logic
def run_tests(iface, ip_addr, mgmt1, client_subnet, dhcp_servers, radius_servers, secret, user, pwd, run_dhcp, run_radius, custom_dns_servers=None, custom_ntp_servers=None):
    # Initialize empty lists if None
    custom_dns_servers = custom_dns_servers or []
    custom_ntp_servers = custom_ntp_servers or []
    # Dictionary to store test results for summary
    test_results = []
    # Set initial DNS
    dns_servers = ['8.8.8.8', '8.8.4.4']
    
    # Write DNS servers to resolv.conf
    def write_resolv(servers):
        with open('/etc/resolv.conf','w') as f:
            for s in servers:
                f.write(f'nameserver {s}\n')
    write_resolv(dns_servers)
    conf.route.resync()
    
    # Initial connectivity
    ping_ok = dns_ok = False
    print(f'\nInitial Ping Tests from {ip_addr}:')
    
    # Test default DNS servers
    for tgt in dns_servers:
        r = run_cmd(['ping', '-c', '2', '-I', ip_addr, tgt], capture_output=True)
        result = r.returncode == 0
        print(f'Ping {tgt} from {ip_addr}: ' + (GREEN+'Success'+RESET if result else RED+'Fail'+RESET))
        test_results.append((f'Initial Ping {tgt} from {ip_addr}', result))
        ping_ok |= result
    
    # Test custom DNS servers if provided
    if custom_dns_servers:
        print(f'\nCustom DNS Server Ping Tests from {ip_addr}:')
        custom_ping_ok = False
        for tgt in custom_dns_servers:
            r = run_cmd(['ping', '-c', '2', '-I', ip_addr, tgt], capture_output=True)
            result = r.returncode == 0
            print(f'Ping {tgt} from {ip_addr}: ' + (GREEN+'Success'+RESET if result else RED+'Fail'+RESET))
            test_results.append((f'Initial Ping Custom DNS {tgt} from {ip_addr}', result))
            custom_ping_ok |= result
        
        # Update ping_ok to include custom DNS server ping results
        ping_ok |= custom_ping_ok


    print(f'\nInitial DNS Tests from {ip_addr} (@ ' + ', '.join(dns_servers) + '):')
    for d in dns_servers:
        r = run_cmd(['dig', f'@{d}', '-b', ip_addr, 'www.google.com', '+short'], capture_output=True, text=True)
        ok = (r.returncode==0 and bool(r.stdout.strip()))
        print(f'DNS @{d} from {ip_addr}: ' + (GREEN+'Success'+RESET if ok else RED+'Fail'+RESET))
        test_results.append((f'Initial DNS @{d} from {ip_addr}', ok))

    # Custom DNS tests from iface interface if provided
    if custom_dns_servers:
        print(f'\n=== Custom DNS tests from {ip_addr} ===')
        for d in custom_dns_servers:
            r = run_cmd(['dig', f'@{d}', '-b', ip_addr, 'www.google.com', '+short'], capture_output=True, text=True)
            ok = (r.returncode==0 and bool(r.stdout.strip()))
            print(f'Custom DNS @{d} from {ip_addr}: ' + (GREEN+'Success'+RESET if ok else RED+'Fail'+RESET))
            test_results.append((f'Custom DNS @{d} from {ip_addr}', ok))
        
        # If custom DNS servers are provided and successful, use them
        successful_custom_dns = []
        for d in custom_dns_servers:
            r = run_cmd(['dig', f'@{d}', '-b', ip_addr, 'www.google.com', '+short'], capture_output=True, text=True)
            if r.returncode == 0 and bool(r.stdout.strip()):
                successful_custom_dns.append(d)
        
        if successful_custom_dns:
            print(f"\nUsing successful custom DNS servers: {', '.join(successful_custom_dns)}")
            dns_servers = successful_custom_dns
            write_resolv(dns_servers)
            # Skip the prompt for DNS servers if we're using custom ones
            if not args.config:  # Only in interactive mode
                print("Using custom DNS servers instead of prompting for new ones.")
        else:
            # If no custom DNS servers were successful, prompt for new ones
            new_dns = prompt_nonempty('Enter DNS server IP(s) (comma-separated): ')
            dns_servers = [s.strip() for s in new_dns.split(',')]
            write_resolv(dns_servers)
    else:
        # No custom DNS servers provided, prompt for new ones
        new_dns = prompt_nonempty('Enter DNS server IP(s) (comma-separated): ')
        dns_servers = [s.strip() for s in new_dns.split(',')]
        write_resolv(dns_servers)

    if not ping_ok:
        print('Initial ping tests failed. Exiting.')
        sys.exit(1)

    # Full suite
    print(f'\nFull Test Suite:')
    
    # Get the IP address of the mgmt1 dummy loopback interface
    mgmt1_ip = str(ipaddress.IPv4Network(mgmt1).network_address+1)
    print(f"Using mgmt1 dummy loopback interface with IP {mgmt1_ip} as source for tests")
    
    # Wait a bit more to ensure stability
    print(f"Preparing {mgmt1_ip} to send tests...")
    run_cmd(['ping', '-c', '4', '-I', mgmt1_ip, tgt], capture_output=True)
    time.sleep(4)

    # Ping tests
    print(f'\n=== Ping tests ===')
    for tgt in dns_servers:
        r = run_cmd(['ping', '-c', '4', '-I', mgmt1_ip, tgt], capture_output=True, text=True)
        result = r.returncode == 0
        print(f'Ping {tgt} from {mgmt1_ip}: ' + (GREEN+'Success'+RESET if result else RED+'Fail'+RESET))
        test_results.append((f'Ping {tgt} from {mgmt1_ip}', result))
    
    # DNS tests
    print(f'\n=== DNS tests ===')
    for d in dns_servers:
        r = run_cmd(['dig', f'@{d}', '-b', mgmt1_ip, 'www.google.com', '+short'], capture_output=True, text=True)
        ok = (r.returncode==0 and bool(r.stdout.strip()))
        print(f'DNS @{d} from {mgmt1_ip}: ' + (GREEN+'Success'+RESET if ok else RED+'Fail'+RESET))
        test_results.append((f'DNS @{d} from {mgmt1_ip}', ok))
    
    # DHCP relay with ping pre-check - using dhcppython library
    if run_dhcp:
        print(f'\n=== DHCP tests (L3 relay) ===')
        # Use the first IP of the client subnet as the helper IP (giaddr)
        helper_ip = str(ipaddress.IPv4Network(client_subnet).network_address+1)
        print(f"Using client subnet first IP {helper_ip} as DHCP relay agent (giaddr)")
        
        # For the source IP, we should use the helper IP address (giaddr)
        # This is what the server will see as the source of the packet
        source_ip = helper_ip
        if DEBUG:
            print(f"Using helper IP {source_ip} as source IP for DHCP packets")
        
        for srv in dhcp_servers:
            p = run_cmd(['ping', '-c', '5', srv], capture_output=True)
            if p.returncode != 0:
                result = False
                print(f'DHCP relay to {srv}: {RED}Fail (unreachable){RESET}')
                test_results.append((f'DHCP relay to {srv}', result))
                continue
            
            # Get the MAC address for the main interface
            iface_mac_output = run_cmd(['ip', 'link', 'show', iface], capture_output=True, text=True).stdout
            iface_mac = None
            for line in iface_mac_output.splitlines():
                if 'link/ether' in line:
                    iface_mac = line.split()[1]
                    break
            
            if not iface_mac:
                print(f"Warning: Could not determine MAC address for {iface}, using random MAC")
                iface_mac = dhcp_utils.random_mac()
                
            # Create a random client MAC address
            client_mac = dhcp_utils.random_mac()
            
            # Using dhcppython for DHCP testing

            if DEBUG:
                print(f"DHCP Test Details:")
                print(f"  Interface: {iface} (MAC: {iface_mac})")
                print(f"  Source IP: {source_ip}")
                print(f"  Destination IP: {srv}")
                print(f"  Client MAC: {client_mac}")
            
            try:
                # Create DHCP client using the main interface
                if DEBUG:
                    print(f"Creating DHCP client on {iface} interface...")
                c = dhcp_client.DHCPClient(
                    iface,
                    send_from_port=67,  # Server port (for relay)
                    send_to_port=67     # Server port
                )
                
                # Create a list of DHCP options
                if DEBUG:
                    print(f"Setting up DHCP options...")
                options_list = dhcp_options.OptionList([
                    # Add standard options
                    dhcp_options.options.short_value_to_object(60, "nile-readiness-test"),  # Class identifier
                    dhcp_options.options.short_value_to_object(12, socket.gethostname()),   # Hostname
                    # Parameter request list - request common options
                    dhcp_options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43])
                ])
                
                if DEBUG:
                    print(f"Attempting to get DHCP lease from {srv}...")
                # Set broadcast=False for unicast to specific server
                # Set server to the DHCP server IP
                try:
                    lease = c.get_lease(
                        client_mac,
                        broadcast=False,
                        options_list=options_list,
                        server=srv,
                        relay=helper_ip
                    )
                    
                    # If we get here, we got a lease
                    if DEBUG:
                        print(f"\nSuccessfully obtained DHCP lease!")
                        print(f"DEBUG: Lease details:")
                        print(f"  Your IP: {lease.ack.yiaddr}")
                        print(f"  Server IP: {lease.ack.siaddr}")
                        print(f"  Gateway: {lease.ack.giaddr}")
                        print(f"  Options: {lease.ack.options}")
                    
                    result = True
                    print(f'DHCP relay to {srv}: ' + GREEN+'Success'+RESET)
                    test_results.append((f'DHCP relay to {srv}', result))
                except Exception as e:
                    print(f"Error during DHCP lease request: {e}")
                    if DEBUG:
                        import traceback
                        traceback.print_exc()
                    result = False
                    print(f'DHCP relay to {srv}: ' + RED+'Fail'+RESET)
                    test_results.append((f'DHCP relay to {srv}', result))
                
                
            except Exception as e:
                print(f"Error during DHCP test: {e}")
                if DEBUG:
                    import traceback
                    traceback.print_exc()
                result = False
                print(f'DHCP relay to {srv}: ' + RED+'Fail'+RESET)
                test_results.append((f'DHCP relay to {srv}', result))
    else:
        print('\nSkipping DHCP tests')

    # RADIUS with ping pre-check
    if run_radius:
        print(f'\n=== RADIUS tests ===')
        for srv in radius_servers:
            p = run_cmd(['ping', '-c', '1', srv], capture_output=True)
            if p.returncode != 0:
                result = False
                print(f'RADIUS {srv}: {RED}Fail (unreachable){RESET}')
                test_results.append((f'RADIUS {srv}', result))
                continue
            cmd = (f'echo "User-Name={user},User-Password={pwd}" '
                  f'| radclient -x -s {srv}:1812 auth {secret}')
            res = run_cmd(cmd, shell=True, capture_output=True, text=True)
            result = res.returncode == 0
            print(f'RADIUS {srv}: ' + (GREEN+'Success'+RESET if result else RED+'Fail'+RESET))
            test_results.append((f'RADIUS {srv}', result))
    else:
        print('\nSkipping RADIUS tests')

    # NTP tests from main interface
    print(f'\n=== NTP tests from main interface ({ip_addr}) ===')
    # Test default NTP servers
    for ntp in ('time.google.com', 'pool.ntp.org'):
        r = run_cmd(['ntpdate', '-q', '-b', ip_addr, ntp], capture_output=True, text=True)
        result = r.returncode == 0
        print(f'NTP {ntp} from {ip_addr}: ' + (GREEN+'Success'+RESET if result else RED+'Fail'+RESET))
        test_results.append((f'NTP {ntp} from {ip_addr}', result))
    
    # Test custom NTP servers if provided
    if custom_ntp_servers:
        print(f'\n=== Custom NTP tests from main interface ({ip_addr}) ===')
        for ntp in custom_ntp_servers:
            r = run_cmd(['ntpdate', '-q', '-b', ip_addr, ntp], capture_output=True, text=True)
            result = r.returncode == 0
            print(f'Custom NTP {ntp} from {ip_addr}: ' + (GREEN+'Success'+RESET if result else RED+'Fail'+RESET))
            test_results.append((f'Custom NTP {ntp} from {ip_addr}', result))
    
    # NTP tests from mgmt1
    print(f'\n=== NTP tests from mgmt1 ({mgmt1_ip}) ===')
    # Test default NTP servers
    for ntp in ('time.google.com', 'pool.ntp.org'):
        r = run_cmd(['ntpdate', '-q', '-b', mgmt1_ip, ntp], capture_output=True, text=True)
        result = r.returncode == 0
        print(f'NTP {ntp} from {mgmt1_ip}: ' + (GREEN+'Success'+RESET if result else RED+'Fail'+RESET))
        test_results.append((f'NTP {ntp} from {mgmt1_ip}', result))
    
    # Test custom NTP servers if provided
    if custom_ntp_servers:
        print(f'\n=== Custom NTP tests from mgmt1 ({mgmt1_ip}) ===')
        for ntp in custom_ntp_servers:
            r = run_cmd(['ntpdate', '-q', '-b', mgmt1_ip, ntp], capture_output=True, text=True)
            result = r.returncode == 0
            print(f'Custom NTP {ntp} from {mgmt1_ip}: ' + (GREEN+'Success'+RESET if result else RED+'Fail'+RESET))
            test_results.append((f'Custom NTP {ntp} from {mgmt1_ip}', result))

    # HTTPS and SSL Certificate tests
    print(f'=== HTTPS and SSL Certificate tests ===')
    
    # Test HTTPS connectivity and SSL certificates for Nile Cloud from main interface
    print(f'\nTesting HTTPS for {NILE_HOSTNAME} from {ip_addr}...')
    parsed = urlparse(f'https://{NILE_HOSTNAME}')
    host, port = parsed.hostname, parsed.port or 443
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((ip_addr, 0))  # Bind to ip_addr with a random port
        sock.connect((host, port))
        sock.close()
        https_ok = True
        print(f'HTTPS {NILE_HOSTNAME} from {ip_addr}: {GREEN}Success{RESET}')
    except Exception as e:
        https_ok = False
        if DEBUG:
            print(f'HTTPS {NILE_HOSTNAME} from {ip_addr}: {RED}Fail{RESET} ({e})')
        else:
            print(f'HTTPS {NILE_HOSTNAME} from {ip_addr}: {RED}Fail{RESET}')
    test_results.append((f'HTTPS {NILE_HOSTNAME} from {ip_addr}', https_ok))
    
    # Test HTTPS connectivity and SSL certificates for Nile Cloud from mgmt1
    print(f'\nTesting HTTPS for {NILE_HOSTNAME} from {mgmt1_ip}...')
    parsed = urlparse(f'https://{NILE_HOSTNAME}')
    host, port = parsed.hostname, parsed.port or 443
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((mgmt1_ip, 0))  # Bind to mgmt1_ip with a random port
        sock.connect((host, port))
        sock.close()
        https_ok = True
        print(f'HTTPS {NILE_HOSTNAME} from {mgmt1_ip}: {GREEN}Success{RESET}')
    except Exception as e:
        https_ok = False
        if DEBUG:
            print(f'HTTPS {NILE_HOSTNAME} from {mgmt1_ip}: {RED}Fail{RESET} ({e})')
        else:
            print(f'HTTPS {NILE_HOSTNAME} from {mgmt1_ip}: {RED}Fail{RESET}')
    test_results.append((f'HTTPS {NILE_HOSTNAME} from {mgmt1_ip}', https_ok))
    
    # Now check the SSL certificate
    print(f'\nChecking SSL certificate for {NILE_HOSTNAME}...')
    # Use dig to resolve the hostname to IP addresses
    r = run_cmd(['dig', NILE_HOSTNAME, '+short'], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        nile_ips = r.stdout.strip().split('\n')
        print(f"\nResolved {NILE_HOSTNAME} to: {', '.join(nile_ips)}")
        nile_ssl_success = False
        for ip in nile_ips:
            if check_ssl_certificate(ip, NILE_HOSTNAME, "Nile Global Inc."):
                nile_ssl_success = True
                print(f"SSL certificate for {NILE_HOSTNAME}: {GREEN}Success{RESET}")
                break
            else:
                print(f"SSL certificate for {NILE_HOSTNAME} (IP: {ip}): {RED}Fail{RESET}")
        test_results.append((f"SSL Certificate for {NILE_HOSTNAME}", nile_ssl_success))
    else:
        print(f"Could not resolve {NILE_HOSTNAME} for SSL check")
        test_results.append((f"SSL Certificate for {NILE_HOSTNAME}", False))
    
    # Test HTTPS connectivity and SSL certificates for Amazon S3 from main interface
    print(f'\nTesting HTTPS for {S3_HOSTNAME} from {ip_addr}...')
    r = run_cmd(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', 
                 '--connect-timeout', '10', '--interface', ip_addr,
                 '-A', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                 '-H', 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                 '-H', 'Accept-Language: en-US,en;q=0.5',
                 f'https://{S3_HOSTNAME}/nile-prod-us-west-2'], capture_output=True, text=True)
    # For HTTPS tests, consider 2xx and 3xx as success (redirects are common)
    https_ok = r.returncode == 0 and (r.stdout.strip().startswith('2') or r.stdout.strip().startswith('3'))
    if https_ok:
        print(f'HTTPS {S3_HOSTNAME} from {ip_addr}: {GREEN}Success{RESET} (Status: {r.stdout.strip()})')
    else:
        # For 403 errors, it's still a successful connection, just forbidden access
        if r.stdout.strip() == '403':
            print(f'HTTPS {S3_HOSTNAME} from {ip_addr}: {GREEN}Success{RESET} (Status: 403 Forbidden - connection successful but access denied)')
            https_ok = True
        else:
            print(f'HTTPS {S3_HOSTNAME} from {ip_addr}: {RED}Fail{RESET} (Status: {r.stdout.strip() if r.stdout else "Connection failed"})')
    test_results.append((f'HTTPS {S3_HOSTNAME} from {ip_addr}', https_ok))
    
    # Test HTTPS connectivity and SSL certificates for Amazon S3 from mgmt1
    print(f'\nTesting HTTPS for {S3_HOSTNAME} from {mgmt1_ip}...')
    r = run_cmd(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', 
                 '--connect-timeout', '10', '--interface', mgmt1_ip,
                 '-A', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                 '-H', 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                 '-H', 'Accept-Language: en-US,en;q=0.5',
                 f'https://{S3_HOSTNAME}/nile-prod-us-west-2'], capture_output=True, text=True)
    # For HTTPS tests, consider 2xx and 3xx as success (redirects are common)
    https_ok = r.returncode == 0 and (r.stdout.strip().startswith('2') or r.stdout.strip().startswith('3'))
    if https_ok:
        print(f'HTTPS {S3_HOSTNAME} from {mgmt1_ip}: {GREEN}Success{RESET} (Status: {r.stdout.strip()})')
    else:
        # For 403 errors, it's still a successful connection, just forbidden access
        if r.stdout.strip() == '403':
            print(f'HTTPS {S3_HOSTNAME} from {mgmt1_ip}: {GREEN}Success{RESET} (Status: 403 Forbidden - connection successful but access denied)')
            https_ok = True
        else:
            print(f'HTTPS {S3_HOSTNAME} from {mgmt1_ip}: {RED}Fail{RESET} (Status: {r.stdout.strip() if r.stdout else "Connection failed"})')
    test_results.append((f'HTTPS {S3_HOSTNAME} from {mgmt1_ip}', https_ok))
    
    # Now check the SSL certificate
    print(f'\nChecking SSL certificate for {S3_HOSTNAME}...')
    # Use dig to resolve the hostname to IP addresses
    r = run_cmd(['dig', S3_HOSTNAME, '+short'], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        s3_ips = r.stdout.strip().split('\n')
        print(f"\nResolved {S3_HOSTNAME} to: {', '.join(s3_ips)}")
        s3_ssl_success = False
        # Only test the first 2 IPs for S3
        for ip in s3_ips[:2]:
            if check_ssl_certificate(ip, S3_HOSTNAME, "Amazon"):
                s3_ssl_success = True
                print(f"SSL certificate for {S3_HOSTNAME}: {GREEN}Success{RESET}")
                break
            else:
                print(f"SSL certificate for {S3_HOSTNAME} (IP: {ip}): {RED}Fail{RESET}")
        test_results.append((f"SSL Certificate for {S3_HOSTNAME}", s3_ssl_success))
    else:
        print(f"Could not resolve {S3_HOSTNAME} for SSL check")
        test_results.append((f"SSL Certificate for {S3_HOSTNAME}", False))
    
    # Test HTTPS connectivity for Nile Secure from main interface
    print(f'\nTesting HTTPS for u1.nilesecure.com from {ip_addr}...')
    r = run_cmd(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', 
                 '--connect-timeout', '10', '--interface', ip_addr,
                 '-A', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                 '-H', 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                 '-H', 'Accept-Language: en-US,en;q=0.5',
                 'https://u1.nilesecure.com'], capture_output=True, text=True)
    # For HTTPS tests, consider 2xx and 3xx as success (redirects are common)
    https_ok = r.returncode == 0 and (r.stdout.strip().startswith('2') or r.stdout.strip().startswith('3'))
    if https_ok:
        print(f'HTTPS u1.nilesecure.com from {ip_addr}: {GREEN}Success{RESET} (Status: {r.stdout.strip()})')
    else:
        # For 403 errors, it's still a successful connection, just forbidden access
        if r.stdout.strip() == '403':
            print(f'HTTPS u1.nilesecure.com from {ip_addr}: {GREEN}Success{RESET} (Status: 403 Forbidden - connection successful but access denied)')
            https_ok = True
        else:
            print(f'HTTPS u1.nilesecure.com from {ip_addr}: {RED}Fail{RESET} (Status: {r.stdout.strip() if r.stdout else "Connection failed"})')
    test_results.append((f'HTTPS u1.nilesecure.com from {ip_addr}', https_ok))
    
    # Test HTTPS connectivity for Nile Secure from mgmt1
    print(f'\nTesting HTTPS for u1.nilesecure.com from {mgmt1_ip}...')
    r = run_cmd(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', 
                 '--connect-timeout', '10', '--interface', mgmt1_ip,
                 '-A', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                 '-H', 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                 '-H', 'Accept-Language: en-US,en;q=0.5',
                 'https://u1.nilesecure.com'], capture_output=True, text=True)
    # For HTTPS tests, consider 2xx and 3xx as success (redirects are common)
    https_ok = r.returncode == 0 and (r.stdout.strip().startswith('2') or r.stdout.strip().startswith('3'))
    if https_ok:
        print(f'HTTPS u1.nilesecure.com from {mgmt1_ip}: {GREEN}Success{RESET} (Status: {r.stdout.strip()})')
    else:
        # For 403 errors, it's still a successful connection, just forbidden access
        if r.stdout.strip() == '403':
            print(f'HTTPS u1.nilesecure.com from {mgmt1_ip}: {GREEN}Success{RESET} (Status: 403 Forbidden - connection successful but access denied)')
            https_ok = True
        else:
            print(f'HTTPS u1.nilesecure.com from {mgmt1_ip}: {RED}Fail{RESET} (Status: {r.stdout.strip() if r.stdout else "Connection failed"})')
    test_results.append((f'HTTPS u1.nilesecure.com from {mgmt1_ip}', https_ok))
    
    # UDP Connectivity Check for Guest Access
    print(f'\n=== UDP Connectivity Check for Guest Access ===')
    guest_success = False
    geneve_success = False
    
    for ip in GUEST_IPS:
        print(f"Testing UDP connectivity to {ip}:{UDP_PORT}...")
        if check_udp_connectivity_netcat(ip, UDP_PORT):
            guest_success = True
            print(f"UDP connectivity to {ip}:{UDP_PORT}: {GREEN}Success{RESET}")
            
            # If basic UDP connectivity succeeds, try Geneve test with separate send and sniff
            print(f"Testing Geneve protocol on {ip}:{UDP_PORT}...")
            
            # First send a Geneve packet
            print(f"Step 1: Sending Geneve packet to {ip}:{UDP_PORT}...")
            send_success, pkt = send_geneve_packet(ip, ip_addr, UDP_PORT)
            
            if send_success:
                print(f"Successfully sent Geneve packet to {ip}:{UDP_PORT}")
                
                # Then sniff for a response - explicitly use the test interface
                print(f"Step 2: Sniffing for Geneve response from {ip}:{UDP_PORT} on interface {iface}...")
                sniff_success, response = sniff_geneve_packet(ip, ip_addr, UDP_PORT, timeout=10, sport=12345, iface=iface)
                
                if sniff_success:
                    geneve_success = True
                    print(f"Geneve protocol on {ip}:{UDP_PORT}: {GREEN}Success{RESET}")
                else:
                    print(f"Geneve protocol on {ip}:{UDP_PORT}: {RED}Fail{RESET} (No valid Geneve response received)")
            else:
                print(f"Geneve protocol on {ip}:{UDP_PORT}: {RED}Fail{RESET} (Failed to send Geneve packet)")
            
            break
        else:
            print(f"UDP connectivity to {ip}:{UDP_PORT}: {RED}Fail{RESET}")
    
    test_results.append(("UDP Connectivity Check for Guest Access", guest_success))
    if guest_success:  # Only add Geneve test result if UDP connectivity succeeded
        test_results.append(("Geneve Protocol Check for Guest Access", geneve_success))
    
    
    return test_results

# Print test summary
def print_test_summary(test_results):
    print("\n=== Test Summary ===")
    success_count = 0
    total_count = len(test_results)
    
    for test_name, result in test_results:
        status = GREEN + "Success" + RESET if result else RED + "Fail" + RESET
        print(f"{test_name}: {status}")
        if result:
            success_count += 1
    
    success_rate = (success_count / total_count) * 100 if total_count > 0 else 0
    print(f"\nOverall: {success_count}/{total_count} tests passed ({success_rate:.1f}%)")

# Main flow
def main():
    # Get user input from config file or interactive prompts
    (test_iface, ip_addr, netmask, gateway, mgmt_interface,
     mgmt1, mgmt2, client_subnet,
     dhcp_servers, radius_servers, secret, username, password,
     run_dhcp, run_radius, custom_dns_servers, custom_ntp_servers) = get_user_input(args.config)
    
    # Print summary of custom DNS and NTP servers if provided
    if custom_dns_servers:
        print(f"\nWill test custom DNS servers: {', '.join(custom_dns_servers)}")
    if custom_ntp_servers:
        print(f"\nWill test custom NTP servers: {', '.join(custom_ntp_servers)}")

    # Record the original state of the interface
    state = record_state(test_iface)
    
    try:
        # Configure the interface
        configure_interface(test_iface, ip_addr, netmask, mgmt_interface)
        
        # Add loopbacks
        add_loopbacks(mgmt1, mgmt2, client_subnet)

        time.sleep(5)

        # Configure static route
        prefix = ipaddress.IPv4Network(f'0.0.0.0/{netmask}').prefixlen
        configure_static_route(gateway, test_iface)

        # Update scapy's routing table
        conf.route.resync()
        
        # Sniff for OSPF Hello packets
        up, area, hi, di = sniff_ospf_hello(test_iface)
        
        # Configure OSPF
        configure_ospf(test_iface, ip_addr, prefix, mgmt1, mgmt2, client_subnet, up, area, hi, di)
        
        # Check OSPF status
        ospf_ok = show_ospf_status()
        print("OSPF adjacency test: " + (GREEN+'Success'+RESET if ospf_ok else RED+'Fail'+RESET))




        # Run connectivity tests
        test_results = run_tests(test_iface, ip_addr, mgmt1, client_subnet, dhcp_servers, radius_servers, secret, username, password, run_dhcp, run_radius, custom_dns_servers, custom_ntp_servers)
    
    finally:
        # Restore the original state
        restore_state(test_iface, state)
        
        # Print test summary after restoring state
        if 'test_results' in locals():
            print_test_summary(test_results)

if __name__=='__main__':
    if os.geteuid()!=0:
        print('Must run as root')
        sys.exit(1)
    main()
