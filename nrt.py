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
from urllib.parse import urlparse
from scapy.config import conf
from scapy.all import sniff, sendp, RandMAC, Ether, BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello

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
    'curl': 'HTTPS test utility (curl)'
}
missing = [name for name in required_bins if shutil.which(name) is None]
if missing:
    print('Error: the following required tools are missing:')
    for name in missing:
        print(f'  - {required_bins[name]}')
    print()
    print('Please install them, e.g.:')
    print('  sudo apt update && sudo apt install frr freeradius-client dnsutils ntpdate curl')
    sys.exit(1)

# Wrapper for subprocess.run with debug
def run_cmd(cmd, **kwargs):
    if DEBUG:
        printed = cmd if isinstance(cmd, str) else ' '.join(cmd)
        print(f'DEBUG: Running: {printed} | kwargs={kwargs}')
    proc = subprocess.run(cmd, **kwargs)
    if DEBUG and kwargs.get('capture_output'):
        print('DEBUG: stdout:')
        print(proc.stdout)
        print('DEBUG: stderr:')
        print(proc.stderr)
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
        frr_iface = config.get('frr_interface', 'enxf0a731f41761')
        ip_addr = config.get('ip_address')
        netmask = config.get('netmask')
        gateway = config.get('gateway')
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
        print(f"  FRR Interface: {frr_iface}")
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
    else:
        # Interactive mode
        print("\nNetwork Interface Configuration:")
        print("--------------------------------")
        frr_iface     = prompt_nonempty('Interface for FRR tests (default: enxf0a731f41761): ') or 'enxf0a731f41761'
        ip_addr       = prompt_nonempty('IP address for FRR interface: ')
        netmask       = prompt_nonempty('Netmask (e.g. 255.255.255.0): ')
        gateway       = prompt_nonempty('Gateway IP: ')
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

    return (frr_iface, ip_addr, netmask, gateway,
            mgmt1, mgmt2, client_subnet,
            dhcp_servers, radius_servers, secret, username, password,
            run_dhcp, run_radius)

# Record/restore host state
def record_state(iface):
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
    run_cmd(['ip','addr','flush','dev',iface], check=True)
    for addr in state['addrs']:
        run_cmd(['ip','addr','add',addr,'dev',iface], check=True)
    run_cmd(['ip','route','flush','default'], check=True)
    for r in state['routes']:
        parts = r.split()
        run_cmd(['ip','route','add'] + parts, check=True)
    for name in ('mgmt1','mgmt2','client'):
        run_cmd(['ip','link','delete',f'dummy_{name}'], check=False)
    with open('/etc/frr/daemons','w') as f: f.write(state['daemons'])
    run_cmd(['rm','-f','/etc/frr/frr.conf'], check=False)
    with open('/etc/resolv.conf','w') as f: f.write(state['resolv'])
    run_cmd(['systemctl','stop','frr'], check=False)
    run_cmd(['systemctl','disable','frr'], check=False)
    print('Removed FRR config, stopped service, restored DNS.')

# Configure main interface
def configure_interface(iface, ip_addr, netmask):
    print(f'Configuring {iface} → {ip_addr}/{netmask}')
    prefix = ipaddress.IPv4Network(f'0.0.0.0/{netmask}').prefixlen
    run_cmd(['ip','addr','flush','dev',iface], check=True)
    run_cmd(['ip','addr','add',f'{ip_addr}/{prefix}','dev',iface], check=True)
    run_cmd(['ip','link','set','dev',iface,'up'], check=True)

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
        print(f'Loopback {iface} → {addr}/{prefix}')

# OSPF Hello sniff
def sniff_ospf_hello(iface, timeout=60):
    print(f'Waiting for OSPF Hello on {iface}...')
    
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
    
    print(f"Configuring FRR and OSPF for interface {iface}")
    
    # Enable ospfd in daemons file
    lines=open('/etc/frr/daemons').read().splitlines()
    with open('/etc/frr/daemons','w') as f:
        for l in lines: f.write('ospfd=yes\n' if l.startswith('ospfd=') else l+'\n')
    
    # Restart FRR
    print("Restarting FRR...")
    run_cmd(['systemctl', 'restart', 'frr'], check=True)
    
    # Wait for FRR to start
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
    run_cmd(cmds, check=True)
    
    # Add route to upstream router
    run_cmd(['ip', 'route', 'add', up, 'via', up, 'dev', iface], check=False)
    
    # Show the routing table
    route_output = run_cmd(['ip', 'route'], capture_output=True, text=True).stdout
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
    print("\n=== FRR Routing Table ===")
    frr_routes = run_cmd(['vtysh', '-c', 'show ip route'], capture_output=True, text=True).stdout
    print(frr_routes)
    
    # Show the kernel routing table
    print(f'\n=== Kernel Routing Table ===')
    route_output = run_cmd(['ip', 'route'], capture_output=True, text=True).stdout
    print(route_output)
    
    # Add a default route via the upstream router after OSPF has had time to establish
    print("Adding default route via upstream router")
    gateway_ip = None
    for line in route_output.splitlines():
        if 'via' in line and not line.startswith('default'):
            parts = line.split()
            if 'via' in parts:
                gateway_ip = parts[parts.index('via') + 1]
                break
    
    if gateway_ip:
        run_cmd(['ip', 'route', 'add', 'default', 'via', gateway_ip], check=False)
        print(f"Added default route via {gateway_ip}")
    
    return success

# Add floating static default
def configure_static_route(gateway,iface):
    run_cmd(['ip','route','add','default','via',gateway,'metric','200'],check=False)

# Connectivity tests with DNS fallback logic
def run_tests(iface, mgmt1, client_subnet, dhcp_servers, radius_servers, secret, user, pwd, run_dhcp, run_radius):
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
    print(f'Initial Ping Tests:')
    for tgt in dns_servers:
        r = run_cmd(['ping', '-c', '2', tgt], capture_output=True)
        print(f'Ping {tgt}: ' + (GREEN+'Success'+RESET if r.returncode==0 else RED+'Fail'+RESET))
        ping_ok |= (r.returncode==0)

    # Initial DNS tests with retry prompt
    while True:
        print(f'Initial DNS Tests (@ ' + ', '.join(dns_servers) + '):')
        dns_ok = False
        for d in dns_servers:
            r = run_cmd(['dig', f'@{d}', 'www.google.com', '+short'], capture_output=True, text=True)
            ok = (r.returncode==0 and bool(r.stdout.strip()))
            print(f'DNS @{d}: ' + (GREEN+'Success'+RESET if ok else RED+'Fail'+RESET))
            dns_ok |= ok
        if dns_ok:
            break
        ans = input('Default DNS tests failed. Enter alternate DNS servers? [y/N]: ').strip().lower()
        if not ans.startswith('y'):
            print('Cannot continue without DNS. Exiting.')
            sys.exit(1)
        new_dns = prompt_nonempty('Enter DNS server IP(s) (comma-separated): ')
        dns_servers = [s.strip() for s in new_dns.split(',')]
        write_resolv(dns_servers)

    if not ping_ok:
        print('Initial ping tests failed. Exiting.')
        sys.exit(1)

    # Full suite
    print(f'\nFull Test Suite:')
    for tgt in dns_servers:
        r = run_cmd(['ping', '-c', '4', tgt], capture_output=True, text=True)
        print(f'Ping {tgt}: ' + (GREEN+'Success'+RESET if r.returncode==0 else RED+'Fail'+RESET))
    for d in dns_servers:
        r = run_cmd(['dig', f'@{d}', 'www.google.com', '+short'], capture_output=True, text=True)
        ok = (r.returncode==0 and bool(r.stdout.strip()))
        print(f'DNS @{d}: ' + (GREEN+'Success'+RESET if ok else RED+'Fail'+RESET))

    # DHCP relay with ping pre-check - using scapy like the original
    if run_dhcp:
        print(f'=== DHCP tests (L3 relay) ===')
        helper_ip = str(ipaddress.IPv4Network(client_subnet).network_address+1)
        for srv in dhcp_servers:
            p = run_cmd(['ping', '-c', '1', srv], capture_output=True)
            if p.returncode != 0:
                print(f'DHCP relay to {srv}: {RED}Fail (unreachable){RESET}')
                continue
            
            # Use scapy to craft and send DHCP packets
            xid = random.randint(1, 0xffffffff)
            client_mac = RandMAC()
            
            # For Layer 3 relay, we need to:
            # 1. Keep ports as 67 as per user feedback
            # 2. Set giaddr to the relay agent IP
            # 3. Include proper DHCP options
            
            pkt = (Ether(dst='ff:ff:ff:ff:ff:ff')/
                  IP(src=helper_ip, dst=srv)/
                  UDP(sport=67, dport=67)/  # Using port 67 for both as per user feedback
                  BOOTP(op=1, chaddr=client_mac, xid=xid, giaddr=helper_ip, flags=0x8000)/  # Set broadcast flag
                  DHCP(options=[
                      ('message-type', 'discover'),
                      ('param_req_list', [1, 3, 6, 15, 51, 58, 59]),  # Common requested options
                      ('end')
                  ]))
            
            print('DHCP DISCOVER packet created:')
            print(f'  Source IP: {helper_ip}, Destination IP: {srv}')
            print(f'  Transaction ID (xid): {hex(xid)}')
            print(f'  Relay Agent IP (giaddr): {helper_ip}')
            
            if DEBUG:
                print('DEBUG: DHCP DISCOVER summary:')
                print(pkt.summary())
                print('DEBUG: DHCP DISCOVER details:')
                print(pkt.show())
            
            # Start sniffing before sending to avoid race conditions
            # Use a more permissive filter to catch all potential responses
            sniff_filter = f'udp'  # Most permissive filter to catch any UDP traffic
            
            print(f'Sending DHCP DISCOVER and waiting for response...')
            
            # Send the packet
            sendp(pkt, iface=iface, verbose=DEBUG)
            
            # Sniff for responses with a longer timeout (30 seconds)
            print(f'Sniffing for DHCP responses on {iface} for 30 seconds...')
            resp = sniff(iface=iface, filter=sniff_filter,
                        timeout=30, count=5,  # Increased timeout and count
                        lfilter=lambda p: p.haslayer(UDP))  # Capture all UDP packets first
            
            # Process captured packets
            dhcp_responses = []
            for p in resp:
                if DEBUG:
                    print(f'DEBUG: Captured packet: {p.summary()}')
                
                # Check if it's a DHCP packet
                if p.haslayer(BOOTP):
                    print(f'Found BOOTP packet: {p.summary()}')
                    if p[BOOTP].op == 2:  # BOOTREPLY
                        print(f'  BOOTREPLY detected, xid={hex(p[BOOTP].xid)}')
                        if p[BOOTP].xid == xid:
                            print(f'  Transaction ID matches!')
                            dhcp_responses.append(p)
                            if p.haslayer(DHCP):
                                print(f'  DHCP layer present')
                                for opt in p[DHCP].options:
                                    if opt[0] == 'message-type' and opt[1] == 2:  # DHCP Offer
                                        print(f'  DHCP OFFER detected!')
            
            # Check if we found any valid responses
            if dhcp_responses:
                print(f'Found {len(dhcp_responses)} valid DHCP responses')
                success = True
            else:
                print(f'No valid DHCP responses found')
                success = False
            
            # Always print response count and summary regardless of DEBUG mode
            print(f'Total UDP packets captured: {len(resp)}')
            for i, p in enumerate(resp):
                print(f'Packet {i+1}: {p.summary()}')
                
            print(f'DHCP relay to {srv}: ' + (GREEN+'Success'+RESET if dhcp_responses else RED+'Fail'+RESET))
    else:
        print('Skipping DHCP tests')

    # RADIUS with ping pre-check
    if run_radius:
        print(f'=== RADIUS tests ===')
        for srv in radius_servers:
            p = run_cmd(['ping', '-c', '1', srv], capture_output=True)
            if p.returncode != 0:
                print(f'RADIUS {srv}: {RED}Fail (unreachable){RESET}')
                continue
            cmd = (f'echo "User-Name={user},User-Password={pwd}" '
                  f'| radclient -x -s {srv}:1812 auth {secret}')
            res = run_cmd(cmd, shell=True, capture_output=True, text=True)
            print(f'RADIUS {srv}: ' + (GREEN+'Success'+RESET if res.returncode==0 else RED+'Fail'+RESET))
    else:
        print('Skipping RADIUS tests')

    # NTP
    print(f'=== NTP tests ===')
    for ntp in ('time.google.com', 'pool.ntp.org'):
        r = run_cmd(['ntpdate', '-q', ntp], capture_output=True, text=True)
        print(f'NTP {ntp}: ' + (GREEN+'Success'+RESET if r.returncode==0 else RED+'Fail'+RESET))

    # HTTPS - using socket.create_connection like the original
    print(f'=== HTTPS tests ===')
    for url in ('https://u1.nilesecure.com',
                'https://ne-u1.nile-global.cloud',
                'https://s3.us-west-2.amazonaws.com/nile-prod-us-west-2'):
        parsed = urlparse(url)
        host, port = parsed.hostname, parsed.port or 443
        try:
            sock = socket.create_connection((host, port), timeout=5)
            sock.close()
            ok = True
        except:
            ok = False
        print(f'HTTPS {url}: ' + (GREEN+'Success'+RESET if ok else RED+'Fail'+RESET))

# Main flow
def main():
    # Get user input from config file or interactive prompts
    (frr_iface, ip_addr, netmask, gateway, mgmt1, mgmt2, client_subnet,
     dhcp_servers, radius_servers, secret, username, password,
     run_dhcp, run_radius) = get_user_input(args.config)

    # Record the original state of the interface
    state = record_state(frr_iface)
    
    try:
        # Configure the interface
        configure_interface(frr_iface, ip_addr, netmask)
        
        # Add loopbacks
        add_loopbacks(mgmt1, mgmt2, client_subnet)
        
        # Configure static route
        prefix = ipaddress.IPv4Network(f'0.0.0.0/{netmask}').prefixlen
        configure_static_route(gateway, frr_iface)
        
        # Update scapy's routing table
        conf.route.resync()
        
        # Sniff for OSPF Hello packets
        up, area, hi, di = sniff_ospf_hello(frr_iface)
        
        # Configure OSPF
        configure_ospf(frr_iface, ip_addr, prefix, mgmt1, mgmt2, client_subnet, up, area, hi, di)
        
        # Check OSPF status
        ospf_ok = show_ospf_status()
        print("OSPF adjacency test: " + (GREEN+'Success'+RESET if ospf_ok else RED+'Fail'+RESET))
        
        # Run connectivity tests
        run_tests(frr_iface, mgmt1, client_subnet, dhcp_servers, radius_servers, secret, username, password, run_dhcp, run_radius)
    
    finally:
        # Restore the original state
        restore_state(frr_iface, state)

if __name__=='__main__':
    if os.geteuid()!=0:
        print('Must run as root')
        sys.exit(1)
    main()
