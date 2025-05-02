#!/usr/bin/env python3
"""
nrt.py - Configures host interface, OSPF adjacency dynamically,
loopback interfaces, default route fallback, connectivity tests (DHCP/RADIUS,
NTP, HTTPS), then restores host to original state (including removing FRR config,
stopping FRR) and DNS changes.

This script uses network namespaces to isolate enxf0a731f41761 for FRR tests while keeping
end0 available for normal Raspberry Pi services.

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

# Network namespace constants
FRR_NS = "frr_ns"  # Namespace for FRR tests

# Network namespace management functions
def create_namespace(ns_name):
    """Create a network namespace if it doesn't exist"""
    print(f"Creating network namespace: {ns_name}")
    run_cmd(['ip', 'netns', 'add', ns_name], check=False)
    # Create loopback interface in the namespace
    run_cmd(['ip', 'netns', 'exec', ns_name, 'ip', 'link', 'set', 'lo', 'up'], check=False)
    return True

def delete_namespace(ns_name):
    """Delete a network namespace"""
    print(f"Deleting network namespace: {ns_name}")
    run_cmd(['ip', 'netns', 'delete', ns_name], check=False)
    return True

def move_interface_to_namespace(iface, ns_name):
    """Move a network interface to a namespace"""
    print(f"Moving interface {iface} to namespace {ns_name}")
    run_cmd(['ip', 'link', 'set', iface, 'netns', ns_name], check=True)
    run_cmd(['ip', 'netns', 'exec', ns_name, 'ip', 'link', 'set', iface, 'up'], check=True)
    return True

def run_in_namespace(ns_name, cmd, **kwargs):
    """Run a command in a network namespace"""
    ns_cmd = ['ip', 'netns', 'exec', ns_name] + (cmd if isinstance(cmd, list) else [cmd])
    return run_cmd(ns_cmd, **kwargs)

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
        print("end0 will be kept for normal Raspberry Pi services")
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

# OSPF Hello sniff in namespace
def sniff_ospf_hello_in_namespace(ns_name, iface, timeout=60):
    print(f'Waiting for OSPF Hello on {iface} in namespace {ns_name}...')
    
    # Since scapy doesn't directly support namespaces, we'll use a workaround
    # We'll create a temporary script to run scapy in the namespace
    script_content = f"""#!/usr/bin/env python3
import sys
from scapy.all import sniff, IP
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello

pkts = sniff(iface='{iface}', filter='ip proto 89', timeout={timeout}, count=1)
if not pkts:
    sys.exit(1)
pkt = pkts[0]
print(f"{{pkt[IP].src}},{{pkt[OSPF_Hdr].area}},{{pkt[OSPF_Hello].hellointerval}},{{pkt[OSPF_Hello].deadinterval}}")
"""
    
    # Write the script to a temporary file
    with open('/tmp/ospf_sniff.py', 'w') as f:
        f.write(script_content)
    
    # Make it executable
    run_cmd(['chmod', '+x', '/tmp/ospf_sniff.py'], check=True)
    
    # Run the script in the namespace
    result = run_in_namespace(ns_name, ['python3', '/tmp/ospf_sniff.py'], capture_output=True, text=True)
    
    # Clean up
    run_cmd(['rm', '/tmp/ospf_sniff.py'], check=False)
    
    if result.returncode != 0:
        print('No OSPF Hello received; aborting.')
        sys.exit(1)
    
    # Parse the output
    src, area, hi, di = result.stdout.strip().split(',')
    # Don't cast area to int as it can be in dotted notation (e.g., 0.0.0.0)
    return src, area, int(hi), int(di)

# Configure OSPF in namespace
def configure_ospf_in_namespace(ns_name, iface, ip, prefix, m1, m2, client, up, area, hi, di):
    n1=ipaddress.IPv4Network(m1);n2=ipaddress.IPv4Network(m2);n3=ipaddress.IPv4Network(client)
    
    # Configure FRR daemons file - this needs to be done in the default namespace
    lines=open('/etc/frr/daemons').read().splitlines()
    with open('/etc/frr/daemons','w') as f:
        for l in lines: f.write('ospfd=yes\n' if l.startswith('ospfd=') else l+'\n')
    
    # Create FRR config directory in the namespace if it doesn't exist
    run_cmd(['mkdir', '-p', f'/etc/netns/{ns_name}/frr'], check=False)
    
    # Create a basic frr.conf file in the namespace
    frr_conf = f"""frr version 7.5
frr defaults traditional
hostname frr-{ns_name}
log syslog
service integrated-vtysh-config
!
router ospf
 network {ip}/{prefix} area {area}
 network {n1.network_address}/{n1.prefixlen} area {area}
 network {n2.network_address}/{n2.prefixlen} area {area}
 network {n3.network_address}/{n3.prefixlen} area {area}
!
interface {iface}
 ip ospf hello-interval {hi}
 ip ospf dead-interval {di}
!
line vty
!
end
"""
    with open(f'/etc/netns/{ns_name}/frr/frr.conf', 'w') as f:
        f.write(frr_conf)
    
    # Copy daemons file to namespace
    run_cmd(['cp', '/etc/frr/daemons', f'/etc/netns/{ns_name}/frr/'], check=False)
    
    # Restart FRR in the namespace
    run_in_namespace(ns_name, ['systemctl', 'restart', 'frr'], check=False)
    
    # Use vtysh in the namespace to verify configuration
    run_in_namespace(ns_name, ['vtysh', '-c', 'show running-config'], check=False)
    
    print(f'OSPF adjacency configured in namespace {ns_name}')

# Show OSPF state Full/DR in namespace
def show_ospf_status_in_namespace(ns_name):
    print(f'\n=== Waiting for OSPF state Full/DR in namespace {ns_name} (30s timeout) ===')
    success=False
    for _ in range(30):
        out=run_in_namespace(ns_name, ['vtysh','-c','show ip ospf neighbor'], capture_output=True, text=True).stdout
        if any('Full/DR' in l for l in out.splitlines()[1:]):
            success=True
            print('OSPF reached Full/DR state')
            break
        time.sleep(1)
    if not success:
        print('OSPF never reached Full/DR state after 30s')
    time.sleep(5)
    print(f'\n=== Routing Table in namespace {ns_name} ===')
    print(run_in_namespace(ns_name, ['vtysh','-c','show ip route'], capture_output=True, text=True).stdout)
    return success

# Add floating static default
def configure_static_route(gateway,iface):
    run_cmd(['ip','route','add','default','via',gateway,'metric','200'],check=False)

# Connectivity tests with DNS fallback logic in namespace
def run_tests_in_namespace(ns_name, iface, mgmt1, client_subnet, dhcp_servers, radius_servers, secret, user, pwd, run_dhcp, run_radius):
    # Set initial DNS
    dns_servers = ['8.8.8.8', '8.8.4.4']
    
    # Create a resolv.conf file in the namespace
    # This is a bit tricky as namespaces don't have their own /etc
    # We'll use a workaround by creating a temporary resolv.conf and copying it
    def write_resolv_in_namespace(ns_name, servers):
        with open('/tmp/resolv.conf.ns', 'w') as f:
            for s in servers:
                f.write(f'nameserver {s}\n')
        # Copy to the namespace's /etc
        run_cmd(['mkdir', '-p', f'/etc/netns/{ns_name}'], check=False)
        run_cmd(['cp', '/tmp/resolv.conf.ns', f'/etc/netns/{ns_name}/resolv.conf'], check=True)
        run_cmd(['rm', '/tmp/resolv.conf.ns'], check=False)
    
    write_resolv_in_namespace(ns_name, dns_servers)
    conf.route.resync()

    # Initial connectivity
    ping_ok = dns_ok = False
    print(f'Initial Ping Tests in namespace {ns_name}:')
    for tgt in dns_servers:
        r = run_in_namespace(ns_name, ['ping', '-c', '2', tgt], capture_output=True)
        print(f'Ping {tgt}: ' + (GREEN+'Success'+RESET if r.returncode==0 else RED+'Fail'+RESET))
        ping_ok |= (r.returncode==0)

    # Initial DNS tests with retry prompt
    while True:
        print(f'Initial DNS Tests in namespace {ns_name} (@ ' + ', '.join(dns_servers) + '):')
        dns_ok = False
        for d in dns_servers:
            r = run_in_namespace(ns_name, ['dig', f'@{d}', 'www.google.com', '+short'], capture_output=True, text=True)
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
        write_resolv_in_namespace(ns_name, dns_servers)

    if not ping_ok:
        print('Initial ping tests failed. Exiting.')
        sys.exit(1)

    # Full suite
    print(f'\nFull Test Suite in namespace {ns_name}:')
    for tgt in dns_servers:
        r = run_in_namespace(ns_name, ['ping', '-c', '4', tgt], capture_output=True, text=True)
        print(f'Ping {tgt}: ' + (GREEN+'Success'+RESET if r.returncode==0 else RED+'Fail'+RESET))
    for d in dns_servers:
        r = run_in_namespace(ns_name, ['dig', f'@{d}', 'www.google.com', '+short'], capture_output=True, text=True)
        ok = (r.returncode==0 and bool(r.stdout.strip()))
        print(f'DNS @{d}: ' + (GREEN+'Success'+RESET if ok else RED+'Fail'+RESET))

    # DHCP relay with ping pre-check
    if run_dhcp:
        print(f'=== DHCP tests (L3 relay) in namespace {ns_name} ===')
        helper_ip = str(ipaddress.IPv4Network(client_subnet).network_address+1)
        for srv in dhcp_servers:
            p = run_in_namespace(ns_name, ['ping', '-c', '1', srv], capture_output=True)
            if p.returncode != 0:
                print(f'DHCP relay to {srv}: {RED}Fail (unreachable){RESET}')
                continue
            
            # Use a simpler approach for DHCP testing in the namespace
            # Instead of using scapy, we'll use dhcping which is more reliable in namespaces
            # If dhcping is not available, we'll fall back to a basic UDP port check
            
            # First try dhcping if available
            dhcping_available = run_cmd(['which', 'dhcping'], capture_output=True).returncode == 0
            
            if dhcping_available:
                # Use dhcping for DHCP testing
                result = run_in_namespace(ns_name, ['dhcping', '-s', srv, '-v'], capture_output=True, text=True)
                success = result.returncode == 0
            else:
                # Fall back to a basic UDP port check
                # This just checks if the DHCP server port is open and responding
                result = run_in_namespace(ns_name, 
                    ['nc', '-zvu', srv, '67', '-w', '5'], 
                    capture_output=True, text=True)
                success = result.returncode == 0
            print(f'DHCP relay to {srv}: ' + (GREEN+'Success'+RESET if success else RED+'Fail'+RESET))
    else:
        print('Skipping DHCP tests')

    # RADIUS with ping pre-check
    if run_radius:
        print(f'=== RADIUS tests in namespace {ns_name} ===')
        for srv in radius_servers:
            p = run_in_namespace(ns_name, ['ping', '-c', '1', srv], capture_output=True)
            if p.returncode != 0:
                print(f'RADIUS {srv}: {RED}Fail (unreachable){RESET}')
                continue
            cmd = (f'echo "User-Name={user},User-Password={pwd}" '
                  f'| radclient -x -s {srv}:1812 auth {secret}')
            res = run_in_namespace(ns_name, cmd, shell=True, capture_output=True, text=True)
            print(f'RADIUS {srv}: ' + (GREEN+'Success'+RESET if res.returncode==0 else RED+'Fail'+RESET))
    else:
        print('Skipping RADIUS tests')

    # NTP
    print(f'=== NTP tests in namespace {ns_name} ===')
    for ntp in ('time.google.com', 'pool.ntp.org'):
        r = run_in_namespace(ns_name, ['ntpdate', '-q', ntp], capture_output=True, text=True)
        print(f'NTP {ntp}: ' + (GREEN+'Success'+RESET if r.returncode==0 else RED+'Fail'+RESET))

    # HTTPS
    print(f'=== HTTPS tests in namespace {ns_name} ===')
    for url in ('https://u1.nilesecure.com',
                'https://ne-u1.nile-global.cloud',
                'https://s3.us-west-2.amazonaws.com/nile-prod-us-west-2'):
        parsed = urlparse(url)
        host, port = parsed.hostname, parsed.port or 443
        
        # First try a simple TCP connection to the host:port
        try:
            # Use nc to check if the port is open
            r = run_in_namespace(ns_name, ['nc', '-z', '-w', '5', host, str(port)], capture_output=True)
            tcp_ok = r.returncode == 0
            
            if tcp_ok:
                # If TCP connection works, try curl with more options
                r = run_in_namespace(ns_name, 
                    ['curl', '-s', '-k', '--connect-timeout', '10', '-o', '/dev/null', '-w', '%{http_code}', url], 
                    capture_output=True, text=True)
                ok = r.returncode == 0 and r.stdout.strip().startswith('2')  # 2xx status code
            else:
                ok = False
                
        except Exception as e:
            if DEBUG:
                print(f"DEBUG: HTTPS test exception: {e}")
            ok = False
            
        print(f'HTTPS {url}: ' + (GREEN+'Success'+RESET if ok else RED+'Fail'+RESET))

# Configure interface in namespace
def configure_interface_in_namespace(ns_name, iface, ip_addr, netmask):
    print(f'Configuring {iface} in namespace {ns_name} → {ip_addr}/{netmask}')
    prefix = ipaddress.IPv4Network(f'0.0.0.0/{netmask}').prefixlen
    run_in_namespace(ns_name, ['ip', 'addr', 'flush', 'dev', iface], check=True)
    run_in_namespace(ns_name, ['ip', 'addr', 'add', f'{ip_addr}/{prefix}', 'dev', iface], check=True)
    run_in_namespace(ns_name, ['ip', 'link', 'set', 'dev', iface, 'up'], check=True)

# Add loopbacks in namespace
def add_loopbacks_in_namespace(ns_name, m1, m2, client):
    for name, subnet in [('mgmt1', m1), ('mgmt2', m2), ('client', client)]:
        net = ipaddress.IPv4Network(subnet)
        iface = f'dummy_{name}'
        addr = str(net.network_address+1)
        prefix = net.prefixlen
        run_in_namespace(ns_name, ['ip', 'link', 'add', iface, 'type', 'dummy'], check=False)
        run_in_namespace(ns_name, ['ip', 'addr', 'add', f'{addr}/{prefix}', 'dev', iface], check=False)
        run_in_namespace(ns_name, ['ip', 'link', 'set', 'dev', iface, 'up'], check=True)
        print(f'Loopback {iface} in namespace {ns_name} → {addr}/{prefix}')

# Configure static route in namespace
def configure_static_route_in_namespace(ns_name, gateway, iface):
    run_in_namespace(ns_name, ['ip', 'route', 'add', 'default', 'via', gateway, 'metric', '200'], check=False)

# Main flow
def main():
    # Get user input from config file or interactive prompts
    (frr_iface, ip_addr, netmask, gateway, mgmt1, mgmt2, client_subnet,
     dhcp_servers, radius_servers, secret, username, password,
     run_dhcp, run_radius) = get_user_input(args.config)

    # Record the original state of the interface
    state = record_state(frr_iface)

    # Create the FRR namespace
    create_namespace(FRR_NS)
    
    try:
        # Move the FRR interface to the namespace
        move_interface_to_namespace(frr_iface, FRR_NS)
        
        # Configure the interface in the namespace
        configure_interface_in_namespace(FRR_NS, frr_iface, ip_addr, netmask)
        
        # Add loopbacks in the namespace
        add_loopbacks_in_namespace(FRR_NS, mgmt1, mgmt2, client_subnet)
        
        # Configure static route in the namespace
        prefix = ipaddress.IPv4Network(f'0.0.0.0/{netmask}').prefixlen
        configure_static_route_in_namespace(FRR_NS, gateway, frr_iface)
        
        # Update scapy's routing table
        conf.route.resync()
        
        # Sniff for OSPF Hello packets in the namespace
        up, area, hi, di = sniff_ospf_hello_in_namespace(FRR_NS, frr_iface)
        
        # Configure OSPF in the namespace
        configure_ospf_in_namespace(FRR_NS, frr_iface, ip_addr, prefix, mgmt1, mgmt2, client_subnet, up, area, hi, di)
        
        # Check OSPF status in the namespace
        ospf_ok = show_ospf_status_in_namespace(FRR_NS)
        print("OSPF adjacency test: " + (GREEN+'Success'+RESET if ospf_ok else RED+'Fail'+RESET))
        
        # Run connectivity tests in the namespace
        run_tests_in_namespace(FRR_NS, frr_iface, mgmt1, client_subnet, dhcp_servers, radius_servers, secret, username, password, run_dhcp, run_radius)
    
    finally:
        # Move the interface back to the default namespace
        print(f"Moving {frr_iface} back to default namespace")
        run_in_namespace(FRR_NS, ['ip', 'link', 'set', frr_iface, 'netns', '1'], check=False)
        
        # Restore the original state
        restore_state(frr_iface, state)
        
        # Delete the namespace
        delete_namespace(FRR_NS)

if __name__=='__main__':
    if os.geteuid()!=0:
        print('Must run as root')
        sys.exit(1)
    main()
