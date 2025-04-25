#!/usr/bin/env python3
"""
config_router.py - Configures host interface, OSPF adjacency dynamically,
loopback interfaces, default route fallback, connectivity tests (DHCP/RADIUS,
NTP, HTTPS), then restores host to original state (including removing FRR config,
stopping FRR) and DNS changes.

Usage: sudo ./config_router.py [--debug]
"""

import os
import sys
import shutil
import subprocess
import random
import ipaddress
import socket
import time
from urllib.parse import urlparse
from scapy.config import conf
from scapy.all import sniff, sendp, RandMAC, Ether, BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello

# Debug flag
DEBUG = False
if '--debug' in sys.argv:
    DEBUG = True
    sys.argv.remove('--debug')

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
def get_user_input():
    iface         = prompt_nonempty('Interface to configure (e.g., eth0): ')
    ip_addr       = prompt_nonempty('IP address: ')
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

    return (iface, ip_addr, netmask, gateway,
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
def sniff_ospf_hello(iface,timeout=60):
    print('Waiting for OSPF Hello...')
    pkts=sniff(iface=iface,filter='ip proto 89',timeout=timeout,count=1)
    if not pkts:
        print('No OSPF Hello received; aborting.')
        sys.exit(1)
    pkt=pkts[0]
    return pkt[IP].src,pkt[OSPF_Hdr].area,pkt[OSPF_Hello].hellointerval,pkt[OSPF_Hello].deadinterval

# Configure OSPF
def configure_ospf(iface,ip,prefix,m1,m2,client,up,area,hi,di):
    n1=ipaddress.IPv4Network(m1);n2=ipaddress.IPv4Network(m2);n3=ipaddress.IPv4Network(client)
    lines=open('/etc/frr/daemons').read().splitlines()
    with open('/etc/frr/daemons','w') as f:
        for l in lines: f.write('ospfd=yes\n' if l.startswith('ospfd=') else l+'\n')
    run_cmd(['systemctl','restart','frr'],check=True)
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
    run_cmd(cmds,check=True)
    print('OSPF adjacency configured')

# Show OSPF state Full/DR
def show_ospf_status():
    print('\n=== Waiting for OSPF state Full/DR (30s timeout) ===')
    success=False
    for _ in range(30):
        out=run_cmd(['vtysh','-c','show ip ospf neighbor'],capture_output=True,text=True).stdout
        if any('Full/DR' in l for l in out.splitlines()[1:]):
            success=True
            print('OSPF reached Full/DR state')
            break
        time.sleep(1)
    if not success:
        print('OSPF never reached Full/DR state after 30s')
    time.sleep(5)
    print('\n=== Routing Table ===')
    print(run_cmd(['vtysh','-c','show ip route'],capture_output=True,text=True).stdout)
    return success

# Add floating static default
def configure_static_route(gateway,iface):
    run_cmd(['ip','route','add','default','via',gateway,'metric','200'],check=False)

# Connectivity tests with DNS fallback logic
def run_tests(iface,mgmt1,client_subnet,dhcp_servers,radius_servers,secret,user,pwd,run_dhcp,run_radius):
    # Set initial DNS
    dns_servers = ['8.8.8.8','8.8.4.4']
    def write_resolv(servers):
        with open('/etc/resolv.conf','w') as f:
            for s in servers:
                f.write(f'nameserver {s}\n')
    write_resolv(dns_servers)
    conf.route.resync()

    # Initial connectivity
    ping_ok = dns_ok = False
    print('Initial Ping Tests:')
    for tgt in dns_servers:
        r = run_cmd(['ping','-c','2',tgt],capture_output=True)
        print(f'Ping {tgt}: '+(GREEN+'Success'+RESET if r.returncode==0 else RED+'Fail'+RESET))
        ping_ok |= (r.returncode==0)

    # Initial DNS tests with retry prompt
    while True:
        print('Initial DNS Tests (@ ' + ', '.join(dns_servers) + '):')
        dns_ok = False
        for d in dns_servers:
            r = run_cmd(['dig', f'@{d}', 'www.google.com','+short'], capture_output=True, text=True)
            ok = (r.returncode==0 and bool(r.stdout.strip()))
            print(f'DNS @{d}: '+(GREEN+'Success'+RESET if ok else RED+'Fail'+RESET))
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
    print('\nFull Test Suite:')
    for tgt in dns_servers:
        r = run_cmd(['ping','-c','4',tgt],capture_output=True,text=True)
        print(f'Ping {tgt}: '+(GREEN+'Success'+RESET if r.returncode==0 else RED+'Fail'+RESET))
    for d in dns_servers:
        r = run_cmd(['dig', f'@{d}', 'www.google.com','+short'], capture_output=True, text=True)
        ok = (r.returncode==0 and bool(r.stdout.strip()))
        print(f'DNS @{d}: '+(GREEN+'Success'+RESET if ok else RED+'Fail'+RESET))

    # DHCP relay with ping pre-check
    if run_dhcp:
        print('=== DHCP tests (L3 relay) ===')
        helper_ip=str(ipaddress.IPv4Network(client_subnet).network_address+1)
        for srv in dhcp_servers:
            p=run_cmd(['ping','-c','1',srv],capture_output=True)
            if p.returncode!=0:
                print(f'DHCP relay to {srv}: {RED}Fail (unreachable){RESET}')
                continue
            xid=random.randint(1,0xffffffff)
            pkt=(Ether(dst='ff:ff:ff:ff:ff:ff')/
                 IP(src=helper_ip,dst=srv)/
                 UDP(sport=67,dport=67)/
                 BOOTP(op=1,chaddr=RandMAC(),xid=xid,giaddr=helper_ip)/
                 DHCP(options=[('message-type','discover'),('end')]))
            if DEBUG:
                print('DEBUG: DHCP DISCOVER summary:')
                print(pkt.summary())
            sendp(pkt,iface=iface,verbose=False)
            resp=sniff(iface=iface,filter='udp and (port 67 or port 68)',
                       timeout=10,count=1,
                       lfilter=lambda p:p.haslayer(BOOTP)
                                     and p[BOOTP].xid==xid
                                     and p[BOOTP].op==2)
            if DEBUG:
                print(f'DEBUG: DHCP response count: {len(resp)}')
                for p in resp: print(p.summary())
            print(f'DHCP relay to {srv}: '+(GREEN+'Success'+RESET if resp else RED+'Fail'+RESET))
    else:
        print('Skipping DHCP tests')

    # RADIUS with ping pre-check
    if run_radius:
        print('=== RADIUS tests ===')
        for srv in radius_servers:
            p=run_cmd(['ping','-c','1',srv],capture_output=True)
            if p.returncode!=0:
                print(f'RADIUS {srv}: {RED}Fail (unreachable){RESET}')
                continue
            cmd=(f'echo "User-Name={user},User-Password={pwd}" '
                 f'| radclient -x -s {srv}:1812 auth {secret}')
            res=run_cmd(cmd,shell=True,capture_output=True,text=True)
            print(f'RADIUS {srv}: '+(GREEN+'Success'+RESET if res.returncode==0 else RED+'Fail'+RESET))
    else:
        print('Skipping RADIUS tests')

    # NTP
    print('=== NTP tests ===')
    for ntp in ('time.google.com','pool.ntp.org'):
        r=run_cmd(['ntpdate','-q',ntp],capture_output=True,text=True)
        print(f'NTP {ntp}: '+(GREEN+'Success'+RESET if r.returncode==0 else RED+'Fail'+RESET))

    # HTTPS
    print('=== HTTPS tests ===')
    for url in ('https://u1.nilesecure.com',
                'https://ne-u1.nile-global.cloud',
                'https://s3.us-west-2.amazonaws.com/nile-prod-us-west-2'):
        parsed=urlparse(url)
        host,port=parsed.hostname,parsed.port or 443
        try:
            sock=socket.create_connection((host,port),timeout=5)
            sock.close()
            ok=True
        except:
            ok=False
        print(f'HTTPS {url}: '+(GREEN+'Success'+RESET if ok else RED+'Fail'+RESET))

# Main flow
def main():
    (iface,ip_addr,netmask,gateway,mgmt1,mgmt2,client_subnet,
     dhcp_servers,radius_servers,secret,username,password,
     run_dhcp,run_radius) = get_user_input()

    # ensure single active interface
    out=run_cmd(['ip','-o','addr','show','scope','global'],capture_output=True,text=True).stdout
    other=set(l.split()[1] for l in out.splitlines())-{iface}
    other={i for i in other if not i.startswith('dummy_') and i!='lo'}
    if other:
        print(f"Error: Other active ifaces: {', '.join(other)}")
        sys.exit(1)

    state=record_state(iface)
    configure_interface(iface,ip_addr,netmask)
    add_loopbacks(mgmt1,mgmt2,client_subnet)
    prefix=ipaddress.IPv4Network(f'0.0.0.0/{netmask}').prefixlen
    configure_static_route(gateway,iface)
    conf.route.resync()
    up,area,hi,di=sniff_ospf_hello(iface)
    configure_ospf(iface,ip_addr,prefix,mgmt1,mgmt2,client_subnet,up,area,hi,di)
    ospf_ok=show_ospf_status()
    print("OSPF adjacency test: "+(GREEN+'Success'+RESET if ospf_ok else RED+'Fail'+RESET))
    run_tests(iface,mgmt1,client_subnet,dhcp_servers,radius_servers,secret,username,password,run_dhcp,run_radius)
    restore_state(iface,state)

if __name__=='__main__':
    if os.geteuid()!=0:
        print('Must run as root')
        sys.exit(1)
    main()
