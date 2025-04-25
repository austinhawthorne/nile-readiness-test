# nile-readiness-test
Script to test that a network is ready to support a Nile installation.  The script mimics what a Nile gateway will perform to bring up a Nile service, as well as tests some basic network services.

Running this script will test:
- OSPF
  - Will listen for OSPF Hello packets and configure OSPF on FRR to build a neighbor adjacency and advertise routes for defined subnets (NSB, Sensor, Client).
  - Will fall back to static if this fails.
- DNS Reachability
  - Will try the default DNS servers for Nile.
  - If that fails, will prompt for a user specified DNS server to use.
- NTP Reachability
  - Will run a test to sync with default Nile defined NTP servers
- DHCP Server Reachability
  - Will run a synthetic test against a user defined DHCP server, from the defined client subnet
- RADIUS Reachability
  - Will run a sythentic test against a user defined RADIUS server.
- Required Site Reachability for Nile Service
  - Will run a TCP SYN test via NMAP

Requires:
- frr
- scapy (python module)
- dig
- ntpdate
- curl
- radclient (bundled with freeradius)

Usage:  
- Connect host to upstream firewall port that will be used for Nile uplink
- Ensure no other network connections are active on host
- Launch script:  sudo python3 nrt.py

Sample Output:
```
austin@client1:~ $ sudo python nrt.py
Interface to configure (e.g., eth0): eth1
IP address: 10.0.0.2
Netmask (e.g. 255.255.255.0): 255.255.255.0
Gateway IP: 10.0.0.1
NSB subnet (CIDR, e.g. 192.168.1.0/24): 10.0.1.0/24
Sensor subnet (CIDR): 10.0.2.0/24
Client subnet (CIDR): 10.0.3.0/24
Perform DHCP tests? [y/N]: y
DHCP server IP(s) (comma-separated): 172.16.0.100
Perform RADIUS tests? [y/N]: y
RADIUS server IP(s) (comma-separated): 172.16.0.100
RADIUS shared secret: abc123
RADIUS test username: bob
RADIUS test password: abc123
Configuring eth1 → 10.0.0.2/255.255.255.0
Loopback dummy_mgmt1 → 10.0.1.1/24
Loopback dummy_mgmt2 → 10.0.2.1/24
Loopback dummy_client → 10.0.3.1/24
Waiting for OSPF Hello...
Note: this version of vtysh never writes vtysh.conf
Building Configuration...
Integrated configuration saved to /etc/frr/frr.conf
[OK]
OSPF adjacency configured

=== Waiting for OSPF state Full/DR (30s timeout) ===
OSPF reached Full/DR state

=== Routing Table ===
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

O   0.0.0.0/0 [110/10] via 10.0.0.1, eth1, weight 1, 00:00:05
K>* 0.0.0.0/0 [0/200] via 10.0.0.1, eth1, 00:00:21
O   10.0.0.0/24 [110/100] is directly connected, eth1, weight 1, 00:00:21
C>* 10.0.0.0/24 is directly connected, eth1, 00:00:21
O   10.0.1.0/24 [110/10] is directly connected, dummy_mgmt1, weight 1, 00:00:21
C>* 10.0.1.0/24 is directly connected, dummy_mgmt1, 00:00:21
O   10.0.2.0/24 [110/10] is directly connected, dummy_mgmt2, weight 1, 00:00:21
C>* 10.0.2.0/24 is directly connected, dummy_mgmt2, 00:00:21
O   10.0.3.0/24 [110/10] is directly connected, dummy_client, weight 1, 00:00:21
C>* 10.0.3.0/24 is directly connected, dummy_client, 00:00:21
O>* 10.0.100.0/24 [110/10] via 10.0.0.1, eth1, weight 1, 00:00:05
O>* 10.10.20.0/24 [110/10] via 10.0.0.1, eth1, weight 1, 00:00:05
O>* 10.253.240.0/20 [110/10] via 10.0.0.1, eth1, weight 1, 00:00:05
O>* 172.16.0.0/24 [110/10] via 10.0.0.1, eth1, weight 1, 00:00:05
O>* 192.168.1.0/24 [110/10] via 10.0.0.1, eth1, weight 1, 00:00:05

OSPF adjacency test: Success
Initial Ping Tests:
Ping 8.8.8.8: Success
Ping 8.8.4.4: Success
Initial DNS Tests (@ 8.8.8.8, 8.8.4.4):
DNS @8.8.8.8: Fail
DNS @8.8.4.4: Fail
Default DNS tests failed. Enter alternate DNS servers? [y/N]: y
Enter DNS server IP(s) (comma-separated): 1.1.1.1
Initial DNS Tests (@ 1.1.1.1):
DNS @1.1.1.1: Success

Full Test Suite:
Ping 1.1.1.1: Success
DNS @1.1.1.1: Success
=== DHCP tests (L3 relay) ===
DHCP relay to 172.16.0.100: Success
=== RADIUS tests ===
RADIUS 172.16.0.100: Success
=== NTP tests ===
NTP time.google.com: Success
NTP pool.ntp.org: Success
=== HTTPS tests ===
HTTPS https://u1.nilesecure.com: Success
HTTPS https://ne-u1.nile-global.cloud: Success
HTTPS https://s3.us-west-2.amazonaws.com/nile-prod-us-west-2: Success

Restoring original state...
Synchronizing state of frr.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install disable frr
Removed FRR config, stopped service, restored DNS.
```

Notes:
- Only tested on Raspberry Pi, should run on any debian based distribution
- Will be adding in checks for Nile Cloud Services, like Guest
