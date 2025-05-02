# Nile Readiness Test with Network Namespace Isolation

This repository contains scripts for running Nile Readiness Tests while isolating network interfaces using Linux network namespaces. This approach allows you to:

1. Run RealVNC server on one interface (e.g., end0) in a separate network namespace
2. Run FRR tests on another interface (e.g., enxf0a731f41761) in the default namespace

## Scripts

- **vnc_namespace.sh**: Creates a network namespace for RealVNC server and moves the specified interface to that namespace
- **nrt_default.py**: Runs FRR tests in the default namespace without moving interfaces to namespaces
- **nrt.py**: Original script that uses network namespaces for FRR tests (not recommended with this approach)

## Prerequisites

- Linux system with network namespace support
- FRR (Free Range Routing) installed
- RealVNC server installed
- Python 3.6+ with required packages:
  - scapy
  - ipaddress
- Required utilities:
  - vtysh (FRR)
  - radclient (FreeRADIUS client)
  - dig (DNS lookup utility)
  - ntpdate (NTP utility)
  - curl (HTTPS test utility)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/nile-readiness-test.git
   cd nile-readiness-test
   ```

2. Install required packages:
   ```
   sudo apt update
   sudo apt install frr freeradius-client dnsutils ntpdate curl python3-scapy python3-ipaddress
   ```

3. Make the scripts executable:
   ```
   chmod +x vnc_namespace.sh nrt_default.py
   ```

## Configuration

1. Edit the configuration in `vnc_namespace.sh`:
   - `VNC_NS`: Namespace name for VNC (default: "vnc_ns")
   - `VNC_IFACE`: Interface to move to VNC namespace (default: "end0")
   - `VNC_IP`: IP address for VNC interface (default: "192.168.1.100")
   - `VNC_NETMASK`: Netmask in CIDR notation (default: "24")
   - `VNC_GATEWAY`: Default gateway for VNC namespace (default: "192.168.1.1")

2. Create a JSON configuration file for `nrt_default.py`:
   ```json
   {
     "frr_interface": "enxf0a731f41761",
     "ip_address": "192.168.2.100",
     "netmask": "255.255.255.0",
     "gateway": "192.168.2.1",
     "nsb_subnet": "10.1.1.0/24",
     "sensor_subnet": "10.1.2.0/24",
     "client_subnet": "10.1.3.0/24",
     "run_dhcp_tests": true,
     "dhcp_servers": ["192.168.2.10"],
     "run_radius_tests": false
   }
   ```

## Usage

### Step 1: Start RealVNC Server in a Separate Namespace

Run the VNC namespace script:
```
sudo ./vnc_namespace.sh
```

This will:
1. Create a network namespace called "vnc_ns"
2. Move the specified interface (default: end0) to that namespace
3. Configure the interface with the specified IP address
4. Start RealVNC server in the namespace
5. Keep running to maintain the namespace (press Ctrl+C to stop and clean up)

### Step 2: Run FRR Tests in the Default Namespace

In a separate terminal, run the FRR tests:
```
sudo ./nrt_default.py --config config.json
```

Or run interactively:
```
sudo ./nrt_default.py
```

This will:
1. Configure the FRR interface (default: enxf0a731f41761) in the default namespace
2. Add loopback interfaces
3. Sniff for OSPF Hello packets
4. Configure OSPF
5. Run connectivity tests (ping, DNS, DHCP, RADIUS, NTP, HTTPS)
6. Restore the original state when done

## Troubleshooting

### VNC Server Issues

- If VNC server fails to start in the namespace, check if it's already running in the default namespace
- Verify that the VNC interface has the correct IP address and can reach the gateway

### FRR Test Issues

- If OSPF adjacency fails, check if the upstream router is sending OSPF Hello packets
- Verify that the FRR interface has the correct IP address and can reach the upstream router
- Check FRR logs: `sudo tail -f /var/log/frr/zebra.log /var/log/frr/ospfd.log`

## Notes

- The scripts must be run as root (sudo)
- When you stop the VNC namespace script (Ctrl+C), it will automatically move the interface back to the default namespace and clean up
- The FRR test script will restore the original state of the interface when it completes or if an error occurs
