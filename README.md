# Nile Readiness Test with Network Namespace Isolation

This repository contains scripts for running Nile Readiness Tests while isolating network interfaces using Linux network namespaces. This approach allows you to:

1. Run WayVNC server on one interface (e.g., end0) in a separate network namespace
2. Run FRR tests on another interface (e.g., enxf0a731f41761) in the default namespace

## Scripts

- **vnc_namespace.sh**: Creates a network namespace for WayVNC server and moves the specified interface to that namespace
- **tigervnc_namespace.sh**: Alternative script that uses TigerVNC instead of WayVNC (more compatible with different systems)
- **nrt.py**: Runs FRR tests in the default namespace without moving interfaces to namespaces

## Prerequisites

- Linux system with network namespace support
- FRR (Free Range Routing) installed
- VNC server (either WayVNC or TigerVNC)
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

   For WayVNC (requires Wayland):
   ```
   sudo apt install wayvnc weston
   ```

   OR for TigerVNC (more compatible with different systems):
   ```
   sudo apt install tigervnc-standalone-server xterm
   ```

3. Make the scripts executable:
   ```
   chmod +x vnc_namespace.sh tigervnc_namespace.sh nrt.py
   ```

## Configuration

1. Edit the configuration in the VNC script you plan to use:

   For `vnc_namespace.sh` (WayVNC):
   - `VNC_NS`: Namespace name for VNC (default: "vnc_ns")
   - `VNC_IFACE`: Interface to move to VNC namespace (default: "end0")
   - `VNC_IP`: IP address for VNC interface (default: "10.2.0.199")
   - `VNC_NETMASK`: Netmask in CIDR notation (default: "24")
   - `VNC_GATEWAY`: Default gateway for VNC namespace (default: "10.2.0.1")

   For `tigervnc_namespace.sh` (TigerVNC):
   - `VNC_NS`: Namespace name for VNC (default: "vnc_ns")
   - `VNC_IFACE`: Interface to move to VNC namespace (default: "end0")
   - `VNC_IP`: IP address for VNC interface (default: "10.2.0.199")
   - `VNC_NETMASK`: Netmask in CIDR notation (default: "24")
   - `VNC_GATEWAY`: Default gateway for VNC namespace (default: "10.2.0.1")
   - `VNC_PORT`: VNC port (default: "5900", which is display :0)
   - `VNC_GEOMETRY`: Screen resolution (default: "1024x768")

2. Create a JSON configuration file for `nrt.py`:
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

### Step 1: Start VNC Server in a Separate Namespace

#### Option A: Using WayVNC (Wayland-based)

Run the WayVNC namespace script:
```
sudo ./vnc_namespace.sh
```

This will:
1. Create a network namespace called "vnc_ns"
2. Move the specified interface (default: end0) to that namespace
3. Configure the interface with the specified IP address
4. Start Weston (Wayland compositor) in the namespace
5. Start WayVNC server in the namespace
6. Keep running to maintain the namespace (press Ctrl+C to stop and clean up)

#### Option B: Using TigerVNC (X11-based, more compatible)

Run the TigerVNC namespace script:
```
sudo ./tigervnc_namespace.sh
```

This will:
1. Create a network namespace called "vnc_ns"
2. Move the specified interface (default: end0) to that namespace
3. Configure the interface with the specified IP address
4. Start TigerVNC server in the namespace
5. Keep running to maintain the namespace (press Ctrl+C to stop and clean up)

You can connect to the TigerVNC server using any VNC client at the IP address and port displayed when the script runs.

### Step 2: Run FRR Tests in the Default Namespace

In a separate terminal, run the FRR tests:
```
sudo ./nrt.py --config nrt_config.json
```

Or run interactively:
```
sudo ./nrt.py
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

#### WayVNC Issues

- If WayVNC server fails to start in the namespace, check if it's already running in the default namespace
- Verify that the VNC interface has the correct IP address and can reach the gateway
- WayVNC requires a running Wayland compositor. The script sets XDG_RUNTIME_DIR and WAYLAND_DISPLAY environment variables, but you may need to:
  - Install Weston if it's not already installed: `sudo apt install weston`
  - If Weston is not available on your system, use the TigerVNC script instead
  - If using a different Wayland compositor, adjust the WAYLAND_DISPLAY value in the script
- If you see errors about XDG_RUNTIME_DIR or WAYLAND_DISPLAY, the script attempts to set these up, but you may need to adjust them based on your system configuration
- If you see "error in libwayland error in client communication", this usually indicates a problem with the Wayland compositor. Try using TigerVNC instead.

#### TigerVNC Issues

- If TigerVNC server fails to start in the namespace, check if it's already running in the default namespace
- Verify that the VNC interface has the correct IP address and can reach the gateway
- If you see "Xvnc: command not found", install TigerVNC with: `sudo apt install tigervnc-standalone-server`
- If you see "xterm: command not found", install xterm with: `sudo apt install xterm`
- If you see "unrecognized option" errors, your version of TigerVNC might have different command line options. The script tries to detect and adapt to different versions, but you may need to:
  - Check the Xvnc man page with `man Xvnc` to see the supported options
  - Edit the script to use the correct options for your version
  - Common variations include `-rfbaddr` vs `-listen` and whether `-xstartup` is supported
- If you have issues connecting to the VNC server, check that your VNC client is connecting to the correct IP address and port

### FRR Test Issues

- If OSPF adjacency fails, check if the upstream router is sending OSPF Hello packets
- Verify that the FRR interface has the correct IP address and can reach the upstream router
- Check FRR logs: `sudo tail -f /var/log/frr/zebra.log /var/log/frr/ospfd.log`

## Notes

- The scripts must be run as root (sudo)
- When you stop the VNC namespace script (Ctrl+C), it will automatically move the interface back to the default namespace and clean up
- The FRR test script will restore the original state of the interface when it completes or if an error occurs
