# Nile Readiness Test with Network Namespace Isolation

This repository contains scripts for running Nile Readiness Tests while isolating network interfaces using Linux network namespaces. This approach allows you to:

1. Run WayVNC server on one interface (e.g., end0) in a separate network namespace
2. Run FRR tests on another interface (e.g., enxf0a731f41761) in the default namespace

## Scripts

- **vnc_namespace.sh**: Creates a network namespace for WayVNC server and moves the specified interface to that namespace
- **tigervnc_namespace.sh**: Alternative script that uses TigerVNC instead of WayVNC (more compatible with different systems)
- **macvlan_vnc.sh**: Improved script that uses macvlan to link the physical interface to the namespace (recommended)
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
   chmod +x vnc_namespace.sh tigervnc_namespace.sh macvlan_vnc.sh nrt.py
   ```

## Configuration

1. Edit the configuration in the VNC script you plan to use:

   For `macvlan_vnc.sh` (Recommended):
   - `VNC_NS`: Namespace name for VNC (default: "vnc_ns")
   - `PHYSICAL_IFACE`: Physical interface to link to (default: "end0")
   - `MACVLAN_IFACE`: Name of the macvlan interface in the namespace (default: "macvlan0")
   - `VNC_IP`: IP address for VNC interface (default: "10.2.0.199")
   - `VNC_NETMASK`: Netmask in CIDR notation (default: "24")
   - `VNC_GATEWAY`: Default gateway for VNC namespace (default: "10.2.0.1")
   - `VNC_PORT`: VNC port (default: "5900", which is display :0)
   - `VNC_GEOMETRY`: Screen resolution (default: "1024x768")

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

#### Option A: Using macvlan with TigerVNC (Recommended)

Run the macvlan VNC script:
```
sudo ./macvlan_vnc.sh
```

This will:
1. Create a network namespace called "vnc_ns"
2. Create a macvlan interface linked to the physical interface
3. Move the macvlan interface to the namespace
4. Configure the interface with the specified IP address
5. Start TigerVNC server in the namespace
6. Set up port forwarding to make the VNC server accessible
7. Keep running to maintain the namespace (press Ctrl+C to stop and clean up)

The macvlan approach has several advantages:
- Doesn't remove the physical interface from the default namespace
- Creates a virtual interface in the namespace that's linked to the physical interface
- Allows for better connectivity between the namespace and the host
- More flexible and less disruptive

#### Option B: Using WayVNC (Wayland-based)

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

#### Option C: Using TigerVNC (X11-based, more compatible)

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

You can connect to the VNC server using any VNC client at the IP address and port displayed when the script runs.

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

#### Macvlan Issues (Recommended Approach)

- If you see "Operation not permitted" when creating the macvlan interface, make sure you're running the script as root
- If you see "RTNETLINK answers: File exists" when creating the macvlan interface, it might already exist. Try removing it with: `sudo ip link del macvlan0`
- If you can't connect to the VNC server:
  - Try connecting to localhost:5900 (the script sets up port forwarding)
  - Try connecting to the namespace IP directly: `vncviewer $VNC_IP:0`
  - Check if the VNC server is listening with: `sudo ip netns exec vnc_ns netstat -tuln | grep 5900`
  - Check if port forwarding is working: `sudo iptables -t nat -L PREROUTING`
  - Make sure your firewall allows connections to port 5900: `sudo ufw status`
  - Try a different VNC client (e.g., TigerVNC Viewer, RealVNC Viewer, Remmina)
- If the namespace can't reach the internet, check:
  - If the default gateway is correct: `sudo ip netns exec vnc_ns ip route`
  - If DNS is working: `sudo ip netns exec vnc_ns ping 8.8.8.8`
  - If the physical interface has internet connectivity

#### WayVNC Issues

- If WayVNC server fails to start in the namespace, check if it's already running in the default namespace
- Verify that the VNC interface has the correct IP address and can reach the gateway
- WayVNC requires a running Wayland compositor. The script sets XDG_RUNTIME_DIR and WAYLAND_DISPLAY environment variables, but you may need to:
  - Install Weston if it's not already installed: `sudo apt install weston`
  - If Weston is not available on your system, use the macvlan_vnc.sh script instead
  - If using a different Wayland compositor, adjust the WAYLAND_DISPLAY value in the script
- If you see errors about XDG_RUNTIME_DIR or WAYLAND_DISPLAY, the script attempts to set these up, but you may need to adjust them based on your system configuration
- If you see "error in libwayland error in client communication", this usually indicates a problem with the Wayland compositor. Try using the macvlan_vnc.sh script instead.

#### TigerVNC Issues

- If TigerVNC server fails to start in the namespace, check if it's already running in the default namespace
- Verify that the VNC interface has the correct IP address and can reach the gateway
- If you see "Xvnc: command not found", install TigerVNC with: `sudo apt install tigervnc-standalone-server`
- If you see "xterm: command not found", install xterm with: `sudo apt install xterm`
- The script now tries multiple approaches to start TigerVNC:
  - Basic start with minimal options
  - With explicit interface binding
  - Using the vncserver script if available
- If you have issues connecting to the VNC server:
  - Try connecting to localhost:5900 (the script sets up port forwarding)
  - Try connecting to the namespace IP directly: `vncviewer $VNC_IP:0`
  - Check if the VNC server is listening with: `sudo ip netns exec vnc_ns netstat -tuln | grep 5900`
  - Check if port forwarding is working: `sudo iptables -t nat -L PREROUTING`
  - Make sure your firewall allows connections to port 5900: `sudo ufw status`
  - Try a different VNC client (e.g., TigerVNC Viewer, RealVNC Viewer, Remmina)

### FRR Test Issues

- If OSPF adjacency fails, check if the upstream router is sending OSPF Hello packets
- Verify that the FRR interface has the correct IP address and can reach the upstream router
- Check FRR logs: `sudo tail -f /var/log/frr/zebra.log /var/log/frr/ospfd.log`

## Notes

- The scripts must be run as root (sudo)
- When you stop the VNC namespace script (Ctrl+C), it will automatically move the interface back to the default namespace and clean up
- The FRR test script will restore the original state of the interface when it completes or if an error occurs
