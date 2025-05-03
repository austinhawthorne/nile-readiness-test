# Nile Readiness Test with Network Namespace Isolation

Script to test that a network is ready to support a Nile installation. The script mimics what a Nile gateway will perform to bring up a Nile service, as well as tests some basic network services.

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
- Required Cloud Reachability for Nile Service
    - Will run a TCP SYN test via NMAP
- HTTPS and SSL Certificate Tests
    - Will test HTTPS connectivity to Nile Cloud, Amazon S3, and Nile Secure
    - Will verify SSL certificates for Nile Cloud and Amazon S3
- UDP Connectivity Check for Guest Access
    - Will test UDP connectivity to Guest Access servers on port 6081
- Additional DNS Resolution Checks
    - Will test DNS resolution using Google DNS
    - Optional custom DNS resolution check


This approach allows you to:

1. Run VNC server on one interface (e.g., end0) in a separate network namespace, the network will still show up when frr is run, so make sure to use unique address space and do not set a default gateway.  This is intended to be a directly connected interface to a laptop for testing Nile network readiness.
2. Run FRR tests on another interface (e.g., enxf0a731f41761) in the default namespace, this is a USB ethernet interface

## Scripts

- **macvlan_vnc.sh**: Script that uses macvlan to link the physical interface to the namespace for VNC
- **nrt.py**: Runs FRR tests in the default namespace without moving interfaces to namespaces

## Prerequisites

- Linux system with network namespace support
- FRR (Free Range Routing) installed
- TigerVNC server
- Python 3.6+ with required packages:
  - scapy
  - ipaddress
  - dhcppython
- Required utilities:
  - vtysh (FRR)
  - radclient (FreeRADIUS client)
  - dig (DNS lookup utility)
  - ntpdate (NTP utility)
  - curl (HTTPS test utility)
  - netcat (nc) for UDP connectivity testing
  - openssl for SSL certificate verification
  - nslookup for DNS resolution testing
- Enable Predictable names to make life easier long term since using USB ethernet interfaces

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/nile-readiness-test.git
   cd nile-readiness-test
   ```

2. Install required packages:
   ```
   sudo apt update
   sudo apt install frr freeradius dnsutils ntpdate curl python3-scapy netcat-openbsd openssl
   ```

   For a Raspberry Pi, I had to add --break-system-packages as shown below to complete the install of dhcppython
   ```
   pip3 install dhcppython --break-system-packages
   ```

   For TigerVNC:
   ```
   sudo apt install tigervnc-standalone-server xterm
   ```

3. Make the scripts executable:
   ```
   chmod +x macvlan_vnc.sh nrt.py
   ```

## Configuration

1. Edit the configuration in the VNC script:

   For `macvlan_vnc.sh`:
   - `VNC_NS`: Namespace name for VNC (default: "vnc_ns")
   - `PHYSICAL_IFACE`: Physical interface to link to (default: "end0")
   - `MACVLAN_IFACE`: Name of the macvlan interface in the namespace (default: "macvlan0")
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

**Important Note on Order of Operations:**
1. First, start the VNC server in a separate namespace using macvlan_vnc.sh
2. Then, in a separate terminal, run the nrt.py script for FRR tests
3. Keep the macvlan_vnc.sh script running while performing the nrt.py tests

### Step 1: Start VNC Server in a Separate Namespace

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

You can connect to the VNC server using any VNC client at the IP address and port displayed when the script runs.

### Step 2: Run FRR Tests in the Default Namespace

While keeping the macvlan_vnc.sh script running in its terminal, open a separate terminal and run the FRR tests:

```
sudo ./nrt.py --config nrt_config.json
```

Or run interactively:
```
sudo ./nrt.py
```

## Notes

- The scripts must be run as root (sudo)
- When you stop the VNC namespace script (Ctrl+C), it will automatically move the interface back to the default namespace and clean up
- The FRR test script will restore the original state of the interface when it completes or if an error occurs
- The nrt.py script now provides a comprehensive test summary at the end of execution, after restoring the system state
- The DHCP testing has been improved to use the dhcppython library instead of scapy for more reliable DHCP relay testing
- Only tested on Raspberry Pi, should run on any debian based distribution. 
- VNC is only used to make it easier to use a portable device like a Raspberry Pi, without carrying around monitor/keyboard.


## Dependencies Details

### Python Dependencies

- **scapy**: Used for OSPF packet sniffing
- **dhcppython**: Used for DHCP relay testing (must be installed via pip3)
- **socket**: Used for hostname resolution and SSL connectivity testing
- **re**: Used for IP address validation
- **subprocess**: Used for executing commands like netcat and openssl

### System Dependencies

- **FRR**: Free Range Routing suite for OSPF testing
- **TigerVNC**: For running the VNC server in a separate namespace
- **radclient**: For RADIUS authentication testing
- **dig**: For DNS lookup testing
- **ntpdate**: For NTP time synchronization testing
- **curl**: For HTTPS connectivity testing
- **xterm**: Used by the VNC server
- **netcat (nc)**: Used for UDP connectivity testing
- **openssl**: Used for SSL certificate verification
- **nslookup**: Used for DNS resolution testing

Make sure all dependencies are installed before running the scripts. The installation commands in the Installation section will install all required dependencies.

License

MIT License

Copyright (c) 2025 Nile Global Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
