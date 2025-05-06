# Nile Readiness Test

Script to test that a network is ready to support a Nile installation. The script mimics what a Nile gateway will perform to bring up a Nile service, as well as tests some basic network services.

Running this script will test:

- OSPF
    - Will listen for OSPF Hello packets and configure OSPF on FRR to build a neighbor adjacency and advertise routes for defined subnets (NSB, Sensor, Client).
    - Will fall back to static if this fails.
- DNS Reachability
    - Will try the default DNS servers for Nile
    - If that fails, will prompt for a user specified DNS server to use.
- NTP Reachability
    - Will run a test to sync with default Nile defined NTP servers from the NSB Gateway IP Address and NSB Subnet IP Address
- DHCP Server Reachability
    - Will run a synthetic test against a user defined DHCP server, from the defined client subnet
- RADIUS Reachability
    - Will run a sythentic test against a user defined RADIUS server.
- Required Cloud Reachability for Nile Service
    - Will run a socket connect from the NSB Gateway IP Address and NSB Subnet IP Address
- HTTPS and SSL Certificate Tests
    - Will test HTTPS connectivity to Nile Cloud, Amazon S3, and Nile Secure from the NSB Gateway IP Address and NSB Subnet IP Address
    - Will verify SSL certificates for Nile Cloud and Amazon S3
- UDP Connectivity Check for Guest Access
    - Will test UDP connectivity to Guest Access servers on port 6081
    - Will test for Geneve protocol support on UDP port 6081 using Scapy
    - Provides detailed troubleshooting information for Geneve protocol testing
- Additional DNS Resolution Checks
    - Will test DNS resolution using Google DNS from the NSB Subnet IP Address
    - Will use any custom DNS servers provided during initial DNS tests
    - Optional additional custom DNS resolution check

## Scripts

- **nrt.py**: Runs FRR tests in the default namespace

## Prerequisites

- Linux system with network namespace support
- FRR (Free Range Routing) installed
- Python 3.6+ with required packages:
  - scapy (with contrib.geneve module for enhanced Geneve testing)
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

   Install or upgrade Scapy with Geneve support:
   ```
   pip3 install --upgrade scapy>=2.4.3
   ```

   For a Raspberry Pi, you may need to add --break-system-packages:
   ```
   pip3 install --upgrade scapy>=2.4.3 --break-system-packages
   pip3 install dhcppython --break-system-packages
   ```

3. Make the script executable:
   ```
   chmod +x nrt.py
   ```an

## Configuration

Create a JSON configuration file for `nrt.py`:
```json
{
  "mgmt_interface": "end0",
  "test_interface": "enxf0a731f41761",
  "ip_address": "10.200.1.2",
  "netmask": "255.255.255.252",
  "gateway": "10.200.1.1",
  "nsb_subnet": "10.200.10.0/24",
  "sensor_subnet": "10.200.12.0/24",
  "client_subnet": "10.234.3.0/24",
  "run_dhcp_tests": true,
  "dhcp_servers": ["172.27.5.5"],
  "run_radius_tests": false,
  "radius_servers": [],
  "radius_secret": "",
  "radius_username": "",
  "radius_password": "",
  "run_custom_dns_tests": true,
  "custom_dns_servers": ["4.2.2.1", "1.1.1.1"],
  "run_custom_ntp_tests": false,
  "custom_ntp_servers": ["ntp.internal.example.com", "10.0.0.123"]
}

```

## Usage

Run the readiness tests:

```
sudo ./nrt.py --config nrt_config.json
```

Or run interactively:
```
sudo ./nrt.py
```

## Notes

- The script must be run as root (sudo)
- The FRR test script will restore the original state of the interface when it completes or if an error occurs
- The nrt.py script now provides a comprehensive test summary at the end of execution, after restoring the system state
- The DHCP testing has been improved to use the dhcppython library instead of scapy for more reliable DHCP relay testing
- The Geneve protocol testing includes detailed troubleshooting guidance for common issues
- Only tested on Raspberry Pi, should run on any debian based distribution.

## Dependencies Details

### Python Dependencies

- **scapy**: Used for OSPF packet sniffing and Geneve protocol testing
  - Version 2.4.3+ recommended for Geneve protocol support
  - To install Scapy with Geneve support: `pip3 install scapy>=2.4.3`
  - If you already have Scapy installed but are missing the Geneve module, you may need to upgrade: `pip3 install --upgrade scapy`
  - On some systems (like Raspberry Pi), you might need to add `--break-system-packages` flag: `pip3 install --upgrade scapy --break-system-packages`
- **dhcppython**: Used for DHCP relay testing (must be installed via pip3)
- **socket**: Used for hostname resolution and SSL connectivity testing
- **re**: Used for IP address validation
- **subprocess**: Used for executing commands like netcat and openssl

### System Dependencies

- **FRR**: Free Range Routing suite for OSPF testing
- **radclient**: For RADIUS authentication testing
- **dig**: For DNS lookup testing
- **ntpdate**: For NTP time synchronization testing
- **curl**: For HTTPS connectivity testing
- **netcat (nc)**: Used for UDP connectivity testing
- **openssl**: Used for SSL certificate verification
- **nslookup**: Used for DNS resolution testing

Make sure all dependencies are installed before running the scripts. The installation commands in the Installation section will install all required dependencies.

## License

MIT License

Copyright (c) 2025 Nile Global Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
