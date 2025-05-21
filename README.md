# Nile Readiness Test (NRT)

This tool helps test network connectivity and features required for Nile Connect, including comprehensive network configuration, routing, and service validation.

## Features

- Network Interface Configuration
  - Configures test interface with specified IP address
  - Creates dummy loopback interfaces for different subnets
  - Preserves and restores original network state

- Routing Configuration and Testing
  - OSPF adjacency configuration and testing
  - Static default route fallback
  - Automatic detection of OSPF parameters (area, hello interval, dead interval)

- Service Testing
  - DNS resolution (including custom DNS servers)
  - DHCP relay functionality
  - RADIUS authentication
  - NTP synchronization (including custom NTP servers)
  - HTTPS connectivity
  - SSL certificate validation
  - UDP connectivity (port 6081) for guest access

## Requirements

- Python 3.6+
- Scapy (with OSPF module support)
- dhcppython library for DHCP testing
- Root/sudo privileges (for network operations)
- Required system tools:
  - FRR (vtysh)
  - FreeRADIUS client (radclient)
  - DNS lookup utility (dig)
  - NTP utility (ntpdate)
  - HTTPS test utility (curl)
  - Netcat (nc) for UDP connectivity testing
  - OpenSSL for SSL certificate verification

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/nile-readiness-test.git
   cd nile-readiness-test
   ```

2. Install required Python packages:
   ```
   pip install scapy dhcppython
   ```

3. Install required system tools:
   ```
   sudo apt update && sudo apt install frr freeradius-client dnsutils ntpdate curl netcat-openbsd openssl
   ```

**Note** Ensure pip is installed.  On some systems you may have to get python modules through apt.  Also, freeradius-client may only be available through freeradius package.

## Usage

### Interactive Mode

Run the script with sudo privileges:

```bash
sudo ./nrt.py
```

The script will prompt you for:
- Management interface to keep enabled
- Interface for Nile Readiness tests
- IP address, netmask, and gateway for the test interface
- NSB subnet, sensor subnet, and client subnet in CIDR notation
- DHCP server IPs (optional)
- RADIUS server IPs, shared secret, username, and password (optional)
- Custom DNS servers (optional)
- Custom NTP servers (optional)

### Configuration File Mode

Create a JSON configuration file (e.g., `nrt_config.json`):

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

Then run the script with the config file:

```bash
sudo ./nrt.py --config nrt_config.json
```

### Debug Mode

Enable debug output for more detailed information:

```bash
sudo ./nrt.py --debug
# or with config file
sudo ./nrt.py --debug --config nrt_config.json
```

## How It Works

The Nile Readiness Test performs the following steps:

1. **Pre-flight Checks**: Verifies all required tools are installed
2. **State Recording**: Records the original state of the network interface
3. **Interface Configuration**: Configures the test interface with the specified IP address
4. **Loopback Creation**: Creates dummy loopback interfaces for each subnet
5. **Static Route Configuration**: Sets up a static default route
6. **OSPF Configuration**:
   - Sniffs for OSPF Hello packets to detect parameters
   - Configures OSPF routing using FRR
   - Verifies OSPF adjacency reaches Full/DR state
7. **Connectivity Tests**:
   - DNS resolution tests
   - DHCP relay tests (if enabled)
   - RADIUS authentication tests (if enabled)
   - NTP synchronization tests
   - HTTPS connectivity tests
   - SSL certificate validation
   - UDP connectivity tests for guest access
8. **State Restoration**: Restores the original state of the network interface
9. **Test Summary**: Displays a summary of all test results

## Troubleshooting

- **Interface Configuration Fails**:
  - Verify you have permission to configure network interfaces (run as root/sudo)
  - Check if the interface exists and is not in use by another process
  - Try disabling NetworkManager or other network management tools

- **OSPF Adjacency Fails**:
  - Verify the upstream router is sending OSPF Hello packets
  - Check if there are firewall rules blocking OSPF traffic (protocol 89)
  - Ensure the OSPF parameters (area, hello interval, dead interval) match

- **DHCP Relay Tests Fail**:
  - Verify the DHCP server is reachable
  - Check if the DHCP server is configured to accept relay requests
  - Ensure the client subnet is properly configured

- **RADIUS Tests Fail**:
  - Verify the RADIUS server is reachable
  - Check if the shared secret, username, and password are correct
  - Ensure the RADIUS server is configured to accept authentication requests

- **DNS/NTP/HTTPS Tests Fail**:
  - Check if the DNS/NTP/HTTPS servers are reachable
  - Verify there are no firewall rules blocking the traffic
  - Ensure the routing is properly configured

## License

This project is licensed under the MIT License.
