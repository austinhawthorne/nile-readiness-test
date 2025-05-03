#!/usr/bin/env python3
"""
Test script for dhcppython library
"""

import dhcppython.client as dhcp_client
import dhcppython.options as dhcp_options
import dhcppython.utils as dhcp_utils
import socket

def main():
    # Parameters
    iface = "en0"  # Change this to your interface
    server = "192.168.1.1"  # Change this to your DHCP server
    helper_ip = "192.168.1.2"  # Change this to your relay agent IP
    
    # Create a random client MAC address
    client_mac = dhcp_utils.random_mac()
    
    print(f"Testing DHCP with dhcppython library")
    print(f"Interface: {iface}")
    print(f"Server: {server}")
    print(f"Relay Agent IP: {helper_ip}")
    print(f"Client MAC: {client_mac}")
    
    try:
        # Create DHCP client
        print(f"Creating DHCP client...")
        c = dhcp_client.DHCPClient(
            iface,
            send_from_port=67,  # Server port (for relay)
            send_to_port=67     # Server port
        )
        
        # Create a list of DHCP options
        print(f"Setting up DHCP options...")
        options_list = dhcp_options.OptionList([
            # Add standard options
            dhcp_options.options.short_value_to_object(60, "dhcp-test"),  # Class identifier
            dhcp_options.options.short_value_to_object(12, socket.gethostname()),  # Hostname
            # Parameter request list - request common options
            dhcp_options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43])
        ])
        
        print(f"Attempting to get DHCP lease from {server}...")
        # Set broadcast=False for unicast to specific server
        # Set server to the DHCP server IP
        lease = c.get_lease(
            client_mac,
            broadcast=False,
            options_list=options_list,
            server=server,
            relay=helper_ip
        )
        
        # If we get here, we got a lease
        print(f"Successfully obtained DHCP lease!")
        print(f"Lease details:")
        print(f"  Your IP: {lease.yiaddr}")
        print(f"  Server IP: {lease.siaddr}")
        print(f"  Gateway: {lease.giaddr}")
        print(f"  Options: {lease.options}")
        
    except Exception as e:
        print(f"Error during DHCP test: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
